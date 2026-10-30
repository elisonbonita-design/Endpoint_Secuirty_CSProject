"""'Scan now' on live data: the Wazuh API client, the rescan request and the progress check."""

import json
import ssl
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from compliance.wazuh_alerts import rescan_progress_query, rescan_progress_response
from tests.test_fleet import FakeFleetIndexer
from tests.test_indexer import FakeConnection, FakeResponse
from webapp import indexer
from webapp.app import create_app
from webapp.wazuh_api import WazuhApiClient, WazuhApiConfig, WazuhApiError, client_from_env

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
HEADERS = {"X-Requested-With": "compliance-dashboard"}
TEST_PASSWORD = "not-a-real-password-123"
_REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context
ENV = {
    "WAZUH_API_URL": "https://127.0.0.1:55000",
    "WAZUH_API_USERNAME": "scan-restart",
    "WAZUH_API_PASSWORD": TEST_PASSWORD,
    "WAZUH_API_CA_FILE": "api.pem",
    "WAZUH_API_TLS_SERVER_NAME": "localhost",
}


def make_api(env=ENV):
    with mock.patch.object(indexer.ssl, "create_default_context",
                           side_effect=lambda cafile=None: _REAL_CREATE_DEFAULT_CONTEXT()):
        return WazuhApiClient(WazuhApiConfig.from_env(env))


class SequenceConnections:
    """Hands out one FakeConnection per request, in order."""

    def __init__(self, *responses):
        self.connections = [FakeConnection(r) for r in responses]
        self.used = []

    def __call__(self):
        conn = self.connections[len(self.used)]
        self.used.append(conn)
        return conn


class WazuhApiClientTests(unittest.TestCase):
    def test_config_requires_all_values(self):
        for missing in ("WAZUH_API_URL", "WAZUH_API_USERNAME", "WAZUH_API_PASSWORD", "WAZUH_API_CA_FILE"):
            with self.subTest(missing=missing):
                self.assertIsNone(WazuhApiConfig.from_env({k: v for k, v in ENV.items() if k != missing}))
        self.assertNotIn(TEST_PASSWORD, repr(WazuhApiConfig.from_env(ENV)))

    def test_hosts_outside_the_lab_are_refused(self):
        self.assertIsNone(client_from_env(dict(ENV, WAZUH_API_URL="https://192.168.100.70:55000")))
        with self.assertRaises(ValueError):
            make_api(dict(ENV, WAZUH_API_URL="http://127.0.0.1:55000"))

    def test_restart_logs_in_then_restarts_only_the_requested_agents(self):
        api = make_api()
        conns = SequenceConnections(
            FakeResponse(200, {"data": {"token": "jwt-token"}}),
            FakeResponse(200, {"data": {"affected_items": ["001"], "failed_items": [
                {"error": {"code": 1707, "message": "Cannot send request, agent is not active"}, "id": ["002"]}]}}))
        with mock.patch.object(api, "_connection", side_effect=conns):
            restarted, failed = api.restart_agents(["002", "001", "001"])
        self.assertEqual(restarted, ["001"])
        self.assertEqual(failed, {"002": "Cannot send request, agent is not active"})
        login, restart = conns.used[0].requests[0], conns.used[1].requests[0]
        self.assertEqual(login[:2], ("POST", "/security/user/authenticate"))
        self.assertTrue(login[3]["Authorization"].startswith("Basic "))
        self.assertEqual(restart[:2], ("PUT", "/agents/restart?agents_list=001%2C002"))
        self.assertEqual(restart[3]["Authorization"], "Bearer jwt-token")

    def test_no_agents_means_no_request(self):
        api = make_api()
        with mock.patch.object(api, "_connection", side_effect=AssertionError("no request expected")):
            self.assertEqual(api.restart_agents([]), ([], {}))

    def test_refused_account_gives_a_safe_message(self):
        api = make_api()
        with mock.patch.object(api, "_connection", side_effect=SequenceConnections(FakeResponse(401, {}))):
            with self.assertRaises(WazuhApiError) as ctx:
                api.restart_agents(["001"])
        self.assertIn("refused", str(ctx.exception))
        self.assertNotIn(TEST_PASSWORD, str(ctx.exception))

    def test_connection_failure(self):
        api = make_api()
        with mock.patch.object(api, "_connection", return_value=FakeConnection(exc=ConnectionRefusedError())):
            with self.assertRaises(WazuhApiError):
                api.restart_agents(["001"])


class MonitoringQueryTests(unittest.TestCase):
    def test_future_snapshots_are_ignored(self):
        from compliance.wazuh_alerts import agents_query
        self.assertEqual(agents_query(as_of=NOW)["query"], {"range": {"timestamp": {"lte": "2026-01-01T12:05:00Z"}}})
        self.assertNotIn("query", agents_query())


class ProgressQueryTests(unittest.TestCase):
    def test_query_filters_agents_and_time(self):
        q = rescan_progress_query(["002", "001"], "2026-01-01T12:00:00Z")
        self.assertIn({"terms": {"agent.id": ["001", "002"]}}, q["query"]["bool"]["filter"])
        self.assertIn({"range": {"timestamp": {"gte": "2026-01-01T12:00:00Z"}}}, q["query"]["bool"]["filter"])
        for bad in ([], ["1"], ["001", "abc"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                rescan_progress_query(bad, "2026-01-01T12:00:00Z")

    def test_response(self):
        response = {"aggregations": {"agents": {"buckets": [
            {"key": "001", "started": {"at": {"value_as_string": "2026-01-01T12:00:03.000Z"}},
             "scanned": {"at": {"value_as_string": "2026-01-01T12:00:41.000Z"}}},
            {"key": "002", "started": {"at": {"value": None}}, "scanned": {}}]}}}
        self.assertEqual(rescan_progress_response(response), {
            "001": {"started": "2026-01-01T12:00:03.000Z", "scanned": "2026-01-01T12:00:41.000Z"},
            "002": {"started": None, "scanned": None}})
        with self.assertRaises(ValueError):
            rescan_progress_response({"hits": {}})


class FakeApi:
    def __init__(self, restarted=None, failed=None, exc=None):
        self.restarted, self.failed, self.exc, self.calls = restarted, failed or {}, exc, []

    def restart_agents(self, agent_ids):
        self.calls.append(list(agent_ids))
        if self.exc:
            raise self.exc
        return (self.restarted if self.restarted is not None else sorted(agent_ids)), self.failed


class ScanIndexer(FakeFleetIndexer):
    """A live fleet plus answers to the rescan progress query."""

    def __init__(self, progress=None):
        super().__init__(
            monitoring=[{"id": "001", "name": "WS01", "status": "active", "lastKeepAlive": "2026-01-01T11:59:00+00:00"},
                        {"id": "002", "name": "WS02", "status": "disconnected",
                         "lastKeepAlive": "2025-12-01T00:00:00+00:00"}],
            activity={"001": "2026-01-01T10:00:00.000Z"}, checks={})
        self.progress = progress or {}

    def search(self, index, body):
        if "started" in body.get("aggs", {}).get("agents", {}).get("aggs", {}):
            self.calls.append("progress")
            return {"aggregations": {"agents": {"buckets": [
                {"key": k, "started": {"at": {"value_as_string": v.get("started")}},
                 "scanned": {"at": {"value_as_string": v.get("scanned")}}} for k, v in self.progress.items()]}}}
        return super().search(index, body)


class ScanRouteTests(unittest.TestCase):
    def client(self, indexer_client, api, now=NOW):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        app = create_app(login_required=False, indexer_client=indexer_client, ai_provider=None, risk_config=None,
                         asset_db_path=Path(tmp) / "a.db", now=lambda: now, wazuh_api=api)
        app.testing = True
        return app.test_client()

    def test_request_asks_wazuh_for_every_agent(self):
        # 002 looks disconnected in the monitoring snapshot, which can be stale: Wazuh decides.
        api = FakeApi(restarted=["001"], failed={"002": "Cannot send request, agent is not active"})
        response = self.client(ScanIndexer(), api).post("/api/scan/request?source=wazuh", headers=HEADERS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(api.calls, [["001", "002"]])
        self.assertEqual(response.get_json(), {"requested_at": "2026-01-01T12:00:00Z", "agents": ["001"],
                                               "failed": {"002": "Cannot send request, agent is not active"}})

    def test_request_needs_the_dashboard_header_and_live_source(self):
        api = FakeApi()
        client = self.client(ScanIndexer(), api)
        self.assertEqual(client.post("/api/scan/request?source=wazuh").status_code, 403)
        self.assertEqual(client.post("/api/scan/request?source=sample", headers=HEADERS).status_code, 400)
        self.assertEqual(api.calls, [])

    def test_request_without_api_config_says_so(self):
        response = self.client(ScanIndexer(), None).post("/api/scan/request?source=wazuh", headers=HEADERS)
        self.assertEqual(response.status_code, 503)
        self.assertIn("not configured", response.get_json()["error"])

    def test_api_failure_is_reported(self):
        api = FakeApi(exc=WazuhApiError("Could not connect to the Wazuh API. Is the Wazuh manager running?"))
        response = self.client(ScanIndexer(), api).post("/api/scan/request?source=wazuh", headers=HEADERS)
        self.assertEqual(response.status_code, 502)
        self.assertIn("Wazuh API", response.get_json()["error"])

    def test_progress(self):
        since = "2026-01-01T12:00:00Z"
        cases = {
            "waiting for restart": ({}, NOW + timedelta(seconds=10), False),
            "restarted, scanning": ({"001": {"started": "2026-01-01T12:00:03.000Z"}}, NOW + timedelta(seconds=30), False),
            "summary received": ({"001": {"started": "2026-01-01T12:00:03.000Z", "scanned": "2026-01-01T12:00:41.000Z"}},
                                 NOW + timedelta(seconds=45), True),
            "no change, settled": ({"001": {"started": "2026-01-01T12:00:03.000Z"}}, NOW + timedelta(seconds=100), True),
        }
        for name, (progress, now, done) in cases.items():
            with self.subTest(name):
                body = self.client(ScanIndexer(progress), FakeApi(), now).get(
                    f"/api/scan/progress?agents=001&since={since}").get_json()
                self.assertEqual(body["done"], done)
                self.assertEqual(body["agents"]["001"]["done"], done)

    def test_progress_rejects_bad_input(self):
        client = self.client(ScanIndexer(), FakeApi())
        for query in ("agents=&since=2026-01-01T12:00:00Z", "agents=1&since=2026-01-01T12:00:00Z",
                      "agents=001&since=yesterday"):
            with self.subTest(query=query):
                self.assertEqual(client.get(f"/api/scan/progress?{query}").status_code, 400)


if __name__ == "__main__":
    unittest.main()
