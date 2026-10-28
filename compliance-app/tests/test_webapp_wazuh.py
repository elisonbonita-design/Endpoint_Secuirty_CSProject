import json
import unittest
from pathlib import Path
from unittest import mock

from tests.test_indexer import ENV, TEST_PASSWORD, FakeConnection, make_client
from webapp.app import create_app
from webapp.indexer import IndexerError

FIXTURES = Path(__file__).parent / "fixtures"


class FakeIndexer:
    def __init__(self, response=None, exc=None):
        self.response, self.exc, self.calls = response, exc, []

    def search(self, index, body):
        self.calls.append((index, body))
        if self.exc:
            raise self.exc
        return self.response


def fixture_response():
    return json.loads((FIXTURES / "wazuh_4x_sca_search_response.json").read_text(encoding="utf-8"))


class WazuhRouteTests(unittest.TestCase):
    def client_for(self, indexer):
        app = create_app(login_required=False, indexer_client=indexer)
        app.testing = True
        return app.test_client()

    def test_live_style_report(self):
        fake = FakeIndexer(fixture_response())
        response = self.client_for(fake).get("/api/wazuh/sca?agent_id=001")
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["overall"],
                         {"passed": 1, "failed": 1, "not_applicable": 1, "unknown": 0, "total": 3, "pass_percentage": 50.0})
        self.assertEqual(report["frameworks"]["pci_dss_v4.0"]["total"], 2)
        self.assertEqual(report["findings"][0]["name"], "Ensure remote assistance is disabled.")
        self.assertEqual(report["source"], "Wazuh agent 001 (test-agent) · Sample Windows Benchmark v1.0.0")
        self.assertFalse(report["truncated"])

        index, body = fake.calls[0]
        self.assertEqual(index, "wazuh-alerts-4.x-*")
        self.assertIn({"term": {"agent.id": "001"}}, body["query"]["bool"]["filter"])

    def test_invalid_agent_id_never_reaches_indexer(self):
        fake = FakeIndexer(fixture_response())
        client = self.client_for(fake)
        for query in ("", "?agent_id=", "?agent_id=1", "?agent_id=abc", "?agent_id=001%0A",
                      "?agent_id=*", '?agent_id=001"}'):
            with self.subTest(query=query):
                response = client.get(f"/api/wazuh/sca{query}")
                self.assertEqual(response.status_code, 400)
                self.assertIn("agent ID", response.get_json()["error"])
        self.assertEqual(fake.calls, [])

    def test_not_configured(self):
        response = self.client_for(None).get("/api/wazuh/sca?agent_id=001")
        self.assertEqual(response.status_code, 503)
        self.assertIn("not configured", response.get_json()["error"])

    def test_indexer_error(self):
        fake = FakeIndexer(exc=IndexerError("Could not connect to the Wazuh Indexer."))
        response = self.client_for(fake).get("/api/wazuh/sca?agent_id=001")
        self.assertEqual(response.status_code, 502)
        self.assertIn("Could not connect", response.get_json()["error"])

    def test_no_results(self):
        response = self.client_for(FakeIndexer({"hits": {"hits": []}})).get("/api/wazuh/sca?agent_id=002")
        self.assertEqual(response.status_code, 404)
        self.assertIn("agent 002", response.get_json()["error"])

    def test_unexpected_indexer_data(self):
        for bad in ({}, {"hits": {"hits": [{"_source": {"data": {}}}]}}):
            with self.subTest(response=bad):
                response = self.client_for(FakeIndexer(bad)).get("/api/wazuh/sca?agent_id=001")
                self.assertEqual(response.status_code, 400)
                self.assertIn("Unsupported SCA data", response.get_json()["error"])

    def test_sample_and_upload_still_work_when_indexer_configured(self):
        client = self.client_for(FakeIndexer(fixture_response()))
        self.assertEqual(client.get("/api/sample").status_code, 200)
        import io
        response = client.post("/api/upload", data={"file": (io.BytesIO(b"[]"), "r.json")},
                               content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)

    def test_credentials_never_reach_the_browser(self):
        real_client = make_client()
        app = create_app(login_required=False, indexer_client=real_client)
        app.testing = True
        client = app.test_client()
        with mock.patch.object(real_client, "_connection",
                               return_value=FakeConnection(exc=ConnectionRefusedError())):
            api = client.get("/api/wazuh/sca?agent_id=001")
        self.assertEqual(api.status_code, 502)
        pages = [api, client.get("/"), client.get("/static/app.js"), client.get("/api/sample")]
        for page in pages:
            body = page.get_data(as_text=True)
            for secret in (TEST_PASSWORD, ENV["WAZUH_INDEXER_USERNAME"] + ":"):
                self.assertNotIn(secret, body)
            page.close()

    def test_client_built_from_environment(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            app = create_app(login_required=False)
        app.testing = True
        self.assertEqual(app.test_client().get("/api/wazuh/sca?agent_id=001").status_code, 503)


if __name__ == "__main__":
    unittest.main()
