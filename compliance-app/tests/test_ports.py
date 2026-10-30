"""Approved listening ports (REQ-NP-01): what is checked, the managed list, its routes and the findings."""

import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from compliance import sources, wazuh_sources
from webapp.app import create_app
from webapp.ports_db import PortError, PortStore

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
HEADERS = {"X-Requested-With": "compliance-dashboard"}


def temp_db(test):
    tmp = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, tmp, True)
    return Path(tmp) / "a.db"


def port(number, process, transport="tcp", local_only=False):
    return {"port": number, "transport": transport, "process": process, "processes": [process],
            "addresses": ["127.0.0.1"] if local_only else ["0.0.0.0"], "local_only": local_only}


WS01 = [port(445, "System"), port(3389, "svchost.exe"), port(42050, "OneDrive.exe", local_only=True),
        port(5353, "svchost.exe", "udp"), port(49664, "lsass.exe"), port(49675, "lsass.exe"),
        port(49674, "spoolsv.exe")]


class PortChecksTests(unittest.TestCase):
    def test_only_network_reachable_tcp_is_checked(self):
        checks, skipped = sources.port_checks(WS01, frozenset({445}), ("lsass.exe",))
        self.assertEqual([(s["port"], s["reason"]) for s in skipped],
                         [(42050, "only this PC can connect"), (5353, "UDP")])
        by_key = {c["key"]: c for c in checks}
        self.assertEqual(sorted(by_key), ["port:tcp:3389", "port:tcp:445", "port:tcp:dyn:lsass.exe",
                                          "port:tcp:dyn:spoolsv.exe"])
        self.assertTrue(by_key["port:tcp:445"]["approved"])
        self.assertFalse(by_key["port:tcp:3389"]["approved"])
        self.assertEqual(by_key["port:tcp:3389"]["title"], "Unapproved listening port 3389/tcp (svchost.exe)")
        # Dynamic ports are grouped per program and approved by program, case-insensitively.
        self.assertEqual(by_key["port:tcp:dyn:lsass.exe"]["ports"], [49664, 49675])
        self.assertTrue(by_key["port:tcp:dyn:lsass.exe"]["approved"])
        upper = {c["key"]: c for c in sources.port_checks(WS01, frozenset(), ("LSASS.EXE",))[0]}
        self.assertTrue(upper["port:tcp:dyn:lsass.exe"]["approved"])
        self.assertEqual(by_key["port:tcp:dyn:spoolsv.exe"]["kind"], "program")
        self.assertFalse(by_key["port:tcp:dyn:spoolsv.exe"]["approved"])

    def test_rule_findings(self):
        endpoint = {"key": "001", "label": "WS01"}
        out = sources.inventory_results([endpoint], {}, {"001": WS01}, set(), {"001"}, {}, (), frozenset({445}),
                                        {"requirements": {}}, NOW, approved_programs=("lsass.exe",))
        self.assertEqual(sorted(r["check_key"] for r in out), ["port:tcp:3389", "port:tcp:dyn:spoolsv.exe"])
        self.assertTrue(all(r["requirement_id"] == "REQ-NP-01" and r["status"] == "failed" for r in out))
        # No approved entries at all: the rule stays off.
        self.assertEqual(sources.inventory_results([endpoint], {}, {"001": WS01}, set(), {"001"}, {}, (), frozenset(),
                                                   {"requirements": {}}, NOW), [])

    def test_ports_response_keeps_addresses_and_programs(self):
        hits = {"hits": {"hits": [
            {"_source": {"agent": {"id": "001"}, "source": {"ip": "0.0.0.0", "port": 445}, "network": {"transport": "tcp"},
                         "interface": {"state": "listening"}, "process": {"name": "System"}}},
            {"_source": {"agent": {"id": "001"}, "source": {"ip": "::", "port": 445}, "network": {"transport": "tcp6"},
                         "interface": {"state": "listening"}, "process": {"name": "System"}}},
            {"_source": {"agent": {"id": "001"}, "source": {"ip": "::1", "port": 42050}, "network": {"transport": "tcp6"},
                         "interface": {"state": "listening"}, "process": {"name": "OneDrive.exe"}}},
            {"_source": {"agent": {"id": "001"}, "source": {"ip": "127.0.0.1", "port": 42050},
                         "network": {"transport": "tcp"}, "interface": {"state": "listening"}}}]}}
        by_port = {p["port"]: p for p in wazuh_sources.ports_response(hits)["001"]}
        self.assertEqual(by_port[445]["addresses"], ["0.0.0.0", "::"])
        self.assertFalse(by_port[445]["local_only"])
        self.assertTrue(by_port[42050]["local_only"])
        self.assertEqual(by_port[42050]["processes"], ["OneDrive.exe"])
        self.assertIn("source.ip", wazuh_sources.ports_query()["_source"])


class PortStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = PortStore(temp_db(self))

    def test_add_remove_policy_and_history(self):
        self.store.add("port", "3389", "Remote support", "admin", NOW)
        self.store.add("port", 445, None, "admin", NOW)
        self.store.add("program", "lsass.exe", None, "admin", NOW)
        self.assertEqual(self.store.policy(), (frozenset({445, 3389}), ("lsass.exe",)))
        rdp = next(e for e in self.store.entries() if e["value"] == "3389")
        self.assertEqual(self.store.remove(rdp["id"], "RDP turned off", "admin2", NOW + timedelta(hours=1)),
                         ("port", "3389"))
        self.assertEqual([(h["action"], h["kind"], h["value"]) for h in self.store.history()][0],
                         ("removed", "port", "3389"))

    def test_entries_are_validated(self):
        for kind, value in (("port", "0"), ("port", "65536"), ("port", "49664"), ("port", "abc"), ("port", None),
                            ("program", ""), ("program", r"C:\Windows\lsass.exe"), ("program", "x" * 101),
                            ("program", "a*b"), ("service", "445")):
            with self.subTest(kind=kind, value=value), self.assertRaises(PortError):
                self.store.add(kind, value, None, "admin", NOW)

    def test_duplicates_without_case(self):
        self.store.add("program", "lsass.exe", None, "admin", NOW)
        with self.assertRaises(PortError):
            self.store.add("program", "LSASS.EXE", None, "admin", NOW)
        self.assertEqual(self.store.add_many([("port", " 445 "), ("port", "445")], None, "admin", NOW), [("port", "445")])

    def test_seed_runs_once_and_skips_dynamic(self):
        self.assertEqual(self.store.seed({445, 135, 50000}, NOW), [("port", "135"), ("port", "445")])
        for e in self.store.entries():
            self.store.remove(e["id"], None, "admin", NOW)
        self.assertEqual(self.store.seed({445}, NOW), [])


class LiveIndexer:
    """One online agent (001) with SCA activity and a port inventory."""

    def __init__(self, ports):
        self.ports = ports

    def search(self, index, body):
        if index == "wazuh-monitoring-*":
            return {"hits": {"hits": [{"_source": {"id": "001", "name": "WS01", "status": "active",
                                                   "lastKeepAlive": "2026-01-01T11:59:00+00:00"}}]}}
        if index == wazuh_sources.PORTS_INDEX:
            return {"hits": {"hits": [{"_source": {"agent": {"id": "001"}, "source": {"ip": ip, "port": number},
                                                   "network": {"transport": "tcp"}, "interface": {"state": "listening"},
                                                   "process": {"name": proc}}} for number, proc, ip in self.ports]}}
        if "aggs" in body and index.startswith("wazuh-alerts"):
            return {"aggregations": {"agents": {"buckets": [
                {"key": "001", "last_event": {"value_as_string": "2026-01-01T11:00:00.000Z"}, "name": {"buckets": []}}]}}}
        return {"hits": {"hits": []}}


LIVE_PORTS = [(445, "System", "0.0.0.0"), (3389, "svchost.exe", "0.0.0.0"), (49664, "lsass.exe", "0.0.0.0"),
              (42050, "OneDrive.exe", "::1")]


class PortRouteTests(unittest.TestCase):
    def client(self, ports=LIVE_PORTS):
        app = create_app(login_required=False, indexer_client=LiveIndexer(ports), ai_provider=None,
                         asset_db_path=temp_db(self), now=lambda: NOW, wazuh_api=None)
        app.testing = True
        return app.test_client()

    def post(self, client, url, body, method="post"):
        return getattr(client, method)(url, json=body, headers=HEADERS)

    def open_port_findings(self, client):
        body = client.get("/api/risk?source=wazuh").get_json()
        return sorted(f["title"] for f in body["findings"] if f["requirement_id"] == "REQ-NP-01")

    def test_view_and_rule_off_while_empty(self):
        client = self.client()
        view = client.get("/api/ports/listening?source=wazuh&id=001").get_json()
        self.assertFalse(view["rule_on"])
        self.assertEqual([(c["kind"], c["value"]) for c in view["checks"]],
                         [("port", "445"), ("port", "3389"), ("program", "lsass.exe")])
        self.assertEqual([s["port"] for s in view["skipped"]], [42050])
        self.assertEqual(self.open_port_findings(client), [])

    def test_unapproved_port_opens_a_finding_and_approving_clears_it(self):
        client = self.client()
        self.post(client, "/api/ports", {"kind": "port", "value": "445", "note": "File sharing"})
        self.post(client, "/api/ports", {"kind": "program", "value": "lsass.exe"})
        self.assertEqual(self.open_port_findings(client), ["Unapproved listening port 3389/tcp (svchost.exe)"])
        self.post(client, "/api/ports", {"kind": "port", "value": "3389", "note": "Approved for IT support"})
        self.assertEqual(self.open_port_findings(client), [])

    def test_baseline_then_removal_reopens(self):
        client = self.client()
        body = self.post(client, "/api/ports/approve-listening?source=wazuh", {"endpoint_id": "001"}).get_json()
        self.assertEqual(body["added"], [{"kind": "port", "value": "445"}, {"kind": "port", "value": "3389"},
                                         {"kind": "program", "value": "lsass.exe"}])
        self.assertEqual(self.open_port_findings(client), [])
        rdp = next(e for e in body["entries"] if e["value"] == "3389")
        self.post(client, f"/api/ports/{rdp['id']}", {"note": "RDP no longer allowed"}, "delete")
        self.assertEqual(self.open_port_findings(client), ["Unapproved listening port 3389/tcp (svchost.exe)"])

    def test_sample_keeps_its_own_list(self):
        client = self.client()
        view = client.get("/api/ports/listening?source=sample&id=S05").get_json()
        self.assertTrue(view["sample_list"])
        self.assertEqual([(c["value"], c["approved"]) for c in view["checks"]], [("445", True), ("3389", False)])
        self.assertEqual(self.post(client, "/api/ports/approve-listening?source=sample",
                                   {"endpoint_id": "S05"}).status_code, 400)

    def test_bad_requests(self):
        client = self.client()
        self.assertEqual(client.post("/api/ports", json={"kind": "port", "value": "3389"}).status_code, 403)
        self.assertEqual(self.post(client, "/api/ports", {"kind": "port", "value": "50000"}).status_code, 400)
        self.assertEqual(self.post(client, "/api/ports/999", {}, "delete").status_code, 400)
        self.assertEqual(client.get("/api/ports/listening?source=wazuh&id=../x").status_code, 400)


class PortPermissionTests(unittest.TestCase):
    def test_reviewer_can_view_but_not_change(self):
        db = temp_db(self)
        app = create_app(indexer_client=LiveIndexer(LIVE_PORTS), ai_provider=None, asset_db_path=db, now=lambda: NOW,
                         wazuh_api=None, secret_key="test-secret")
        app.testing = True
        from webapp.auth import UserStore
        UserStore(db).create("reviewer1", "a-long-test-password", "reviewer", NOW)
        client = app.test_client()
        client.post("/login", data={"username": "reviewer1", "password": "a-long-test-password"})
        self.assertEqual(client.get("/api/ports").status_code, 200)
        self.assertEqual(client.post("/api/ports", json={"kind": "port", "value": "3389"}, headers=HEADERS).status_code, 403)
        self.assertEqual(client.post("/api/ports/approve-listening?source=wazuh", json={"endpoint_id": "001"},
                                     headers=HEADERS).status_code, 403)


if __name__ == "__main__":
    unittest.main()
