import io
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from compliance.fleet import (build_endpoint, classify_connectivity, classify_endpoint,
                              expected_from_description, group_documents_by_agent, prioritize_failures,
                              summarize_fleet)
from compliance.scoring import compute_compliance_score
from compliance.wazuh_alerts import (alert_to_document, monitoring_response_to_agents,
                                     sca_activity_response)
from webapp.app import create_app
from webapp.assets_db import AssetError, AssetStore

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
HEADERS = {"X-Requested-With": "compliance-dashboard"}


def doc(check_id, result, agent_id="001", name="pc-a", policy="P", **check):
    return {"check": {"id": check_id, "name": f"Check {check_id}", "result": result, **check},
            "policy": {"name": policy}, "agent": {"id": agent_id, "name": name},
            "state": {"modified_at": "2026-01-01T09:00:00Z"}}


def alert(agent_id, name, check_id, result, ts="2026-01-01T10:00:00.000+0000"):
    return {"_source": {"timestamp": ts, "agent": {"id": agent_id, "name": name},
                        "data": {"sca": {"type": "check", "policy": "CIS Test",
                                         "check": {"id": check_id, "title": f"Check {check_id}", "result": result,
                                                   "compliance": {"cis": "1.1"}, "command": ["net accounts"]}}}}}


class FakeFleetIndexer:
    """Answers the three query kinds the live fleet issues, keyed by index and agent."""

    def __init__(self, monitoring, activity, checks):
        self.monitoring, self.activity, self.checks, self.calls = monitoring, activity, checks, []

    def search(self, index, body):
        self.calls.append(index)
        if index == "wazuh-monitoring-*":
            return {"hits": {"hits": [{"_source": a} for a in self.monitoring]}}
        if "aggs" in body:
            return {"aggregations": {"agents": {"buckets": [
                {"key": k, "last_event": {"value_as_string": v}, "name": {"buckets": []}}
                for k, v in self.activity.items()]}}}
        agent_id = next(f["term"]["agent.id"] for f in body["query"]["bool"]["filter"] if "agent.id" in f.get("term", {}))
        return {"hits": {"hits": self.checks.get(agent_id, [])}}


class StatusClassificationTests(unittest.TestCase):
    def counts(self, *results):
        return compute_compliance_score([{"check": {"result": r}} for r in results])

    def test_endpoint_status(self):
        self.assertEqual(classify_endpoint(self.counts("passed", "failed")), "noncompliant")
        self.assertEqual(classify_endpoint(self.counts("passed", "not applicable")), "compliant")
        # Unknown results are never treated as passes.
        self.assertEqual(classify_endpoint(self.counts("passed", None)), "unknown")
        self.assertEqual(classify_endpoint(self.counts("passed", "not run")), "unknown")
        self.assertEqual(classify_endpoint(self.counts("not applicable")), "unknown")
        self.assertEqual(classify_endpoint(self.counts()), "unknown")

    def test_connectivity(self):
        self.assertEqual(classify_connectivity("active", "2026-01-01T11:59:00+00:00", NOW), "online")
        self.assertEqual(classify_connectivity("active", "2025-12-31T09:00:00Z", NOW), "stale")
        for status in ("disconnected", "pending", "never_connected"):
            self.assertEqual(classify_connectivity(status, "2026-01-01T11:59:00Z", NOW), "offline")
        self.assertEqual(classify_connectivity(None, None, NOW), "unknown")

    def test_check_labels_keep_unknown_and_not_applicable_separate(self):
        e = build_endpoint("001", {}, [doc("1", "passed"), doc("2", "failed"), doc("3", "Not applicable"),
                                       doc("4", None), doc("5", "weird")], None, NOW)
        self.assertEqual([c["label"] for c in e["checks"]],
                         ["Compliant", "Noncompliant", "Not applicable", "Unknown", "Unknown"])
        self.assertEqual(e["counts"]["not_applicable"], 1)
        self.assertEqual(e["counts"]["unknown"], 2)

    def test_expected_only_from_stated_recommendation(self):
        self.assertEqual(expected_from_description("Text. The recommended state for this setting is: Disabled."),
                         "Disabled")
        self.assertIsNone(expected_from_description("No recommendation sentence here."))
        self.assertIsNone(expected_from_description(None))


class AssociationTests(unittest.TestCase):
    def test_documents_grouped_by_their_own_agent_id(self):
        docs = [doc("1", "passed", "001"), doc("1", "failed", "002"), {"check": {"id": "x", "result": "passed"}}]
        by_agent, unattributed = group_documents_by_agent(docs)
        self.assertEqual(sorted(by_agent), ["001", "002"])
        self.assertEqual(by_agent["002"][0]["check"]["result"], "failed")
        self.assertEqual(unattributed, 1)

    def test_live_fleet_attributes_checks_to_the_correct_agent(self):
        fake = FakeFleetIndexer(
            monitoring=[{"id": "001", "name": "pc-a", "status": "active", "lastKeepAlive": "2026-01-01T11:59:00+00:00"},
                        {"id": "002", "name": "pc-b", "status": "disconnected", "lastKeepAlive": "2025-12-01T00:00:00+00:00"},
                        {"id": "003", "name": "pc-c", "status": "active", "lastKeepAlive": "2026-01-01T11:59:00+00:00"}],
            activity={"001": "2026-01-01T10:05:00.000Z", "002": "2025-12-01T00:00:00.000Z"},
            checks={"001": [alert("001", "pc-a", "1", "passed"), alert("001", "pc-a", "2", "passed"),
                            alert("999", "intruder", "3", "failed")],  # wrong agent.id must be dropped
                    "002": [alert("002", "pc-b", "1", "failed")]})
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        app = create_app(login_required=False, indexer_client=fake, ai_provider=None, asset_db_path=Path(tmp) / "a.db", now=lambda: NOW)
        body = app.test_client().get("/api/fleet?source=wazuh").get_json()
        by_id = {e["agent_id"]: e for e in body["endpoints"]}
        self.assertEqual(body["source"]["is_sample"], False)
        self.assertEqual(by_id["001"]["counts"]["total"], 2)
        self.assertEqual(by_id["001"]["status"], "compliant")
        self.assertEqual(by_id["001"]["last_assessment"], "2026-01-01T10:05:00Z")
        self.assertEqual(by_id["002"]["status"], "noncompliant")
        self.assertEqual(by_id["002"]["connectivity"], "offline")
        # Agent with no SCA data: no checks, unknown status, no assessment time, never "compliant".
        self.assertEqual(by_id["003"]["counts"]["total"], 0)
        self.assertEqual(by_id["003"]["status"], "unknown")
        self.assertIsNone(by_id["003"]["last_assessment"])
        self.assertNotIn("999", by_id)
        self.assertEqual(body["summary"]["pcs"]["offline_or_stale"], 1)

        detail = app.test_client().get("/api/fleet/endpoint?source=wazuh&id=001").get_json()["endpoint"]
        self.assertEqual({c["id"] for c in detail["checks"]}, {"1", "2"})
        self.assertEqual(detail["checks"][0]["targets"], {"command": ["net accounts"]})

    def test_live_fleet_not_configured(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        app = create_app(login_required=False, indexer_client=None, ai_provider=None, asset_db_path=Path(tmp) / "a.db")
        response = app.test_client().get("/api/fleet?source=wazuh")
        self.assertEqual(response.status_code, 503)


class WazuhParsingTests(unittest.TestCase):
    def test_monitoring_keeps_newest_snapshot_per_agent(self):
        agents = monitoring_response_to_agents({"hits": {"hits": [
            {"_source": {"id": "001", "name": "pc", "status": "active", "lastKeepAlive": "t2", "os": {"name": "Win"}}},
            {"_source": {"id": "001", "name": "pc", "status": "disconnected", "lastKeepAlive": "t1"}},
            {"_source": {"name": "no-id"}}]}})
        self.assertEqual(list(agents), ["001"])
        self.assertEqual(agents["001"]["status"], "active")
        self.assertEqual(agents["001"]["os"], "Win")

    def test_activity_and_targets(self):
        activity = sca_activity_response({"aggregations": {"agents": {"buckets": [
            {"key": "001", "last_event": {"value_as_string": "2026-01-01T00:00:00.000Z"},
             "name": {"buckets": [{"key": "pc"}]}}]}}})
        self.assertEqual(activity, {"001": {"last_event": "2026-01-01T00:00:00.000Z", "name": "pc"}})
        with self.assertRaises(ValueError):
            sca_activity_response({})
        mapped = alert_to_document(alert("001", "pc", "1", "failed")["_source"])
        self.assertEqual(mapped["check"]["targets"], {"command": ["net accounts"]})


class AssetStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = AssetStore(Path(self.tmp) / "assets.db")

    def test_agent_id_beats_hostname_and_hostname_is_case_insensitive(self):
        self.store.upsert("hostname", "PC-A", {"department": "By host"})
        find = self.store.lookup_table()
        self.assertEqual(find("001", "pc-a")["department"], "By host")
        self.store.upsert("agent_id", "001", {"department": "By agent", "floor": 2})
        find = self.store.lookup_table()
        self.assertEqual(find("001", "PC-A")["department"], "By agent")
        self.assertEqual(find("001", "PC-A")["floor"], "2")
        self.assertIsNone(find("002", "other"))

    def test_upsert_updates_and_persists(self):
        self.store.upsert("agent_id", "001", {"department": "A", "room": "1"})
        self.store.upsert("agent_id", "001", {"department": "B"})
        rows = AssetStore(Path(self.tmp) / "assets.db").all()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["department"], rows[0]["room"]), ("B", None))

    def test_validation(self):
        for key_type, key, fields in (("mac", "x", {}), ("agent_id", "", {}), ("agent_id", "0 1", {}),
                                      ("hostname", "-bad", {}), ("agent_id", "001", {"department": "x" * 101}),
                                      ("agent_id", "001", {"room": "a\x00b"}), ("agent_id", "001", {"floor": ["2"]})):
            with self.subTest(key=key, fields=fields), self.assertRaises(AssetError):
                self.store.upsert(key_type, key, fields)

    def test_csv_import_is_all_or_nothing(self):
        good = "agent_id,hostname,department,building,floor,room\n001,,Finance,HQ,2,201\n,PC-B,HR,,,\n"
        self.assertEqual(self.store.import_csv(good), 2)
        self.assertEqual(self.store.lookup_table()(None, "pc-b")["department"], "HR")
        with self.assertRaises(AssetError) as ctx:
            self.store.import_csv("agent_id,department\n002,IT\n,Missing key\n")
        self.assertIn("Line 3", str(ctx.exception))
        self.assertIsNone(self.store.lookup_table()("002", None))
        with self.assertRaises(AssetError):
            self.store.import_csv("department,room\nIT,1\n")


class FleetApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        app = create_app(login_required=False, indexer_client=None, ai_provider=None, asset_db_path=Path(self.tmp) / "a.db")
        app.testing = True
        self.client = app.test_client()

    def fleet(self):
        return {e["agent_id"]: e for e in self.client.get("/api/fleet").get_json()["endpoints"]}

    def test_sample_fleet_is_labelled_and_summarised(self):
        body = self.client.get("/api/fleet?source=sample").get_json()
        self.assertTrue(body["source"]["is_sample"])
        self.assertIn("Sample", body["source"]["label"])
        pcs = body["summary"]["pcs"]
        self.assertEqual(pcs["total"], pcs["compliant"] + pcs["noncompliant"] + pcs["unknown"])
        self.assertNotIn("checks", body["endpoints"][0])
        self.assertEqual(self.client.get("/api/fleet?source=other").status_code, 400)

    def test_missing_metadata_shows_unassigned_and_is_never_guessed(self):
        e = self.fleet()["S06"]  # hostname SAMPLE-LAB-01 has no assignment
        self.assertEqual(e["department"], "Unassigned")
        self.assertFalse(e["assigned"])
        self.assertEqual(e["location"], {"department": None, "building": None, "floor": None, "room": None})
        never = self.fleet()["S07"]  # never-connected agent with no SCA data
        self.assertEqual((never["status"], never["connectivity"], never["last_assessment"]),
                         ("unknown", "offline", None))

    def test_saved_assignment_overrides_and_requires_dashboard_header(self):
        payload = {"key_type": "agent_id", "key_value": "S06", "department": "Lab", "floor": "4"}
        self.assertEqual(self.client.put("/api/assets", json=payload).status_code, 403)
        response = self.client.put("/api/assets", json=payload, headers=HEADERS)
        self.assertEqual(response.status_code, 200)
        e = self.fleet()["S06"]
        self.assertEqual((e["department"], e["location"]["floor"], e["assigned"]), ("Lab", "4", True))
        self.assertEqual(self.client.delete("/api/assets", json=payload, headers=HEADERS).status_code, 200)
        self.assertEqual(self.fleet()["S06"]["department"], "Unassigned")
        self.assertEqual(self.client.delete("/api/assets", json=payload, headers=HEADERS).status_code, 404)

    def test_invalid_assignment_rejected(self):
        response = self.client.put("/api/assets", json={"key_type": "agent_id", "key_value": "<x>"}, headers=HEADERS)
        self.assertEqual(response.status_code, 400)
        self.assertIn("not valid", response.get_json()["error"])

    def test_csv_import_endpoint(self):
        data = {"file": (io.BytesIO(b"agent_id,department,room\nS07,Reception,R1\n"), "a.csv")}
        self.assertEqual(self.client.post("/api/assets/import", data=data).status_code, 403)
        data = {"file": (io.BytesIO(b"agent_id,department,room\nS07,Reception,R1\n"), "a.csv")}
        response = self.client.post("/api/assets/import", data=data, headers=HEADERS)
        self.assertEqual(response.get_json()["imported"], 1)
        self.assertEqual(self.fleet()["S07"]["department"], "Reception")

    def test_endpoint_details(self):
        body = self.client.get("/api/fleet/endpoint?id=S01").get_json()
        e = body["endpoint"]
        self.assertTrue(all(c.get("assessed_at") for c in e["checks"]))
        failed = [c for c in e["checks"] if c["status"] == "failed"]
        self.assertTrue(failed and all(c["label"] == "Noncompliant" and c["remediation"] for c in failed))
        self.assertEqual(self.client.get("/api/fleet/endpoint?id=NOPE").status_code, 404)
        self.assertEqual(self.client.get("/api/fleet/endpoint?id=../x").status_code, 400)

    def test_findings_endpoint(self):
        body = self.client.get("/api/fleet/findings").get_json()
        self.assertIn("no risk score", body["basis"])
        affected = [g["affected"] for g in body["findings"]]
        self.assertEqual(affected, sorted(affected, reverse=True))

    def test_existing_routes_still_work(self):
        self.assertEqual(self.client.get("/api/sample").status_code, 200)
        self.assertIn("Configuration Compliance", self.client.get("/").get_data(as_text=True))


class PrioritizationTests(unittest.TestCase):
    def endpoint(self, agent_id, department, docs):
        return build_endpoint(agent_id, {"name": f"pc-{agent_id}"}, docs,
                              {"department": department} if department else None, NOW)

    def test_groups_repeated_failures_and_orders_by_observed_spread(self):
        endpoints = [
            self.endpoint("001", "Finance", [doc("A", "failed", "001", compliance={"cis": ["1"], "pci": ["2"]}),
                                             doc("B", "failed", "001")]),
            self.endpoint("002", "HR", [doc("A", "failed", "002", compliance={"cis": ["1"]}),
                                        doc("B", "passed", "002")]),
            self.endpoint("003", None, [doc("A", "passed", "003"), doc("B", None, "003")]),
        ]
        groups = prioritize_failures(endpoints)
        self.assertEqual([g["id"] for g in groups], ["A", "B"])
        a = groups[0]
        self.assertEqual(a["affected"], 2)
        self.assertEqual(a["reported_on"], 3)
        self.assertEqual(a["departments"], ["Finance", "HR"])
        self.assertEqual(a["frameworks"], {"cis": ["1"], "pci": ["2"]})
        self.assertIn("Fails on 2 endpoints of 3", a["why"][0])
        # Unknown results count neither as passed nor as reported.
        self.assertEqual(groups[1]["reported_on"], 2)
        summary = summarize_fleet(endpoints)
        self.assertEqual(summary["pcs"]["unassigned"], 1)
        self.assertEqual(summary["departments"][-1]["name"], "Unassigned")


if __name__ == "__main__":
    unittest.main()
