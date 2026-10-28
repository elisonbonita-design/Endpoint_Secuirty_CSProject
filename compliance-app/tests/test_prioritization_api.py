"""Prioritization through the web app: /api/risk, explanations with the local AI mocked, seat colours,
recompute on asset changes and the background-thread guards. No network access is used."""

import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from compliance.ai_explain import AI_LABEL, EXPLAIN_FIELDS
from webapp import prioritization
from webapp.ai_providers import AIError, AITimeout
from webapp.app import create_app

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
HEADERS = {"X-Requested-With": "compliance-dashboard"}


class FakeAI:
    model = "fake-local"

    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.prompts = answer, error, []

    def generate(self, prompt):
        self.prompts.append(prompt)
        if self.error:
            raise self.error
        return self.answer


class RiskApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "a.db"

    def tearDown(self):
        self.tmp.cleanup()

    def client(self, ai=None):
        # SCA-only sample: these tests check scoring and AI behaviour, not the other sources.
        app = create_app(login_required=False, indexer_client=None, ai_provider=ai, asset_db_path=self.db, now=lambda: NOW,
                         observations_sample_path=Path(self.tmp.name) / "no-observations.json")
        app.testing = True
        return app.test_client()

    def db_snapshot(self):
        conn = sqlite3.connect(self.db)
        try:
            return (conn.execute("SELECT * FROM findings ORDER BY id").fetchall(),
                    conn.execute("SELECT * FROM risk_scores ORDER BY id").fetchall())
        finally:
            conn.close()

    def test_risk_list_sorted_with_needs_data_separate(self):
        body = self.client().get("/api/risk?source=sample").get_json()
        self.assertEqual((body["weights_version"], body["catalogue_version"]), ("1.0", "1.3"))
        scores = [(f["score"], f["opened_at"]) for f in body["findings"]]
        self.assertEqual(scores, sorted(scores, key=lambda s: (-s[0], s[1])))
        self.assertTrue(all(f["state"] == "non_compliant" for f in body["findings"]))
        self.assertEqual(body["needs_data_count"], len(body["needs_data"]))
        self.assertTrue(body["needs_data"] and all(n["state"] == "unknown" and n["score"] is None
                                                   for n in body["needs_data"]))
        self.assertFalse(body["ai_enabled"])
        top = body["findings"][0]
        self.assertEqual((top["requirement_id"], top["severity"], top["band"]), ("REQ-PW-01", "high", "Medium"))
        self.assertTrue(top["reason"].startswith("Medium (40): Ensure minimum password length"))

    def test_fleet_reports_what_a_scan_changed(self):
        client = self.client()
        first = client.get("/api/fleet?source=sample").get_json()["scan"]
        self.assertEqual(set(first), {"created", "reopened", "cleared", "verified", "as_of"})
        self.assertGreater(first["created"], 0)
        second = client.get("/api/fleet?source=sample").get_json()["scan"]
        self.assertEqual((second["created"], second["reopened"], second["cleared"], second["verified"]),
                         (0, 0, 0, 0))

    def test_band_and_endpoint_filters(self):
        client = self.client()
        low = client.get("/api/risk?source=sample&band=low").get_json()["findings"]
        self.assertTrue(low and all(f["band"] == "Low" for f in low))
        one = client.get("/api/risk?source=sample&endpoint=S03").get_json()["findings"]
        self.assertTrue(one and all(f["endpoint_id"] == "S03" for f in one))
        self.assertEqual(client.get("/api/risk?source=sample&endpoint=../x").status_code, 400)

    def test_asset_fields_change_the_score_immediately(self):
        client = self.client()
        before = {f["id"]: f["score"] for f in client.get("/api/risk?source=sample").get_json()["findings"]
                  if f["endpoint_id"] == "S01"}
        response = client.put("/api/assets", headers=HEADERS, json={
            "key_type": "agent_id", "key_value": "S01", "department": "Finance (sample)", "building": "HQ",
            "floor": "2", "room": "201", "handles_client_data": True, "role": "team_lead"})
        self.assertEqual(response.status_code, 200)
        # Stored scores were recomputed by the asset change itself, before any page reload.
        conn = sqlite3.connect(self.db)
        stored = dict(conn.execute("SELECT finding_id, score FROM risk_scores r WHERE id = "
                                   "(SELECT MAX(id) FROM risk_scores WHERE finding_id = r.finding_id)").fetchall())
        conn.close()
        self.assertEqual({k: stored[k] for k in before}, {k: v + 20 for k, v in before.items()})
        bad = client.put("/api/assets", headers=HEADERS, json={"key_type": "agent_id", "key_value": "S01",
                                                               "role": "manager"})
        self.assertEqual(bad.status_code, 400)

    def test_seat_colours_on_the_fleet(self):
        client = self.client()
        seats = {e["key"]: e["risk"] for e in client.get("/api/fleet?source=sample").get_json()["endpoints"]}
        self.assertEqual(seats["S07"], {"band": "unknown", "letter": "?", "top_score": None, "scored": 0})  # gray
        self.assertEqual((seats["S02"]["band"], seats["S02"]["letter"]), ("clear", "✓"))  # green: nothing open
        self.assertEqual((seats["S01"]["band"], seats["S01"]["letter"]), ("medium", "M"))
        client.put("/api/assets", headers=HEADERS, json={"key_type": "agent_id", "key_value": "S01",
                                                         "handles_client_data": True, "role": "it_admin"})
        seats = {e["key"]: e["risk"] for e in client.get("/api/fleet?source=sample").get_json()["endpoints"]}
        self.assertEqual((seats["S01"]["band"], seats["S01"]["letter"], seats["S01"]["top_score"]), ("high", "H", 60))

    def explain(self, client, finding_id=None, headers=HEADERS):
        if finding_id is None:
            finding_id = client.get("/api/risk?source=sample").get_json()["findings"][0]["id"]
        return client.post("/api/risk/explain?source=sample", headers=headers, json={"finding_id": finding_id})

    def test_ai_disabled_shows_rule_based_reason_and_remediation(self):
        response = self.explain(self.client(ai=None))
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(body["ai"])
        self.assertTrue(body["explanation"].startswith("Medium (40)"))
        self.assertIn("Minimum password length to 14", body["remediation"])
        self.assertIn("rule-based", body["note"])

    def test_ai_timeout_and_errors_fall_back(self):
        for error in (AITimeout("The local AI did not respond in time."), AIError("Could not reach the local AI.")):
            with self.subTest(error=type(error).__name__):
                ai = FakeAI(error=error)
                body = self.explain(self.client(ai=ai)).get_json()
                self.assertFalse(body["ai"])
                self.assertEqual(body["explanation"], body["reason"])
                self.assertTrue(body["note"].startswith(str(error)))
                self.assertEqual(len(ai.prompts), 1)
        unreadable = self.explain(self.client(ai=FakeAI(answer="STEPS:\n1. only"))).get_json()
        self.assertFalse(unreadable["ai"])

    def test_ai_explains_only_and_never_changes_stored_data(self):
        ai = FakeAI(answer="EXPLANATION: Short passwords are easy to guess. Set the minimum to 14.\n"
                           "STEPS:\n1. Edit the Default Domain Policy.\n2. Run gpupdate.\n3. Re-assess.")
        client = self.client(ai=ai)
        client.get("/api/risk?source=sample")
        before = self.db_snapshot()
        response = self.explain(client)
        body = response.get_json()
        self.assertEqual((body["ai"], body["label"], body["model"]), (True, AI_LABEL, "fake-local"))
        self.assertEqual(AI_LABEL, "AI-generated explanation – check before acting")
        self.assertEqual(body["steps"], ["Edit the Default Domain Policy.", "Run gpupdate.", "Re-assess."])
        self.assertEqual(self.db_snapshot(), before)
        # The prompt carries exactly the allowed fields: no agent ID, IP, seat or timestamps.
        sent = json.loads(ai.prompts[0].split("FINDING (JSON): ", 1)[1].split("\n", 1)[0])
        self.assertEqual(set(sent), set(EXPLAIN_FIELDS))
        for leaked in ("192.0.2.", '"S0', "Room", "opened_at", "2026-01-01"):
            self.assertNotIn(leaked, ai.prompts[0])

    def test_daily_summary_sends_aggregates_only(self):
        ai = FakeAI(answer="Four findings are medium priority.")
        client = self.client(ai=ai)
        body = client.post("/api/risk/summary?source=sample", headers=HEADERS, json={}).get_json()
        self.assertEqual((body["ai"], body["summary"]), (True, "Four findings are medium priority."))
        self.assertEqual(sum(body["counts"]["by_band"].values()), body["counts"]["open_scored_findings"])
        for leaked in ("SAMPLE-", "password", "192.0.2."):
            self.assertNotIn(leaked, ai.prompts[0])
        off = self.client(ai=None).post("/api/risk/summary?source=sample", headers=HEADERS, json={}).get_json()
        self.assertEqual((off["ai"], off["summary"]), (False, None))

    def test_explain_requests_need_the_dashboard_header_and_a_valid_id(self):
        client = self.client()
        self.assertEqual(self.explain(client, headers={}).status_code, 403)
        self.assertEqual(self.explain(client, finding_id=999999).status_code, 404)
        self.assertEqual(self.explain(client, finding_id="1").status_code, 400)

    def test_broken_config_disables_prioritization_but_not_the_fleet(self):
        app = create_app(login_required=False, indexer_client=None, ai_provider=None, asset_db_path=self.db, risk_config=None)
        app.testing = True
        client = app.test_client()
        self.assertEqual(client.get("/api/risk?source=sample").status_code, 503)
        fleet = client.get("/api/fleet?source=sample")
        self.assertEqual(fleet.status_code, 200)
        self.assertTrue(all(e["risk"] is None for e in fleet.get_json()["endpoints"]))

    def test_old_cloud_chat_endpoint_is_gone(self):
        self.assertEqual(self.client().post("/api/assistant/chat", json={"question": "x"}).status_code, 404)


class ConcurrencyTests(unittest.TestCase):
    def test_background_recompute_and_requests_do_not_lock_each_other_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app(login_required=False, indexer_client=None, ai_provider=None, asset_db_path=Path(tmp) / "a.db", now=lambda: NOW)
            app.testing = True
            app.test_client().get("/api/risk?source=sample")
            service = app.extensions["risk_service"]()
            errors, stop = [], threading.Event()

            def background():
                while not stop.is_set():
                    try:
                        service.recompute()
                    except Exception as e:  # noqa: BLE001 - any failure fails the test
                        errors.append(e)

            def requests(n):
                client = app.test_client()
                for i in range(15):
                    for response in (client.get("/api/risk?source=sample"), client.put(
                            "/api/assets", headers=HEADERS, json={"key_type": "agent_id", "key_value": f"S0{n}",
                                                                  "handles_client_data": i % 2 == 0})):
                        if response.status_code != 200:
                            errors.append(response.get_data(as_text=True))

            workers = [threading.Thread(target=background)] + [threading.Thread(target=requests, args=(n,))
                                                                for n in (1, 2)]
            for w in workers:
                w.start()
            for w in workers[1:]:
                w.join(60)
            stop.set()
            workers[0].join(10)
            self.assertEqual(errors, [])


class BackgroundThreadTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(prioritization._refresher, {"started": False}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_create_app_starts_no_thread(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(prioritization, "start_background_recompute") \
                as start:
            before = {t.name for t in threading.enumerate()}
            app = create_app(login_required=False, indexer_client=None, ai_provider=None, asset_db_path=Path(tmp) / "a.db")
            app.test_client().get("/api/risk?source=sample")
            start.assert_not_called()
            self.assertNotIn("risk-recompute", {t.name for t in threading.enumerate()} - before)

    def test_starts_once_and_not_in_the_reloader_parent(self):
        service = mock.Mock()
        with mock.patch.object(prioritization.threading, "Thread") as thread:
            self.assertFalse(prioritization.start_background_recompute(service, debug=True, environ={}))
            self.assertFalse(prioritization.start_background_recompute(
                service, environ={"COMPLIANCE_DISABLE_BACKGROUND": "1"}))
            self.assertFalse(prioritization.start_background_recompute(None, environ={}))
            thread.assert_not_called()
            self.assertTrue(prioritization.start_background_recompute(
                service, debug=True, environ={"WERKZEUG_RUN_MAIN": "true"}))
            self.assertFalse(prioritization.start_background_recompute(service, environ={}))
            self.assertEqual(thread.call_count, 1)
            self.assertTrue(thread.call_args.kwargs["daemon"])

    def test_loop_recomputes_and_survives_errors(self):
        service = mock.Mock()
        calls = []

        def recompute():
            calls.append(1)
            if len(calls) == 1:
                raise sqlite3.OperationalError("database is locked")
            return {}
        service.recompute.side_effect = recompute
        with self.assertLogs("webapp.prioritization", "ERROR"):
            self.assertTrue(prioritization.start_background_recompute(service, interval=0.01, environ={}))
            deadline = threading.Event()
            for _ in range(200):
                if service.recompute.call_count >= 3:
                    break
                deadline.wait(0.01)
        prioritization._refresher["stop"].set()
        self.assertGreaterEqual(service.recompute.call_count, 3)


if __name__ == "__main__":
    unittest.main()
