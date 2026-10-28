"""Login and roles, the finding workflow and its audit trail, the compliance report and the BitLocker collector."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webapp.app import create_app
from webapp.auth import AuthError, UserStore
from webapp.collector import ReportRejected, parse_report
from webapp.findings_db import FindingStore

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
H = {"X-Requested-With": "compliance-dashboard"}
PASSWORD = "synthetic-lab-pass-1"  # test fixture only, not a real credential
TOKEN = "t" * 40


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "a.db"
        self.clock = Clock()
        self.users = UserStore(self.db)
        self.users.create("admin1", PASSWORD, "admin", NOW)
        self.users.create("rev1", PASSWORD, "reviewer", NOW)
        self.app = create_app(indexer_client=None, ai_provider=None, asset_db_path=self.db, now=self.clock,
                              secret_key="k" * 64, collector_token=TOKEN)
        self.app.testing = True

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, username="admin1", password=PASSWORD):
        client = self.app.test_client()
        response = client.post("/login", data={"username": username, "password": password})
        return client, response


class AuthTests(Base):
    def test_pages_and_api_need_a_session(self):
        client = self.app.test_client()
        self.assertEqual(client.get("/").status_code, 302)
        self.assertEqual(client.get("/api/fleet?source=sample").status_code, 401)
        self.assertEqual(client.get("/report").status_code, 302)
        self.assertEqual(client.get("/login").status_code, 200)
        self.assertEqual(client.get("/static/app.css").status_code, 200)

    def test_login_logout_and_cookie_flags(self):
        client, response = self.login()
        self.assertEqual(response.status_code, 302)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(client.get("/api/me").get_json()["role"], "admin")
        self.assertEqual(client.post("/logout").status_code, 403)  # needs the dashboard header
        self.assertEqual(client.post("/logout", headers=H).status_code, 200)
        self.assertEqual(client.get("/api/me").status_code, 401)

    def test_wrong_password_and_lockout(self):
        for _ in range(5):
            self.assertEqual(self.login(password="wrong-password-123")[1].status_code, 401)
        locked = self.login()[1]
        self.assertEqual(locked.status_code, 429)
        self.assertIn("Too many failed sign-ins", locked.get_data(as_text=True))
        self.clock.now = NOW + timedelta(minutes=16)
        self.assertEqual(self.login()[1].status_code, 302)
        self.assertEqual(self.login(username="nobody")[1].status_code, 401)

    def test_cross_site_login_rejected(self):
        client = self.app.test_client()
        response = client.post("/login", data={"username": "admin1", "password": PASSWORD},
                               headers={"Origin": "http://evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_disabled_account_loses_access_immediately(self):
        client, _ = self.login("rev1")
        rev = next(u for u in self.users.all() if u["username"] == "rev1")
        self.users.update(rev["id"], active=False)
        self.assertEqual(client.get("/api/me").status_code, 401)

    def test_roles(self):
        reviewer, _ = self.login("rev1")
        self.assertEqual(reviewer.get("/api/users").status_code, 403)
        self.assertEqual(reviewer.put("/api/assets", headers=H, json={"key_type": "agent_id", "key_value": "S01"}).status_code, 403)
        admin, _ = self.login()
        self.assertEqual(admin.put("/api/assets", headers=H, json={"key_type": "agent_id", "key_value": "S01"}).status_code, 200)
        created = admin.post("/api/users", headers=H, json={"username": "rev2", "password": PASSWORD, "role": "reviewer"})
        self.assertEqual(created.status_code, 200)
        self.assertEqual(admin.post("/api/users", headers=H, json={"username": "rev3", "password": "short",
                                                                   "role": "reviewer"}).status_code, 400)
        me = next(u for u in admin.get("/api/users").get_json()["users"] if u["username"] == "admin1")
        self.assertEqual(admin.patch(f"/api/users/{me['id']}", headers=H, json={"role": "reviewer"}).status_code, 400)

    def test_user_store_rules(self):
        with self.assertRaises(AuthError):
            self.users.create("admin1", PASSWORD, "admin", NOW)
        with self.assertRaises(AuthError):
            self.users.create("x", PASSWORD, "admin", NOW)
        admin = next(u for u in self.users.all() if u["username"] == "admin1")
        with self.assertRaises(AuthError):
            self.users.update(admin["id"], role="reviewer")  # last active admin
        conn_hash = self.users.authenticate("admin1", PASSWORD, NOW)
        self.assertEqual(conn_hash["role"], "admin")


class WorkflowTests(Base):
    def first_finding(self, client, source="sca"):
        findings = client.get("/api/risk?source=sample").get_json()["findings"]
        return next(f for f in findings if f["source"] == source)

    def test_reviewer_flow_and_history(self):
        client, _ = self.login("rev1")
        f = self.first_finding(client)
        detail = client.get(f"/api/findings/{f['id']}?source=sample").get_json()
        self.assertEqual(detail["allowed"], ["in_review", "fixed_pending"])  # no exception for reviewers
        self.assertEqual(detail["history"][0]["kind"], "created")
        url = f"/api/findings/{f['id']}/status?source=sample"
        self.assertEqual(client.post(url, headers=H, json={"status": "fixed_pending"}).status_code, 400)  # note needed
        self.assertEqual(client.post(url, headers=H, json={"status": "verified", "note": "x"}).status_code, 400)
        self.assertEqual(client.post(url, headers=H, json={"status": "exception", "note": "x"}).status_code, 403)
        self.assertEqual(client.post(url, headers=H, json={"status": "in_review"}).status_code, 200)
        done = client.post(url, headers=H, json={"status": "fixed_pending", "note": "Set GPO value, ran gpupdate"})
        self.assertEqual(done.get_json()["finding"]["status"], "fixed_pending")
        client.post(f"/api/findings/{f['id']}/notes?source=sample", headers=H, json={"note": "Waiting for next scan"})
        history = client.get(f"/api/findings/{f['id']}?source=sample").get_json()["history"]
        self.assertEqual([(h["kind"], h["actor"]) for h in history][-3:],
                         [("status", "rev1"), ("status", "rev1"), ("note", "rev1")])
        # Still failing in the sample data, so the next assessment does not verify it.
        self.assertEqual(client.get(f"/api/findings/{f['id']}?source=sample").get_json()["finding"]["status"],
                         "fixed_pending")
        self.assertNotIn(f["id"], [x["id"] for x in client.get("/api/risk?source=sample").get_json()["findings"]
                                   if x["status"] == "verified"])

    def test_admin_exception_removes_score_and_can_be_revoked(self):
        client, _ = self.login()
        f = self.first_finding(client)
        url = f"/api/findings/{f['id']}/status?source=sample"
        self.assertEqual(client.post(url, headers=H, json={"status": "exception"}).status_code, 400)
        r = client.post(url, headers=H, json={"status": "exception", "note": "Lab kiosk, accepted until rebuild"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(f["id"], [x["id"] for x in client.get("/api/risk?source=sample").get_json()["findings"]])
        client.post(url, headers=H, json={"status": "open", "note": "Exception withdrawn"})
        self.assertIn(f["id"], [x["id"] for x in client.get("/api/risk?source=sample").get_json()["findings"]])

    def test_sync_verifies_only_after_a_later_passing_assessment(self):
        store = FindingStore(self.db)
        client, _ = self.login("rev1")
        client.get("/api/risk?source=sample")
        catalogue = self.app.extensions["risk_service"]().config["catalogue"]
        payload = lambda status, at: [{"endpoint_id": "S01", "endpoint_label": "SAMPLE-FIN-01", "checks": [
            {"policy": "Sample Hardening Policy", "id": "S2", "name": "Ensure minimum password length is 14 or more characters.",
             "status": status, "assessed_at": at.strftime("%Y-%m-%dT%H:%M:%SZ")}]}]
        f = next(x for x in store.all("sample") if x["endpoint_id"] == "S01" and x["check_key"].endswith("::S2"))
        client.post(f"/api/findings/{f['id']}/status?source=sample", headers=H,
                    json={"status": "fixed_pending", "note": "GPO applied"})
        store.sync("sample", payload("passed", NOW + timedelta(hours=1)), catalogue, NOW + timedelta(hours=2))
        after = store.get(f["id"])
        self.assertEqual((after["status"], after["verified_at"]), ("verified", "2026-10-23T13:00:00Z"))
        self.assertEqual(store.history(f["id"])[-1]["actor"], "system")


class ReportTests(Base):
    def test_report_page_and_csv(self):
        client, _ = self.login("rev1")
        page = client.get("/report?source=sample")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        for text in ("Endpoint Compliance Report", "Open findings by priority", "Needs data", "rev1 (reviewer)",
                     "fictional sample data", "History ("):
            self.assertIn(text, html)
        csv_body = client.get("/api/reports/findings.csv?source=sample")
        self.assertEqual(csv_body.mimetype, "text/csv")
        lines = csv_body.get_data(as_text=True).splitlines()
        self.assertTrue(lines[0].startswith("id,endpoint_label,endpoint_id,seat,source"))
        self.assertGreater(len(lines), 10)

    def test_csv_cells_cannot_become_formulas(self):
        from webapp.routes_workflow import _csv_cell
        self.assertEqual(_csv_cell("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual(_csv_cell("-2"), "'-2")
        self.assertEqual(_csv_cell("WS01"), "WS01")


class CollectorTests(Base):
    BODY = {"hostname": "WS01", "collected_at": "2026-10-23T11:50:00Z", "volumes": [
        {"mount_point": "C:", "volume_type": "OperatingSystem", "volume_status": "FullyEncrypted",
         "protection_status": "Off", "encryption_percentage": 100, "encryption_method": "XtsAes256",
         "lock_status": "Unlocked"}]}

    def post(self, body, token=TOKEN):
        return self.app.test_client().post("/api/collector/bitlocker", json=body,
                                           headers={"Authorization": f"Bearer {token}"} if token else {})

    def test_token_required(self):
        self.assertEqual(self.post(self.BODY, token=None).status_code, 401)
        self.assertEqual(self.post(self.BODY, token="x" * 40).status_code, 401)
        app = create_app(indexer_client=None, ai_provider=None, asset_db_path=self.db, secret_key="k" * 64,
                         collector_token=None)
        self.assertEqual(app.test_client().post("/api/collector/bitlocker", json=self.BODY).status_code, 503)

    def test_report_stored_and_evaluated(self):
        response = self.post(self.BODY)
        self.assertEqual(response.get_json(), {"stored": 1, "hostname": "WS01"})
        reports = FindingStore(self.db).latest_bitlocker_reports()
        self.assertEqual(reports["ws01"][0]["protection_status"], "Off")

    def test_recovery_material_is_rejected_and_nothing_stored(self):
        for leak in ({"recovery_password": "000000-000000"}, {"KeyProtector": []}):
            body = {**self.BODY, "volumes": [{**self.BODY["volumes"][0], **leak}]}
            response = self.post(body)
            self.assertEqual(response.status_code, 400)
            self.assertIn("never be sent", response.get_json()["error"])
        self.assertEqual(FindingStore(self.db).latest_bitlocker_reports(), {})

    def test_report_validation(self):
        cases = [{**self.BODY, "hostname": "bad host"}, {**self.BODY, "collected_at": "yesterday"},
                 {**self.BODY, "collected_at": "2026-10-24T12:00:00Z"}, {**self.BODY, "volumes": []},
                 {**self.BODY, "extra": 1},
                 {**self.BODY, "volumes": [{**self.BODY["volumes"][0], "protection_status": "Maybe"}]},
                 {**self.BODY, "volumes": [{**self.BODY["volumes"][0], "encryption_percentage": 101}]}]
        for body in cases:
            with self.subTest(body=body), self.assertRaises(ReportRejected):
                parse_report(body, NOW)


if __name__ == "__main__":
    unittest.main()
