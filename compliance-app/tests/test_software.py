"""Approved software (REQ-SW-01): the managed list, its routes and the findings it drives."""

import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from compliance import wazuh_sources
from webapp.app import create_app
from webapp.software_db import SoftwareError, SoftwareStore

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
HEADERS = {"X-Requested-With": "compliance-dashboard"}


def temp_db(test):
    tmp = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, tmp, True)
    return Path(tmp) / "a.db"


class SoftwareStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = SoftwareStore(temp_db(self))

    def test_add_remove_and_history(self):
        self.store.add("7-Zip 24.08 (x64)", "IT ticket 12", "admin", NOW)
        self.store.add("Microsoft Visual C++*", None, "admin", NOW)
        self.assertEqual(self.store.names(), ("7-Zip 24.08 (x64)", "Microsoft Visual C++*"))
        entry = self.store.entries()[0]
        self.assertEqual(self.store.remove(entry["id"], "no longer used", "admin2", NOW + timedelta(hours=1)),
                         "7-Zip 24.08 (x64)")
        self.assertEqual(self.store.names(), ("Microsoft Visual C++*",))
        history = self.store.history()
        self.assertEqual([(h["action"], h["name"], h["actor"]) for h in history],
                         [("removed", "7-Zip 24.08 (x64)", "admin2"), ("added", "Microsoft Visual C++*", "admin"),
                          ("added", "7-Zip 24.08 (x64)", "admin")])
        self.assertEqual(history[0]["note"], "no longer used")

    def test_duplicates_are_refused_without_case(self):
        self.store.add("Notepad++", None, "admin", NOW)
        with self.assertRaises(SoftwareError):
            self.store.add("notepad++", None, "admin", NOW)
        self.assertEqual(self.store.add_many(["NOTEPAD++", "Git"], None, "admin", NOW), ["Git"])

    def test_names_are_validated(self):
        for bad in ("", "   ", "*", "ab*", "Micro*soft", "x" * 201, "bad\x07name", None, 42):
            with self.subTest(bad=bad), self.assertRaises(SoftwareError):
                self.store.add(bad, None, "admin", NOW)
        self.assertEqual(self.store.add("  Google   Chrome ", None, "admin", NOW), "Google Chrome")

    def test_seed_runs_once(self):
        self.assertEqual(self.store.seed(("A Program", "B Program"), NOW), ["A Program", "B Program"])
        entry = self.store.entries()[0]
        self.store.remove(entry["id"], None, "admin", NOW)
        self.store.remove(self.store.entries()[0]["id"], None, "admin", NOW)
        # Emptied on purpose by an administrator: the config file must not bring the entries back.
        self.assertEqual(self.store.seed(("A Program",), NOW), [])
        self.assertEqual(self.store.names(), ())


class LiveIndexer:
    """One online agent (001) with SCA activity and a software inventory."""

    def __init__(self, packages):
        self.packages = packages

    def search(self, index, body):
        if index == "wazuh-monitoring-*":
            return {"hits": {"hits": [{"_source": {"id": "001", "name": "WS01", "status": "active",
                                                   "lastKeepAlive": "2026-01-01T11:59:00+00:00"}}]}}
        if index == wazuh_sources.PACKAGES_INDEX:
            return {"hits": {"hits": [{"_source": {"agent": {"id": "001"}, "package": {"name": n}}}
                                      for n in self.packages]}}
        if "aggs" in body and index.startswith("wazuh-alerts"):
            return {"aggregations": {"agents": {"buckets": [
                {"key": "001", "last_event": {"value_as_string": "2026-01-01T11:00:00.000Z"}, "name": {"buckets": []}}]}}}
        return {"hits": {"hits": []}}


class SoftwareRouteTests(unittest.TestCase):
    def client(self, packages=("Office Suite 2024", "Remote Tool")):
        app = create_app(login_required=False, indexer_client=LiveIndexer(packages), ai_provider=None,
                         asset_db_path=temp_db(self), now=lambda: NOW, wazuh_api=None)
        app.testing = True
        return app.test_client()

    def post(self, client, url, body, method="post"):
        return getattr(client, method)(url, json=body, headers=HEADERS)

    def open_software_findings(self, client):
        body = client.get("/api/risk?source=wazuh").get_json()
        return sorted(f["title"] for f in body["findings"] if f["requirement_id"] == "REQ-SW-01")

    def test_rule_is_off_while_the_list_is_empty(self):
        client = self.client()
        installed = client.get("/api/software/installed?source=wazuh&id=001").get_json()
        self.assertFalse(installed["rule_on"])
        self.assertEqual([p["approved"] for p in installed["programs"]], [False, False])
        self.assertEqual(self.open_software_findings(client), [])

    def test_unapproved_program_opens_a_finding_and_approving_clears_it(self):
        client = self.client()
        self.assertEqual(self.post(client, "/api/software", {"name": "Office*", "note": "Standard suite"}).status_code, 200)
        self.assertEqual(self.open_software_findings(client), ["Unapproved software installed: Remote Tool"])

        installed = client.get("/api/software/installed?source=wazuh&id=001").get_json()
        self.assertEqual(installed["programs"], [
            {"name": "Office Suite 2024", "approved": True, "matched_by": "Office*"},
            {"name": "Remote Tool", "approved": False, "matched_by": None}])

        self.post(client, "/api/software", {"name": "Remote Tool", "note": "Approved for IT support"})
        self.assertEqual(self.open_software_findings(client), [])

    def test_removing_an_entry_reopens_the_finding(self):
        client = self.client()
        listing = self.post(client, "/api/software", {"name": "Office*"}).get_json()
        self.post(client, "/api/software", {"name": "Remote Tool"})
        self.assertEqual(self.open_software_findings(client), [])
        remote = next(e for e in self.post(client, "/api/software", {"name": "Spare Entry"}).get_json()["entries"]
                      if e["name"] == "Remote Tool")
        body = self.post(client, f"/api/software/{remote['id']}", {"note": "Removed from the baseline"}, "delete").get_json()
        self.assertEqual([e["name"] for e in body["entries"]], ["Office*", "Spare Entry"])
        self.assertEqual(body["history"][0]["action"], "removed")
        self.assertEqual(self.open_software_findings(client), ["Unapproved software installed: Remote Tool"])
        self.assertTrue(listing["rule_on"])

    def test_baseline_approves_everything_installed(self):
        client = self.client()
        body = self.post(client, "/api/software/approve-installed?source=wazuh", {"endpoint_id": "001"}).get_json()
        self.assertEqual(body["added"], ["Office Suite 2024", "Remote Tool"])
        self.assertEqual(body["entries"][0]["note"], "Baseline from endpoint 001")
        again = self.post(client, "/api/software/approve-installed?source=wazuh", {"endpoint_id": "001"}).get_json()
        self.assertEqual(again["added"], [])

    def test_sample_data_keeps_its_own_list(self):
        client = self.client()
        installed = client.get("/api/software/installed?source=sample&id=S06").get_json()
        self.assertTrue(installed["sample_list"])
        self.assertEqual([p["approved"] for p in installed["programs"]], [True, True, False])
        refused = self.post(client, "/api/software/approve-installed?source=sample", {"endpoint_id": "S06"})
        self.assertEqual(refused.status_code, 400)

    def test_changes_need_the_dashboard_header_and_valid_input(self):
        client = self.client()
        self.assertEqual(client.post("/api/software", json={"name": "Remote Tool"}).status_code, 403)
        self.assertEqual(self.post(client, "/api/software", {"name": "*"}).status_code, 400)
        self.assertEqual(self.post(client, "/api/software/999", {}, "delete").status_code, 400)
        self.assertEqual(client.get("/api/software/installed?source=wazuh&id=../x").status_code, 400)
        self.assertEqual(client.get("/api/software").get_json()["entries"], [])


class SoftwarePermissionTests(unittest.TestCase):
    def test_reviewer_can_view_but_not_change(self):
        db = temp_db(self)
        app = create_app(indexer_client=LiveIndexer(()), ai_provider=None, asset_db_path=db, now=lambda: NOW,
                         wazuh_api=None, secret_key="test-secret")
        app.testing = True
        from webapp.auth import UserStore
        UserStore(db).create("reviewer1", "a-long-test-password", "reviewer", NOW)
        client = app.test_client()
        client.post("/login", data={"username": "reviewer1", "password": "a-long-test-password"})
        self.assertEqual(client.get("/api/software").status_code, 200)
        self.assertEqual(client.post("/api/software", json={"name": "Remote Tool"}, headers=HEADERS).status_code, 403)
        self.assertEqual(client.post("/api/software/approve-installed?source=wazuh", json={"endpoint_id": "001"},
                                     headers=HEADERS).status_code, 403)
        self.assertEqual(client.get("/api/software").get_json()["entries"], [])


if __name__ == "__main__":
    unittest.main()
