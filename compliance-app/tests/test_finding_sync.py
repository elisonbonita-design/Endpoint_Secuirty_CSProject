"""Finding status transitions on sync, the findings store, score history and the schema migration."""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from compliance.finding_sync import transition
from compliance.risk_config import load_requirements, load_weights
from webapp.assets_db import SCHEMA, AssetStore
from webapp.db_migrations import LATEST, migrate
from webapp.findings_db import FindingStore
from webapp.prioritization import RiskService

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
CUSTOM = "Capstone Windows supplementary checks v1.0"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class TransitionTests(unittest.TestCase):
    def row(self, status, state="non_compliant", reopened=0, changed=T0):
        return {"state": state, "status": status, "times_reopened": reopened, "verified_at": None,
                "status_changed_at": iso(changed)}

    def test_new_findings_only_for_failed_or_unknown(self):
        created = transition(None, "failed", iso(T0), T0 + timedelta(hours=1))
        self.assertEqual((created["state"], created["status"], created["times_reopened"], created["opened_at"]),
                         ("non_compliant", "open", 0, iso(T0)))
        self.assertEqual(transition(None, "unknown", None, T0)["state"], "unknown")
        self.assertIsNone(transition(None, "passed", iso(T0), T0))
        self.assertIsNone(transition(None, "not_applicable", iso(T0), T0))

    def test_pass_before_anyone_marked_it_fixed_is_cleared(self):
        for status in ("open", "in_review"):
            with self.subTest(status=status):
                self.assertEqual(transition(self.row(status), "passed", iso(T0), T0),
                                 {"state": "compliant", "status": "cleared", "status_changed_at": iso(T0)})

    def test_fixed_pending_becomes_verified_only_after_a_later_pass(self):
        marked = T0 + timedelta(hours=2)
        later = transition(self.row("fixed_pending", changed=marked), "passed", iso(marked + timedelta(minutes=5)),
                           marked + timedelta(hours=1))
        self.assertEqual((later["status"], later["verified_at"]), ("verified", iso(marked + timedelta(minutes=5))))
        # An assessment from before it was marked fixed cannot verify it.
        earlier = transition(self.row("fixed_pending", changed=marked), "passed", iso(T0), marked + timedelta(hours=1))
        self.assertEqual(earlier, {"state": "compliant"})

    def test_cleared_or_verified_finding_that_fails_again_reopens(self):
        for status in ("cleared", "verified"):
            with self.subTest(status=status):
                again = T0 + timedelta(days=3)
                changes = transition(self.row(status, state="compliant", reopened=1), "failed", iso(again),
                                     again + timedelta(minutes=1))
                self.assertEqual((changes["status"], changes["times_reopened"], changes["opened_at"],
                                  changes["verified_at"]), ("open", 2, iso(again), None))

    def test_other_statuses_keep_their_status(self):
        self.assertEqual(transition(self.row("exception"), "passed", None, T0), {"state": "compliant"})
        self.assertEqual(transition(self.row("in_review"), "failed", None, T0), {"state": "non_compliant"})
        self.assertEqual(transition(self.row("open"), "unknown", None, T0), {"state": "unknown"})
        self.assertEqual(transition(self.row("open"), "not_applicable", None, T0), {"state": "not_applicable"})
        with self.assertRaises(ValueError):
            transition(None, "maybe", None, T0)

    def test_future_assessment_time_is_clamped_to_now(self):
        self.assertEqual(transition(None, "failed", iso(T0 + timedelta(days=1)), T0)["opened_at"], iso(T0))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "a.db"
        self.store = FindingStore(self.db)
        self.catalogue = load_requirements()

    def tearDown(self):
        self.tmp.cleanup()

    def sync(self, status, when, check_id="99001", source="wazuh"):
        endpoints = [{"endpoint_id": "001", "endpoint_label": "WS01", "checks": [
            {"policy": CUSTOM, "id": check_id, "name": "BitLocker protection on", "status": status,
             "remediation": "check text", "assessed_at": iso(when)}]}]
        self.store.sync(source, endpoints, self.catalogue, when)
        return [f for f in self.store.all(source) if f["check_key"] == f"{CUSTOM}::{check_id}"]

    def test_full_lifecycle(self):
        [f] = self.sync("failed", T0)
        self.assertEqual((f["state"], f["status"], f["requirement_id"], f["severity"], f["catalogue_version"]),
                         ("non_compliant", "open", "REQ-BL-01", "critical", "1.3"))
        self.assertIn("recovery key kept in Active Directory", f["remediation"])  # requirement text wins
        [f] = self.sync("passed", T0 + timedelta(hours=1))
        self.assertEqual((f["state"], f["status"]), ("compliant", "cleared"))
        [f] = self.sync("failed", T0 + timedelta(days=1))
        self.assertEqual((f["status"], f["times_reopened"], f["opened_at"]), ("open", 1, iso(T0 + timedelta(days=1))))
        self.store.set_status(f["id"], "fixed_pending", T0 + timedelta(days=1, hours=1))
        [f] = self.sync("passed", T0 + timedelta(days=1, hours=2))
        self.assertEqual((f["status"], f["verified_at"]), ("verified", iso(T0 + timedelta(days=1, hours=2))))
        [f] = self.sync("failed", T0 + timedelta(days=2))
        self.assertEqual((f["status"], f["times_reopened"], f["verified_at"]), ("open", 2, None))

    def test_scan_tally_counts_each_kind_of_change(self):
        def tally_of(status, when):
            tally = {}
            endpoints = [{"endpoint_id": "001", "endpoint_label": "WS01", "checks": [
                {"policy": CUSTOM, "id": "99001", "name": "BitLocker protection on", "status": status,
                 "remediation": "x", "assessed_at": iso(when)}]}]
            self.store.sync("wazuh", endpoints, self.catalogue, when, tally=tally)
            return tally
        self.assertEqual(tally_of("failed", T0), {"created": 1})
        self.assertEqual(tally_of("failed", T0 + timedelta(minutes=5)), {})  # nothing changed
        self.assertEqual(tally_of("passed", T0 + timedelta(hours=1)), {"cleared": 1})
        self.assertEqual(tally_of("failed", T0 + timedelta(days=1)), {"reopened": 1})
        [f] = [f for f in self.store.all("wazuh")]
        self.store.set_status(f["id"], "fixed_pending", T0 + timedelta(days=1, hours=1))
        self.assertEqual(tally_of("passed", T0 + timedelta(days=1, hours=2)), {"verified": 1})

    def test_sources_stay_separate_and_unmapped_checks_have_no_requirement(self):
        self.catalogue = {**self.catalogue, "sca_scope": "all"}   # track every failed check
        self.sync("failed", T0, source="sample")
        [f] = self.sync("failed", T0, check_id="12345")
        self.assertIsNone(f["requirement_id"])
        self.assertIsNone(f["severity"])
        self.assertEqual(f["remediation"], "check text")
        self.assertEqual(len(self.store.all("sample")), 1)
        self.assertEqual(len(self.store.all("wazuh")), 1)

    def test_mapped_scope_only_tracks_checks_in_the_catalogue(self):
        self.assertEqual(self.catalogue["sca_scope"], "mapped")   # shipped catalogue
        self.assertEqual(self.sync("failed", T0, check_id="12345"), [])   # not in any requirement: no finding
        [f] = self.sync("failed", T0)                                    # 99001 -> REQ-BL-01
        self.assertEqual(f["requirement_id"], "REQ-BL-01")

    def test_catalogue_version_stays_with_the_finding(self):
        self.sync("failed", T0)
        newer = {**self.catalogue, "version": "2.0"}
        self.store.sync("wazuh", [{"endpoint_id": "001", "endpoint_label": "WS01", "checks": [
            {"policy": CUSTOM, "id": "99001", "name": "BitLocker protection on", "status": "failed",
             "assessed_at": iso(T0)}]}], newer, T0 + timedelta(hours=1))
        self.assertEqual(self.store.all("wazuh")[0]["catalogue_version"], "1.3")


class ScopeTests(unittest.TestCase):
    def test_rows_stored_under_scope_all_are_hidden_when_scope_is_mapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "a.db"
            store, assets = FindingStore(db), AssetStore(db)
            catalogue = load_requirements()
            checks = [{"policy": CUSTOM, "id": "99001", "name": "BitLocker", "status": "failed", "assessed_at": iso(T0)},
                      {"policy": CUSTOM, "id": "55555", "name": "Unmapped check", "status": "failed", "assessed_at": iso(T0)}]
            store.sync("wazuh", [{"endpoint_id": "001", "endpoint_label": "WS01", "checks": checks}],
                       {**catalogue, "sca_scope": "all"}, T0)
            self.assertEqual(len(store.all("wazuh")), 2)                 # both stored (as before the setting)
            config = {"weights": load_weights(), "catalogue": catalogue, "approved_ports": frozenset(),
                      "kev": frozenset()}
            service = RiskService(store, lambda: assets, config, lambda: T0)
            scored, unknown = service.prioritized("wazuh")
            self.assertEqual([f["title"] for f in scored], ["BitLocker"])  # unmapped row hidden, not deleted
            self.assertEqual(len(store.all("wazuh")), 2)
            self.assertEqual(service.seats("wazuh", [{"key": "001", "counts": {"passed": 0, "failed": 2}}])["001"]["scored"], 1)


class ScoreHistoryTests(unittest.TestCase):
    def test_9_new_weights_version_is_stored_on_new_score_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "a.db"
            store = FindingStore(db)
            assets = AssetStore(db)
            weights = load_weights()
            config = {"weights": weights, "catalogue": load_requirements(), "approved_ports": frozenset(),
                      "kev": frozenset()}
            now = T0 + timedelta(days=2)
            service = RiskService(store, lambda: assets, config, lambda: now)
            store.sync("wazuh", [{"endpoint_id": "001", "endpoint_label": "WS01", "checks": [
                {"policy": CUSTOM, "id": "99001", "name": "BitLocker", "status": "failed", "assessed_at": iso(T0)}]}],
                config["catalogue"], now)
            service.recompute()
            service.recompute()  # unchanged score: no duplicate row
            [finding] = store.all()
            self.assertEqual([r["weights_version"] for r in store.score_history(finding["id"])], ["1.0"])
            config["weights"] = {**weights, "version": "1.1"}
            service.recompute()
            history = store.score_history(finding["id"])
            self.assertEqual([r["weights_version"] for r in history], ["1.0", "1.1"])
            self.assertEqual(history[-1]["score"], 44)  # 40 critical + 4 for two days open
            self.assertTrue(history[-1]["reason"].startswith("Medium (44): BitLocker – critical requirement (40)"))


class MigrationTests(unittest.TestCase):
    def test_existing_database_is_migrated_and_rows_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "old.db"
            conn = sqlite3.connect(db)
            conn.executescript(SCHEMA)
            conn.execute("INSERT INTO asset_assignments (key_type, key_value, department, building, floor, room, "
                         "updated_at) VALUES ('agent_id', '001', 'Ops', 'HQ', '1', 'Row A Seat 3', 'x')")
            conn.commit()
            conn.close()
            store = AssetStore(db)
            [row] = store.all()
            self.assertEqual((row["room"], row["handles_client_data"], row["role"]), ("Row A Seat 3", 0, "agent"))
            self.assertEqual(migrate(db), [])  # second run is a no-op
            conn = sqlite3.connect(db)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], LATEST)
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            conn.close()
            self.assertTrue({"findings", "risk_scores"} <= tables)

    def test_asset_risk_fields_validation_and_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AssetStore(Path(tmp) / "a.db")
            store.upsert("agent_id", "001", {"department": "Ops", "role": "team_lead", "handles_client_data": True})
            store.upsert("agent_id", "001", {"department": "Ops2"})  # risk fields absent: kept
            [row] = store.all()
            self.assertEqual((row["department"], row["role"], row["handles_client_data"]), ("Ops2", "team_lead", 1))
            from webapp.assets_db import AssetError
            for bad in ({"role": "boss"}, {"handles_client_data": "maybe"}, {"handles_client_data": 1}):
                with self.subTest(bad=bad), self.assertRaises(AssetError):
                    store.upsert("agent_id", "002", bad)
            count = store.import_csv("agent_id,department,handles_client_data,role\n"
                                     "002,Support,yes,shared_kiosk\n001,Ops3,,\n")
            self.assertEqual(count, 2)
            rows = {r["key_value"]: r for r in store.all()}
            self.assertEqual((rows["002"]["handles_client_data"], rows["002"]["role"]), (1, "shared_kiosk"))
            self.assertEqual((rows["001"]["department"], rows["001"]["role"]), ("Ops3", "team_lead"))
            with self.assertRaises(AssetError):
                store.import_csv("agent_id,role\n003,boss\n")


if __name__ == "__main__":
    unittest.main()
