"""Per-PC requirement compliance (separate from the CIS benchmark score)."""

import tempfile
import unittest
from pathlib import Path

from compliance.requirement_status import evaluate_endpoint, requirement_sources
from webapp.app import create_app
from webapp.prioritization import load_risk_config

CONFIG = load_risk_config()


def result(rid, status, title="check"):
    return {"requirement_id": rid, "status": status, "title": title, "source": "sca"}


def finding(rid, state, status, title="finding"):
    return {"requirement_id": rid, "state": state, "status": status, "title": title}


def status_of(view, rid):
    return next(r for r in view["requirements"] if r["id"] == rid)


class RequirementStatusTests(unittest.TestCase):
    def evaluate(self, results=(), findings=(), coverage=None):
        return evaluate_endpoint(CONFIG, list(results), list(findings), coverage or {}, {"REQ-AC-03": ["4720"]})

    def test_sources_come_from_the_config(self):
        sources = requirement_sources(CONFIG)
        self.assertEqual(sources["REQ-AV-01"], {"sca", "event"})   # SCA 99002/26395 + event 5001
        self.assertEqual(sources["REQ-BL-02"], {"bitlocker"})
        self.assertEqual(sources["REQ-FI-01"], {"fim"})
        self.assertEqual(sources["REQ-NP-01"], {"ports"})

    def test_open_finding_beats_a_passing_check(self):
        view = self.evaluate([result("REQ-AV-01", "passed")], [finding("REQ-AV-01", "non_compliant", "open", "Defender off (event 5001)")])
        r = status_of(view, "REQ-AV-01")
        self.assertEqual((r["status"], r["evidence"]), ("non_compliant", ["Open finding: Defender off (event 5001)"]))
        fixed = self.evaluate(findings=[finding("REQ-AV-01", "non_compliant", "fixed_pending")])
        self.assertEqual(status_of(fixed, "REQ-AV-01")["status"], "non_compliant")   # not verified yet

    def test_exception_cleared_and_verified(self):
        self.assertEqual(status_of(self.evaluate(findings=[finding("REQ-AC-04", "non_compliant", "exception")]),
                                   "REQ-AC-04")["status"], "exception")
        verified = status_of(self.evaluate(findings=[finding("REQ-AC-01", "compliant", "verified", "Lockout")]), "REQ-AC-01")
        self.assertEqual((verified["status"], verified["evidence"]), ("compliant", ["Verified fix: Lockout"]))
        cleared = status_of(self.evaluate([result("REQ-PW-01", "passed", "Min length")],
                                          [finding("REQ-PW-01", "compliant", "cleared", "Min length")]), "REQ-PW-01")
        self.assertEqual(cleared["evidence"], ["Passed: Min length"])   # not listed twice

    def test_unknown_not_applicable_and_no_data(self):
        self.assertEqual(status_of(self.evaluate([result("REQ-SB-01", "unknown")]), "REQ-SB-01")["status"], "unknown")
        self.assertEqual(status_of(self.evaluate([result("REQ-SB-01", "not_applicable")]), "REQ-SB-01")["status"],
                         "not_applicable")
        nodata = status_of(self.evaluate(), "REQ-BL-02")
        self.assertEqual(nodata["status"], "no_data")
        self.assertIn("no BitLocker collector report", nodata["evidence"][0])

    def test_coverage_is_weak_evidence_only_when_the_source_was_read(self):
        self.assertEqual(status_of(self.evaluate(), "REQ-AC-03")["status"], "no_data")
        covered = status_of(self.evaluate(coverage={"event": True}), "REQ-AC-03")
        self.assertEqual((covered["status"], covered["evidence"]), ("compliant", ["No event 4720 in the last 30 days"]))
        # An unknown SCA result wins over "no event seen": an undecided assessment is not a pass.
        mixed = status_of(self.evaluate([result("REQ-AV-01", "unknown")], coverage={"event": True}), "REQ-AV-01")
        self.assertEqual(mixed["status"], "unknown")
        self.assertEqual(status_of(self.evaluate(coverage={"software": False}), "REQ-SW-01")["status"], "no_data")

    def test_rate_counts_only_decided_requirements(self):
        view = self.evaluate([result("REQ-PW-01", "passed"), result("REQ-PW-02", "passed"), result("REQ-SB-01", "unknown")],
                             [finding("REQ-AC-01", "non_compliant", "open"), finding("REQ-AC-04", "non_compliant", "exception")])
        s = view["summary"]
        self.assertEqual((s["compliant"], s["non_compliant"], s["exception"], s["unknown"]), (2, 1, 1, 1))
        self.assertEqual(s["compliance_rate"], round(2 / 3 * 100, 2))
        self.assertEqual(s["total"], len(CONFIG["catalogue"]["requirements"]))
        self.assertIsNone(self.evaluate()["summary"]["compliance_rate"])   # nothing decided: no rate, not 0 or 100


class RequirementApiTests(unittest.TestCase):
    def test_endpoint_has_both_measures(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app(login_required=False, indexer_client=None, ai_provider=None, asset_db_path=Path(tmp) / "a.db")
            client = app.test_client()
            e = client.get("/api/fleet/endpoint?source=sample&id=S01").get_json()["endpoint"]
            self.assertIsNotNone(e["counts"]["pass_percentage"])                    # CIS benchmark (raw SCA)
            self.assertEqual(e["requirement_summary"]["total"], len(e["requirements"]))  # selected requirements
            open_ids = {r["id"] for r in e["requirements"] if r["status"] == "non_compliant"}
            risk = client.get("/api/risk?source=sample&endpoint=S01").get_json()["findings"]
            self.assertEqual(open_ids, {f["requirement_id"] for f in risk if f["requirement_id"]})
            listed = client.get("/api/fleet?source=sample").get_json()["endpoints"][0]
            self.assertIn("requirement_summary", listed)
            self.assertNotIn("requirements", listed)                               # list stays small


if __name__ == "__main__":
    unittest.main()
