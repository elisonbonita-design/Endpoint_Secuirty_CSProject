"""Rule-based risk scoring (compliance/risk.py) with the shipped weights and a fixed clock."""

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from compliance.risk import band_for, days_open, needs_data, score_finding, seat_band, sort_key
from compliance.risk_config import (ConfigError, load_kev, load_requirements, load_weights, match_requirement,
                                    validate_requirements, validate_weights)

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
WEIGHTS = load_weights()
REQUIREMENTS = {
    "REQ-BL-01": {"severity": "critical", "exposure": None},
    "REQ-AV-01": {"severity": "critical", "exposure": "defender_off"},
    "REQ-FW-01": {"severity": "critical", "exposure": "firewall_off"},
    "REQ-PW-01": {"severity": "high", "exposure": None},
}
AGENT = {"handles_client_data": False, "role": "agent"}
CLIENT_DATA_AGENT = {"handles_client_data": True, "role": "agent"}


def finding(fid, title, *, requirement_id=None, severity=None, source="sca", days=0, reopened=0,
            state="non_compliant", status="open", cvss=None, cve_id=None):
    return {"id": fid, "title": title, "source": source, "requirement_id": requirement_id, "severity": severity,
            "state": state, "status": status, "cvss": cvss, "cve_id": cve_id,
            "opened_at": (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"), "times_reopened": reopened}


def score(f, others=(), asset=AGENT, weights=WEIGHTS, **kwargs):
    return score_finding(f, requirements=REQUIREMENTS, endpoint_findings=[f, *others], asset=asset,
                         weights=weights, now=NOW, **kwargs)


class RequiredCasesTests(unittest.TestCase):
    def test_1_bitlocker_off_with_defender_off_on_same_endpoint(self):
        bitlocker = finding(1, "BitLocker protection off", requirement_id="REQ-BL-01", severity="critical",
                            days=4, reopened=1)
        defender = finding(2, "Defender real-time protection off", requirement_id="REQ-AV-01", severity="critical")
        result = score(bitlocker, [defender], asset=CLIENT_DATA_AGENT)
        self.assertEqual(result["parts"], {"severity": 40, "exposure": 15, "asset": 12, "time_open": 8, "repeat": 5})
        self.assertEqual((result["score"], result["band"]), (80, "Critical"))
        self.assertEqual(result["reason"],
                         "Critical (80): BitLocker protection off – critical requirement (40) + Defender real-time "
                         "protection off on this endpoint (15) + handles client data (12) + open 4 days (8) + "
                         "happened before (5)")
        self.assertEqual(result["weights_version"], "1.0")

    def test_2_vulnerability_cvss_without_requirement(self):
        vuln = finding(3, "Outdated viewer", source="vulnerability", cvss=7.8, cve_id="CVE-2099-0001", days=1)
        result = score(vuln)
        self.assertEqual(result["parts"], {"severity": 31, "exposure": 0, "asset": 0, "time_open": 2, "repeat": 0})
        self.assertEqual((result["score"], result["band"]), (33, "Low"))

    def test_3_password_length_high_requirement(self):
        pw = finding(4, "Minimum password length", requirement_id="REQ-PW-01", severity="high", days=0)
        result = score(pw, asset=CLIENT_DATA_AGENT)
        self.assertEqual(result["parts"], {"severity": 30, "exposure": 0, "asset": 12, "time_open": 0, "repeat": 0})
        self.assertEqual((result["score"], result["band"]), (42, "Medium"))

    def test_4_vulnerability_in_kev_snapshot(self):
        vuln = finding(3, "Outdated viewer", source="vulnerability", cvss=7.8, cve_id="CVE-2099-0001", days=1)
        result = score(vuln, kev_ids=frozenset({"CVE-2099-0001"}))
        self.assertEqual(result["parts"], {"severity": 31, "exposure": 25, "asset": 0, "time_open": 2, "repeat": 0})
        self.assertEqual((result["score"], result["band"]), (58, "Medium"))
        self.assertIn("CVE-2099-0001 is in the known-exploited list (25)", result["reason"])

    def test_5_exposure_and_asset_caps(self):
        target = finding(5, "Password history", requirement_id="REQ-PW-01", severity="high")
        others = [finding(6, "Defender off", requirement_id="REQ-AV-01", severity="critical"),
                  finding(7, "Firewall off", requirement_id="REQ-FW-01", severity="critical")]
        lead = {"handles_client_data": True, "role": "team_lead"}
        # Raw exposure 15 + 15 + 10 (unapproved port) = 40 -> 25; asset 12 + 8 = 20.
        result = score(target, others, asset=lead, listening_ports=(3389,), approved_ports=frozenset({443}))
        self.assertEqual(result["parts"]["exposure"], 25)
        self.assertEqual(result["parts"]["asset"], 20)
        self.assertIn("(exposure capped at 25) (25)", result["reason"])
        # Raw asset above the cap (15 + 8 = 23) is capped at 20.
        heavier = copy.deepcopy(WEIGHTS)
        heavier["asset"]["handles_client_data"] = 15
        capped = score(target, others, asset=lead, weights=heavier)
        self.assertEqual(capped["parts"]["asset"], 20)
        self.assertIn("handles client data, team lead role (asset importance capped at 20) (20)", capped["reason"])

    def test_6_defender_finding_gets_no_defender_bonus_for_itself(self):
        defender = finding(8, "Defender real-time protection off", requirement_id="REQ-AV-01", severity="critical")
        self.assertEqual(score(defender)["parts"]["exposure"], 0)
        # Another open Defender finding on the same endpoint is the same condition, not extra exposure.
        twin = finding(9, "Defender off (second check)", requirement_id="REQ-AV-01", severity="critical")
        self.assertEqual(score(defender, [twin])["parts"]["exposure"], 0)
        # A different condition (firewall off) still counts.
        firewall = finding(10, "Firewall off", requirement_id="REQ-FW-01", severity="critical")
        result = score(defender, [firewall])
        self.assertEqual(result["parts"]["exposure"], 15)
        self.assertNotIn("Defender real-time protection off on this endpoint", result["reason"])

    def test_7_band_boundaries(self):
        for value, band in ((0, "Low"), (39, "Low"), (40, "Medium"), (59, "Medium"), (60, "High"), (79, "High"),
                            (80, "Critical"), (100, "Critical")):
            with self.subTest(score=value):
                self.assertEqual(band_for(value, WEIGHTS), band)

    def test_8_unknown_and_closed_findings_are_not_scored(self):
        unknown = finding(11, "Screen lock", requirement_id="REQ-PW-01", severity="high", state="unknown")
        self.assertIsNone(score(unknown))
        self.assertTrue(needs_data(unknown))
        for status in ("verified", "cleared", "exception"):
            with self.subTest(status=status):
                self.assertIsNone(score(finding(12, "x", severity="high", requirement_id="REQ-PW-01", status=status)))
        for status in ("open", "in_review", "fixed_pending"):
            with self.subTest(status=status):
                self.assertIsNotNone(score(finding(13, "x", status=status)))
        # An unknown finding on the endpoint gives no exposure to others.
        defender_unknown = finding(14, "Defender", requirement_id="REQ-AV-01", severity="critical", state="unknown")
        self.assertEqual(score(finding(15, "x"), [defender_unknown])["parts"]["exposure"], 0)

    def test_9_weights_version_is_reported(self):
        # Storage of the version on new rows is covered in test_finding_sync.ScoreHistoryTests.
        changed = copy.deepcopy(WEIGHTS)
        changed["version"] = "1.1"
        self.assertEqual(score(finding(16, "x"), weights=changed)["weights_version"], "1.1")


class FormulaDetailTests(unittest.TestCase):
    def test_time_open_counts_full_days_and_caps(self):
        self.assertEqual(days_open(NOW - timedelta(days=3, hours=23), NOW), 3)
        self.assertEqual(days_open(NOW + timedelta(hours=1), NOW), 0)
        self.assertEqual(days_open(None, NOW), 0)
        self.assertEqual(score(finding(1, "x", days=30))["parts"]["time_open"], 10)

    def test_default_severity_and_cvss_rounding(self):
        self.assertEqual(score(finding(1, "x"))["parts"]["severity"], 10)
        self.assertEqual(score(finding(1, "x", source="vulnerability", cvss=10.0))["parts"]["severity"], 40)
        self.assertEqual(score(finding(1, "x", source="vulnerability", cvss=6.125))["parts"]["severity"], 25)
        # CVSS only counts for vulnerability findings; a requirement severity wins over CVSS.
        self.assertEqual(score(finding(1, "x", cvss=9.0))["parts"]["severity"], 10)
        both = finding(1, "x", source="vulnerability", cvss=9.9, requirement_id="REQ-PW-01", severity="high")
        self.assertEqual(score(both)["parts"]["severity"], 30)

    def test_roles_and_score_never_exceeds_100(self):
        self.assertEqual(score(finding(1, "x"), asset={"role": "shared_kiosk"})["parts"]["asset"], 4)
        self.assertEqual(score(finding(1, "x"), asset={"role": "it_admin"})["parts"]["asset"], 8)
        self.assertEqual(score(finding(1, "x"), asset={})["parts"]["asset"], 0)
        big = copy.deepcopy(WEIGHTS)
        big["severity"].update(max=100, default=100)
        self.assertEqual(score(finding(1, "x", days=9, reopened=2), weights=big)["score"], 100)

    def test_sort_score_then_oldest_first(self):
        items = [{"score": 50, "opened_at": "2026-10-20T00:00:00Z"}, {"score": 70, "opened_at": "2026-10-22T00:00:00Z"},
                 {"score": 50, "opened_at": "2026-10-01T00:00:00Z"}]
        self.assertEqual([(i["score"], i["opened_at"][:10]) for i in sorted(items, key=sort_key)],
                         [(70, "2026-10-22"), (50, "2026-10-01"), (50, "2026-10-20")])


class SeatBandTests(unittest.TestCase):
    def test_seat_colour_mapping(self):
        counts = {"passed": 3, "failed": 1, "unknown": 0}
        self.assertEqual(seat_band(["High", "Critical", "Low"], counts, WEIGHTS), "critical")
        self.assertEqual(seat_band(["Medium", "High"], counts, WEIGHTS), "high")
        self.assertEqual(seat_band(["Low"], counts, WEIGHTS), "low")
        self.assertEqual(seat_band([], counts, WEIGHTS), "clear")  # results, nothing open/scored: green
        # Only unknown / not-applicable results, or none at all: gray.
        self.assertEqual(seat_band([], {"passed": 0, "failed": 0, "unknown": 4}, WEIGHTS), "unknown")
        self.assertEqual(seat_band([], {"passed": 0, "failed": 0, "unknown": 0, "not_applicable": 2}, WEIGHTS),
                         "unknown")


class ConfigTests(unittest.TestCase):
    def test_shipped_config_is_valid(self):
        catalogue = load_requirements()
        self.assertEqual((WEIGHTS["version"], catalogue["version"]), ("1.0", "1.3"))
        self.assertEqual(catalogue["requirements"]["REQ-BL-01"]["severity"], "critical")
        self.assertEqual(catalogue["requirements"]["REQ-AV-01"]["exposure"], "defender_off")
        self.assertEqual(match_requirement(catalogue, "Capstone Windows supplementary checks v1.0", "99001"),
                         "REQ-BL-01")
        self.assertIsNone(match_requirement(catalogue, "Other policy", "99001"))
        cis = "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"
        self.assertEqual(match_requirement(catalogue, cis, "26116"), "REQ-FW-01")
        self.assertEqual(match_requirement(catalogue, cis, "26003"), "REQ-PW-01")
        for rid in ("REQ-FW-01", "REQ-FW-02", "REQ-FW-03"):
            # CIS firewall-state IDs confirmed in the VMware lab (Wazuh 4.14.9).
            self.assertEqual(len(catalogue["requirements"][rid]["sca_checks"]), 1)
            self.assertEqual(catalogue["requirements"][rid]["exposure"], "firewall_off")
        severities = {r["area"]: r["severity"] for r in catalogue["requirements"].values()}
        self.assertEqual(severities["Screen lock"], "medium")
        self.assertEqual(severities["Audit policy"], "high")

    def test_invalid_weights_and_requirements_rejected(self):
        broken = copy.deepcopy(WEIGHTS)
        del broken["exposure"]["defender_off"]
        with self.assertRaises(ConfigError):
            validate_weights(broken)
        with self.assertRaises(ConfigError):
            validate_weights({**WEIGHTS, "version": ""})
        with self.assertRaises(ConfigError):
            validate_requirements({"version": "1.0", "requirements": [
                {"id": "REQ-XX-01", "title": "t", "severity": "urgent"}]})
        with self.assertRaises(ConfigError):
            validate_requirements({"version": "1.0", "requirements": [
                {"id": "REQ-XX-01", "title": "t", "severity": "low", "sca_checks": [{"policy": "p", "id": "1"}]},
                {"id": "REQ-XX-02", "title": "t", "severity": "low", "sca_checks": [{"policy": "p", "id": "1"}]}]})

    def test_kev_snapshot_formats_and_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kev.json"
            self.assertEqual(load_kev(path), frozenset())
            path.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-0001"}, {"cveID": "bad"}]}))
            self.assertEqual(load_kev(path), frozenset({"CVE-2099-0001"}))
            path.write_text(json.dumps(["CVE-2099-0002"]))
            self.assertEqual(load_kev(path), frozenset({"CVE-2099-0002"}))
            path.write_text("{not json")
            self.assertEqual(load_kev(path), frozenset())


if __name__ == "__main__":
    unittest.main()
