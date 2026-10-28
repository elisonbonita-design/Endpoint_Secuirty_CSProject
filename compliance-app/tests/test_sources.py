"""Non-SCA sources: Windows events, FIM, vulnerabilities, inventory and BitLocker (pure evaluation + parsers)."""

import unittest
from datetime import datetime, timedelta, timezone

from compliance import sources, wazuh_sources
from compliance.risk_config import load_fim_baseline, load_monitored_events, load_requirements

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
CATALOGUE = load_requirements()
MONITORED = load_monitored_events(CATALOGUE)
FIM = load_fim_baseline(CATALOGUE)
CUSTOM = "Capstone Windows supplementary checks v1.0"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def endpoint(checks=(), key="001", hostname="WS01"):
    return {"key": key, "hostname": hostname, "checks": list(checks)}


def row(status, changed, source="event", key="event:5001", title="t", requirement_id="REQ-AV-01", state="non_compliant"):
    return {"status": status, "status_changed_at": iso(changed), "state": state, "title": title,
            "requirement_id": requirement_id}


def by_key(results):
    return {(r["source"], r["check_key"]): r for r in results}


class EventTests(unittest.TestCase):
    def run_events(self, events, existing=None, checks=()):
        return by_key(sources.event_results([endpoint(checks)], {"001": events}, {"001"}, existing or {},
                                            MONITORED, CATALOGUE))

    def test_alert_opens_finding_mapped_to_requirement(self):
        out = self.run_events({"5001": {"last": iso(NOW - timedelta(hours=1)), "count": 1}})
        r = out[("event", "event:5001")]
        self.assertEqual((r["status"], r["requirement_id"]), ("failed", "REQ-AV-01"))
        self.assertIn("event 5001", r["title"])

    def test_failed_sign_ins_need_the_minimum_count(self):
        self.assertEqual(self.run_events({"4625": {"last": iso(NOW), "count": 4}}), {})
        self.assertIn(("event", "event:4625"), self.run_events({"4625": {"last": iso(NOW), "count": 5}}))

    def test_closed_finding_reopens_only_for_a_newer_alert(self):
        closed = {("001", "event", "event:4720"): row("verified", NOW - timedelta(hours=2), key="event:4720")}
        self.assertEqual(self.run_events({"4720": {"last": iso(NOW - timedelta(hours=3)), "count": 1}}, closed), {})
        out = self.run_events({"4720": {"last": iso(NOW - timedelta(hours=1)), "count": 1}}, closed)
        self.assertEqual(out[("event", "event:4720")]["status"], "failed")

    def test_alert_alone_never_closes_a_finding(self):
        open_row = {("001", "event", "event:4720"): row("open", NOW - timedelta(days=1), key="event:4720")}
        self.assertEqual(self.run_events({}, open_row), {})

    def test_fixed_finding_verified_by_later_linked_sca_pass(self):
        mark = NOW - timedelta(hours=3)
        pending = {("001", "event", "event:5001"): row("fixed_pending", mark)}
        old_alert = {"5001": {"last": iso(mark - timedelta(hours=1)), "count": 1}}
        sca_pass = {"policy": CUSTOM, "id": "99002", "name": "Defender RTP", "status": "passed",
                    "assessed_at": iso(NOW - timedelta(hours=1))}
        out = self.run_events(old_alert, pending, [sca_pass])
        self.assertEqual(out[("event", "event:5001")]["status"], "passed")
        # A linked check that has not passed since the fix does not verify; neither does any other scan.
        stale = dict(sca_pass, assessed_at=iso(mark - timedelta(minutes=5)))
        other = {"policy": CUSTOM, "id": "99006", "name": "x", "status": "passed", "assessed_at": iso(NOW)}
        self.assertEqual(self.run_events(old_alert, pending, [stale, other]), {})

    def test_fixed_finding_without_linked_check_needs_newer_scan_and_no_repeat(self):
        mark = NOW - timedelta(hours=3)
        pending = {("001", "event", "event:4720"): row("fixed_pending", mark, key="event:4720")}
        scan = {"policy": CUSTOM, "id": "99006", "name": "x", "status": "passed", "assessed_at": iso(NOW)}
        out = self.run_events({}, pending, [scan])
        self.assertEqual(out[("event", "event:4720")]["status"], "passed")
        repeat = {"4720": {"last": iso(mark + timedelta(minutes=10)), "count": 2}}
        self.assertEqual(self.run_events(repeat, pending, [scan])[("event", "event:4720")]["status"], "failed")
        no_scan = self.run_events({}, pending, [dict(scan, assessed_at=iso(mark - timedelta(hours=1)))])
        self.assertEqual(no_scan, {})

    def test_uncovered_endpoints_are_skipped(self):
        out = sources.event_results([endpoint()], {"001": {"5001": {"last": iso(NOW), "count": 1}}}, set(), {},
                                    MONITORED, CATALOGUE)
        self.assertEqual(out, [])


class FimTests(unittest.TestCase):
    def test_only_protected_paths_become_findings(self):
        alerts = {"001": [
            {"path": "C:\\LabData\\ClientRecords\\client_0001.csv", "event": "modified", "at": iso(NOW)},
            {"path": "c:/labdata/clientrecords/sub/x.csv", "event": "added", "at": iso(NOW)},
            {"path": "C:\\LabData\\ClientRecordsOld\\y.csv", "event": "deleted", "at": iso(NOW)},
            {"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "event": "added",
             "at": iso(NOW)},
        ]}
        out = sources.fim_results([endpoint()], alerts, {"001"}, {}, FIM, CATALOGUE)
        self.assertEqual(sorted(r["requirement_id"] for r in out), ["REQ-FI-01", "REQ-FI-01", "REQ-FI-02"])
        self.assertTrue(all(r["status"] == "failed" for r in out))
        self.assertFalse(any("clientrecordsold" in r["check_key"] for r in out))

    def test_fixed_change_verified_by_a_later_fim_record(self):
        mark = NOW - timedelta(hours=2)
        path = "c:\\labdata\\clientrecords\\client_0001.csv"
        existing = {("001", "fim", f"fim:{path}"): row("fixed_pending", mark, source="fim", key=f"fim:{path}",
                                                          requirement_id="REQ-FI-01")}
        before = {"001": [{"path": path, "event": "modified", "at": iso(mark - timedelta(hours=1))}]}
        self.assertEqual(sources.fim_results([endpoint()], before, {"001"}, existing, FIM, CATALOGUE), [])
        after = {"001": before["001"] + [{"path": path, "event": "modified", "at": iso(NOW)}]}
        [r] = sources.fim_results([endpoint()], after, {"001"}, existing, FIM, CATALOGUE)
        self.assertEqual(r["status"], "passed")


class StateSourceTests(unittest.TestCase):
    def test_vulnerability_present_then_gone(self):
        vulns = {"001": [{"cve": "CVE-2099-0001", "package": "Viewer", "version": "1", "cvss": 7.8}]}
        [r] = sources.vulnerability_results([endpoint()], vulns, {"001"}, {}, NOW)
        self.assertEqual((r["status"], r["cvss"], r["cve_id"], r["requirement_id"]), ("failed", 7.8, "CVE-2099-0001", None))
        existing = {("001", "vulnerability", r["check_key"]): row("open", NOW, source="vulnerability", key=r["check_key"],
                                                                  requirement_id=None)}
        [gone] = sources.vulnerability_results([endpoint()], {}, {"001"}, existing, NOW)
        self.assertEqual(gone["status"], "passed")
        # Not covered (scan not read for this endpoint): nothing is assumed fixed.
        self.assertEqual(sources.vulnerability_results([endpoint()], {}, set(), existing, NOW), [])

    def test_inventory_rules_off_without_baselines(self):
        packages, ports = {"001": ["Tool"]}, {"001": [{"port": 3389, "transport": "tcp"}]}
        self.assertEqual(sources.inventory_results([endpoint()], packages, ports, {"001"}, {"001"}, {}, (), frozenset(),
                                                   CATALOGUE, NOW), [])
        out = by_key(sources.inventory_results([endpoint()], packages, ports, {"001"}, {"001"}, {}, ("Office*",),
                                               frozenset({445}), CATALOGUE, NOW))
        self.assertEqual(out[("inventory", "pkg:tool")]["requirement_id"], "REQ-SW-01")
        self.assertEqual(out[("inventory", "port:tcp:3389")]["requirement_id"], "REQ-NP-01")
        self.assertTrue(sources.software_approved("Office Suite 2024", ("Office*",)))
        self.assertFalse(sources.software_approved("My Office", ("Office*",)))


class BitLockerTests(unittest.TestCase):
    def volume(self, **kw):
        base = {"mount_point": "C:", "volume_type": "OperatingSystem", "volume_status": "FullyEncrypted",
                "protection_status": "On", "encryption_percentage": 100.0, "encryption_method": "XtsAes256",
                "lock_status": "Unlocked", "collected_at": iso(NOW - timedelta(hours=1))}
        return {**base, **kw}

    def test_evaluation(self):
        self.assertEqual(sources.evaluate_bitlocker([self.volume()], NOW, 24)[:2], ("passed", "passed"))
        self.assertEqual(sources.evaluate_bitlocker([self.volume(protection_status="Off")], NOW, 24)[0], "failed")
        self.assertEqual(sources.evaluate_bitlocker([self.volume(volume_status="EncryptionInProgress",
                                                                 encryption_percentage=40.0)], NOW, 24)[0], "failed")
        self.assertEqual(sources.evaluate_bitlocker([self.volume(encryption_method="XtsAes128")], NOW, 24)[1], "failed")
        self.assertEqual(sources.evaluate_bitlocker([self.volume(protection_status="Unknown")], NOW, 24)[0], "unknown")
        self.assertEqual(sources.evaluate_bitlocker([self.volume(volume_type="Data")], NOW, 24)[:2], ("unknown", "unknown"))
        stale = self.volume(collected_at=iso(NOW - timedelta(days=3)))
        self.assertEqual(sources.evaluate_bitlocker([stale], NOW, 24)[:2], ("unknown", "unknown"))
        self.assertEqual(sources.evaluate_bitlocker([stale], NOW, None)[0], "passed")

    def test_results_match_by_hostname(self):
        out = sources.bitlocker_results([endpoint(hostname="WS01")], {"ws01": [self.volume(protection_status="Off")]},
                                        CATALOGUE, NOW)
        self.assertEqual({(r["requirement_id"], r["status"]) for r in out}, {("REQ-BL-02", "failed"),
                                                                             ("REQ-BL-03", "passed")})
        self.assertEqual(sources.bitlocker_results([endpoint(hostname="WS02")], {"ws01": []}, CATALOGUE, NOW), [])


class WazuhParserTests(unittest.TestCase):
    def test_events_query_and_response(self):
        query = wazuh_sources.events_query(["4719", "5001"], 30)
        self.assertEqual(query["query"]["bool"]["filter"][0], {"terms": {"data.win.system.eventID": ["4719", "5001"]}})
        response = {"aggregations": {"agents": {"buckets": [{"key": "001", "events": {"buckets": [
            {"key": "5001", "doc_count": 2, "last": {"value_as_string": "2026-10-20T10:00:00.000Z"}}]}}]}}}
        self.assertEqual(wazuh_sources.events_response(response),
                         {"001": {"5001": {"last": "2026-10-20T10:00:00.000Z", "count": 2}}})
        with self.assertRaises(ValueError):
            wazuh_sources.events_response({"hits": {}})

    def test_fim_response(self):
        response = {"aggregations": {"agents": {"buckets": [{"key": "001", "paths": {"buckets": [
            {"key": "c:\\labdata\\clientrecords\\a.csv", "latest": {"hits": {"hits": [{"_source": {
                "timestamp": "2026-10-20T10:00:00.000+0000",
                "syscheck": {"path": "c:\\labdata\\clientrecords\\a.csv", "event": "modified"}}}]}}}]}}]}}}
        self.assertEqual(wazuh_sources.fim_response(response), {"001": [
            {"path": "c:\\labdata\\clientrecords\\a.csv", "event": "modified", "at": "2026-10-20T10:00:00.000+0000"}]})

    def test_state_responses_accept_4x_and_5x_agent_fields(self):
        vulns = {"hits": {"hits": [
            {"_source": {"agent": {"id": "001"}, "package": {"name": "Viewer", "version": "1"},
                         "vulnerability": {"id": "CVE-2099-0001", "score": {"base": 7.8}}}},
            {"_source": {"wazuh": {"agent": {"id": "002"}}, "vulnerability": {"id": "CVE-2099-0002", "score": {"base": 99}}}}]}}
        out = wazuh_sources.vulnerabilities_response(vulns)
        self.assertEqual(out["001"][0]["cvss"], 7.8)
        self.assertIsNone(out["002"][0]["cvss"])  # out-of-range score ignored
        ports = {"hits": {"hits": [
            {"_source": {"agent": {"id": "001"}, "source": {"port": 3389}, "network": {"transport": "tcp"},
                         "interface": {"state": "listening"}, "process": {"name": "svchost.exe"}}},
            {"_source": {"agent": {"id": "001"}, "source": {"port": 50000}, "network": {"transport": "tcp"},
                         "interface": {"state": "established"}}},
            {"_source": {"agent": {"id": "001"}, "source": {"port": 5353}, "network": {"transport": "udp"}}},
            {"_source": {"agent": {"id": "001"}, "source": {"port": 3389}, "network": {"transport": "tcp6"},
                         "interface": {"state": "listening"}}}]}}
        # Field names confirmed in Wazuh 4.14.9 (VMware lab); tcp and tcp6 sockets on one port are merged.
        parsed = wazuh_sources.ports_response(ports)["001"]
        self.assertEqual(sorted((p["transport"], p["port"]) for p in parsed), [("tcp", 3389), ("udp", 5353)])
        packages = {"hits": {"hits": [{"_source": {"agent": {"id": "001"}, "package": {"name": "Tool"}}},
                                      {"_source": {"agent": {"id": "001"}, "package": {"name": "Tool"}}}]}}
        self.assertEqual(wazuh_sources.packages_response(packages), {"001": ["Tool"]})


if __name__ == "__main__":
    unittest.main()
