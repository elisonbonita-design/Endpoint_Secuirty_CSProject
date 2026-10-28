import copy
import json
import unittest
from pathlib import Path

from compliance import compute_compliance_score, compute_framework_scores, list_findings

# Copied verbatim from wazuh-src/docs/ref/modules/sca/output-samples.md.
FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def stateful_with_result(result):
    """The real stateful sample with only check.result changed."""
    doc = copy.deepcopy(load_fixture("sca_stateful_sample.json"))
    doc["check"]["result"] = result
    return doc


class WazuhSampleTests(unittest.TestCase):
    def test_stateful_sample_not_run_is_unknown(self):
        self.assertEqual(
            compute_compliance_score([load_fixture("sca_stateful_sample.json")]),
            {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 1, "total": 1, "pass_percentage": None},
        )

    def test_stateless_sample_failed(self):
        self.assertEqual(
            compute_compliance_score([load_fixture("sca_stateless_sample.json")]),
            {"passed": 0, "failed": 1, "not_applicable": 0, "unknown": 0, "total": 1, "pass_percentage": 0.0},
        )

    def test_samples_mixed_with_passed(self):
        docs = [
            load_fixture("sca_stateful_sample.json"),   # Not run -> unknown
            load_fixture("sca_stateless_sample.json"),  # failed
            stateful_with_result("Passed"),
            stateful_with_result("passed"),
            stateful_with_result("Failed"),
        ]
        self.assertEqual(
            compute_compliance_score(docs),
            {"passed": 2, "failed": 2, "not_applicable": 0, "unknown": 1, "total": 5, "pass_percentage": 50.0},
        )

    def test_stateless_without_check_is_invalid(self):
        doc = load_fixture("sca_stateless_sample.json")
        del doc["data"]["check"]
        with self.assertRaises(ValueError):
            compute_compliance_score([doc])


def sca_doc(check_id, result):
    """Synthetic SCA stateful document shaped like output-samples.md."""
    return {
        "checksum": {"hash": {"sha1": f"sample-{check_id}"}},
        "check": {
            "id": check_id,
            "name": f"Sample check {check_id}",
            "result": result,
            "reason": None,
            "remediation": "Sample remediation.",
        },
        "policy": {"id": "sample_policy", "name": "Sample Policy", "file": "sample.yml"},
        "state": {"modified_at": "2026-01-01T00:00:00Z"},
    }


class ComputeComplianceScoreTests(unittest.TestCase):
    def test_normal_mixed_results(self):
        docs = [sca_doc("1", "passed"), sca_doc("2", "Passed"), sca_doc("3", "failed"),
                sca_doc("4", "Not applicable")]
        self.assertEqual(
            compute_compliance_score(docs),
            {"passed": 2, "failed": 1, "not_applicable": 1, "unknown": 0, "total": 4, "pass_percentage": 66.67},
        )

    def test_all_passed(self):
        score = compute_compliance_score([sca_doc("1", "passed"), sca_doc("2", "PASSED")])
        self.assertEqual(score["pass_percentage"], 100.0)

    def test_empty_input(self):
        self.assertEqual(
            compute_compliance_score([]),
            {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 0, "total": 0, "pass_percentage": None},
        )

    def test_only_unknown_results(self):
        docs = [sca_doc("1", "Not run"), sca_doc("2", None), sca_doc("3", "not applicable"),
                sca_doc("4", "something-else")]
        score = compute_compliance_score(docs)
        self.assertEqual((score["unknown"], score["not_applicable"]), (3, 1))
        self.assertIsNone(score["pass_percentage"])

    def test_missing_result_is_unknown(self):
        doc = sca_doc("1", None)
        del doc["check"]["result"]
        self.assertEqual(compute_compliance_score([doc])["unknown"], 1)

    def test_invalid_container(self):
        for bad in (None, 42, "passed", {"check": {"result": "passed"}}):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                compute_compliance_score(bad)

    def test_invalid_document(self):
        with self.assertRaises(TypeError):
            compute_compliance_score(["not-a-dict"])

    def test_missing_check_object(self):
        with self.assertRaises(ValueError):
            compute_compliance_score([{"policy": {}}])

    def test_invalid_result_type(self):
        with self.assertRaises(TypeError):
            compute_compliance_score([sca_doc("1", 1)])


def framework_doc(check_id, result, compliance):
    doc = sca_doc(check_id, result)
    doc["check"]["compliance"] = compliance
    return doc


class ComputeFrameworkScoresTests(unittest.TestCase):
    def test_wazuh_samples(self):
        docs = [load_fixture("sca_stateful_sample.json"), load_fixture("sca_stateless_sample.json")]
        expected = {"passed": 0, "failed": 1, "not_applicable": 0, "unknown": 1, "total": 2, "pass_percentage": 0.0}
        self.assertEqual(compute_framework_scores(docs),
                         {"nist_800_53": expected, "pci_dss": expected})

    def test_multi_framework_check_counts_once_per_framework(self):
        docs = [
            framework_doc("1", "passed", {"pci_dss": ["2.2.4"], "hipaa": ["164.308.a.1"]}),
            framework_doc("2", "failed", {"pci_dss": ["8.3.6", "8.3.7"]}),
        ]
        scores = compute_framework_scores(docs)
        self.assertEqual(scores["pci_dss"],
                         {"passed": 1, "failed": 1, "not_applicable": 0, "unknown": 0, "total": 2, "pass_percentage": 50.0})
        self.assertEqual(scores["hipaa"],
                         {"passed": 1, "failed": 0, "not_applicable": 0, "unknown": 0, "total": 1, "pass_percentage": 100.0})
        # Overall counts are per check, not per framework mapping.
        self.assertEqual(compute_compliance_score(docs)["total"], 2)

    def test_missing_or_malformed_compliance_is_skipped(self):
        docs = [
            sca_doc("1", "passed"),                       # no compliance key
            framework_doc("2", "failed", None),
            framework_doc("3", "failed", {}),
            framework_doc("4", "failed", ["pci_dss"]),    # not a mapping
            framework_doc("5", "failed", {"pci_dss": []}),  # no controls
            framework_doc("6", "passed", {"gdpr": ["IV_32.1.a"]}),
        ]
        self.assertEqual(list(compute_framework_scores(docs)), ["gdpr"])
        self.assertEqual(compute_compliance_score(docs)["total"], 6)

    def test_framework_with_only_unknown_results(self):
        docs = [framework_doc("1", "Not run", {"nis2": ["21.2.e"]}),
                framework_doc("2", None, {"nis2": ["21.2.a"]})]
        self.assertEqual(compute_framework_scores(docs)["nis2"],
                         {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 2, "total": 2, "pass_percentage": None})

    def test_empty_and_invalid_inputs(self):
        self.assertEqual(compute_framework_scores([]), {})
        with self.assertRaises(TypeError):
            compute_framework_scores(None)
        with self.assertRaises(ValueError):
            compute_framework_scores([{"policy": {}}])


class ListFindingsTests(unittest.TestCase):
    def test_wazuh_samples(self):
        findings = list_findings([load_fixture("sca_stateful_sample.json"),
                                  load_fixture("sca_stateless_sample.json")])
        self.assertEqual([f["status"] for f in findings], ["unknown", "failed"])
        self.assertEqual(findings[0]["result"], "Not run")
        self.assertEqual(findings[0]["remediation"], "Set 'SMB1' registry key to 0.")
        self.assertEqual(findings[0]["compliance"], {"pci_dss": ["2.2.4"], "nist_800_53": ["CM.1"]})

    def test_missing_and_malformed_fields(self):
        doc = {"check": {"result": None, "name": 7, "reason": ["x"], "compliance": "pci_dss"}}
        self.assertEqual(list_findings([doc]), [{
            "id": None, "name": None, "status": "unknown", "result": None,
            "reason": None, "remediation": None, "compliance": {},
        }])

    def test_invalid_input(self):
        with self.assertRaises(TypeError):
            list_findings(None)
        with self.assertRaises(ValueError):
            list_findings([{"policy": {}}])


if __name__ == "__main__":
    unittest.main()
