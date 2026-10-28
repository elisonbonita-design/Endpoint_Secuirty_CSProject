import json
import unittest
from pathlib import Path

from compliance import compute_compliance_score, compute_framework_scores, list_findings
from compliance.wazuh_alerts import (alert_to_document, latest_checks_query,
                                     search_response_to_documents)

FIXTURES = Path(__file__).parent / "fixtures"


def load_response():
    return json.loads((FIXTURES / "wazuh_4x_sca_search_response.json").read_text(encoding="utf-8"))


class LatestChecksQueryTests(unittest.TestCase):
    def test_query_filters_agent_and_collapses_per_check(self):
        query = latest_checks_query("001")
        self.assertIn({"term": {"agent.id": "001"}}, query["query"]["bool"]["filter"])
        self.assertIn({"term": {"data.sca.type": "check"}}, query["query"]["bool"]["filter"])
        self.assertEqual(query["collapse"], {"field": "data.sca.check.id"})
        self.assertEqual(query["sort"], [{"timestamp": {"order": "desc"}}])

    def test_rejects_invalid_agent_ids(self):
        for bad in ("1", "12", "abc", "001\n", "001 OR *", "123456789", None, 1):
            with self.subTest(agent_id=bad), self.assertRaises(ValueError):
                latest_checks_query(bad)


class AlertMappingTests(unittest.TestCase):
    def test_maps_4x_alert_fields(self):
        docs = search_response_to_documents(load_response())
        self.assertEqual(len(docs), 3)
        first = docs[0]
        self.assertEqual(first["check"]["id"], "9001")
        self.assertEqual(first["check"]["name"], "Ensure remote assistance is disabled.")
        self.assertEqual(first["check"]["result"], "failed")
        self.assertEqual(first["check"]["compliance"],
                         {"pci_dss_v4.0": ["1.2.5", "2.2.4"], "pci_dss_v3.2.1": ["2.2.2"],
                          "cis": ["18.9.35.2"], "soc_2": ["CC6.3", "CC6.6"]})
        self.assertEqual(first["policy"], {"name": "Sample Windows Benchmark v1.0.0"})
        self.assertEqual(first["agent"], {"id": "001", "name": "test-agent"})
        self.assertEqual(docs[1]["check"]["compliance"]["nist_sp_800-53"], ["7"])
        self.assertNotIn("empty_fw", docs[2]["check"]["compliance"])

    def test_mapped_documents_work_with_existing_scoring(self):
        docs = search_response_to_documents(load_response())
        self.assertEqual(compute_compliance_score(docs),
                         {"passed": 1, "failed": 1, "not_applicable": 1, "unknown": 0, "total": 3, "pass_percentage": 50.0})
        self.assertEqual(compute_framework_scores(docs)["cis"]["total"], 3)
        findings = list_findings(docs)
        self.assertEqual(findings[2]["status"], "not_applicable")
        self.assertEqual(findings[2]["reason"], "Unable to read registry key (not found).")

    def test_flat_dotted_framework_keys_also_supported(self):
        doc = alert_to_document({"data": {"sca": {"check": {"id": "1", "result": "passed",
                                                            "compliance": {"cmmc_v2.0": "CM.L2-3.4.7"}}}}})
        self.assertEqual(doc["check"]["compliance"], {"cmmc_v2.0": ["CM.L2-3.4.7"]})

    def test_missing_compliance_is_empty(self):
        doc = alert_to_document({"data": {"sca": {"check": {"id": "1", "result": "passed"}}}})
        self.assertEqual(doc["check"]["compliance"], {})
        self.assertEqual(doc["agent"], {"id": None, "name": None})

    def test_malformed_alerts(self):
        for bad in (None, {}, {"data": {}}, {"data": {"sca": {"type": "summary"}}}):
            with self.subTest(source=bad), self.assertRaises((TypeError, ValueError)):
                alert_to_document(bad)

    def test_malformed_search_response(self):
        for bad in (None, {}, {"hits": {}}, {"hits": {"hits": "x"}}):
            with self.subTest(response=bad), self.assertRaises(ValueError):
                search_response_to_documents(bad)

    def test_empty_search_response(self):
        self.assertEqual(search_response_to_documents({"hits": {"hits": []}}), [])


if __name__ == "__main__":
    unittest.main()
