"""Not-applicable results as their own category, and per-policy selection of Wazuh results."""

import copy
import json
import unittest
from pathlib import Path

from compliance import compute_compliance_score, compute_framework_scores, list_findings
from tests.test_webapp_wazuh import FakeIndexer
from webapp.app import ALL_POLICIES, create_app, select_policy

FIXTURES = Path(__file__).parent / "fixtures"
CIS = "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"
EXTRA = "Capstone Windows supplementary checks v1.0"


def doc(result, frameworks=None):
    return {"check": {"id": "1", "result": result, "compliance": frameworks or {}}}


def two_policy_response():
    """Fixture response with its checks split over the CIS policy and the custom policy."""
    response = json.loads((FIXTURES / "wazuh_4x_sca_search_response.json").read_text(encoding="utf-8"))
    hits = response["hits"]["hits"]
    for hit in hits:
        hit["_source"]["data"]["sca"]["policy"] = CIS
    extra = copy.deepcopy(hits[1])  # a passed check
    extra["_source"]["data"]["sca"]["policy"] = EXTRA
    extra["_source"]["data"]["sca"]["check"].update(id="99002", title="Ensure Defender real-time protection is on.")
    hits.append(extra)
    return response


class NotApplicableScoringTests(unittest.TestCase):
    def test_classification(self):
        cases = {"Not applicable": "not_applicable", "not applicable": "not_applicable",
                 " NOT  APPLICABLE ": "not_applicable", "not_applicable": "not_applicable",
                 "Not run": "unknown", None: "unknown", "invalid-ish": "unknown",
                 "Passed": "passed", "failed": "failed"}
        for raw, expected in cases.items():
            with self.subTest(result=raw):
                self.assertEqual(list_findings([doc(raw)])[0]["status"], expected)

    def test_not_applicable_excluded_from_percentage_but_counted(self):
        score = compute_compliance_score([doc("passed"), doc("failed"), doc("failed"),
                                          doc("Not applicable"), doc("Not run")])
        self.assertEqual(score, {"passed": 1, "failed": 2, "not_applicable": 1, "unknown": 1,
                                 "total": 5, "pass_percentage": 33.33})

    def test_framework_not_applicable_counts(self):
        scores = compute_framework_scores([doc("Not applicable", {"cis": ["5.3"]}),
                                           doc("passed", {"cis": ["1.1"]}),
                                           doc(None, {"cis": ["9.1"]})])
        self.assertEqual(scores["cis"], {"passed": 1, "failed": 0, "not_applicable": 1, "unknown": 1,
                                         "total": 3, "pass_percentage": 100.0})


class SelectPolicyTests(unittest.TestCase):
    def docs(self, *names):
        return [{"policy": {"name": n}, "check": {"id": str(i), "result": "passed"}} for i, n in enumerate(names)]

    def test_defaults_to_largest_cis_policy(self):
        docs = self.docs(CIS, CIS, EXTRA, "CIS Small Policy")
        selected, name, policies = select_policy(docs, None)
        self.assertEqual(name, CIS)
        self.assertEqual(len(selected), 2)
        self.assertEqual(policies, [{"name": EXTRA, "checks": 1}, {"name": CIS, "checks": 2},
                                    {"name": "CIS Small Policy", "checks": 1}])

    def test_defaults_to_all_without_cis(self):
        selected, name, _ = select_policy(self.docs(EXTRA, "Other"), "")
        self.assertEqual((len(selected), name), (2, None))

    def test_explicit_and_all(self):
        docs = self.docs(CIS, EXTRA)
        self.assertEqual(select_policy(docs, EXTRA)[1], EXTRA)
        self.assertEqual(len(select_policy(docs, ALL_POLICIES)[0]), 2)

    def test_invalid_policy(self):
        from webapp.app import ApiError
        for bad in ("Nope", 5, "x" * 300):
            with self.subTest(policy=bad), self.assertRaises(ApiError):
                select_policy(self.docs(CIS), bad)


class PolicyRouteTests(unittest.TestCase):
    def make(self):
        self.indexer = FakeIndexer(two_policy_response())
        app = create_app(login_required=False, indexer_client=self.indexer, ai_provider=None)
        app.testing = True
        return app.test_client()

    def test_default_shows_cis_only_and_lists_all_policies(self):
        report = self.make().get("/api/wazuh/sca?agent_id=001").get_json()
        self.assertEqual(report["policy"], CIS)
        self.assertEqual(report["policies"], [{"name": EXTRA, "checks": 1}, {"name": CIS, "checks": 3}])
        self.assertEqual(report["overall"], {"passed": 1, "failed": 1, "not_applicable": 1, "unknown": 0,
                                             "total": 3, "pass_percentage": 50.0})
        self.assertEqual(report["source"], f"Wazuh agent 001 (test-agent) · {CIS}")

    def test_select_custom_and_all(self):
        client = self.make()
        extra = client.get("/api/wazuh/sca", query_string={"agent_id": "001", "policy": EXTRA}).get_json()
        self.assertEqual((extra["policy"], extra["overall"]["total"]), (EXTRA, 1))
        self.assertEqual(extra["findings"][0]["id"], "99002")
        both = client.get("/api/wazuh/sca", query_string={"agent_id": "001", "policy": ALL_POLICIES}).get_json()
        self.assertIsNone(both["policy"])
        self.assertEqual(both["overall"]["total"], 4)
        self.assertEqual(len(both["policies"]), 2)

    def test_unknown_policy_rejected(self):
        response = self.make().get("/api/wazuh/sca", query_string={"agent_id": "001", "policy": "Nope"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("no results for this agent", response.get_json()["error"])


class CustomPolicyFileTests(unittest.TestCase):
    """Line-based sanity checks of the custom SCA policy (no YAML dependency)."""

    path = Path(__file__).resolve().parent.parent / "wazuh" / "sca" / "capstone_windows_extra.yml"

    def checks(self):
        lines = self.path.read_text(encoding="utf-8").splitlines()
        start = lines.index("checks:")
        blocks, current = [], None
        for line in lines[start + 1:]:
            if line.startswith("  - id: "):
                current = {"id": int(line.split(":", 1)[1]), "lines": []}
                blocks.append(current)
            elif current is not None:
                current["lines"].append(line)
        return lines, blocks

    def test_policy_header(self):
        lines, _ = self.checks()
        self.assertIn('  id: "capstone_windows_extra"', lines)
        self.assertIn('  file: "capstone_windows_extra.yml"', lines)

    def test_checks_well_formed_and_read_only(self):
        _, blocks = self.checks()
        self.assertEqual([b["id"] for b in blocks], list(range(99001, 99007)))
        for block in blocks:
            text = "\n".join(block["lines"])
            with self.subTest(check=block["id"]):
                for field in ("    title: ", "    description: ", "    rationale: ", "    remediation: ",
                              "    condition: all", "    rules:"):
                    self.assertIn(field, text)
                rules = [l.strip() for l in block["lines"] if l.strip().startswith("- '")]
                self.assertTrue(rules)
                for rule in rules:
                    self.assertTrue(rule.startswith("- 'c:powershell ") and " -> " in rule, rule)
                    for verb in ("Set-", "Enable-", "Disable-", "New-ItemProperty", "reg add", "Remove-Item HK"):
                        self.assertNotIn(verb, rule.split(" -> ")[0])


if __name__ == "__main__":
    unittest.main()
