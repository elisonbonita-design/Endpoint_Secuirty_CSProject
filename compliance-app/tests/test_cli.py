import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from compliance import compute_compliance_score, compute_framework_scores
from compliance.cli import main

APP_DIR = Path(__file__).resolve().parent.parent
SAMPLE = APP_DIR / "samples" / "sca_results_sample.json"
FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, content):
        path = Path(self.tmp.name) / "results.json"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_sample_file(self):
        code, out, err = run_cli(str(SAMPLE))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("Passed:          2", out)
        self.assertIn("Failed:          1", out)
        self.assertIn("Not applicable:  1", out)
        self.assertIn("Unknown:         0", out)
        self.assertIn("Pass percentage: 66.67%", out)

    def test_sample_file_framework_section(self):
        _, out, _ = run_cli(str(SAMPLE))
        self.assertIn("By framework:", out)
        self.assertRegex(out, r"pci_dss\s+1\s+1\s+0\s+0\s+50\.00%")
        self.assertRegex(out, r"nist_800_53\s+1\s+0\s+1\s+0\s+100\.00%")
        self.assertRegex(out, r"hipaa\s+0\s+1\s+0\s+0\s+0\.00%")

    def test_no_compliance_metadata_omits_framework_section(self):
        code, out, _ = run_cli(self.write('[{"check": {"result": "passed"}}]'))
        self.assertEqual(code, 0)
        self.assertNotIn("By framework:", out)

    def test_json_output_matches_scoring_functions(self):
        out_path = Path(self.tmp.name) / "report.json"
        code, out, err = run_cli(str(SAMPLE), "--json-output", str(out_path))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, run_cli(str(SAMPLE))[1])  # terminal output unchanged

        docs = json.loads(SAMPLE.read_text(encoding="utf-8"))
        report = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(report, {
            "overall": compute_compliance_score(docs),
            "frameworks": compute_framework_scores(docs),
        })
        self.assertEqual(report["overall"],
                         {"passed": 2, "failed": 1, "not_applicable": 1, "unknown": 0, "total": 4, "pass_percentage": 66.67})
        self.assertEqual(report["frameworks"]["pci_dss"]["pass_percentage"], 50.0)

    def test_json_output_null_percentage_and_no_frameworks(self):
        out_path = Path(self.tmp.name) / "report.json"
        code, _, _ = run_cli(self.write("[]"), "--json-output", str(out_path))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out_path.read_text(encoding="utf-8")), {
            "overall": {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 0, "total": 0, "pass_percentage": None},
            "frameworks": {},
        })

    def test_json_output_invalid_path(self):
        for bad in (Path(self.tmp.name) / "no-such-dir" / "report.json", Path(self.tmp.name)):
            with self.subTest(path=bad):
                code, _, err = run_cli(str(SAMPLE), "--json-output", str(bad))
                self.assertEqual(code, 1)
                self.assertIn("cannot write JSON report", err)

    def test_json_output_not_written_for_invalid_input(self):
        out_path = Path(self.tmp.name) / "report.json"
        code, _, _ = run_cli(self.write("{not json"), "--json-output", str(out_path))
        self.assertEqual(code, 1)
        self.assertFalse(out_path.exists())

    def test_single_wazuh_document(self):
        code, out, _ = run_cli(str(FIXTURES / "sca_stateful_sample.json"))
        self.assertEqual(code, 0)
        self.assertIn("Unknown:         1", out)
        self.assertIn("Pass percentage: N/A", out)

    def test_empty_list(self):
        code, out, _ = run_cli(self.write("[]"))
        self.assertEqual(code, 0)
        self.assertIn("Pass percentage: N/A", out)

    def test_missing_file(self):
        code, out, err = run_cli(str(Path(self.tmp.name) / "missing.json"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("cannot read", err)

    def test_malformed_json(self):
        code, _, err = run_cli(self.write("{not json"))
        self.assertEqual(code, 1)
        self.assertIn("invalid JSON", err)

    def test_wrong_structure(self):
        for content in ('"text"', "[1, 2]", '[{"policy": {}}]', '[{"check": {"result": 5}}]'):
            with self.subTest(content=content):
                code, _, err = run_cli(self.write(content))
                self.assertEqual(code, 1)
                self.assertIn("invalid SCA results", err)


if __name__ == "__main__":
    unittest.main()
