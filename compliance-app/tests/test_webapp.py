import io
import json
import unittest
from pathlib import Path

from compliance import compute_compliance_score, compute_framework_scores
from webapp.app import MAX_UPLOAD_BYTES, create_app

APP_DIR = Path(__file__).resolve().parent.parent
SAMPLE = APP_DIR / "samples" / "sca_results_sample.json"
FIXTURES = Path(__file__).parent / "fixtures"


class WebappTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(login_required=False, indexer_client=None)
        self.app.testing = True
        self.client = self.app.test_client()

    def upload(self, content, filename="results.json"):
        if isinstance(content, str):
            content = content.encode("utf-8")
        return self.client.post("/api/upload", data={"file": (io.BytesIO(content), filename)},
                                content_type="multipart/form-data")

    def test_index_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Configuration Compliance", html)
        self.assertIn("/static/app.js", html)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_static_assets_load(self):
        for path in ("/static/app.js", "/static/app.css", "/static/favicon.svg"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                response.close()

    def test_sample_report(self):
        response = self.client.get("/api/sample")
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        docs = json.loads(SAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(report["overall"], compute_compliance_score(docs))
        self.assertEqual(report["frameworks"], compute_framework_scores(docs))
        self.assertEqual(report["source"], "Bundled sample")
        self.assertEqual(len(report["findings"]), 4)
        failed = next(f for f in report["findings"] if f["status"] == "failed")
        self.assertEqual(failed["remediation"], "Set minimum password length to 14 or more.")
        self.assertEqual(failed["compliance"], {"pci_dss": ["8.3.6"], "hipaa": ["164.308.a.5"]})

    def test_upload_valid_wazuh_document(self):
        content = (FIXTURES / "sca_stateless_sample.json").read_text(encoding="utf-8")
        response = self.upload(content, "stateless.json")
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["overall"]["failed"], 1)
        self.assertEqual(report["source"], "stateless.json")
        self.assertEqual(report["findings"][0]["name"], "Ensure SMBv1 is disabled.")
        self.assertEqual(report["findings"][0]["result"], "failed")

    def test_upload_markup_is_returned_as_data_not_html(self):
        payload = json.dumps([{"check": {"name": "<script>alert(1)</script>", "result": "failed"}}])
        response = self.upload(payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(response.get_json()["findings"][0]["name"], "<script>alert(1)</script>")

    def test_upload_empty_list(self):
        response = self.upload("[]")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get_json()["overall"]["pass_percentage"])

    def test_upload_invalid_json(self):
        response = self.upload("{not json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid JSON", response.get_json()["error"])

    def test_upload_non_utf8(self):
        response = self.upload(b"\xff\xfe\x00bad")
        self.assertEqual(response.status_code, 400)
        self.assertIn("UTF-8", response.get_json()["error"])

    def test_upload_unsupported_data(self):
        for content in ('"text"', "[1, 2]", '[{"policy": {}}]', '[{"check": {"result": 5}}]'):
            with self.subTest(content=content):
                response = self.upload(content)
                self.assertEqual(response.status_code, 400)
                self.assertIn("Unsupported SCA data", response.get_json()["error"])

    def test_upload_missing_file(self):
        response = self.client.post("/api/upload", data={}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn("No file was uploaded", response.get_json()["error"])

    def test_upload_too_large(self):
        response = self.upload(b" " * (MAX_UPLOAD_BYTES + 1))
        self.assertEqual(response.status_code, 413)
        self.assertIn("too large", response.get_json()["error"])

    def test_upload_requires_post(self):
        self.assertEqual(self.client.get("/api/upload").status_code, 405)


if __name__ == "__main__":
    unittest.main()
