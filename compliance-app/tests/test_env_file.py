import tempfile
import unittest
from pathlib import Path

from webapp.env_file import ALLOWED_KEYS, DEFAULT_PATH, load_env_file


class LoadEnvFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text):
        path = Path(self.tmp.name) / "ai.env"
        path.write_text(text, encoding="utf-8")
        return path

    def test_only_local_ai_settings_are_loaded(self):
        env = {}
        path = self.write("# comment\nAI_ENABLED=true\nAI_MODEL='llama3.2:3b'\nAI_BASE_URL=http://127.0.0.1:11434\n"
                          "AI_TIMEOUT_SECONDS=15\nOPENROUTER_API_KEY=old\nGEMINI_API_KEY=old\nPATH=/evil\n"
                          "WAZUH_INDEXER_PASSWORD=x\nnot a line\n")
        self.assertEqual(load_env_file(path, env), ["AI_ENABLED", "AI_MODEL", "AI_BASE_URL", "AI_TIMEOUT_SECONDS"])
        self.assertEqual(env, {"AI_ENABLED": "true", "AI_MODEL": "llama3.2:3b", "AI_BASE_URL": "http://127.0.0.1:11434",
                               "AI_TIMEOUT_SECONDS": "15"})
        self.assertEqual(ALLOWED_KEYS, {"AI_ENABLED", "AI_BASE_URL", "AI_MODEL", "AI_TIMEOUT_SECONDS"})

    def test_placeholders_are_ignored(self):
        for value in ("*****", "<model>", ""):
            with self.subTest(value=value):
                env = {}
                load_env_file(self.write(f"AI_MODEL={value}\n"), env)
                self.assertNotIn("AI_MODEL", env)

    def test_existing_environment_wins(self):
        env = {"AI_MODEL": "from-env"}
        load_env_file(self.write("AI_MODEL=from-file\n"), env)
        self.assertEqual(env["AI_MODEL"], "from-env")

    def test_missing_file_is_fine(self):
        self.assertEqual(load_env_file(Path(self.tmp.name) / "missing.env", {}), [])

    def test_shipped_example_keeps_ai_off_and_local(self):
        env = {}
        load_env_file(DEFAULT_PATH.with_name("ai.env.example"), env)
        self.assertEqual(env, {"AI_ENABLED": "false", "AI_BASE_URL": "http://127.0.0.1:11434",
                               "AI_MODEL": "llama3.2:3b", "AI_TIMEOUT_SECONDS": "20"})


if __name__ == "__main__":
    unittest.main()
