"""Optional local AI (Ollama) provider, the outbound network allowlist and the AI payload rules."""

import io
import json
import socket
import unittest
import urllib.error
import urllib.request
from unittest import mock

from compliance.ai_explain import (EXPLAIN_FIELDS, explain_payload, explain_prompt, parse_explanation,
                                   summary_payload, summary_prompt)
from webapp import ai_providers
from webapp.ai_providers import AIError, AITimeout, OllamaProvider, provider_from_env
from webapp.indexer import client_from_env
from webapp.netpolicy import NetworkPolicyError, check_url, host_allowed


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def reply(text="EXPLANATION: x"):
    return FakeResponse(json.dumps({"model": "m", "response": text, "done": True}).encode("utf-8"))


class NetworkPolicyTests(unittest.TestCase):
    def test_allowed_hosts(self):
        for host in ("127.0.0.1", "localhost", "LOCALHOST", "10.20.0.1", "10.20.0.20", "10.20.0.254"):
            with self.subTest(host=host):
                self.assertTrue(host_allowed(host))
        for host in ("10.20.1.5", "10.21.0.1", "8.8.8.8", "127.0.0.2", "::1", "example.com",
                     "generativelanguage.googleapis.com", "", None):
            with self.subTest(host=host):
                self.assertFalse(host_allowed(host))

    def test_check_url(self):
        self.assertEqual(check_url("http://10.20.0.20:11434", ("http",), "X").port, 11434)
        for url in ("https://8.8.8.8", "http://127.0.0.1@evil.example/", "ftp://127.0.0.1", "http://", "nonsense",
                    "http://user:pw@127.0.0.1/", "http://127.0.0.1:99999"):
            with self.subTest(url=url), self.assertRaises(NetworkPolicyError):
                check_url(url, ("http", "https"), "X")

    def test_indexer_outside_lab_is_refused(self):
        env = {"WAZUH_INDEXER_URL": "https://203.0.113.9:9200", "WAZUH_INDEXER_USERNAME": "reader",
               "WAZUH_INDEXER_PASSWORD": "not-a-real-password", "WAZUH_INDEXER_CA_FILE": "x.pem"}
        with self.assertLogs("webapp.indexer", "ERROR") as logs:
            self.assertIsNone(client_from_env(env))
        self.assertIn("not allowed", logs.output[0])
        self.assertNotIn("not-a-real-password", logs.output[0])


class ProviderSettingsTests(unittest.TestCase):
    def test_disabled_by_default(self):
        self.assertIsNone(provider_from_env({}))
        self.assertIsNone(provider_from_env({"AI_ENABLED": "false", "AI_MODEL": "x"}))

    def test_defaults_when_enabled(self):
        provider = provider_from_env({"AI_ENABLED": "true"})
        self.assertEqual((provider.base_url, provider.model, provider.timeout),
                         ("http://127.0.0.1:11434", "llama3.2:3b", 20.0))
        lab = provider_from_env({"AI_ENABLED": "1", "AI_BASE_URL": "http://10.20.0.20:11434/", "AI_MODEL": "qwen2.5:3b",
                                 "AI_TIMEOUT_SECONDS": "7"})
        self.assertEqual((lab.base_url, lab.model, lab.timeout), ("http://10.20.0.20:11434", "qwen2.5:3b", 7.0))

    def test_base_url_outside_allowlist_keeps_ai_disabled(self):
        for url in ("https://api.example.com", "http://192.168.1.10:11434", "http://10.20.1.1:11434"):
            with self.subTest(url=url), self.assertLogs("webapp.ai_providers", "ERROR") as logs:
                self.assertIsNone(provider_from_env({"AI_ENABLED": "true", "AI_BASE_URL": url}))
                self.assertIn("Local AI disabled", logs.output[0])
        with self.assertLogs("webapp.ai_providers", "ERROR"):
            self.assertIsNone(provider_from_env({"AI_ENABLED": "true", "AI_MODEL": "../x y"}))

    def test_proxy_variables_are_ignored_and_redirects_refused(self):
        # Even with proxy variables set, no handler routes through a proxy.
        with mock.patch.dict("os.environ", {"HTTP_PROXY": "http://203.0.113.1:3128",
                                            "HTTPS_PROXY": "http://203.0.113.1:3128"}):
            handlers = ai_providers.build_opener().handlers
            # Control: urllib's default opener would pick the proxy up.
            default = urllib.request.build_opener().handlers
        self.assertTrue([h for h in default if isinstance(h, urllib.request.ProxyHandler) and h.proxies])
        self.assertFalse([h for h in handlers if isinstance(h, urllib.request.ProxyHandler) and h.proxies])
        self.assertTrue(any(isinstance(h, ai_providers._NoRedirect) for h in handlers))


class OllamaRequestTests(unittest.TestCase):
    def setUp(self):
        self.provider = OllamaProvider("http://127.0.0.1:11434", "llama3.2:3b", timeout=5)

    def call(self, result):
        with mock.patch.object(ai_providers._OPENER, "open") as opener:
            if isinstance(result, BaseException):
                opener.side_effect = result
            else:
                opener.return_value = result
            try:
                return self.provider.generate("hello"), opener
            except AIError as e:
                return e, opener

    def test_request_shape(self):
        answer, opener = self.call(reply("EXPLANATION: fine"))
        self.assertEqual(answer, "EXPLANATION: fine")
        request = opener.call_args.args[0]
        self.assertEqual((request.full_url, request.get_method()), ("http://127.0.0.1:11434/api/generate", "POST"))
        self.assertEqual(json.loads(request.data), {"model": "llama3.2:3b", "prompt": "hello", "stream": False})
        self.assertEqual(opener.call_args.kwargs["timeout"], 5)

    def test_failures(self):
        cases = [
            (socket.timeout("timed out"), AITimeout),
            (urllib.error.URLError(socket.timeout()), AITimeout),
            (urllib.error.URLError(ConnectionRefusedError()), AIError),
            (urllib.error.HTTPError("http://127.0.0.1:11434/api/generate", 302, "redirect", {}, None), AIError),
            (FakeResponse(b"not json"), AIError),
            (reply(""), AIError),
        ]
        for result, error in cases:
            with self.subTest(result=result):
                answer, _ = self.call(result)
                self.assertIsInstance(answer, error)

    def test_url_rechecked_before_every_request(self):
        self.provider.base_url = "http://203.0.113.5:11434"
        with self.assertLogs("webapp.ai_providers", "ERROR"):
            answer, opener = self.call(reply())
        self.assertIsInstance(answer, AIError)
        opener.assert_not_called()


class PayloadTests(unittest.TestCase):
    VIEW = {
        "id": 7, "finding_title": "BitLocker protection off", "title": "BitLocker protection off", "source": "sca",
        "requirement_title": "Ensure the OS drive is encrypted", "severity": "critical", "band": "Critical",
        "score": 80, "reason": "Critical (80): ...", "days_open": 4, "endpoint_label": "WS01",
        "remediation": "Resume BitLocker.", "endpoint_id": "001", "ip": "10.20.0.101", "status": "open",
        "location": {"building": "Lab", "floor": "1", "room": "Row A Seat 3"}, "opened_at": "2026-10-19T00:00:00Z",
    }

    def test_only_allowed_fields_reach_the_prompt(self):
        payload = explain_payload(self.VIEW)
        self.assertEqual(tuple(payload), EXPLAIN_FIELDS)
        self.assertEqual(set(EXPLAIN_FIELDS), {"finding_title", "source", "requirement_title", "severity", "band",
                                               "score", "reason", "days_open", "endpoint_label", "remediation"})
        prompt = explain_prompt(payload)
        for leaked in ("10.20.0.101", "Row A Seat 3", '"001"', "2026-10-19"):
            self.assertNotIn(leaked, prompt)
        sent = json.loads(prompt.split("FINDING (JSON): ", 1)[1].split("\n", 1)[0])
        self.assertEqual(set(sent), set(EXPLAIN_FIELDS))

    def test_summary_sends_counts_only(self):
        items = [{"band": "Critical", "title": "secret-ish title", "endpoint_label": "WS01",
                  "location": {"building": "Lab", "floor": "1"}},
                 {"band": "Low", "title": "x", "endpoint_label": "WS02", "location": {}}]
        payload = summary_payload(items, 3, ["Critical", "High", "Medium", "Low"])
        self.assertEqual(payload["by_band"], {"Critical": 1, "High": 0, "Medium": 0, "Low": 1})
        self.assertEqual(payload["by_floor"]["Lab / Floor 1"]["Critical"], 1)
        prompt = summary_prompt(payload)
        self.assertNotIn("secret-ish title", prompt)
        self.assertNotIn("WS01", prompt)

    def test_parse_explanation(self):
        parsed = parse_explanation("EXPLANATION: The drive is **not** encrypted. Data could be read.\n"
                                   "STEPS:\n1. Resume BitLocker.\n2) Check status.\n- Re-assess.\n"
                                   "4. a\n5. b\n6. too many")
        self.assertEqual(parsed["explanation"], "The drive is not encrypted. Data could be read.")
        self.assertEqual(parsed["steps"], ["Resume BitLocker.", "Check status.", "Re-assess.", "a", "b"])
        self.assertEqual(parse_explanation("Plain answer.\n1. Do this")["steps"], ["Do this"])
        self.assertEqual(parse_explanation("Plain answer.\n1. Do this")["explanation"], "Plain answer.")
        self.assertIsNone(parse_explanation("STEPS:\n1. only steps"))
        self.assertIsNone(parse_explanation(None))


if __name__ == "__main__":
    unittest.main()
