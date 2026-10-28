import base64
import json
import ssl
import unittest
from unittest import mock

from webapp import indexer
from webapp.indexer import IndexerClient, IndexerConfig, IndexerError, client_from_env

TEST_PASSWORD = "not-a-real-password-123"
_REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context
ENV = {
    "WAZUH_INDEXER_URL": "https://127.0.0.1:9200",
    "WAZUH_INDEXER_USERNAME": "reader",
    "WAZUH_INDEXER_PASSWORD": TEST_PASSWORD,
    "WAZUH_INDEXER_CA_FILE": "ca.pem",
    "WAZUH_INDEXER_TLS_SERVER_NAME": "wazuh.indexer",
}


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")

    def read(self):
        return self._body


class FakeConnection:
    def __init__(self, response=None, exc=None):
        self.response, self.exc, self.requests, self.closed = response, exc, [], False

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, body, headers))
        if self.exc:
            raise self.exc

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def make_client(env=ENV):
    # No real CA file in tests: build a default verifying context instead.
    with mock.patch.object(indexer.ssl, "create_default_context",
                           side_effect=lambda cafile=None: _REAL_CREATE_DEFAULT_CONTEXT()) as ctx:
        client = IndexerClient(IndexerConfig.from_env(env))
    ctx.assert_called_once_with(cafile="ca.pem")
    return client


class IndexerConfigTests(unittest.TestCase):
    def test_from_env_requires_all_values(self):
        for missing in ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USERNAME", "WAZUH_INDEXER_PASSWORD",
                        "WAZUH_INDEXER_CA_FILE"):
            env = {k: v for k, v in ENV.items() if k != missing}
            with self.subTest(missing=missing):
                self.assertIsNone(IndexerConfig.from_env(env))
                self.assertIsNone(client_from_env(env))

    def test_from_env_and_password_hidden_from_repr(self):
        config = IndexerConfig.from_env(ENV)
        self.assertEqual((config.url, config.username, config.tls_server_name),
                         ("https://127.0.0.1:9200", "reader", "wazuh.indexer"))
        self.assertNotIn(TEST_PASSWORD, repr(config))

    def test_rejects_non_https_url(self):
        with self.assertRaises(ValueError):
            make_client({**ENV, "WAZUH_INDEXER_URL": "http://127.0.0.1:9200"})


class IndexerClientTests(unittest.TestCase):
    def setUp(self):
        self.client = make_client()

    def search_with(self, conn):
        with mock.patch.object(self.client, "_connection", return_value=conn):
            return self.client.search("wazuh-alerts-4.x-*", {"size": 1})

    def test_search_sends_authenticated_post(self):
        conn = FakeConnection(FakeResponse(200, {"hits": {"hits": []}}))
        self.assertEqual(self.search_with(conn), {"hits": {"hits": []}})
        method, path, body, headers = conn.requests[0]
        self.assertEqual((method, path), ("POST", "/wazuh-alerts-4.x-*/_search"))
        self.assertEqual(json.loads(body), {"size": 1})
        expected = base64.b64encode(f"reader:{TEST_PASSWORD}".encode()).decode()
        self.assertEqual(headers["Authorization"], f"Basic {expected}")
        self.assertTrue(conn.closed)

    def test_tls_verification_is_enforced(self):
        self.assertEqual(self.client._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(self.client._context.check_hostname)
        self.assertEqual(self.client._tls_server_name, "wazuh.indexer")
        self.assertEqual(make_client({k: v for k, v in ENV.items()
                                      if k != "WAZUH_INDEXER_TLS_SERVER_NAME"})._tls_server_name, "127.0.0.1")
        # Only the strict X.509 profile is relaxed (Wazuh's generated root CA has no keyUsage); chain checks stay.
        self.assertFalse(self.client._context.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0))
        self.assertEqual(self.client._context.verify_mode, ssl.CERT_REQUIRED)

    def test_connection_verifies_against_tls_server_name(self):
        context = mock.Mock()
        conn = indexer._VerifiedHTTPSConnection("127.0.0.1", 9200, "wazuh.indexer", context, 5)
        with mock.patch.object(indexer.socket, "create_connection", return_value="raw-socket") as create:
            conn.connect()
        create.assert_called_once_with(("127.0.0.1", 9200), 5)
        context.wrap_socket.assert_called_once_with("raw-socket", server_hostname="wazuh.indexer")

    def test_error_responses_are_safe(self):
        cases = [
            (FakeConnection(FakeResponse(401, {"error": "x"})), "rejected the configured credentials"),
            (FakeConnection(FakeResponse(500, {"error": "x"})), "HTTP 500"),
            (FakeConnection(FakeResponse(200, b"not json")), "unreadable response"),
            (FakeConnection(exc=ConnectionRefusedError()), "Could not connect"),
            (FakeConnection(exc=ssl.SSLCertVerificationError("bad cert")), "TLS verification"),
        ]
        for conn, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(IndexerError) as ctx:
                    self.search_with(conn)
                self.assertIn(message, str(ctx.exception))
                self.assertNotIn(TEST_PASSWORD, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
