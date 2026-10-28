"""Minimal read-only Wazuh Indexer (OpenSearch) client for the dashboard backend.

Configuration comes only from server-side environment variables, never from the
browser:

    WAZUH_INDEXER_URL              e.g. https://127.0.0.1:9200
    WAZUH_INDEXER_USERNAME
    WAZUH_INDEXER_PASSWORD
    WAZUH_INDEXER_CA_FILE          PEM root CA used to verify the Indexer certificate
    WAZUH_INDEXER_TLS_SERVER_NAME  optional; name to verify the certificate against
                                   when it differs from the URL host (e.g. wazuh.indexer)

TLS certificate and hostname verification are always on. The client only
issues ``_search`` requests, and only to 127.0.0.1, localhost or the offline lab
subnet 10.20.0.0/24 (see ``netpolicy``).
"""

import base64
import http.client
import json
import logging
import os
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

from .netpolicy import NetworkPolicyError, check_url

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15


class IndexerError(Exception):
    """Indexer failure; the message is safe to show to users (no credentials)."""


@dataclass(frozen=True)
class IndexerConfig:
    url: str
    username: str
    password: str = field(repr=False)
    ca_file: str
    tls_server_name: str = ""
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls, environ=None):
        """Return a config from environment variables, or None if any required one is missing."""
        env = os.environ if environ is None else environ
        values = {key: env.get(f"WAZUH_INDEXER_{key.upper()}", "").strip()
                  for key in ("url", "username", "password", "ca_file")}
        if not all(values.values()):
            return None
        return cls(tls_server_name=env.get("WAZUH_INDEXER_TLS_SERVER_NAME", "").strip(), **values)


class _VerifiedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that verifies the certificate against ``tls_server_name``."""

    def __init__(self, host, port, tls_server_name, context, timeout):
        super().__init__(host, port, context=context, timeout=timeout)
        self._tls_server_name = tls_server_name

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._tls_server_name)


def indexer_ssl_context(ca_file):
    """TLS context trusting only the lab's Wazuh root CA, with chain and hostname verification on.

    Python 3.13+ also enables the strict X.509 profile by default, and the root CA that
    wazuh-install.sh generates (checked with 4.14.9) has no keyUsage extension, so strict
    mode rejects it ("CA cert does not include key usage extension"). Only that strict-profile
    flag is cleared; the certificate must still chain to the pinned CA and match the host name.
    """
    context = ssl.create_default_context(cafile=ca_file)
    context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return context


class IndexerClient:
    def __init__(self, config):
        parts = urlsplit(config.url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("WAZUH_INDEXER_URL must be an https:// URL")
        check_url(config.url, ("https",), "WAZUH_INDEXER_URL")  # offline lab: loopback or 10.20.0.0/24 only
        self._host = parts.hostname
        self._port = parts.port or 9200
        self._tls_server_name = config.tls_server_name or parts.hostname
        self._timeout = config.timeout
        self._context = indexer_ssl_context(config.ca_file)
        token = base64.b64encode(f"{config.username}:{config.password}".encode("utf-8")).decode("ascii")
        self._auth_header = f"Basic {token}"

    def _connection(self):
        return _VerifiedHTTPSConnection(self._host, self._port, self._tls_server_name,
                                        self._context, self._timeout)

    def search(self, index, body):
        """Run a read-only ``_search`` and return the parsed JSON response."""
        path = f"/{quote(index, safe='*,-_.')}/_search"
        conn = self._connection()
        try:
            conn.request("POST", path, body=json.dumps(body).encode("utf-8"), headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
            response = conn.getresponse()
            raw = response.read()
        except ssl.SSLError as e:
            raise IndexerError("TLS verification with the Wazuh Indexer failed. "
                               "Check WAZUH_INDEXER_CA_FILE and WAZUH_INDEXER_TLS_SERVER_NAME.") from e
        except (OSError, http.client.HTTPException) as e:
            raise IndexerError("Could not connect to the Wazuh Indexer. Is the Wazuh lab running?") from e
        finally:
            conn.close()

        if response.status in (401, 403):
            raise IndexerError("The Wazuh Indexer rejected the configured credentials.")
        if response.status != 200:
            raise IndexerError(f"The Wazuh Indexer returned HTTP {response.status}.")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise IndexerError("The Wazuh Indexer returned an unreadable response.") from e


def client_from_env(environ=None):
    """Client from the environment, or None if unset or the URL is outside the allowed lab hosts (logged)."""
    config = IndexerConfig.from_env(environ)
    if not config:
        return None
    try:
        return IndexerClient(config)
    except NetworkPolicyError as e:
        log.error("Wazuh Indexer access disabled: %s", e)
        return None
