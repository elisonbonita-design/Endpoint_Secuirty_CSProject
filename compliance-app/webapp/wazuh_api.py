"""Minimal Wazuh server API client: the one command "Scan now" needs, restarting agents.

An agent runs its SCA policies and inventory when it starts, so restarting it is how
"Scan now" asks for a fresh assessment. Configuration comes only from server-side
environment variables, never from the browser:

    WAZUH_API_URL              e.g. https://127.0.0.1:55000
    WAZUH_API_USERNAME         an API user whose role allows only agent:restart
    WAZUH_API_PASSWORD
    WAZUH_API_CA_FILE          PEM certificate used to verify the API (the API's own
                               self-signed certificate in a default install)
    WAZUH_API_TLS_SERVER_NAME  optional; name to verify the certificate against
                               (a default install's API certificate is for "localhost")

TLS certificate and hostname verification are always on, and only 127.0.0.1, localhost
or the offline lab subnet 10.20.0.0/24 are allowed (see ``netpolicy``).
"""

import base64
import http.client
import json
import logging
import os
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from .indexer import _VerifiedHTTPSConnection, indexer_ssl_context
from .netpolicy import NetworkPolicyError, check_url

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15


class WazuhApiError(Exception):
    """Wazuh API failure; the message is safe to show to users (no credentials)."""


@dataclass(frozen=True)
class WazuhApiConfig:
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
        values = {key: env.get(f"WAZUH_API_{key.upper()}", "").strip()
                  for key in ("url", "username", "password", "ca_file")}
        if not all(values.values()):
            return None
        return cls(tls_server_name=env.get("WAZUH_API_TLS_SERVER_NAME", "").strip(), **values)


class WazuhApiClient:
    def __init__(self, config):
        parts = urlsplit(config.url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("WAZUH_API_URL must be an https:// URL")
        check_url(config.url, ("https",), "WAZUH_API_URL")
        self._host = parts.hostname
        self._port = parts.port or 55000
        self._tls_server_name = config.tls_server_name or parts.hostname
        self._timeout = config.timeout
        self._context = indexer_ssl_context(config.ca_file)
        token = base64.b64encode(f"{config.username}:{config.password}".encode("utf-8")).decode("ascii")
        self._basic = f"Basic {token}"

    def _connection(self):
        return _VerifiedHTTPSConnection(self._host, self._port, self._tls_server_name,
                                        self._context, self._timeout)

    def _request(self, method, path, auth):
        conn = self._connection()
        try:
            conn.request(method, path, headers={"Authorization": auth, "Accept": "application/json"})
            response = conn.getresponse()
            raw = response.read()
        except ssl.SSLError as e:
            raise WazuhApiError("TLS verification with the Wazuh API failed. "
                                "Check WAZUH_API_CA_FILE and WAZUH_API_TLS_SERVER_NAME.") from e
        except (OSError, http.client.HTTPException) as e:
            raise WazuhApiError("Could not connect to the Wazuh API. Is the Wazuh manager running?") from e
        finally:
            conn.close()
        if response.status in (401, 403):
            raise WazuhApiError("The Wazuh API refused the configured account "
                                "(wrong password, or its role does not allow restarting agents).")
        if response.status != 200:
            raise WazuhApiError(f"The Wazuh API returned HTTP {response.status}.")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise WazuhApiError("The Wazuh API returned an unreadable response.") from e

    def restart_agents(self, agent_ids):
        """Ask the manager to restart these agents. Returns ``(restarted_ids, {agent_id: reason})``."""
        ids = sorted(set(agent_ids))
        if not ids:
            return [], {}
        login = self._request("POST", "/security/user/authenticate", self._basic)
        token = (login.get("data") or {}).get("token") if isinstance(login, dict) else None
        if not isinstance(token, str) or not token:
            raise WazuhApiError("The Wazuh API did not return a session token.")
        body = self._request("PUT", "/agents/restart?" + urlencode({"agents_list": ",".join(ids)}),
                             f"Bearer {token}")
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            raise WazuhApiError("The Wazuh API returned an unexpected restart response.")
        restarted = sorted(str(a) for a in data.get("affected_items") or [] if str(a) in ids)
        failed = {}
        for item in data.get("failed_items") or []:
            error = item.get("error") if isinstance(item, dict) else None
            reason = (error or {}).get("message") if isinstance(error, dict) else None
            for agent in (item.get("id") or []) if isinstance(item, dict) else []:
                failed[str(agent)] = reason or "The agent could not be restarted."
        return restarted, failed


def client_from_env(environ=None):
    """Client from the environment, or None if unset or the URL is outside the allowed lab hosts (logged)."""
    config = WazuhApiConfig.from_env(environ)
    if not config:
        return None
    try:
        return WazuhApiClient(config)
    except NetworkPolicyError as e:
        log.error("Wazuh API access disabled: %s", e)
        return None
