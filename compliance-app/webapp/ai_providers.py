"""Optional local AI (Ollama) that only writes explanations. It never decides priority.

Settings (server-side environment variables or instance/ai.env):

    AI_ENABLED          true to turn it on (default false)
    AI_BASE_URL         default http://127.0.0.1:11434; host must be 127.0.0.1, localhost
                        or inside 10.20.0.0/24, checked at startup and before every request
    AI_MODEL            default llama3.2:3b
    AI_TIMEOUT_SECONDS  default 20

Requests go only to ``{AI_BASE_URL}/api/generate`` with {"model", "prompt", "stream": false}.
Proxies from the environment are ignored and redirects are refused, so a request can
never leave the allowed hosts. There are no API keys and no cloud providers.
"""

import json
import logging
import os
import re
import socket
import urllib.error
import urllib.request

from .netpolicy import NetworkPolicyError, check_url

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_TIMEOUT = 20.0
MAX_RESPONSE_BYTES = 256 * 1024
MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_TRUE = ("1", "true", "yes", "on")


class AIError(Exception):
    """The local AI could not answer; the message is safe to show users."""


class AITimeout(AIError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not followed", headers, fp)


def build_opener():
    """Opener without proxies (HTTP(S)_PROXY variables can never route AI traffic elsewhere) or redirects."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


_OPENER = build_opener()


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url, model, timeout=DEFAULT_TIMEOUT):
        check_url(base_url, ("http", "https"), "AI_BASE_URL")
        if not MODEL_PATTERN.fullmatch(model or ""):
            raise NetworkPolicyError("AI_MODEL is not a valid model name.")
        self.base_url = base_url.strip().rstrip("/")
        self.model = model
        self.timeout = timeout

    def __repr__(self):
        return f"OllamaProvider(base_url={self.base_url!r}, model={self.model!r})"

    def generate(self, prompt):
        """Return the model's text for ``prompt``. Raises ``AIError`` / ``AITimeout``."""
        try:
            check_url(self.base_url, ("http", "https"), "AI_BASE_URL")  # re-checked before every request
        except NetworkPolicyError as e:
            log.error("Local AI request blocked: %s", e)
            raise AIError("The local AI address is not allowed.") from e
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode("utf-8")
        request = urllib.request.Request(f"{self.base_url}/api/generate", data=body, method="POST",
                                         headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with _OPENER.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as e:
            raise AIError(f"The local AI returned an error (HTTP {e.code}).") from None
        except (TimeoutError, socket.timeout) as e:
            raise AITimeout("The local AI did not respond in time.") from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                raise AITimeout("The local AI did not respond in time.") from e
            raise AIError("Could not reach the local AI. Is Ollama running?") from e
        except OSError as e:
            raise AIError("Could not reach the local AI. Is Ollama running?") from e
        if len(raw) > MAX_RESPONSE_BYTES:
            raise AIError("The local AI response was too large.")
        try:
            text = json.loads(raw.decode("utf-8")).get("response")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as e:
            raise AIError("The local AI returned an unreadable response.") from e
        if not isinstance(text, str) or not text.strip():
            raise AIError("The local AI returned an empty answer.")
        return text.strip()


def provider_from_env(environ=None):
    """The configured provider, or None when AI is disabled or misconfigured (the reason is logged)."""
    env = os.environ if environ is None else environ
    if env.get("AI_ENABLED", "").strip().lower() not in _TRUE:
        return None
    base_url = env.get("AI_BASE_URL", "").strip() or DEFAULT_BASE_URL
    model = env.get("AI_MODEL", "").strip() or DEFAULT_MODEL
    try:
        timeout = float(env.get("AI_TIMEOUT_SECONDS", "").strip() or DEFAULT_TIMEOUT)
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    try:
        return OllamaProvider(base_url, model, timeout=max(1.0, min(timeout, 120.0)))
    except NetworkPolicyError as e:
        log.error("Local AI disabled: %s", e)
        return None
