"""Load the optional local AI settings from instance/ai.env (copy ai.env.example).

Only the four AI_* variables below are read; nothing else in the file is used, and
values are never printed. Existing environment variables win, and placeholder
values (e.g. *****) are ignored. There are no API keys: the AI is a local Ollama.
"""

import os
import re
from pathlib import Path

ALLOWED_KEYS = {"AI_ENABLED", "AI_BASE_URL", "AI_MODEL", "AI_TIMEOUT_SECONDS"}
DEFAULT_PATH = Path(__file__).resolve().parent.parent / "instance" / "ai.env"
# Server settings for the lab deployment (instance/app.env, copy app.env.example).
APP_KEYS = {"APP_HOST", "APP_PORT", "TLS_CERT", "TLS_KEY", "COLLECTOR_TOKEN", "SESSION_COOKIE_SECURE"}
APP_PATH = DEFAULT_PATH.with_name("app.env")
_PLACEHOLDER = re.compile(r"\*+|<.*>|your[-_ ]?.*key.*", re.I)


def load_env_file(path=DEFAULT_PATH, environ=None, allowed=None):
    """Set allowed, non-placeholder values from ``path`` that are not already set.

    Returns the names that were loaded (never the values).
    """
    env = os.environ if environ is None else environ
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return []
    loaded = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1].strip()
        if name not in (ALLOWED_KEYS if allowed is None else allowed) or not value or _PLACEHOLDER.fullmatch(value) or env.get(name):
            continue
        env[name] = value
        loaded.append(name)
    return loaded
