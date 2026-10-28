"""Run the dashboard: python -m webapp

Defaults to http://127.0.0.1:5000. In the lab, instance/app.env can set APP_HOST to the
SEC01 lab address (10.20.0.0/24 only) with TLS_CERT / TLS_KEY so the BitLocker collector
on WS01 can reach it over HTTPS.
"""

import logging
import os
import sys

from .app import create_app
from .env_file import APP_KEYS, APP_PATH, load_env_file
from .netpolicy import host_allowed
from .prioritization import start_background_recompute

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

# Optional settings files; real environment variables take precedence.
load_env_file()
load_env_file(APP_PATH, allowed=APP_KEYS)

host = os.environ.get("APP_HOST", "127.0.0.1").strip()
port = int(os.environ.get("APP_PORT", "5000"))
cert, key = os.environ.get("TLS_CERT", "").strip(), os.environ.get("TLS_KEY", "").strip()
if not host_allowed(host):
    sys.exit(f"APP_HOST {host!r} is not allowed: use 127.0.0.1 or an address in 10.20.0.0/24.")
if host not in ("127.0.0.1", "localhost") and not (cert and key):
    sys.exit("Listening on the lab network requires TLS_CERT and TLS_KEY (HTTPS).")

app = create_app()
DEBUG = False
# Recompute risk scores every 5 minutes so "time open" ages; started once, never under tests.
start_background_recompute(app.extensions["risk_service"](), debug=DEBUG)

# The Flask development server is enough for the isolated three-laptop lab, not for production.
app.run(host=host, port=port, debug=DEBUG, ssl_context=(cert, key) if cert and key else None)
