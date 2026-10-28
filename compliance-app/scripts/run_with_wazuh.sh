#!/usr/bin/env bash
# Start the dashboard (Windows Python) connected to the local Wazuh Docker lab.
# Run from WSL Ubuntu:  bash "/mnt/a/CAPSTONE SYSTEM/compliance-app/scripts/run_with_wazuh.sh"
#
# The local AI explainer (Ollama) is optional and off by default: set AI_ENABLED=true (and
# optionally AI_BASE_URL, AI_MODEL, AI_TIMEOUT_SECONDS) in this shell or in instance/ai.env.
# It must run on this machine or the offline lab network (see webapp/ai_providers.py).
#
# Indexer credentials are read from the lab's compose config at launch and passed
# to the server process as environment variables only; nothing secret is written
# to disk or printed. Requires instance/wazuh-root-ca.pem (the lab's public root CA).
set -euo pipefail

LAB_DIR="${WAZUH_LAB_DIR:-$HOME/labs/wazuh-docker/single-node}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "$APP_DIR/instance/wazuh-root-ca.pem" ]; then
    echo "Missing $APP_DIR/instance/wazuh-root-ca.pem. Copy the public CA with:" >&2
    echo "  (cd \"$LAB_DIR\" && docker compose cp wazuh.indexer:/usr/share/wazuh-indexer/config/certs/root-ca.pem \"$APP_DIR/instance/wazuh-root-ca.pem\")" >&2
    exit 1
fi

eval "$(cd "$LAB_DIR" && docker compose config --format json | python3 -c '
import json, shlex, sys
env = json.load(sys.stdin)["services"]["wazuh.dashboard"].get("environment", {})
print("export WAZUH_INDEXER_USERNAME=" + shlex.quote(env.get("INDEXER_USERNAME", "")))
print("export WAZUH_INDEXER_PASSWORD=" + shlex.quote(env.get("INDEXER_PASSWORD", "")))
')"
if [ -z "$WAZUH_INDEXER_USERNAME" ] || [ -z "$WAZUH_INDEXER_PASSWORD" ]; then
    echo "Could not read Indexer credentials from $LAB_DIR/docker-compose.yml" >&2
    exit 1
fi

export WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://127.0.0.1:9200}"
export WAZUH_INDEXER_CA_FILE="instance/wazuh-root-ca.pem"
export WAZUH_INDEXER_TLS_SERVER_NAME="${WAZUH_INDEXER_TLS_SERVER_NAME:-wazuh.indexer}"
export WSLENV="WAZUH_INDEXER_URL:WAZUH_INDEXER_USERNAME:WAZUH_INDEXER_PASSWORD:WAZUH_INDEXER_CA_FILE:WAZUH_INDEXER_TLS_SERVER_NAME"
# Optional local AI settings, passed through if set in this shell (e.g. export AI_ENABLED=true).
WSLENV="$WSLENV:AI_ENABLED:AI_BASE_URL:AI_MODEL:AI_TIMEOUT_SECONDS"

cd "$APP_DIR"
echo "Dashboard: http://127.0.0.1:5000/  (Ctrl+C to stop)"
exec python.exe -m webapp
