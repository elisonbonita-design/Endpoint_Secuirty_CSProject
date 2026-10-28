# Compliance monitoring app (capstone prototype)

This Flask and SQLite dashboard reads Wazuh SCA results from the Wazuh Indexer (read
only), sorts them into four states and shows them as several views:

- a fleet overview, an endpoint map and a floor plan;
- a list of findings ranked by a rule-based risk score (see
  [docs/prioritization.md](docs/prioritization.md)).

The app is built for an **isolated lab**. It only talks to 127.0.0.1, localhost or
addresses inside 10.20.0.0/24, and it refuses any other Indexer or AI address at
startup.

## Run

```bash
pip install -r requirements.txt
python -m webapp.auth create-user admin --role admin   # first time: asks for a password (12+ chars)
python -m webapp                     # http://127.0.0.1:5000, sign in, sample data available
bash scripts/run_with_wazuh.sh       # from WSL: also connects to the local Wazuh lab
```

Sign-in is required. Admins manage accounts, assets, floor plans and exceptions;
reviewers review findings, record simulated fixes and print reports. See
[docs/sources.md](docs/sources.md) for the data sources, the workflow and the roles.

### Lab deployment (SEC01) and the BitLocker collector

1. Copy `instance/app.env.example` to `instance/app.env` and set these values:

   | Setting | Value |
   |---|---|
   | `APP_HOST` | `10.20.0.20` |
   | `APP_PORT` | `8443` |
   | `TLS_CERT` / `TLS_KEY` | the lab certificate files |
   | `SESSION_COOKIE_SECURE` | `1` |
   | `COLLECTOR_TOKEN` | a random value of 32+ characters |

   The app refuses any host outside 127.0.0.1 or 10.20.0.0/24, and refuses a lab
   address without TLS.
2. On WS01, put the same token in `C:\ProgramData\CapstoneCollector\token.txt` and
   restrict that file to Administrators and SYSTEM.
3. Schedule `collector\Send-BitLockerStatus.ps1 -ServerUrl https://10.20.0.20:8443` as
   SYSTEM (GPO LAB-WS-Deploy). Run it with `-DryRun` first to see exactly what it would
   send.

The database `instance/assets.db` is created or upgraded automatically on first start,
and existing rows are kept. Migrations are tracked with `PRAGMA user_version`; see
`webapp/db_migrations.py`.

## Test

```bash
python -m unittest discover -s tests          # unit and API tests, no network
python -m pytest tests                        # same tests, if pytest is installed
```

The browser flows need `playwright-cli` and a test server running on port 5001:

```bash
python tests/browser/serve_e2e.py 5001            # no sign-in (test only), for the dashboard/floor plan flows
playwright-cli run-code --filename=tests/browser/prioritization_flows.js
python tests/browser/serve_e2e.py 5002 --login    # synthetic e2e accounts, for the workflow flow
playwright-cli run-code --filename=tests/browser/workflow_flows.js
```

## Optional local AI (Ollama)

The AI is **off by default**. It only writes plain-language explanations: priority
always comes from the rule-based score, and the AI cannot change any stored value.
It must run on this machine or on the offline lab network. No cloud AI is used, and
no API key exists.

1. While the lab is in **setup mode** (online), install Ollama on SEC01 or on the
   machine that runs the app, then download a small model:
   `ollama pull llama3.2:3b`
2. Switch the lab back to **lab mode** (offline). Ollama works without internet once
   the model is downloaded.
3. Copy `instance/ai.env.example` to `instance/ai.env` and set `AI_ENABLED=true`. The
   other settings are:

   | Setting | Default | Notes |
   |---|---|---|
   | `AI_BASE_URL` | `http://127.0.0.1:11434` | Must be 127.0.0.1, localhost or an address in 10.20.0.0/24. Any other address keeps AI disabled and logs an error. |
   | `AI_MODEL` | `llama3.2:3b` | |
   | `AI_TIMEOUT_SECONDS` | `20` | |

4. Restart the app. Each finding now has an **Explain** button, and the Overview has a
   **Daily summary** button. If Ollama is not running or is too slow, the app shows
   the rule-based reason and remediation instead.
