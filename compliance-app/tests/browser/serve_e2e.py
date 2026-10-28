"""Start the dashboard for browser tests: python tests/browser/serve_e2e.py [port] [--login]

Uses a fresh temporary database and no Wazuh Indexer, so runs are repeatable and never
touch instance/assets.db. Without --login every request acts as a test administrator
(login is tested separately). With --login, sign-in is required and two synthetic
accounts exist: e2e-admin / e2e-reviewer, password "e2e-synthetic-pass" (test only).
"""

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from webapp.app import create_app  # noqa: E402
from webapp.auth import UserStore  # noqa: E402

args = [a for a in sys.argv[1:] if not a.startswith("--")]
port = int(args[0]) if args else 5001
login = "--login" in sys.argv
db = Path(tempfile.mkdtemp(prefix="compliance-e2e-")) / "assets.db"
if login:
    users = UserStore(db)
    users.create("e2e-admin", "e2e-synthetic-pass", "admin", datetime.now(timezone.utc))
    users.create("e2e-reviewer", "e2e-synthetic-pass", "reviewer", datetime.now(timezone.utc))
create_app(login_required=login, indexer_client=None, ai_provider=None, asset_db_path=db,
           secret_key="e2e-only-" + "0" * 64, collector_token=None).run(host="127.0.0.1", port=port, debug=False)
