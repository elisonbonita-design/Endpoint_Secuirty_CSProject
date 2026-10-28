"""App accounts: login with lockout, two roles, and the first-admin command.

Roles (paper, Scope): ``admin`` manages accounts, assets, floor plans and exceptions;
``reviewer`` reviews findings, records simulated fixes and notes, and prepares reports.
Only password hashes (werkzeug, scrypt) are stored. After ``MAX_FAILED_LOGINS`` wrong
passwords an account is locked for ``LOCKOUT``.

Create the first administrator (prompts for the password, never echoes it):
    python -m webapp.auth create-user <username> --role admin
"""

import argparse
import getpass
import re
import secrets
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from .assets_db import ensure_schema
from .db_migrations import connect

ROLES = ("admin", "reviewer")
MIN_PASSWORD_CHARS = 12
MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
USERNAME = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
# Checked when the user does not exist, so a wrong username takes as long as a wrong password.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


class AuthError(ValueError):
    """Bad account input; the message is safe to show users."""


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None


def check_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_CHARS:
        raise AuthError(f"The password must have at least {MIN_PASSWORD_CHARS} characters.")
    if len(password) > 256:
        raise AuthError("The password is too long.")
    return password


class UserStore:
    def __init__(self, path):
        self._path = str(path)
        ensure_schema(self._path)

    @contextmanager
    def _connect(self):
        conn = connect(self._path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def count(self):
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def all(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT id, username, role, active, locked_until, created_at, last_login_at "
                                "FROM users ORDER BY username").fetchall()
        return [dict(r) for r in rows]

    def get(self, user_id):
        with self._connect() as conn:
            row = conn.execute("SELECT id, username, role, active FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def create(self, username, password, role, now):
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise AuthError("The username must be 3-32 letters, digits, dots, dashes or underscores.")
        if role not in ROLES:
            raise AuthError(f"The role must be one of: {', '.join(ROLES)}.")
        hashed = generate_password_hash(check_password(password))
        try:
            with self._connect() as conn:
                cur = conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                                   (username, hashed, role, _iso(now)))
        except Exception as e:  # sqlite3.IntegrityError: duplicate username
            if "UNIQUE" in str(e):
                raise AuthError("That username already exists.") from None
            raise
        return cur.lastrowid

    def update(self, user_id, role=None, active=None, password=None, actor_id=None):
        changes = {}
        if role is not None:
            if role not in ROLES:
                raise AuthError(f"The role must be one of: {', '.join(ROLES)}.")
            changes["role"] = role
        if active is not None:
            if not isinstance(active, bool):
                raise AuthError("active must be true or false.")
            changes["active"] = int(active)
        if password is not None:
            changes.update(password_hash=generate_password_hash(check_password(password)), failed_logins=0,
                           locked_until=None)
        if not changes:
            raise AuthError("Nothing to change.")
        with self._connect() as conn:
            row = conn.execute("SELECT role, active FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise AuthError("That user does not exist.")
            demoting = (changes.get("role", row["role"]) != "admin" or changes.get("active", row["active"]) == 0)
            if row["role"] == "admin" and row["active"] and demoting:
                admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
                if admins <= 1:
                    raise AuthError("Keep at least one active administrator.")
            if user_id == actor_id and ("role" in changes or changes.get("active") == 0):
                raise AuthError("You cannot change your own role or disable your own account.")
            columns = ", ".join(f"{k} = ?" for k in changes)
            conn.execute(f"UPDATE users SET {columns} WHERE id = ?", (*changes.values(), user_id))

    def authenticate(self, username, password, now):
        """The user dict on success, else None. Wrong passwords count toward a temporary lockout.

        Returns ("locked", None) style information through ``AuthError`` for locked accounts so the
        login page can say so without revealing whether other usernames exist.
        """
        if not isinstance(username, str) or not isinstance(password, str) or len(password) > 256:
            return None
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
            if row is None:
                check_password_hash(_DUMMY_HASH, password)
                return None
            locked = _parse(row["locked_until"])
            if locked and locked > now:
                raise AuthError("Too many failed sign-ins. Try again later.")
            if not check_password_hash(row["password_hash"], password):
                failed = row["failed_logins"] + 1
                lock = _iso(now + LOCKOUT) if failed >= MAX_FAILED_LOGINS else None
                conn.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                             (0 if lock else failed, lock, row["id"]))
                return None
            if not row["active"]:
                return None
            conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
                         (_iso(now), row["id"]))
            return {"id": row["id"], "username": row["username"], "role": row["role"]}


def load_secret_key(path):
    """Flask session key from ``path``; created once with 32 random bytes (keep instance/ private)."""
    path = Path(path)
    try:
        key = path.read_text(encoding="ascii").strip()
        if len(key) >= 64:
            return key
    except OSError:
        pass
    key = secrets.token_hex(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key, encoding="ascii")
    return key


def main(argv=None):
    from .app import ASSET_DB_PATH
    parser = argparse.ArgumentParser(prog="python -m webapp.auth")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user", help="create an account (asks for the password)")
    create.add_argument("username")
    create.add_argument("--role", choices=ROLES, default="reviewer")
    args = parser.parse_args(argv)
    password = getpass.getpass("Password (12+ characters): ")
    if password != getpass.getpass("Repeat password: "):
        print("The passwords do not match.", file=sys.stderr)
        return 1
    try:
        UserStore(ASSET_DB_PATH).create(args.username, password, args.role, datetime.now(timezone.utc))
    except AuthError as e:
        print(e, file=sys.stderr)
        return 1
    print(f"Created {args.role} account '{args.username}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
