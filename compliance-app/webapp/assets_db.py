"""Persistent endpoint asset assignments (department, building, floor, room) in SQLite.

Each assignment also carries the two asset-importance fields used by risk scoring:
``handles_client_data`` (default false) and ``role`` (agent, team_lead, it_admin or
shared_kiosk; default agent). Schema changes are applied by ``db_migrations``.

An assignment is keyed by a Wazuh agent ID or by a hostname. Lookups prefer the
agent ID and fall back to the hostname (case-insensitive). Nothing is ever
derived from a hostname's text: an endpoint without an assignment stays
unassigned.
"""

import csv
import io
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from compliance.fleet import LOCATION_FIELDS
from compliance.risk import ROLES

from .db_migrations import connect, migrate

KEY_TYPES = ("agent_id", "hostname")
MAX_FIELD_CHARS = 100
MAX_IMPORT_ROWS = 2000
_KEY_PATTERNS = {
    "agent_id": re.compile(r"^[A-Za-z0-9_-]{1,32}$"),
    "hostname": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$"),
}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_assignments (
    key_type   TEXT NOT NULL CHECK (key_type IN ('agent_id', 'hostname')),
    key_value  TEXT NOT NULL,
    department TEXT,
    building   TEXT,
    floor      TEXT,
    room       TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (key_type, key_value)
);
CREATE TABLE IF NOT EXISTS floor_plans (
    building     TEXT NOT NULL,
    floor        TEXT NOT NULL,
    content_type TEXT NOT NULL,
    image        BLOB NOT NULL,
    uploaded_at  TEXT NOT NULL,
    PRIMARY KEY (building, floor)
);
-- One marker per endpoint, valid only while the endpoint is assigned to this building and floor.
CREATE TABLE IF NOT EXISTS marker_positions (
    agent_id   TEXT PRIMARY KEY,
    building   TEXT NOT NULL,
    floor      TEXT NOT NULL,
    x          REAL NOT NULL CHECK (x BETWEEN 0 AND 1),
    y          REAL NOT NULL CHECK (y BETWEEN 0 AND 1),
    updated_at TEXT NOT NULL
);
"""

MAX_IMAGE_BYTES = 2 * 1024 * 1024
# Raster formats only (no SVG: it can carry script). The file content must match the extension.
IMAGE_TYPES = {"image/png": (".png",), "image/jpeg": (".jpg", ".jpeg"), "image/webp": (".webp",)}


class AssetError(ValueError):
    """Invalid assignment input; the message is safe to show users."""


def sniff_image_type(data):
    """Content type from the file signature, or None if not PNG, JPEG or WebP."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_place(building, floor):
    """Validated (building, floor); both are required."""
    values = _clean_fields({"building": building, "floor": floor})
    if not values["building"] or not values["floor"]:
        raise AssetError("Building and floor are both required.")
    return values["building"], values["floor"]


def _coordinate(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise AssetError(f"{name} must be a number from 0 to 1.")
    return float(value)


def _clean_key(key_type, key_value):
    if key_type not in KEY_TYPES:
        raise AssetError("key_type must be 'agent_id' or 'hostname'.")
    value = key_value.strip() if isinstance(key_value, str) else ""
    if not _KEY_PATTERNS[key_type].fullmatch(value):
        raise AssetError(f"The {key_type.replace('_', ' ')} is not valid.")
    return value.lower() if key_type == "hostname" else value


_TRUE = ("1", "true", "yes", "y")
_FALSE = ("0", "false", "no", "n")


def _clean_risk_fields(fields):
    """``{"handles_client_data": 0|1, "role": ...}`` for the keys present (and not None) in ``fields``."""
    cleaned = {}
    flag = fields.get("handles_client_data")
    if flag is not None:
        if isinstance(flag, str) and flag.strip().lower() in _TRUE + _FALSE:
            flag = flag.strip().lower() in _TRUE
        if not isinstance(flag, bool):
            raise AssetError("Handles client data must be true or false.")
        cleaned["handles_client_data"] = int(flag)
    role = fields.get("role")
    if role is not None:
        role = role.strip().lower() if isinstance(role, str) else role
        if role not in ROLES:
            raise AssetError(f"Role must be one of: {', '.join(ROLES)}.")
        cleaned["role"] = role
    return cleaned


def _clean_fields(fields):
    cleaned = {}
    for name in LOCATION_FIELDS:
        value = fields.get(name)
        if value is None:
            cleaned[name] = None
            continue
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise AssetError(f"{name.capitalize()} must be text.")
        value = " ".join(str(value).split())
        if _CONTROL.search(value) or len(value) > MAX_FIELD_CHARS:
            raise AssetError(f"{name.capitalize()} must be at most {MAX_FIELD_CHARS} plain characters.")
        cleaned[name] = value or None
    return cleaned


def ensure_schema(path):
    """Create the original tables if missing, then apply pending migrations."""
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
    migrate(path)


class AssetStore:
    def __init__(self, path):
        self._path = str(path)
        ensure_schema(self._path)

    @contextmanager
    def _connect(self):
        """Connection that commits on success, rolls back on error and is always closed."""
        conn = connect(self._path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def all(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM asset_assignments ORDER BY key_type, key_value").fetchall()
        return [dict(row) for row in rows]

    def upsert(self, key_type, key_value, fields, conn=None):
        """Save the location fields; risk fields change only when present (not None) in ``fields``."""
        key_value = _clean_key(key_type, key_value)
        values = _clean_fields(fields)
        risk = _clean_risk_fields(fields)
        row = (key_type, key_value, *[values[f] for f in LOCATION_FIELDS],
               datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        sql = ("INSERT INTO asset_assignments (key_type, key_value, department, building, floor, room, updated_at) "
               "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (key_type, key_value) DO UPDATE SET "
               "department=excluded.department, building=excluded.building, floor=excluded.floor, "
               "room=excluded.room, updated_at=excluded.updated_at")
        statements = [(sql, row)]
        if risk:
            assignments = ", ".join(f"{name} = ?" for name in risk)
            statements.append((f"UPDATE asset_assignments SET {assignments} WHERE key_type = ? AND key_value = ?",
                               (*risk.values(), key_type, key_value)))
        if conn is not None:
            for statement in statements:
                conn.execute(*statement)
            return
        with self._connect() as own:
            for statement in statements:
                own.execute(*statement)

    def delete(self, key_type, key_value):
        key_value = _clean_key(key_type, key_value)
        with self._connect() as conn:
            return conn.execute("DELETE FROM asset_assignments WHERE key_type = ? AND key_value = ?",
                                (key_type, key_value)).rowcount > 0

    def lookup_table(self):
        """Return ``find(agent_id, hostname) -> assignment or None`` over a snapshot of all rows."""
        rows = self.all()
        by_type = {t: {r["key_value"]: r for r in rows if r["key_type"] == t} for t in KEY_TYPES}

        def find(agent_id, hostname):
            if agent_id and agent_id in by_type["agent_id"]:
                return by_type["agent_id"][agent_id]
            if hostname:
                return by_type["hostname"].get(hostname.lower())
            return None
        return find

    def import_csv(self, text):
        """Upsert rows from CSV with columns agent_id, hostname, department, building, floor, room
        and optional handles_client_data (true/false) and role.

        Each row needs an agent_id or a hostname (agent_id wins when both are set). An empty or
        missing risk column keeps the saved value (or the default for a new row).
        All rows are validated first; nothing is saved if any row is invalid.
        """
        reader = csv.DictReader(io.StringIO(text))
        header = [h.strip().lower() for h in (reader.fieldnames or [])]
        if not ({"agent_id", "hostname"} & set(header)):
            raise AssetError("The CSV needs a header row with an agent_id or hostname column.")
        reader.fieldnames = header
        pending, errors = [], []
        for line, row in enumerate(reader, start=2):
            if len(pending) + len(errors) >= MAX_IMPORT_ROWS:
                raise AssetError(f"The CSV has more than {MAX_IMPORT_ROWS} rows.")
            row = {k: (v.strip() if isinstance(v, str) else None) for k, v in row.items() if k}
            if not any(row.values()):
                continue
            key_type = "agent_id" if row.get("agent_id") else "hostname"
            try:
                key_value = _clean_key(key_type, row.get(key_type))
                fields = {f: row.get(f) or None for f in (*LOCATION_FIELDS, "handles_client_data", "role")}
                _clean_fields(fields)
                _clean_risk_fields(fields)
                pending.append((key_type, key_value, fields))
            except AssetError as e:
                errors.append(f"Line {line}: {e}")
        if errors:
            raise AssetError("Nothing was imported. " + " ".join(errors[:10]))
        with self._connect() as conn:
            for key_type, key_value, fields in pending:
                self.upsert(key_type, key_value, fields, conn=conn)
        return len(pending)

    # ---- Floor plans ----

    def save_floor_plan(self, building, floor, filename, data):
        building, floor = clean_place(building, floor)
        if not data:
            raise AssetError("The image file is empty.")
        if len(data) > MAX_IMAGE_BYTES:
            raise AssetError(f"The image is too large. The limit is {MAX_IMAGE_BYTES // (1024 * 1024)} MB.")
        content_type = sniff_image_type(data)
        extension = "." + filename.rsplit(".", 1)[-1].lower() if isinstance(filename, str) and "." in filename else ""
        if content_type is None or extension not in IMAGE_TYPES[content_type]:
            raise AssetError("Upload a PNG, JPEG or WebP image whose file extension matches its content.")
        with self._connect() as conn:
            conn.execute("INSERT INTO floor_plans (building, floor, content_type, image, uploaded_at) "
                         "VALUES (?, ?, ?, ?, ?) ON CONFLICT (building, floor) DO UPDATE SET "
                         "content_type=excluded.content_type, image=excluded.image, uploaded_at=excluded.uploaded_at",
                         (building, floor, content_type, sqlite3.Binary(data), _now()))

    def floor_plans(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT building, floor, content_type, length(image) AS size, uploaded_at "
                                "FROM floor_plans ORDER BY building, floor").fetchall()
        return [dict(row) for row in rows]

    def floor_plan_image(self, building, floor):
        """(content_type, bytes) or None."""
        building, floor = clean_place(building, floor)
        with self._connect() as conn:
            row = conn.execute("SELECT content_type, image FROM floor_plans WHERE building = ? AND floor = ?",
                               (building, floor)).fetchone()
        return (row["content_type"], bytes(row["image"])) if row else None

    def delete_floor_plan(self, building, floor):
        building, floor = clean_place(building, floor)
        with self._connect() as conn:
            return conn.execute("DELETE FROM floor_plans WHERE building = ? AND floor = ?",
                                (building, floor)).rowcount > 0

    # ---- Marker positions (fractions of the floor-plan image, 0..1) ----

    def set_position(self, agent_id, building, floor, x, y):
        agent_id = _clean_key("agent_id", agent_id)
        building, floor = clean_place(building, floor)
        x, y = _coordinate(x, "x"), _coordinate(y, "y")
        with self._connect() as conn:
            conn.execute("INSERT INTO marker_positions (agent_id, building, floor, x, y, updated_at) "
                         "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (agent_id) DO UPDATE SET building=excluded.building, "
                         "floor=excluded.floor, x=excluded.x, y=excluded.y, updated_at=excluded.updated_at",
                         (agent_id, building, floor, x, y, _now()))

    def positions(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM marker_positions").fetchall()
        return {row["agent_id"]: dict(row) for row in rows}

    def delete_position(self, agent_id):
        agent_id = _clean_key("agent_id", agent_id)
        with self._connect() as conn:
            return conn.execute("DELETE FROM marker_positions WHERE agent_id = ?", (agent_id,)).rowcount > 0
