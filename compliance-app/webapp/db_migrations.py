"""Schema migrations for instance/assets.db, tracked with ``PRAGMA user_version``.

Version 0 is the original schema created by ``assets_db.SCHEMA`` (asset_assignments,
floor_plans, marker_positions). Each migration runs once, inside one transaction;
running ``migrate`` again is a no-op. Existing rows are kept.
"""

import sqlite3

BUSY_TIMEOUT_SECONDS = 10

MIGRATIONS = {
    1: """
ALTER TABLE asset_assignments ADD COLUMN handles_client_data INTEGER NOT NULL DEFAULT 0
    CHECK (handles_client_data IN (0, 1));
ALTER TABLE asset_assignments ADD COLUMN role TEXT NOT NULL DEFAULT 'agent'
    CHECK (role IN ('agent', 'team_lead', 'it_admin', 'shared_kiosk'));

-- One row per (data source, endpoint, source, check). Sample and live rows never mix.
CREATE TABLE findings (
    id                INTEGER PRIMARY KEY,
    data_source       TEXT NOT NULL CHECK (data_source IN ('sample', 'wazuh')),
    endpoint_id       TEXT NOT NULL,
    endpoint_label    TEXT,
    check_key         TEXT NOT NULL,
    requirement_id    TEXT,
    catalogue_version TEXT,
    source            TEXT NOT NULL CHECK (source IN ('sca', 'event', 'inventory', 'vulnerability', 'fim', 'bitlocker')),
    title             TEXT NOT NULL,
    remediation       TEXT,
    state             TEXT NOT NULL CHECK (state IN ('compliant', 'non_compliant', 'not_applicable', 'unknown')),
    status            TEXT NOT NULL CHECK (status IN ('open', 'in_review', 'exception', 'fixed_pending', 'cleared', 'verified')),
    severity          TEXT CHECK (severity IS NULL OR severity IN ('critical', 'high', 'medium', 'low')),
    cvss              REAL CHECK (cvss IS NULL OR cvss BETWEEN 0 AND 10),
    cve_id            TEXT,
    opened_at         TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    verified_at       TEXT,
    status_changed_at TEXT NOT NULL,
    times_reopened    INTEGER NOT NULL DEFAULT 0 CHECK (times_reopened >= 0),
    UNIQUE (data_source, endpoint_id, source, check_key)
);

-- Score history: a row is added only when a finding's score, band, reason or weights version changes.
CREATE TABLE risk_scores (
    id              INTEGER PRIMARY KEY,
    finding_id      INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    score           INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    band            TEXT NOT NULL,
    reason          TEXT NOT NULL,
    weights_version TEXT NOT NULL,
    computed_at     TEXT NOT NULL
);
CREATE INDEX risk_scores_by_finding ON risk_scores (finding_id, id);
""",
    2: """
-- Audit trail of every finding: status changes by people or by sync, and review notes.
CREATE TABLE finding_events (
    id          INTEGER PRIMARY KEY,
    finding_id  INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('created', 'status', 'note', 'sync')),
    from_status TEXT,
    to_status   TEXT,
    note        TEXT
);
CREATE INDEX finding_events_by_finding ON finding_events (finding_id, id);

-- App accounts. Only password hashes are stored.
CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'reviewer')),
    active          INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

-- BitLocker status fields sent by the PowerShell collector. Never recovery keys or key protectors.
CREATE TABLE bitlocker_reports (
    id                    INTEGER PRIMARY KEY,
    hostname              TEXT NOT NULL COLLATE NOCASE,
    received_at           TEXT NOT NULL,
    collected_at          TEXT NOT NULL,
    mount_point           TEXT NOT NULL,
    volume_type           TEXT,
    volume_status         TEXT,
    protection_status     TEXT,
    encryption_percentage REAL CHECK (encryption_percentage IS NULL OR encryption_percentage BETWEEN 0 AND 100),
    encryption_method     TEXT,
    lock_status           TEXT
);
CREATE INDEX bitlocker_reports_by_host ON bitlocker_reports (hostname, id);
""",
}
LATEST = max(MIGRATIONS)


def connect(path):
    """Connection with a busy timeout so short writes from the background job and requests wait, not fail."""
    conn = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def migrate(path):
    """Bring the database at ``path`` up to ``LATEST``. Returns the versions applied."""
    conn = connect(path)
    conn.isolation_level = None  # explicit BEGIN/COMMIT below
    applied = []
    try:
        # WAL lets page reads continue while the background job writes.
        conn.execute("PRAGMA journal_mode = WAL")
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        for version in sorted(v for v in MIGRATIONS if v > current):
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Re-check inside the write lock: another process may have migrated meanwhile.
                if conn.execute("PRAGMA user_version").fetchone()[0] >= version:
                    conn.execute("ROLLBACK")
                    continue
                for statement in (s.strip() for s in MIGRATIONS[version].split(";")):
                    if statement and not all(line.strip().startswith("--") for line in statement.splitlines()):
                        conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {int(version)}")
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            applied.append(version)
    finally:
        conn.close()
    return applied
