"""Persistent findings, their audit trail and risk-score history (same SQLite file as the assets).

Only the minimum the workflow and the risk score need is stored: no file contents,
credentials or raw alerts. Every write is one short transaction (read first, compute in
Python, then write), so the background recompute and web requests do not block each
other for long.

Status changes by people follow ``MANUAL_TRANSITIONS``. Nobody can set ``cleared`` or
``verified`` by hand: only a later assessment (sync) can, so a finding never becomes
verified just because someone changed a status field.
"""

import re
from contextlib import contextmanager
from datetime import timezone

from compliance.finding_sync import STATUSES, transition
from compliance.sources import sca_results

from .assets_db import ensure_schema
from .db_migrations import connect

DATA_SOURCES = ("sample", "wazuh")
FINDING_SOURCES = ("sca", "event", "inventory", "vulnerability", "fim", "bitlocker")
_RESULTS = ("passed", "failed", "not_applicable", "unknown")
MAX_NOTE_CHARS = 1000
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# from status -> statuses a person may set. exception (set or revoke) needs an admin and a justification.
MANUAL_TRANSITIONS = {
    "open": ("in_review", "fixed_pending", "exception"),
    "in_review": ("open", "fixed_pending", "exception"),
    "fixed_pending": ("open", "in_review"),
    "exception": ("open",),
    "cleared": (),
    "verified": (),
}
NOTE_REQUIRED = ("fixed_pending", "exception")


class WorkflowError(ValueError):
    """A status change or note that is not allowed; the message is safe to show users."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_key(policy, check_id, name):
    ident = str(check_id) if check_id is not None else f"name:{name}"
    return f"{policy or ''}::{ident}"


def clean_note(note):
    if note is None:
        return None
    if not isinstance(note, str):
        raise WorkflowError("The note must be text.")
    note = _CONTROL.sub("", note).strip()
    if len(note) > MAX_NOTE_CHARS:
        raise WorkflowError(f"The note can be at most {MAX_NOTE_CHARS} characters.")
    return note or None


class FindingStore:
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

    def all(self, data_source=None):
        sql = "SELECT * FROM findings" + (" WHERE data_source = ?" if data_source else "") + " ORDER BY id"
        with self._connect() as conn:
            rows = conn.execute(sql, (data_source,) if data_source else ()).fetchall()
        return [dict(r) for r in rows]

    def get(self, finding_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def sync(self, data_source, endpoints, catalogue, now, tally=None):
        """SCA-only convenience: ``endpoints`` = [{"endpoint_id", "endpoint_label", "checks": [...]}]."""
        shaped = [{"key": e["endpoint_id"], "hostname": e.get("endpoint_label"), "checks": e["checks"]}
                  for e in endpoints]
        return self.apply(data_source, sca_results(shaped, catalogue), catalogue, now, tally=tally)

    def apply(self, data_source, results, catalogue, now, tally=None):
        """Apply assessment results (see ``compliance.sources``) to the findings of ``data_source``.

        New findings store the catalogue version and the requirement's severity at creation.
        Status changes made here are logged in finding_events with actor "system".
        Returns the number of findings created or changed. If ``tally`` (a dict) is given, it is
        incremented under "created", "reopened", "cleared" and "verified" for the "Scan now" summary.
        """
        tally = tally if tally is not None else {}
        if data_source not in DATA_SOURCES:
            raise ValueError("unknown data source")
        existing = {(r["endpoint_id"], r["source"], r["check_key"]): r for r in self.all(data_source)}
        stamp = _iso(now)
        written = 0
        with self._connect() as conn:
            for r in results:
                if r.get("status") not in _RESULTS or r.get("source") not in FINDING_SOURCES:
                    continue
                key = (r["endpoint_id"], r["source"], r["check_key"])
                row = existing.get(key)
                changes = transition(row, r["status"], r.get("observed_at"), now)
                if row is None:
                    if changes is None:
                        continue
                    req = catalogue["requirements"].get(r.get("requirement_id") or "")
                    cur = conn.execute(
                        "INSERT INTO findings (data_source, endpoint_id, endpoint_label, check_key, requirement_id, "
                        "catalogue_version, source, title, remediation, state, status, severity, cvss, cve_id, "
                        "opened_at, updated_at, verified_at, status_changed_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (data_source, r["endpoint_id"], r.get("endpoint_label"), r["check_key"],
                         r.get("requirement_id") if req else None, catalogue["version"], r["source"], r["title"],
                         r.get("remediation"), changes["state"], changes["status"], req.get("severity") if req else None,
                         r.get("cvss"), r.get("cve_id"), changes["opened_at"], stamp, changes["verified_at"],
                         changes["status_changed_at"]))
                    conn.execute("INSERT INTO finding_events (finding_id, at, actor, kind, to_status, note) "
                                 "VALUES (?, ?, 'system', 'created', ?, ?)",
                                 (cur.lastrowid, stamp, changes["status"], f"Assessment result: {changes['state']}"))
                    existing[key] = {**changes, "id": cur.lastrowid, "endpoint_label": r.get("endpoint_label"),
                                     "title": r["title"], "cvss": r.get("cvss")}
                    written += 1
                    tally["created"] = tally.get("created", 0) + 1
                    continue
                changes = dict(changes or {})
                for field in ("endpoint_label", "title", "cvss"):
                    if r.get(field) is not None and r[field] != row.get(field):
                        changes[field] = r[field]
                changes = {k: v for k, v in changes.items() if row.get(k) != v}
                if not changes:
                    continue
                columns = ", ".join(f"{name} = ?" for name in changes)
                conn.execute(f"UPDATE findings SET {columns}, updated_at = ? WHERE id = ?",
                             (*changes.values(), stamp, row["id"]))
                if "status" in changes:
                    conn.execute("INSERT INTO finding_events (finding_id, at, actor, kind, from_status, to_status, "
                                 "note) VALUES (?, ?, 'system', 'sync', ?, ?, ?)",
                                 (row["id"], stamp, row["status"], changes["status"],
                                  f"Assessment result: {changes.get('state', row['state'])}"))
                    kind = ("reopened" if changes["status"] == "open" else changes["status"])
                    if kind in ("reopened", "cleared", "verified"):
                        tally[kind] = tally.get(kind, 0) + 1
                existing[key] = {**row, **changes}
                written += 1
        return written

    def change_status(self, finding_id, to_status, actor, role, note, now):
        """A person changes a finding's status. Raises ``WorkflowError`` if the change is not allowed."""
        note = clean_note(note)
        if to_status not in STATUSES:
            raise WorkflowError("Unknown status.")
        if to_status in ("cleared", "verified"):
            raise WorkflowError("Only a later assessment can mark a finding cleared or verified.")
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if row is None:
                raise WorkflowError("That finding does not exist.", 404)
            current = row["status"]
            if to_status not in MANUAL_TRANSITIONS[current]:
                raise WorkflowError(f"A finding that is '{current}' cannot be set to '{to_status}'.")
            if (to_status == "exception" or current == "exception") and role != "admin":
                raise WorkflowError("Only an administrator can approve or revoke an exception.", 403)
            if to_status in NOTE_REQUIRED and not note:
                raise WorkflowError("Add a note: describe the fix that was made, or justify the exception.")
            stamp = _iso(now)
            conn.execute("UPDATE findings SET status = ?, status_changed_at = ?, updated_at = ? WHERE id = ?",
                         (to_status, stamp, stamp, finding_id))
            conn.execute("INSERT INTO finding_events (finding_id, at, actor, kind, from_status, to_status, note) "
                         "VALUES (?, ?, ?, 'status', ?, ?, ?)", (finding_id, stamp, actor, current, to_status, note))
        return self.get(finding_id)

    def add_note(self, finding_id, actor, note, now):
        note = clean_note(note)
        if not note:
            raise WorkflowError("The note is empty.")
        with self._connect() as conn:
            if conn.execute("SELECT 1 FROM findings WHERE id = ?", (finding_id,)).fetchone() is None:
                raise WorkflowError("That finding does not exist.", 404)
            conn.execute("INSERT INTO finding_events (finding_id, at, actor, kind, note) VALUES (?, ?, ?, 'note', ?)",
                         (finding_id, _iso(now), actor, note))

    def history(self, finding_id):
        with self._connect() as conn:
            rows = conn.execute("SELECT at, actor, kind, from_status, to_status, note FROM finding_events "
                                "WHERE finding_id = ? ORDER BY id", (finding_id,)).fetchall()
        return [dict(r) for r in rows]

    def histories(self, finding_ids):
        """{finding_id: [events]} for many findings (reports)."""
        wanted = set(finding_ids)
        with self._connect() as conn:
            rows = conn.execute("SELECT finding_id, at, actor, kind, from_status, to_status, note "
                                "FROM finding_events ORDER BY id").fetchall()
        out = {}
        for r in rows:
            if r["finding_id"] in wanted:
                out.setdefault(r["finding_id"], []).append({k: r[k] for k in r.keys() if k != "finding_id"})
        return out

    def set_status(self, finding_id, status, now):
        """Set a status directly (tests only; bypasses the workflow rules)."""
        if status not in STATUSES:
            raise ValueError("unknown status")
        with self._connect() as conn:
            return conn.execute("UPDATE findings SET status = ?, status_changed_at = ?, updated_at = ? WHERE id = ?",
                                (status, _iso(now), _iso(now), finding_id)).rowcount > 0

    def latest_scores(self, finding_ids=None):
        """{finding_id: newest risk_scores row}."""
        sql = ("SELECT r.* FROM risk_scores r JOIN (SELECT finding_id, MAX(id) AS id FROM risk_scores "
               "GROUP BY finding_id) latest ON latest.id = r.id")
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()
        wanted = None if finding_ids is None else set(finding_ids)
        return {r["finding_id"]: dict(r) for r in rows if wanted is None or r["finding_id"] in wanted}

    def score_history(self, finding_id):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM risk_scores WHERE finding_id = ? ORDER BY id", (finding_id,)).fetchall()
        return [dict(r) for r in rows]

    def record_scores(self, scores, now):
        """Append a risk_scores row for each score whose score, band, reason or weights version changed."""
        latest = self.latest_scores([s["finding_id"] for s in scores])
        fields = ("score", "band", "reason", "weights_version")
        rows = [(s["finding_id"], s["score"], s["band"], s["reason"], s["weights_version"], _iso(now))
                for s in scores
                if s["finding_id"] not in latest or any(latest[s["finding_id"]][f] != s[f] for f in fields)]
        if rows:
            with self._connect() as conn:
                conn.executemany("INSERT INTO risk_scores (finding_id, score, band, reason, weights_version, "
                                 "computed_at) VALUES (?, ?, ?, ?, ?, ?)", rows)
        return len(rows)

    # ---- BitLocker collector reports ----

    def save_bitlocker_report(self, hostname, collected_at, volumes, now):
        stamp = _iso(now)
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO bitlocker_reports (hostname, received_at, collected_at, mount_point, volume_type, "
                "volume_status, protection_status, encryption_percentage, encryption_method, lock_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(hostname, stamp, collected_at, v["mount_point"], v.get("volume_type"), v.get("volume_status"),
                  v.get("protection_status"), v.get("encryption_percentage"), v.get("encryption_method"),
                  v.get("lock_status")) for v in volumes])

    def latest_bitlocker_reports(self):
        """{hostname lower: [volume rows of that host's newest report]}."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT b.* FROM bitlocker_reports b JOIN (SELECT hostname, MAX(received_at) AS received_at "
                "FROM bitlocker_reports GROUP BY hostname) latest "
                "ON latest.hostname = b.hostname AND latest.received_at = b.received_at ORDER BY b.id").fetchall()
        out = {}
        for r in rows:
            out.setdefault(r["hostname"].lower(), []).append(dict(r))
        return out
