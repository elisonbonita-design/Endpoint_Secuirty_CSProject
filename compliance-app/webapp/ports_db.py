"""Approved listening ports list (REQ-NP-01) in instance/assets.db, with an append-only change history.

An entry is either a fixed TCP port number (below 49152) or a program allowed to listen on
Windows' dynamic ports (49152-65535). Administrators change the list in the dashboard; it starts
from config/approved_ports.json the first time it is empty.
"""

import re
import sqlite3
from contextlib import contextmanager

from compliance.sources import DYNAMIC_PORTS

from .assets_db import ensure_schema
from .db_migrations import connect
from .software_db import clean_note

MAX_PROGRAM = 100
_PROGRAM = re.compile(r"^[^\\/:*?\"<>|\x00-\x1f\x7f]+$")
KINDS = ("port", "program")


class PortError(ValueError):
    """Rejected change; the message is safe to show."""


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_entry(kind, value):
    """Normalized (kind, value as text) or ``PortError``."""
    if kind == "port":
        try:
            port = int(str(value).strip())
        except (TypeError, ValueError):
            raise PortError("Enter the port as a number, for example 3389.") from None
        if not 1 <= port < DYNAMIC_PORTS.start:
            raise PortError(f"A port number must be 1-{DYNAMIC_PORTS.start - 1}. Ports {DYNAMIC_PORTS.start}-65535 "
                            "change at every restart; approve the program that uses them instead.")
        return kind, str(port)
    if kind == "program":
        name = value.strip() if isinstance(value, str) else ""
        if not name or len(name) > MAX_PROGRAM or not _PROGRAM.fullmatch(name):
            raise PortError(f"Enter the program's file name, for example lsass.exe (1-{MAX_PROGRAM} characters, "
                            "no folder).")
        return kind, name
    raise PortError("The entry must be a port or a program.")


class PortStore:
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

    def entries(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT id, kind, value, note, added_by, added_at FROM approved_ports "
                                "ORDER BY kind DESC, CASE kind WHEN 'port' THEN CAST(value AS INTEGER) END, "
                                "value COLLATE NOCASE").fetchall()
        return [dict(r) for r in rows]

    def policy(self):
        """(approved port numbers, approved program names) as used by ``sources.port_checks``."""
        entries = self.entries()
        return (frozenset(int(e["value"]) for e in entries if e["kind"] == "port"),
                tuple(e["value"] for e in entries if e["kind"] == "program"))

    def history(self, limit=50):
        with self._connect() as conn:
            rows = conn.execute("SELECT at, actor, action, kind, value, note FROM approved_port_events "
                                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def add_many(self, items, note, actor, now):
        """Add each (kind, value) not listed yet. Returns the (kind, value) pairs added; duplicates are skipped."""
        cleaned = [clean_entry(kind, value) for kind, value in items]
        note = clean_note(note)
        added, at = [], _iso(now)
        with self._connect() as conn:
            for kind, value in cleaned:
                try:
                    conn.execute("INSERT INTO approved_ports (kind, value, note, added_by, added_at) "
                                 "VALUES (?, ?, ?, ?, ?)", (kind, value, note, actor, at))
                except sqlite3.IntegrityError:
                    continue
                conn.execute("INSERT INTO approved_port_events (at, actor, action, kind, value, note) "
                             "VALUES (?, ?, 'added', ?, ?, ?)", (at, actor, kind, value, note))
                added.append((kind, value))
        return added

    def add(self, kind, value, note, actor, now):
        added = self.add_many([(kind, value)], note, actor, now)
        if not added:
            raise PortError("That entry is already on the approved list.")
        return added[0]

    def remove(self, entry_id, note, actor, now):
        note = clean_note(note)
        with self._connect() as conn:
            row = conn.execute("SELECT kind, value FROM approved_ports WHERE id = ?", (entry_id,)).fetchone()
            if row is None:
                raise PortError("That entry is not on the approved list.")
            conn.execute("DELETE FROM approved_ports WHERE id = ?", (entry_id,))
            conn.execute("INSERT INTO approved_port_events (at, actor, action, kind, value, note) "
                         "VALUES (?, ?, 'removed', ?, ?, ?)", (_iso(now), actor, row["kind"], row["value"], note))
        return row["kind"], row["value"]

    def seed(self, ports, now):
        """Start the list from the config file once: only while it has never had an entry."""
        with self._connect() as conn:
            if conn.execute("SELECT EXISTS (SELECT 1 FROM approved_port_events)").fetchone()[0]:
                return []
        items = [("port", p) for p in sorted(ports) if p < DYNAMIC_PORTS.start]
        return self.add_many(items, "Imported from config/approved_ports.json", "config", now) if items else []
