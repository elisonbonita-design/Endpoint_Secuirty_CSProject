"""Approved software list (REQ-SW-01) in instance/assets.db, with an append-only change history.

Administrators add and remove entries in the dashboard. A name ending in ``*`` matches
every program whose name starts with the text before it (see ``sources.software_approved``).
The list starts from config/approved_software.json the first time it is empty.
"""

import re
import sqlite3
from contextlib import contextmanager

from .assets_db import ensure_schema
from .db_migrations import connect

MAX_NAME = 200
MAX_NOTE = 500
MIN_PREFIX = 3
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class SoftwareError(ValueError):
    """Rejected change; the message is safe to show."""


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_name(name):
    if not isinstance(name, str):
        raise SoftwareError("Enter the program name as text.")
    name = " ".join(name.split())
    if not name or len(name) > MAX_NAME or _CONTROL.search(name):
        raise SoftwareError(f"The program name must be 1-{MAX_NAME} characters.")
    if "*" in name[:-1]:
        raise SoftwareError("Use * only at the end of a name, to match every program starting with that text.")
    if name.endswith("*") and len(name[:-1].strip()) < MIN_PREFIX:
        raise SoftwareError(f"A prefix entry needs at least {MIN_PREFIX} characters before the *.")
    return name


def clean_note(note):
    if note is None:
        return None
    if not isinstance(note, str):
        raise SoftwareError("The note must be text.")
    note = note.strip()
    if len(note) > MAX_NOTE or _CONTROL.search(note.replace("\n", " ").replace("\t", " ")):
        raise SoftwareError(f"The note must be at most {MAX_NOTE} characters of plain text.")
    return note or None


class SoftwareStore:
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
            rows = conn.execute("SELECT id, name, note, added_by, added_at FROM approved_software "
                                "ORDER BY name COLLATE NOCASE").fetchall()
        return [dict(r) for r in rows]

    def names(self):
        return tuple(e["name"] for e in self.entries())

    def history(self, limit=50):
        with self._connect() as conn:
            rows = conn.execute("SELECT at, actor, action, name, note FROM approved_software_events "
                                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def add_many(self, names, note, actor, now):
        """Add each name not listed yet. Returns the names added (in order); duplicates are skipped."""
        cleaned = [clean_name(n) for n in names]
        note = clean_note(note)
        added, at = [], _iso(now)
        with self._connect() as conn:
            for name in cleaned:
                try:
                    conn.execute("INSERT INTO approved_software (name, note, added_by, added_at) VALUES (?, ?, ?, ?)",
                                 (name, note, actor, at))
                except sqlite3.IntegrityError:
                    continue  # already approved (names are compared without case)
                conn.execute("INSERT INTO approved_software_events (at, actor, action, name, note) "
                             "VALUES (?, ?, 'added', ?, ?)", (at, actor, name, note))
                added.append(name)
        return added

    def add(self, name, note, actor, now):
        added = self.add_many([name], note, actor, now)
        if not added:
            raise SoftwareError("That program is already on the approved list.")
        return added[0]

    def remove(self, entry_id, note, actor, now):
        note = clean_note(note)
        with self._connect() as conn:
            row = conn.execute("SELECT name FROM approved_software WHERE id = ?", (entry_id,)).fetchone()
            if row is None:
                raise SoftwareError("That entry is not on the approved list.")
            conn.execute("DELETE FROM approved_software WHERE id = ?", (entry_id,))
            conn.execute("INSERT INTO approved_software_events (at, actor, action, name, note) "
                         "VALUES (?, ?, 'removed', ?, ?)", (_iso(now), actor, row["name"], note))
        return row["name"]

    def seed(self, names, now):
        """Start the list from the config file once: only while it has never had an entry."""
        with self._connect() as conn:
            if conn.execute("SELECT EXISTS (SELECT 1 FROM approved_software_events)").fetchone()[0]:
                return []
        return self.add_many(names, "Imported from config/approved_software.json", "config", now) if names else []
