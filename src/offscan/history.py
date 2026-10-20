"""Scan history and false-positive marks (per user, SQLite)."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import paths
from .scan.results import Detection

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL NOT NULL,
    finished REAL,
    state TEXT NOT NULL,
    mode TEXT NOT NULL,
    targets TEXT NOT NULL,          -- JSON list of {volume, label, os, device}
    options TEXT NOT NULL,          -- JSON
    summary TEXT NOT NULL,          -- JSON
    definitions TEXT                -- JSON: set id and source versions
);
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    volume TEXT NOT NULL,
    path TEXT NOT NULL,
    engine TEXT NOT NULL,
    signature TEXT NOT NULL,
    severity TEXT NOT NULL,
    sha256 TEXT,
    size INTEGER,
    source TEXT,
    category TEXT,
    details TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'   -- open | false_positive | quarantined | deleted
);
CREATE INDEX IF NOT EXISTS detections_scan ON detections(scan_id);
CREATE TABLE IF NOT EXISTS false_positives (
    engine TEXT NOT NULL,
    signature TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created REAL NOT NULL,
    note TEXT,
    PRIMARY KEY (engine, signature, sha256)
);
"""


class History:
    def __init__(self, path: Path | None = None):
        self.path = path or paths.history_db()
        paths.ensure_dir(self.path.parent)
        self.db = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def add_scan(self, summary: dict[str, Any], options: dict[str, Any], targets: list[dict[str, Any]],
                 detections: Iterable[Detection], definitions: dict[str, Any] | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO scans (started, finished, state, mode, targets, options, summary, definitions) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (summary.get("started", time.time()), summary.get("finished"), summary.get("state", "?"),
             options.get("mode", "?"), json.dumps(targets), json.dumps(options), json.dumps(summary),
             json.dumps(definitions or {})))
        scan_id = int(cur.lastrowid)
        self.db.executemany(
            "INSERT INTO detections (scan_id, volume, path, engine, signature, severity, sha256, size, "
            "source, category, details, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, d.volume, d.path, d.engine, d.signature, d.severity, d.sha256, d.size, d.source,
              d.category, json.dumps(d.details),
              "false_positive" if self.is_false_positive(d) else "open") for d in detections])
        self.db.commit()
        return scan_id

    def scans(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM scans ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            for key in ("targets", "options", "summary", "definitions"):
                item[key] = json.loads(item[key] or "null")
            out.append(item)
        return out

    def detections(self, scan_id: int) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM detections WHERE scan_id = ? ORDER BY id", (scan_id,))
        out = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item["details"] or "{}")
            out.append(item)
        return out

    def set_status(self, detection_id: int, status: str) -> None:
        self.db.execute("UPDATE detections SET status = ? WHERE id = ?", (status, detection_id))
        self.db.commit()

    def delete_scan(self, scan_id: int) -> None:
        self.db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self.db.commit()

    # -- false positives ------------------------------------------------------

    def mark_false_positive(self, engine: str, signature: str, sha256: str, note: str = "") -> None:
        self.db.execute("INSERT OR REPLACE INTO false_positives VALUES (?, ?, ?, ?, ?)",
                        (engine, signature, sha256, time.time(), note))
        self.db.execute("UPDATE detections SET status = 'false_positive' WHERE engine = ? AND "
                        "signature = ? AND sha256 = ? AND status = 'open'", (engine, signature, sha256))
        self.db.commit()

    def unmark_false_positive(self, engine: str, signature: str, sha256: str) -> None:
        self.db.execute("DELETE FROM false_positives WHERE engine = ? AND signature = ? AND sha256 = ?",
                        (engine, signature, sha256))
        self.db.execute("UPDATE detections SET status = 'open' WHERE engine = ? AND signature = ? AND "
                        "sha256 = ? AND status = 'false_positive'", (engine, signature, sha256))
        self.db.commit()

    def is_false_positive(self, det: Detection) -> bool:
        """``sha256`` holds the file hash, or a persistence entry's fingerprint (``Detection.identity``)."""
        identity = det.identity
        if not identity:
            return False
        row = self.db.execute("SELECT 1 FROM false_positives WHERE engine = ? AND signature = ? AND "
                              "sha256 = ?", (det.engine, det.signature, identity)).fetchone()
        return row is not None

    def false_positives(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM false_positives ORDER BY created DESC")]
