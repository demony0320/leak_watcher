"""SQLite state: every finding by fingerprint, its lifecycle, and suppressions.

Lifecycle:  new → open ⇄ resolved (auto, when a deterministic leak disappears)
                 ↘ suppressed (human feedback: false positive / accepted risk)
A resolved finding that reappears is "reopened" and alerted again.
"""
from __future__ import annotations

import fnmatch
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import SEVERITY_RANK, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  detector TEXT, rule TEXT, category TEXT, severity TEXT, target TEXT, location TEXT,
  title TEXT, evidence TEXT, evidence_hash TEXT, extra TEXT,
  status TEXT,              -- open | resolved | suppressed
  first_seen TEXT, last_seen TEXT, seen_count INTEGER DEFAULT 1,
  resolved_at TEXT, triage TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT, finished TEXT,
  detectors TEXT, total INTEGER, new INTEGER, reopened INTEGER, resolved INTEGER, errors TEXT
);
CREATE TABLE IF NOT EXISTS suppressions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT, rule TEXT, target TEXT, location_glob TEXT,
  reason TEXT, created TEXT, expires TEXT
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(data_dir / "leakwatch.db")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---------------------------------------------------------- suppressions
    def is_suppressed(self, f: Finding) -> str | None:
        t = now()
        for s in self.db.execute("SELECT * FROM suppressions WHERE expires IS NULL OR expires > ?", (t,)):
            if s["fingerprint"] and s["fingerprint"] == f.fingerprint:
                return s["reason"]
            if s["rule"] and fnmatch.fnmatch(f.rule, s["rule"]) \
                    and (not s["target"] or s["target"] == f.target) \
                    and (not s["location_glob"] or fnmatch.fnmatch(f.location, s["location_glob"])):
                return s["reason"]
        return None

    def add_suppression(self, *, fingerprint=None, rule=None, target=None, location_glob=None,
                        reason="", expires=None):
        self.db.execute("INSERT INTO suppressions(fingerprint, rule, target, location_glob, reason, created, expires)"
                        " VALUES (?,?,?,?,?,?,?)", (fingerprint, rule, target, location_glob, reason, now(), expires))
        if fingerprint:
            self.db.execute("UPDATE findings SET status='suppressed', note=? WHERE fingerprint=?", (reason, fingerprint))
        self.db.commit()

    # ---------------------------------------------------------- upsert
    def ingest(self, findings: list[Finding], ran_detectors: dict[str, bool], targets_scanned: set[tuple]):
        """Returns (new, reopened, escalated, resolved) lists."""
        t = now()
        new, reopened, escalated = [], [], []
        seen = set()
        for f in findings:
            fp = f.fingerprint
            if fp in seen:
                continue
            seen.add(fp)
            row = self.db.execute("SELECT * FROM findings WHERE fingerprint=?", (fp,)).fetchone()
            supp = self.is_suppressed(f)
            if row is None:
                status = "suppressed" if supp else "open"
                self.db.execute(
                    "INSERT INTO findings(fingerprint, detector, rule, category, severity, target, location, title,"
                    " evidence, evidence_hash, extra, status, first_seen, last_seen, note)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fp, f.detector, f.rule, f.category, f.severity, f.target, f.location, f.title, f.evidence,
                     f.evidence_hash, json.dumps(f.extra, ensure_ascii=False), status, t, t, supp))
                if not supp:
                    new.append(f)
                continue
            status = row["status"]
            if status == "resolved" and not supp:
                status = "open"
                reopened.append(f)
            elif status == "open" and SEVERITY_RANK[f.severity] > SEVERITY_RANK.get(row["severity"], 0):
                escalated.append(f)
            if supp:
                status = "suppressed"
            self.db.execute(
                "UPDATE findings SET severity=?, title=?, evidence=?, extra=?, status=?, last_seen=?,"
                " seen_count=seen_count+1, resolved_at=CASE WHEN ?='open' THEN NULL ELSE resolved_at END"
                " WHERE fingerprint=?",
                (f.severity, f.title, f.evidence, json.dumps(f.extra, ensure_ascii=False), status, t, status, fp))

        # auto-resolve: deterministic detector ran on this target and didn't see the finding again
        resolved = []
        for det, auto in ran_detectors.items():
            if not auto:
                continue
            for row in self.db.execute("SELECT * FROM findings WHERE detector=? AND status='open'", (det,)).fetchall():
                if row["fingerprint"] not in seen and (det, row["target"]) in targets_scanned:
                    self.db.execute("UPDATE findings SET status='resolved', resolved_at=? WHERE fingerprint=?",
                                    (t, row["fingerprint"]))
                    resolved.append(dict(row))
        self.db.commit()
        return new, reopened, escalated, resolved

    def set_triage(self, fingerprint: str, triage: dict):
        self.db.execute("UPDATE findings SET triage=? WHERE fingerprint=?",
                        (json.dumps(triage, ensure_ascii=False), fingerprint))
        self.db.commit()

    def set_status(self, fingerprint: str, status: str, note: str = ""):
        self.db.execute("UPDATE findings SET status=?, note=?, resolved_at=CASE WHEN ?='resolved' THEN ? ELSE resolved_at END"
                        " WHERE fingerprint LIKE ?", (status, note, status, now(), fingerprint + "%"))
        self.db.commit()

    def record_run(self, started, detectors, total, new, reopened, resolved, errors):
        self.db.execute("INSERT INTO runs(started, finished, detectors, total, new, reopened, resolved, errors)"
                        " VALUES (?,?,?,?,?,?,?,?)",
                        (started, now(), ",".join(detectors), total, new, reopened, resolved, json.dumps(errors)))
        self.db.commit()

    def findings(self, status: str | None = None) -> list[dict]:
        q = "SELECT * FROM findings" + (" WHERE status=?" if status else "")
        rows = [dict(r) for r in self.db.execute(q, (status,) if status else ())]
        rows.sort(key=lambda r: (-SEVERITY_RANK.get(r["severity"], 0), r["target"], r["rule"]))
        return rows

    def get(self, prefix: str) -> dict | None:
        r = self.db.execute("SELECT * FROM findings WHERE fingerprint LIKE ?", (prefix + "%",)).fetchone()
        return dict(r) if r else None

    def runs(self, n: int = 20) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (n,))]
