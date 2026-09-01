"""
database.py
-------------
SQLite persistence for scan history (docs: "You don't need a huge database"
-- Scans, ThreatIndicators, Reports). SQLite chosen for the MVP per the
tech-stack doc (PostgreSQL is the stated production upgrade path; nothing
here is Postgres-incompatible SQL, it's plain enough to swap later).

Privacy note (matches the docs' data-handling stance): only a short
preview of raw input is stored, never full screenshots/OTPs/passwords --
see pipeline.py's `raw_input_preview[:280]` truncation and the fact that
uploaded images themselves are never written to persistent storage, only
processed in-memory/tmp and discarded.
"""

from __future__ import annotations
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from contextlib import contextmanager

# Vercel Functions (like most serverless platforms) ship a read-only
# filesystem except for /tmp -- writing to data/phantomguard.db as before
# would raise "unable to open database file" on every request. Vercel sets
# the VERCEL env var automatically, so we use that to switch to /tmp there
# while leaving local/Docker runs (where data/ is writable) unchanged.
#
# Note this means history/dashboard stats are NOT durable on Vercel: /tmp
# is wiped on cold starts and isn't shared across concurrent instances.
# Fine for a demo; swap in Postgres (e.g. Vercel Postgres/Neon) for real
# persistence -- the SQL here is plain enough to port, per the note below.
if os.environ.get("VERCEL"):
    DB_PATH = Path(tempfile.gettempdir()) / "phantomguard.db"
else:
    DB_PATH = Path(__file__).resolve().parent.parent / "data" / "phantomguard.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    input_type TEXT NOT NULL,
    raw_input_preview TEXT,
    language_primary TEXT,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    scam_category TEXT,
    full_result_json TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    was_actually_scam TEXT NOT NULL,      -- 'yes' | 'no'
    report_category TEXT,
    created_at REAL NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
"""


@contextmanager
def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def save_scan(scan_result: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, input_type, raw_input_preview, language_primary,
                risk_score, risk_level, scam_category, full_result_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_result["scan_id"],
                scan_result["input_type"],
                scan_result["raw_input_preview"],
                scan_result["language"]["primary"],
                scan_result["risk"]["total_score"],
                scan_result["risk"]["risk_level"],
                scan_result["scam_category"]["category_label"],
                json.dumps(scan_result),
                scan_result["timestamp"],
            ),
        )


def get_scan(scan_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT full_result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row["full_result_json"]) if row else None


def get_history(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT scan_id, input_type, raw_input_preview, risk_score, risk_level,
                      scam_category, language_primary, created_at
               FROM scans ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def save_report(scan_id: str, was_actually_scam: str, report_category: str | None) -> None:
    import time
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO reports (scan_id, was_actually_scam, report_category, created_at) VALUES (?, ?, ?, ?)",
            (scan_id, was_actually_scam, report_category, time.time()),
        )


def get_dashboard_stats() -> dict:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        by_level = conn.execute(
            "SELECT risk_level, COUNT(*) c FROM scans GROUP BY risk_level"
        ).fetchall()
        by_category = conn.execute(
            "SELECT scam_category, COUNT(*) c FROM scans WHERE risk_level != 'SAFE' "
            "GROUP BY scam_category ORDER BY c DESC LIMIT 8"
        ).fetchall()
        by_lang = conn.execute(
            "SELECT language_primary, COUNT(*) c FROM scans GROUP BY language_primary"
        ).fetchall()
        threats = conn.execute(
            "SELECT COUNT(*) c FROM scans WHERE risk_level IN ('SUSPICIOUS','HIGH','CRITICAL')"
        ).fetchone()["c"]
        critical = conn.execute("SELECT COUNT(*) c FROM scans WHERE risk_level = 'CRITICAL'").fetchone()["c"]

        return {
            "total_scans": total,
            "threats_detected": threats,
            "critical": critical,
            "by_level": {r["risk_level"]: r["c"] for r in by_level},
            "by_category": {r["scam_category"]: r["c"] for r in by_category},
            "by_language": {r["language_primary"]: r["c"] for r in by_lang},
        }


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
    print("Dashboard stats:", get_dashboard_stats())
