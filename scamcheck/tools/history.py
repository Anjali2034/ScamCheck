"""Local memory of indicators from past investigations ("flagged by N other people").

Counts people, not checks: one person checking the same message ten times is one report, and nobody's own earlier
checks count against what they check now. People are stored as a keyed hash (the key lives in the same database and
is made on first use), never as a raw phone number or address.
"""
import hashlib
import hmac
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

from scamcheck.config import DB_PATH

_lock = threading.Lock()
LEGACY = "legacy"  # rows saved before people were recorded count as one person between them


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS indicators (
        kind TEXT, value TEXT, verdict TEXT, scam_type TEXT, seen_at TEXT)""")
    if "reporter" not in {r[1] for r in c.execute("PRAGMA table_info(indicators)")}:
        c.execute("ALTER TABLE indicators ADD COLUMN reporter TEXT")
    c.execute("CREATE INDEX IF NOT EXISTS ix_val ON indicators(kind, value)")
    c.execute("CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT)")
    return c


def reporter_id(who: str) -> str:
    """A stable, unguessable stand-in for a person ("wa:+9198…", a network address). "" (the CLI) stays ""."""
    if not who:
        return ""
    with _lock, _conn() as c:
        row = c.execute("SELECT value FROM meta WHERE name='reporter_key'").fetchone()
        if not row:
            c.execute("INSERT OR IGNORE INTO meta VALUES ('reporter_key', ?)", (secrets.token_hex(32),))
            row = c.execute("SELECT value FROM meta WHERE name='reporter_key'").fetchone()
    return hmac.new(bytes.fromhex(row[0]), who.encode(), hashlib.sha256).hexdigest()[:24]


def lookup_previous_reports(kind: str, value: str, exclude: str = "") -> dict:
    """Earlier reports of this indicator by people other than `exclude`, each person's latest verdict counted once."""
    value = value.strip().lower()
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT COALESCE(reporter, ?) AS who, verdict, scam_type, seen_at FROM indicators "
            "WHERE kind=? AND value=? ORDER BY seen_at DESC", (LEGACY, kind, value)).fetchall()
    latest = {}
    for who, v, st, at in rows:
        if who != exclude or not exclude:
            latest.setdefault(who, (v, st, at))
    if not latest:
        return {"kind": kind, "value": value, "times_seen": 0}
    verdicts = {}
    for v, _, _ in latest.values():
        verdicts[v] = verdicts.get(v, 0) + 1
    newest = max(latest.values(), key=lambda r: r[2])
    return {"kind": kind, "value": value, "times_seen": len(latest), "verdicts": verdicts,
            "latest_scam_type": newest[1], "last_seen": newest[2]}


def record_indicators(indicators: list[dict], verdict: str, scam_type: str | None, reporter: str = "") -> None:
    """One row per person per indicator: checking again replaces that person's earlier verdict rather than adding one."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = [(i["kind"], i["value"].strip().lower()) for i in indicators]
    with _lock, _conn() as c:
        if reporter:
            c.executemany("DELETE FROM indicators WHERE kind=? AND value=? AND reporter=?", [(*r, reporter) for r in rows])
        c.executemany("INSERT INTO indicators (kind, value, verdict, scam_type, seen_at, reporter) VALUES (?,?,?,?,?,?)",
                      [(*r, verdict, scam_type, now, reporter or None) for r in rows])
