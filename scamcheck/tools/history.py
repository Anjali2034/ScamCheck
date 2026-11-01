"""Local memory of indicators from past investigations ("seen in N earlier reports")."""
import sqlite3
import threading
from datetime import datetime, timezone

from scamcheck.config import DB_PATH

_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS indicators (
        kind TEXT, value TEXT, verdict TEXT, scam_type TEXT, seen_at TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_val ON indicators(kind, value)")
    return c


def lookup_previous_reports(kind: str, value: str) -> dict:
    value = value.strip().lower()
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT verdict, scam_type, seen_at FROM indicators WHERE kind=? AND value=? ORDER BY seen_at DESC",
            (kind, value)).fetchall()
    if not rows:
        return {"kind": kind, "value": value, "times_seen": 0}
    verdicts = {}
    for v, _, _ in rows:
        verdicts[v] = verdicts.get(v, 0) + 1
    return {"kind": kind, "value": value, "times_seen": len(rows), "verdicts": verdicts,
            "latest_scam_type": rows[0][1], "last_seen": rows[0][2]}


def record_indicators(indicators: list[dict], verdict: str, scam_type: str | None) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock, _conn() as c:
        c.executemany("INSERT INTO indicators VALUES (?,?,?,?,?)",
                      [(i["kind"], i["value"].strip().lower(), verdict, scam_type, now) for i in indicators])
