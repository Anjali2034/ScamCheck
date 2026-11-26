"""Keeps ScamCheck inside its free tiers: Groq's daily AI budget, Meta's monthly WhatsApp allowance, and fair use.

Nobody is turned away for using it a lot: past a soft limit, every check still runs and only the AI is skipped, so
the reply comes from the rules. Hard limits only stop floods (a bot, a stuck script), and even then the message
says what to do. Budgets are counted in the same database as the history (Supabase Postgres in production), so
restarts and redeploys don't reset them. If the database can't be reached, budgets read as unused and every use is
allowed: a check never fails over a counter, and Groq's own 429 is the backstop.
"""
import re
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from scamcheck import config, db

# The last slice of the daily AI budget is kept for people who say they've lost money: the AI fills in their complaint.
VICTIM_RESERVE = 0.10
# WhatsApp messages kept back for safety: OTP warnings and the one "out of free replies" notice per person.
WHATSAPP_RESERVE = 50

# Usage rows are kept this long. Only today's and this month's are ever read; older ones (some named after a
# WhatsApp number) are deleted once a day.
KEEP_DAYS = 35
_DATED = re.compile(r":(\d{4}-\d{2}(?:-\d{2})?)$")

_lock = threading.Lock()
_ai_paused_until = 0.0
_windows: dict[str, deque] = {}
_pruned_on = ""


def _day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


@contextmanager
def _conn():
    with db.connect(config.DB_PATH) as c:
        if db.backend() == "sqlite":  # Postgres gets its tables from supabase/schema.sql
            c.execute("CREATE TABLE IF NOT EXISTS usage (bucket TEXT PRIMARY KEY, n INTEGER NOT NULL)")
        yield c


def _prune(c) -> None:
    """Once a UTC day, delete usage rows whose day or month ended more than KEEP_DAYS ago."""
    global _pruned_on
    today = _day()
    if _pruned_on == today:
        return
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
    old = [(b,) for (b,) in c.execute("SELECT bucket FROM usage").fetchall()
           if (m := _DATED.search(b)) and m.group(1) < cutoff[:len(m.group(1))]]
    if old:
        c.executemany("DELETE FROM usage WHERE bucket=?", old)
    _pruned_on = today


def used(bucket: str) -> int:
    try:
        with _lock, _conn() as c:
            row = c.execute("SELECT n FROM usage WHERE bucket=?", (bucket,)).fetchone()
    except db.StorageError:
        return 0
    return row[0] if row else 0


def _add(bucket: str, n: int = 1) -> int:
    try:
        with _lock, _conn() as c:
            _prune(c)
            return c.execute("INSERT INTO usage (bucket, n) VALUES (?, ?) "
                             "ON CONFLICT (bucket) DO UPDATE SET n = usage.n + excluded.n RETURNING n",
                             (bucket, n)).fetchone()[0]
    except db.StorageError:
        return 0


def _take_if_under(bucket: str, limit: int) -> bool:
    """Count one use if that stays within the limit. One statement, so two servers at once can't both take the last one."""
    if limit <= 0:
        return False
    try:
        with _lock, _conn() as c:
            _prune(c)
            return c.execute("INSERT INTO usage (bucket, n) VALUES (?, 1) "
                             "ON CONFLICT (bucket) DO UPDATE SET n = usage.n + 1 WHERE usage.n < ? RETURNING n",
                             (bucket, limit)).fetchone() is not None
    except db.StorageError:
        return True


# --- The AI ---------------------------------------------------------------------------------------------------

def ai_allowed(person: str, already_paid: bool) -> tuple[bool, str]:
    """Whether this check may use the AI. The reason ("", "busy", "daily", "person") is shown to the person."""
    if time.monotonic() < _ai_paused_until:
        return False, "busy"
    tokens = used(f"ai_tokens:{_day()}")
    budget = config.AI_DAILY_TOKENS
    if tokens >= budget or (tokens >= budget * (1 - VICTIM_RESERVE) and not already_paid):
        return False, "daily"
    if person and not already_paid and used(f"ai_checks:{person}:{_day()}") >= config.AI_CHECKS_PER_PERSON_PER_DAY:
        return False, "person"
    return True, ""


def record_ai_tokens(tokens: int) -> None:
    _add(f"ai_tokens:{_day()}", tokens)


def record_ai_check(person: str) -> None:
    if person:
        _add(f"ai_checks:{person}:{_day()}")


def pause_ai(seconds: float) -> None:
    """Groq said "too many requests": stop asking until it says to, instead of making every check wait for a refusal."""
    global _ai_paused_until
    _ai_paused_until = max(_ai_paused_until, time.monotonic() + min(seconds, 24 * 3600))


# --- Floods -----------------------------------------------------------------------------------------------------

def _in_window(key: str, limit: int, seconds: float) -> bool:
    """Sliding window in memory: True and counted if this use fits, False if over."""
    now = time.monotonic()
    with _lock:
        q = _windows.setdefault(key, deque())
        while q and q[0] <= now - seconds:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        if len(_windows) > 50_000:  # forget idle senders so memory stays flat on a 512 MB server
            for k in [k for k, v in _windows.items() if not v or v[-1] <= now - seconds][:10_000]:
                del _windows[k]
        return True


def web_check_allowed(network: str) -> bool:
    """Per network address, generous on purpose: Jio and Airtel put thousands of phones behind one address (CGNAT)."""
    return _in_window(f"web:{network}", config.WEB_CHECKS_PER_NETWORK_PER_10_MIN, 600)


def whatsapp_check_allowed(number: str) -> bool:
    """Per WhatsApp number, per day. Each check costs one of the month's free messages."""
    return _take_if_under(f"wa_checks:{number}:{_day()}", config.WHATSAPP_CHECKS_PER_NUMBER_PER_DAY)


def first_notice(key: str, monthly: bool = False) -> bool:
    """For "you've hit the limit" messages: once per person per day (or month), not on every message they send."""
    return _take_if_under(f"notice:{key}:{_month() if monthly else _day()}", 1)


# --- WhatsApp's monthly allowance -------------------------------------------------------------------------------

def take_whatsapp_message(urgent: bool = False) -> bool:
    """Count one outgoing message. Ordinary replies stop WHATSAPP_RESERVE short; urgent ones can use the reserve."""
    limit = config.WHATSAPP_MONTHLY_MESSAGES if urgent else max(0, config.WHATSAPP_MONTHLY_MESSAGES - WHATSAPP_RESERVE)
    return _take_if_under(f"wa_messages:{_month()}", limit)


def whatsapp_replies_left() -> int:
    return max(0, config.WHATSAPP_MONTHLY_MESSAGES - WHATSAPP_RESERVE - used(f"wa_messages:{_month()}"))


def status() -> dict:
    """For /api/health: how much of today's and this month's free budget is left."""
    return {"ai_tokens_left_today": max(0, config.AI_DAILY_TOKENS - used(f"ai_tokens:{_day()}")),
            "ai_paused": time.monotonic() < _ai_paused_until,
            "whatsapp_replies_left_this_month": whatsapp_replies_left(),
            "storage": db.backend()}
