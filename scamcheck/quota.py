"""Keeps ScamCheck inside its free tiers: Groq's daily AI budget, Meta's monthly WhatsApp allowance, and fair use.

Nobody is turned away for using it a lot: past a soft limit, every check still runs and only the AI is skipped, so
the reply comes from the rules. Hard limits only stop floods (a bot, a stuck script), and even then the message
says what to do. Budgets are counted in the same SQLite file as the history, so a restart doesn't reset them
(on Render's free disk, a redeploy still does; Groq's own 429 is the backstop).
"""
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime, timezone

from scamcheck import config

# The last slice of the daily AI budget is kept for people who say they've lost money: the AI fills in their complaint.
VICTIM_RESERVE = 0.10
# WhatsApp messages kept back for safety: OTP warnings and the one "out of free replies" notice per person.
WHATSAPP_RESERVE = 50

_lock = threading.Lock()
_ai_paused_until = 0.0
_windows: dict[str, deque] = {}


def _day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _conn():
    c = sqlite3.connect(config.DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS usage (bucket TEXT PRIMARY KEY, n INTEGER NOT NULL)")
    return c


def used(bucket: str) -> int:
    with _lock, _conn() as c:
        row = c.execute("SELECT n FROM usage WHERE bucket=?", (bucket,)).fetchone()
    return row[0] if row else 0


def _add(bucket: str, n: int = 1) -> int:
    with _lock, _conn() as c:
        c.execute("INSERT INTO usage VALUES (?, ?) ON CONFLICT(bucket) DO UPDATE SET n = n + excluded.n", (bucket, n))
        return c.execute("SELECT n FROM usage WHERE bucket=?", (bucket,)).fetchone()[0]


def _take_if_under(bucket: str, limit: int) -> bool:
    """Count one use if that stays within the limit. Atomic, so two replies at once can't both take the last one."""
    with _lock, _conn() as c:
        row = c.execute("SELECT n FROM usage WHERE bucket=?", (bucket,)).fetchone()
        if (row[0] if row else 0) >= limit:
            return False
        c.execute("INSERT INTO usage VALUES (?, 1) ON CONFLICT(bucket) DO UPDATE SET n = n + 1", (bucket,))
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
            "whatsapp_replies_left_this_month": whatsapp_replies_left()}
