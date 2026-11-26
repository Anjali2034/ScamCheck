"""Where the history and usage counters are stored: Supabase Postgres when SUPABASE_DB_URL is set, else SQLite.

Callers write SQL once, with ? placeholders, and use connect() the same way for both. A database problem never
stops a check: connect() raises StorageError, callers fall back to a safe default, and after a failure the
database is skipped for a short while so an outage doesn't add a timeout to every call.
"""
import atexit
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from scamcheck import config

SCHEMA = config.ROOT / "supabase" / "schema.sql"
POOL_TIMEOUT = 3  # seconds to wait for a free connection before giving up on this call
CONNECT_TIMEOUT = 5  # seconds to open a new connection
RETRY_AFTER = 30  # seconds the database is skipped after a failure

_lock = threading.Lock()
_pool = None
_pool_url = ""
_schema_ready = False
_down_until = 0.0


class StorageError(Exception):
    """The database couldn't be used for this call. The caller carries on with a safe default."""


def backend() -> str:
    """Read at call time, so tests and local runs can switch it."""
    return "postgres" if config.SUPABASE_DB_URL else "sqlite"


def failed(error: Exception) -> StorageError:
    """Log a database failure, skip the database for RETRY_AFTER seconds, and return the error for callers."""
    global _down_until
    _down_until = time.monotonic() + RETRY_AFTER
    print(f"[storage] database unavailable, using safe defaults for {RETRY_AFTER}s: {error!r}")
    return StorageError(str(error))


class _Postgres:
    """The subset of sqlite3.Connection the app uses, on a psycopg connection: ? placeholders, execute, executemany."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params=()):
        return self._conn.execute(sql.replace("?", "%s"), params)

    def executemany(self, sql: str, rows):
        cur = self._conn.cursor()
        cur.executemany(sql.replace("?", "%s"), rows)
        return cur


def _get_pool():
    """The connection pool for the current SUPABASE_DB_URL, made on first use and remade if the URL changes."""
    global _pool, _pool_url, _schema_ready
    if _pool is None or _pool_url != config.SUPABASE_DB_URL:
        from psycopg_pool import ConnectionPool

        if _pool is not None:
            _pool.close()
        _pool = ConnectionPool(config.SUPABASE_DB_URL, min_size=1, max_size=4, timeout=POOL_TIMEOUT, max_idle=300,
                               check=ConnectionPool.check_connection, open=False, name="scamcheck",
                               kwargs={"prepare_threshold": None, "connect_timeout": CONNECT_TIMEOUT})
        _pool.open(wait=False)  # a database that's down at boot mustn't stop the server starting
        _pool_url, _schema_ready = config.SUPABASE_DB_URL, False
    return _pool


@atexit.register
def _close_pool() -> None:
    if _pool is not None:
        _pool.close()


def ensure_schema(conn) -> None:
    """Create the Postgres tables once per process. Marked done only on success, so a failed first try is retried."""
    global _schema_ready
    if _schema_ready:
        return
    conn.execute(SCHEMA.read_text(encoding="utf-8"))
    conn.commit()
    _schema_ready = True


@contextmanager
def connect(sqlite_path: Path):
    """A transaction: commits if the block succeeds, rolls back if it raises. Raises StorageError on Postgres trouble."""
    if backend() == "sqlite":
        c = sqlite3.connect(sqlite_path)
        try:
            with c:
                yield c
        finally:
            c.close()
        return

    import psycopg

    if time.monotonic() < _down_until:
        raise StorageError("skipped after a recent failure")
    try:
        with _lock:
            pool = _get_pool()
        with pool.connection() as conn:
            with _lock:
                ensure_schema(conn)
            yield _Postgres(conn)
    except (psycopg.Error, OSError) as e:  # OSError: schema.sql missing from the deploy
        raise failed(e) from e
