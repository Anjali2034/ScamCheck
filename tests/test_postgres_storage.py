"""Storage on a real Postgres (what Supabase runs). Skipped unless PG_TEST_URL points at a database to use.

    docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
    PG_TEST_URL=postgresql://postgres:postgres@localhost:5432/postgres pytest tests/test_postgres_storage.py

Or a spare free Supabase project's Session pooler URI. Never the live one: every test empties the tables.
"""
import contextlib
import os
import threading
import time

import pytest

from scamcheck import config, db, quota
from scamcheck.tools import history

PG_TEST_URL = os.getenv("PG_TEST_URL", "").strip()
pytestmark = pytest.mark.skipif(not PG_TEST_URL, reason="set PG_TEST_URL to run the Postgres storage tests")
UNREACHABLE = "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=1"


@pytest.fixture(autouse=True)
def postgres(monkeypatch):
    monkeypatch.setattr(config, "SUPABASE_DB_URL", PG_TEST_URL)
    monkeypatch.setattr(db, "_down_until", 0.0)
    monkeypatch.setattr(history, "_keys", {})
    monkeypatch.setattr(quota, "_pruned_on", "")
    with db.connect(config.DB_PATH) as c:  # also creates the tables
        c.execute("TRUNCATE indicators, meta, usage")
    yield


def test_backend_and_health_say_postgres():
    assert db.backend() == "postgres"
    assert quota.status()["storage"] == "postgres"


def test_tables_are_closed_to_supabase_public_api():
    with db.connect(config.DB_PATH) as c:
        rows = c.execute("SELECT relname, relrowsecurity FROM pg_class "
                         "WHERE relname IN ('indicators', 'meta', 'usage')").fetchall()
    assert dict(rows) == {"indicators": True, "meta": True, "usage": True}


def test_schema_can_run_again():
    with db.connect(config.DB_PATH) as c:
        c.execute(db.SCHEMA.read_text(encoding="utf-8"))


def test_reporter_id_is_stable_and_kept_in_the_database():
    first = history.reporter_id("wa:+919876543210")
    history._keys.clear()  # as if the server restarted: the key must come back from the database
    assert history.reporter_id("wa:+919876543210") == first
    assert history.reporter_id("wa:+919999999999") != first
    assert history.reporter_id("") == ""


def test_one_row_per_person_and_rechecking_replaces_the_earlier_verdict():
    a, b = history.reporter_id("web:1.2.3.4"), history.reporter_id("web:5.6.7.8")
    upi = [{"kind": "upi", "value": "Refund.Desk@ybl"}]
    history.record_indicators(upi, "SUSPICIOUS", "Refund", reporter=a)
    history.record_indicators(upi, "SCAM", "Refund", reporter=a)
    history.record_indicators(upi, "SCAM", "Refund", reporter=b)
    seen = history.lookup_previous_reports("upi", "refund.desk@ybl")
    assert seen["times_seen"] == 2 and seen["verdicts"] == {"SCAM": 2}
    assert history.lookup_previous_reports("upi", "refund.desk@ybl", exclude=a)["times_seen"] == 1
    with db.connect(config.DB_PATH) as c:
        assert c.execute("SELECT count(*) FROM indicators").fetchone()[0] == 2


def test_take_if_under_stops_exactly_at_the_limit():
    assert [quota._take_if_under("t:2026-11-26", 3) for _ in range(5)] == [True, True, True, False, False]
    assert quota.used("t:2026-11-26") == 3
    assert quota._take_if_under("t:zero", 0) is False


def test_take_if_under_is_atomic_in_the_database_itself(monkeypatch):
    monkeypatch.setattr(quota, "_lock", contextlib.nullcontext())  # as if 20 separate servers asked at once
    results, start = [], threading.Barrier(20)

    def take():
        start.wait()
        results.append(quota._take_if_under("race:2026-11-26", 5))

    threads = [threading.Thread(target=take) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 5 and quota.used("race:2026-11-26") == 5


def test_add_accumulates():
    assert quota._add("ai_tokens:2026-11-26", 1200) == 1200
    assert quota._add("ai_tokens:2026-11-26", 800) == 2000
    assert quota.used("ai_tokens:2026-11-26") == 2000


def test_old_usage_rows_are_pruned_and_current_ones_kept():
    with db.connect(config.DB_PATH) as c:
        c.executemany("INSERT INTO usage (bucket, n) VALUES (?, 1)",
                      [("wa_checks:+919876543210:2026-01-01",), ("wa_messages:2026-01",), ("undated",),
                       (f"keep:{quota._day()}",), (f"keep_month:{quota._month()}",)])
    quota._add(f"ai_tokens:{quota._day()}", 1)
    with db.connect(config.DB_PATH) as c:
        left = {b for (b,) in c.execute("SELECT bucket FROM usage").fetchall()}
    assert left == {"undated", f"keep:{quota._day()}", f"keep_month:{quota._month()}", f"ai_tokens:{quota._day()}"}


def test_unreachable_database_never_stops_a_check(monkeypatch):
    monkeypatch.setattr(config, "SUPABASE_DB_URL", UNREACHABLE)
    assert history.lookup_previous_reports("upi", "a@ybl") == {"kind": "upi", "value": "a@ybl", "times_seen": 0}
    history.record_indicators([{"kind": "upi", "value": "a@ybl"}], "SCAM", None, reporter="r")
    assert quota._take_if_under("t:2026-11-26", 1) is True
    assert quota.used("t:2026-11-26") == 0 and quota._add("t:2026-11-26") == 0
    assert history.reporter_id("wa:+91") == history.reporter_id("wa:+91")  # consistent within this process


def test_after_one_failure_the_database_is_skipped_without_waiting(monkeypatch):
    monkeypatch.setattr(config, "SUPABASE_DB_URL", UNREACHABLE)
    quota.used("t")  # fails once, waiting for the pool timeout
    t = time.monotonic()
    for _ in range(10):
        quota.used("t")
        history.lookup_previous_reports("upi", "a@ybl")
    assert time.monotonic() - t < 0.5
