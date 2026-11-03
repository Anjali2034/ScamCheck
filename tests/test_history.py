"""'Seen before' counts people, not checks, and can't snowball from its own reports."""
import sqlite3

import pytest

from scamcheck import agent, llm, rules
from scamcheck.agent import Investigation
from scamcheck.tools import history

UPI = "refund.help@ybl"
PLAIN = f"Someone asked me to pay {UPI}, is it ok?"  # no red flags of its own


@pytest.fixture
def no_ai(monkeypatch):
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "")


def _report(who: str, verdict: str = "SCAM", value: str = UPI) -> None:
    history.record_indicators([{"kind": "upi", "value": value}], verdict, "Refund scam", reporter=history.reporter_id(who))


def test_one_person_checking_again_is_still_one_report():
    for _ in range(10):
        _report("net:1.2.3.4")
    r = history.lookup_previous_reports("upi", UPI)
    assert r["times_seen"] == 1 and r["verdicts"] == {"SCAM": 1}


def test_your_own_reports_dont_count_against_you():
    me = history.reporter_id("net:1.2.3.4")
    _report("net:1.2.3.4")
    assert history.lookup_previous_reports("upi", UPI, exclude=me)["times_seen"] == 0
    _report("wa:+919800000001")
    assert history.lookup_previous_reports("upi", UPI, exclude=me)["times_seen"] == 1


def test_a_persons_latest_verdict_replaces_their_earlier_one():
    _report("net:1.2.3.4", "SCAM")
    _report("net:1.2.3.4", "SUSPICIOUS")
    assert history.lookup_previous_reports("upi", UPI)["verdicts"] == {"SUSPICIOUS": 1}


def test_people_are_stored_as_a_keyed_hash_never_raw():
    _report("wa:+919812345678")
    with sqlite3.connect(history.DB_PATH) as c:
        stored = c.execute("SELECT reporter FROM indicators").fetchone()[0]
    assert "9812345678" not in stored and stored == history.reporter_id("wa:+919812345678")
    assert history.reporter_id("wa:+919812345678") != history.reporter_id("wa:+919812345679")


def test_rows_from_before_this_change_count_as_one_person():
    with sqlite3.connect(history.DB_PATH) as c:  # the old table, with no reporter column
        c.execute("CREATE TABLE indicators (kind TEXT, value TEXT, verdict TEXT, scam_type TEXT, seen_at TEXT)")
        c.executemany("INSERT INTO indicators VALUES ('upi', ?, 'SCAM', '', '2026-10-01T00:00:00+00:00')", [(UPI,)] * 14)
    assert history.lookup_previous_reports("upi", UPI)["times_seen"] == 1
    _report("net:5.6.7.8")
    assert history.lookup_previous_reports("upi", UPI)["times_seen"] == 2


def test_one_other_person_is_a_hint_two_are_strong():
    one = rules._history_evidence({"value": UPI, "verdicts": {"SCAM": 1}})
    two = rules._history_evidence({"value": UPI, "verdicts": {"SCAM": 1, "LIKELY_SCAM": 1}})
    assert one[0]["severity"] == "medium" and "1 other person" in one[0]["finding"]
    assert two[0]["severity"] == "high" and "2 other people" in two[0]["finding"]
    assert rules._history_evidence({"value": UPI, "verdicts": {"SUSPICIOUS": 3}}) == []


def test_earlier_reports_alone_dont_make_a_new_report(no_ai):
    _report("net:1.1.1.1")
    _report("net:2.2.2.2")
    r = Investigation().run(PLAIN, reporter="net:3.3.3.3")
    assert r["verdict"] == "SUSPICIOUS" and any(e["source"] == rules.HISTORY for e in r["evidence"])
    assert history.lookup_previous_reports("upi", UPI)["times_seen"] == 2  # no snowball


def test_a_scam_on_its_own_merits_is_still_remembered(no_ai):
    _report("net:1.1.1.1")
    msg = f"Your SBI KYC expired. Pay Rs 10 to {UPI} now or your account will be blocked today. Share the OTP."
    r = Investigation().run(msg, reporter="net:3.3.3.3")
    assert r["verdict"] in ("SCAM", "LIKELY_SCAM")
    assert history.lookup_previous_reports("upi", UPI)["times_seen"] == 2


def test_rechecking_your_own_message_gives_the_same_answer(no_ai):
    first = Investigation().run(PLAIN, reporter="net:9.9.9.9")
    again = [Investigation().run(PLAIN, reporter="net:9.9.9.9")["verdict"] for _ in range(5)]
    assert set(again) == {first["verdict"]}
