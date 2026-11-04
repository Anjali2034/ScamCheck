"""Someone who says they've paid or shared a code must never be told it's safe."""
import pytest

from scamcheck import agent, llm, rules
from scamcheck.agent import Investigation

GENUINE_OTP = "Your OTP for HDFC Bank NetBanking login is 482913. Do not share it with anyone. -HDFC Bank"
PAID_WITH_OTP = "I got OTP 482913 and I already paid Rs 4999 to scammer@ybl after a fake KYC call"
OFFICIAL_LINK = "https://www.irctc.co.in"
SAFE_VERDICTS = ("SAFE", "LIKELY_SAFE")


@pytest.fixture
def no_ai(monkeypatch):
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "")
    _official_links(monkeypatch)


def _official_links(monkeypatch):
    monkeypatch.setattr(agent, "_investigate_url", lambda url, emit, me="": {
        "url": url, "domain": {"host": "www.irctc.co.in", "is_official_domain": True, "brand": "IRCTC"},
        "reputation": None, "sandbox": None})


def _ai_answers(monkeypatch, **fields):
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "x")
    _official_links(monkeypatch)
    monkeypatch.setattr(llm, "complete_json", lambda *a, **k: {
        "verdict": "SAFE", "confidence": "high", "scam_type": "", "user_message": "Call 1930 now.",
        "already_paid": False, "wording_observations": [], "complaint": None, **fields})


def test_a_code_in_a_paid_message_is_not_called_a_normal_otp_message(no_ai):
    r = Investigation().run(PAID_WITH_OTP)
    assert r["already_paid"] and r["verdict"] not in SAFE_VERDICTS
    assert not any(e["severity"] == "reassuring" for e in r["evidence"])
    assert "1930" in r["user_message"] and r["complaint"]


def test_saying_you_shared_the_code_after_a_genuine_otp_message_ends_the_reassurance(no_ai):
    inv = Investigation()
    assert inv.run(GENUINE_OTP)["verdict"] == "LIKELY_SAFE"
    r = inv.run("I shared the OTP with him")
    assert r["already_paid"] and r["verdict"] not in SAFE_VERDICTS
    assert not any(e["source"] == "OTP message" for e in r["evidence"])


def test_an_official_link_stays_as_evidence_but_is_not_safe_for_someone_who_paid(no_ai):
    r = Investigation().run(f"I already paid Rs 4999 on {OFFICIAL_LINK}")
    assert r["already_paid"] and r["verdict"] == "INCONCLUSIVE"
    assert any(e["severity"] == "reassuring" for e in r["evidence"])


def test_the_ai_cannot_call_a_paid_message_safe(monkeypatch):
    _ai_answers(monkeypatch)
    r = Investigation().run(PAID_WITH_OTP)
    assert r["verdict"] == "INCONCLUSIVE" and r["checked_by"] == "ai" and r["user_message"] == "Call 1930 now."


def test_when_only_the_ai_notices_the_payment_the_reassurance_still_goes(monkeypatch):
    _ai_answers(monkeypatch, already_paid=True)
    r = Investigation().run("Your OTP is 482913. The caller from the bank has it now.")
    assert r["already_paid"] and r["verdict"] == "INCONCLUSIVE"
    assert not any(e["source"] == "OTP message" for e in r["evidence"])


def test_the_ai_may_still_be_stricter_for_someone_who_paid(monkeypatch):
    _ai_answers(monkeypatch, verdict="LIKELY_SCAM")
    assert Investigation().run(PAID_WITH_OTP)["verdict"] == "LIKELY_SCAM"


def test_the_ai_is_told_the_real_minimum_verdict(monkeypatch):
    prompts = []
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "x")
    _official_links(monkeypatch)
    monkeypatch.setattr(llm, "complete_json", lambda system, user, **k: prompts.append(user) or {})
    Investigation().run(f"I already paid Rs 4999 on {OFFICIAL_LINK}")
    assert "Minimum verdict the evidence allows: INCONCLUSIVE." in prompts[0]


@pytest.mark.parametrize("text, verdict", [(GENUINE_OTP, "LIKELY_SAFE"), (OFFICIAL_LINK, "LIKELY_SAFE")])
def test_people_who_havent_paid_are_still_reassured(no_ai, text, verdict):
    r = Investigation().run(text)
    assert not r["already_paid"] and r["verdict"] == verdict


def test_the_ai_can_still_call_a_genuine_otp_message_safe(monkeypatch):
    _ai_answers(monkeypatch)
    assert Investigation().run(GENUINE_OTP)["verdict"] == "SAFE"


def test_the_rules_floor_only_changes_for_someone_who_paid():
    reassuring = [{"source": "Official domain list", "finding": "Official.", "severity": "reassuring"}]
    assert rules.floor_for(reassuring) == "SAFE"
    assert rules.floor_for(reassuring, already_paid=True) == "INCONCLUSIVE"
    assert rules.verdict_from(reassuring)[0] == "LIKELY_SAFE"
    assert rules.verdict_from(reassuring, already_paid=True)[0] == "INCONCLUSIVE"
