"""The scam type people see is plain words in their language, never a code like `utility_scams`."""
import pytest

from scamcheck import llm, rules
from scamcheck.agent import Investigation, format_for_whatsapp

KYC = "Dear customer, your SBI KYC has expired. Your account will be blocked today. Share the OTP with our officer."
KYC_HI = "प्रिय ग्राहक, आपका एसबीआई केवाईसी समाप्त हो गया है। आपका खाता आज बंद हो जाएगा। ओटीपी हमारे अधिकारी को बताएं।"


def _ai_labels_it(monkeypatch, label):
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "x")
    monkeypatch.setattr(llm, "complete_json", lambda *a, **k: {
        "verdict": "SCAM", "confidence": "high", "scam_type": label, "user_message": "Scam.",
        "already_paid": False, "wording_observations": [], "complaint": None})


def test_a_known_script_keeps_its_own_name_whatever_the_ai_calls_it(monkeypatch):
    _ai_labels_it(monkeypatch, "fake_kyc_scam")
    r = Investigation().run(KYC)
    assert r["scam_type"] == "Fake KYC / account block" and r["scam_label"] == "Fake KYC / account block"


def test_a_hindi_verdict_shows_the_hindi_name(monkeypatch):
    _ai_labels_it(monkeypatch, "fake_kyc")
    r = Investigation().run(KYC_HI)
    assert r["scam_type"] == "Fake KYC / account block"  # what history and the complaint record
    assert r["scam_label"] == rules.SCRIPT_NAMES_HI["fake_kyc"] and "_" not in r["scam_label"]
    assert rules.SCRIPT_NAMES_HI["fake_kyc"] in format_for_whatsapp(r)


def test_every_script_has_a_hindi_name():
    from scamcheck.tools import scripts
    assert {s["id"] for s in scripts._SCRIPTS} == set(rules.SCRIPT_NAMES_HI)
    assert all(n.strip() and not n.isascii() for n in rules.SCRIPT_NAMES_HI.values())


@pytest.mark.parametrize("raw, shown", [
    ("utility_scams", "Utility scams"),
    ("digital_arrest", "Digital arrest"),
    ("PHISHING-LINK", "Phishing link"),
    ("Fake courier fee", "Fake courier fee"),
    ("SBI phishing", "SBI phishing"),
    ("", ""),
])
def test_an_ai_label_is_tidied_into_words(raw, shown):
    assert rules.tidy_label(raw) == shown
