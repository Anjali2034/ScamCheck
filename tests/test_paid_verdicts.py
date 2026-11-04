"""Someone who says they've paid or shared a code must never be told it's safe."""
import pytest

from scamcheck import agent, llm, otp_shield, rules
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


@pytest.mark.parametrize("text", [
    "I already paid 5000", "I've paid them", "I sent 5000 to him", "I sent him the money",
    "I gave him the OTP", "I told them the OTP 482913", "He took my OTP and money got deducted",
    "Money got deducted from my account", "5000 was debited from my account", "I lost 5000 to a scammer",
    "I got scammed", "They scammed me", "They took 20000 from my account",
    "I clicked the link and entered my card details", "I entered my UPI PIN",
    "I scanned the QR code and money went",
    "Maine paise bhej diye", "Maine 5000 bhej diye", "Maine OTP de diya", "Maine OTP bata diya", "OTP de diya",
    "Maine OTP 482913 de diya aur 5000 bhej diye", "Mere paise kat gaye", "Mere account se 5000 kat gaye",
    "Paise chale gaye", "Mera account khali ho gaya", "Mere saath fraud ho gaya",
    "मैंने पैसे भेज दिए", "मैंने OTP बता दिया", "मैंने ओटीपी दे दिया", "मेरे खाते से पैसे कट गए", "मेरे पैसे चले गए",
    "मेरे साथ धोखा हो गया",
])
def test_every_way_of_saying_the_money_or_code_has_gone_is_recognised(text):
    masked, _ = otp_shield.mask_otps(text)
    assert rules.says_paid([masked])


@pytest.mark.parametrize("text", [
    # Denials
    "I never shared my OTP", "I did not share my OTP", "I was told not to share OTP", "I have not paid anything",
    "Maine paise nahi bheje", "Maine OTP nahi diya", "मैंने पैसे नहीं भेजे", "मैंने OTP नहीं बताया",
    # Threats and warnings in someone else's voice
    "Your money will be deducted today", "Your money was stolen, click here to recover it",
    "Rs.5000 debited from your a/c XX1234", "Money was debited from your account", "5000 will be deducted from my account",
    "Aapke paise kat jayenge", "Paise kat jayenge agar KYC nahi kiya", "Aapke account se 5000 kat gaye",
    "OTP kisi ko mat do", "आपके पैसे कट जाएंगे", "Do not share the OTP with anyone",
    # Everyday messages
    "My money is safe", "I lost my phone", "Mera network chala gaya", "I gave my pin code to the courier",
    "I sent you 5000 by mistake, please return it", "I sent 2 messages", "No money was deducted",
    # The refund scam's opening line, in the sender's voice
    "Sir I sent Rs 5000 to you by mistake. Please approve the collect request and enter your UPI PIN",
    "Sir maine galti se aapko 5000 bhej diye. Refund ke liye request approve karo",
    "सर मैंने गलती से आपको ₹5000 भेज दिए। रिफंड के लिए रिक्वेस्ट अप्रूव करें",
    # Not lost anything yet: a warning is right, the helpline isn't
    "I clicked the link",
])
def test_denials_threats_and_everyday_messages_are_not_read_as_a_loss(text):
    assert not rules.says_paid([text])


@pytest.mark.parametrize("text", ["Mere paise kat gaye", "I got scammed", "मेरे पैसे चले गए"])
def test_a_few_panicked_words_get_the_helpline_not_the_help_text(no_ai, text):
    r = Investigation().run(text)
    assert r["verdict"] and r["already_paid"] and "1930" in r["user_message"] and r["complaint"]


@pytest.mark.parametrize("text, opening", [
    ("help", "Forward me"), ("mere paise", "Suspicious message"), ("पैसे गए", "संदिग्ध मैसेज")])
def test_even_the_help_text_points_to_the_helpline_in_the_persons_language(no_ai, text, opening):
    r = Investigation().run(text)
    assert r["verdict"] is None and r["user_message"].startswith(opening) and "1930" in r["user_message"]


@pytest.mark.parametrize("text", ["Mere paise kat gaye", "Maine OTP de diya"])
def test_short_hinglish_victim_messages_get_a_hinglish_reply(no_ai, text):
    r = Investigation().run(text)
    assert r["language"] == "Hinglish" and "1930 par call" in r["user_message"]


def test_a_reply_that_forgets_1930_is_replaced(monkeypatch):
    _ai_answers(monkeypatch, user_message="Do not share OTPs with anyone.")
    r = Investigation().run(PAID_WITH_OTP)
    assert "1930" in r["user_message"] and r["checked_by"] == "ai"


def test_whatsapp_says_act_now_instead_of_inconclusive(no_ai):
    text = agent.format_for_whatsapp(Investigation().run("Mere paise kat gaye, abhi kya karu"))
    assert "Abhi kadam uthaiye" in text and "Inconclusive" not in text and "confidence" not in text and "1930" in text


def test_whatsapp_keeps_the_scam_heading_for_a_confirmed_scam(no_ai):
    inv = Investigation()
    inv.run("Your SBI KYC has expired. Your account will be blocked today. Share your OTP and update KYC immediately or pay penalty")
    result = inv.run("I already paid ₹4,999 via PhonePe")
    text = agent.format_for_whatsapp(result)
    assert result["verdict"] in ("SCAM", "LIKELY_SCAM") and "Act now" not in text and "1930" in text


def test_someone_who_has_lost_nothing_keeps_the_normal_heading(no_ai):
    assert "Act now" not in agent.format_for_whatsapp(Investigation().run(OFFICIAL_LINK))


def test_the_rules_floor_only_changes_for_someone_who_paid():
    reassuring = [{"source": "Official domain list", "finding": "Official.", "severity": "reassuring"}]
    assert rules.floor_for(reassuring) == "SAFE"
    assert rules.floor_for(reassuring, already_paid=True) == "INCONCLUSIVE"
    assert rules.verdict_from(reassuring)[0] == "LIKELY_SAFE"
    assert rules.verdict_from(reassuring, already_paid=True)[0] == "INCONCLUSIVE"
