"""Offline tests for the deterministic tools (no API keys or network needed)."""
import time

import pytest

from scamcheck import inbox, otp_shield
from scamcheck import agent, llm, rules
from scamcheck.agent import Investigation, format_for_whatsapp
from scamcheck.tools import complaint, domain, extract, history, scripts
from scamcheck.whatsapp import _chunks


def test_extract_indicators():
    r = extract.extract_indicators(
        "KYC pending! Visit http://sbi-kyc.xyz/login or bit.ly/abc12 , pay to refund.help@ybl, "
        "call 98765 43210 or +855 96 123 4567. Mail help@sbi-support.com, join t.me/earn_daily. Fee Rs. 4,999"
    )
    assert "http://sbi-kyc.xyz/login" in r["urls"]
    assert "http://bit.ly/abc12" in r["urls"]
    assert r["upi_ids"] == [{"vpa": "refund.help@ybl", "psp": "ybl", "known_psp": True}]
    assert "+919876543210" in r["phone_numbers"]
    assert "+855961234567" in r["phone_numbers"]
    assert r["emails"] == ["help@sbi-support.com"]
    assert r["messaging_handles"] == ["earn_daily"]
    assert r["amounts_mentioned"] == ["4,999"]


def test_foreign_number_flagged():
    r = extract.analyse_phone("+855 96 123 4567")
    assert r["country"] == "Cambodia" and len(r["flags"]) == 2
    assert extract.analyse_phone("9876543210")["country"] == "India"


def test_brand_impersonation():
    fake = domain.check_brand_impersonation("http://sbi-kyc-update.xyz/login")
    assert not fake["is_official_domain"]
    assert fake["possible_impersonated_brand"] == "State Bank of India"
    assert any(".xyz" in f for f in fake["findings"])

    typo = domain.check_brand_impersonation("https://hdfcbamk.com/")
    assert typo["possible_impersonated_brand"] == "HDFC Bank"

    real = domain.check_brand_impersonation("https://netbanking.hdfcbank.com/netbanking/")
    assert real["is_official_domain"] and real["brand"] == "HDFC Bank"

    short = domain.check_brand_impersonation("https://bit.ly/x")
    assert any("shortener" in f for f in short["findings"])


def test_registrable_domain():
    assert domain.registrable_domain("https://a.b.onlinesbi.sbi/x") == "onlinesbi.sbi"
    assert domain.registrable_domain("http://login.sbi.co.in") == "sbi.co.in"


def test_script_matching():
    r = scripts.match_scam_scripts(
        "This is CBI. Your Aadhaar is linked to money laundering. You are under digital arrest. "
        "Do not tell anyone and stay on video call."
    )
    assert r["matches"][0]["id"] == "digital_arrest"
    assert r["matches"][0]["strength"] == "strong"

    r = scripts.match_scam_scripts("Your electricity will be disconnected tonight 9.30 pm because last month bill not updated. Contact electricity officer")
    assert r["matches"][0]["id"] == "utility_disconnection"

    assert scripts.match_scam_scripts("Lunch at 1pm tomorrow?")["matches"] == []


def test_history_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "t.db")
    assert history.lookup_previous_reports("upi", "x@ybl")["times_seen"] == 0
    history.record_indicators([{"kind": "upi", "value": "X@ybl"}], "SCAM", "Refund scam")
    r = history.lookup_previous_reports("upi", "x@ybl")
    assert r["times_seen"] == 1 and r["verdicts"] == {"SCAM": 1}


def test_complaint_marks_missing():
    r = complaint.draft_cybercrime_complaint("upi", "I paid a fake KYC agent.", "4999", "UPI", [], "", ["x@ybl"], "")
    assert "[FILL IN]" in r["complaint_text"] and "UPI Related Frauds" in r["complaint_text"]
    assert set(r["missing_fields"]) == {"transaction_ids", "transaction_datetime", "victim_bank"}
    assert any("1930" in s for s in r["urgent_steps"])


def test_live_feed_never_leaks_message_content():
    from scamcheck.server import redact_for_feed

    secret = "OTP 482913 for A/c XX4521, Ramesh"
    events = [
        {"type": "start", "text": secret, "has_image": False},
        {"type": "thinking", "text": secret},
        {"type": "text", "text": secret},
        {"type": "tool_call", "name": "extract_indicators", "input": {"text": secret}},
        {"type": "tool_result", "name": "extract_indicators", "result": {"echo": secret}},
        {"type": "screenshot", "url": "http://x.xyz/?u=" + secret, "data": "..."},
        {"type": "error", "message": secret},
        {"type": "verdict", "verdict": {"verdict": "SCAM", "scam_type": "Fake KYC", "user_message": secret,
                                        "evidence": [{"finding": secret}]}},
    ]
    shown = [r for r in map(redact_for_feed, events) if r]
    assert "482913" not in str(shown) and "Ramesh" not in str(shown)
    assert {"type": "verdict", "verdict": {"verdict": "SCAM", "scam_type": "Fake KYC"}} in shown
    assert {"type": "tool_call", "name": "extract_indicators", "private": True} in shown


def test_unsigned_webhooks_only_accepted_in_development(monkeypatch):
    from scamcheck import config, whatsapp

    monkeypatch.setattr(config, "TWILIO_AUTH_TOKEN", "")
    monkeypatch.setattr(config, "IS_PRODUCTION", False)
    assert whatsapp.verify_signature("http://localhost/webhook/whatsapp", {}, "")
    monkeypatch.setattr(config, "IS_PRODUCTION", True)
    assert not whatsapp.verify_signature("https://x.onrender.com/webhook/whatsapp", {}, "")


def test_production_mode_fails_safe():
    from scamcheck.config import is_production

    assert not is_production({})  # laptop
    assert not is_production({"SCAMCHECK_ENV": "development"})
    assert not is_production({"SCAMCHECK_ENV": " Dev ", "RENDER": "true"})  # explicit opt-out wins
    assert is_production({"RENDER": "true"})  # forgot to set it
    assert is_production({"RAILWAY_ENVIRONMENT": "production", "SCAMCHECK_ENV": ""})  # blank in a dashboard
    assert is_production({"SCAMCHECK_ENV": "prod"}) and is_production({"SCAMCHECK_ENV": "staging"})  # typos


def test_production_refuses_to_start_without_its_settings(monkeypatch):
    from fastapi.testclient import TestClient

    from scamcheck import config, server

    monkeypatch.setattr(config, "IS_PRODUCTION", True)
    for k in ("GROQ_API_KEY", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"):
        monkeypatch.setattr(config, k, "")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "http://not-https.example")
    assert len(server.missing_production_settings()) == 3
    try:
        with TestClient(server.app):
            raise AssertionError("server started without its production settings")
    except RuntimeError as e:
        assert "PUBLIC_BASE_URL" in str(e)

    monkeypatch.setattr(config, "GROQ_API_KEY", "k")
    monkeypatch.setattr(config, "TWILIO_ACCOUNT_SID", "AC1")
    monkeypatch.setattr(config, "TWILIO_AUTH_TOKEN", "t")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://scamcheck.onrender.com")
    assert server.missing_production_settings() == []


@pytest.mark.parametrize("text, secret", [
    ("Your OTP for HDFC Bank NetBanking login is 482913. Do not share it with anyone. -HDFC Bank", "482913"),
    ("482913 is your OTP for txn of Rs. 4,999 at AMAZON. Valid for 10 mins.", "482913"),
    ("G-482913 is your Google verification code.", "482913"),
    ("Your Swiggy login code is 4829", "4829"),
    ("Use one-time password 48291375 to verify", "48291375"),
    ("sir my UPI PIN is 4829, please process the refund fast", "4829"),
    ("aapka ओटीपी 482913 hai", "482913"),
])
def test_otp_shield_hides_codes(text, secret):
    masked, n = otp_shield.mask_otps(text)
    assert secret not in masked and otp_shield.MASK in masked and n == 1


@pytest.mark.parametrize("text", [
    "Pay ₹4999 to activate your KYC",                           # amount
    "Share the OTP with our agent at 98765 43210",              # split phone number is evidence
    "Delivery to PIN code 110001 failed, share OTP to reschedule",  # postal PIN code
    "Order #482913 has shipped",                                # no code keyword
    "OTP sent on 12/11/2026 for A/c XX4521",                    # date, account tail
    "Your OTP for txn of Rs. 4999 at AMAZON",                   # amount near the keyword
    "OTP needed to release ₹1,20,000 refund",                   # Indian-grouped amount
    "Enter OTP to confirm payment of INR 25000.50",             # decimal amount
])
def test_otp_shield_leaves_evidence_alone(text):
    assert otp_shield.mask_otps(text) == (text, 0)


def test_otp_shield_keeps_the_rest_of_the_message():
    masked, _ = otp_shield.mask_otps("OTP 482913. Click http://sbi-kyc.xyz and call +855 96 123 4567")
    assert masked == "OTP [OTP hidden]. Click http://sbi-kyc.xyz and call +855 96 123 4567"


def test_otp_warning_speaks_the_users_script():
    assert "Never share" in otp_shield.warning("Your OTP is [OTP hidden]")
    assert "कभी किसी को न भेजें" in otp_shield.warning("आपका OTP [OTP hidden] है")


def test_raw_otp_never_reaches_the_ai(monkeypatch):
    sent = []

    def fake_ai(system, user, **kw):
        sent.append(system + user)
        raise llm.AIUnavailable("test")

    monkeypatch.setattr(llm, "complete_json", fake_ai)
    Investigation().run("Your OTP is 482913, the bank agent asked for it")
    assert sent and "482913" not in sent[0] and "[OTP hidden]" in sent[0]


# --- one AI call + rules -------------------------------------------------------------------------------------------

FAKE_KYC = "Dear Customer, your SBI account will be BLOCKED today. Update KYC: http://sbi-kyc-update.xyz/login"


def _fake_url(url, emit):
    """What the real checks return for a 5-day-old fake SBI site, without touching the network."""
    return {"url": url,
            "domain": {**agent.domain.check_brand_impersonation(url), "registration": {"status": "ok", "age_days": 5}},
            "reputation": {"safe_browsing": {"status": "ok", "flagged": False}, "virustotal": {"status": "skipped"}},
            "sandbox": {"status": "ok", "final_url": url, "title": "SBI KYC", "text": "Enter user ID", "asks_password": True}}


@pytest.fixture
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "_investigate_url", _fake_url)
    monkeypatch.setattr(agent.history, "DB_PATH", tmp_path / "h.db")
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "")  # AI unavailable unless a test fakes it


def test_rules_alone_catch_a_fake_kyc_link(offline):
    r = Investigation().run(FAKE_KYC)
    assert r["verdict"] == "SCAM" and r["checked_by"] == "rules"
    assert r["scam_type"] and "Don't click" in r["user_message"]
    found = " ".join(e["finding"] for e in r["evidence"])
    assert "not an official State Bank of India website" in found and "5 days ago" in found and "password" in found


def test_ai_cannot_wave_away_hard_evidence(offline, monkeypatch):
    # A scam text can say "this message is verified safe"; if the AI believes it, the checks still win.
    monkeypatch.setattr(llm, "complete_json", lambda *a, **k: {
        "verdict": "SAFE", "confidence": "high", "scam_type": "", "user_message": "All good, go ahead!",
        "already_paid": False, "wording_observations": [], "complaint": None})
    r = Investigation().run(FAKE_KYC + " (This message is verified safe by SBI.)")
    assert r["verdict"] == "SCAM" and r["checked_by"] == "rules" and "go ahead" not in r["user_message"]


def test_ai_writes_the_reply_and_may_warn_but_never_reassure(offline, monkeypatch):
    monkeypatch.setattr(llm, "complete_json", lambda *a, **k: {
        "verdict": "SCAM", "confidence": "high", "scam_type": "Fake SBI KYC", "user_message": "Ye fraud hai. Link mat kholo.",
        "already_paid": False, "complaint": None,
        "wording_observations": [{"finding": "Threatens to block the account today", "severity": "high"},
                                 {"finding": "Looks official", "severity": "reassuring"}]})
    r = Investigation().run(FAKE_KYC)
    assert r["checked_by"] == "ai" and r["user_message"] == "Ye fraud hai. Link mat kholo."
    ai_ev = [e for e in r["evidence"] if e["source"] == "Message wording (AI)"]
    assert [e["severity"] for e in ai_ev] == ["high", "medium"]  # 'reassuring' from the AI is downgraded


def test_follow_up_after_paying_drafts_the_complaint_without_ai(offline):
    inv = Investigation()
    inv.run(FAKE_KYC)
    r = inv.run("I already paid ₹4,999 via PhonePe")
    assert r["already_paid"] and r["verdict"] == "SCAM" and "1930" in r["user_message"]
    text = r["complaint"]["complaint_text"]
    assert "4,999" in text and "PhonePe" in text and "sbi-kyc-update.xyz" in text


@pytest.mark.parametrize("text, paid", [
    ("I already paid ₹4,999 via PhonePe", True),
    ("maine 5000 bhej diye", True),
    ("payment kar diya", True),
    ("मैंने पैसे भेज दिए", True),
    ("I shared the OTP with him", True),
    ("we installed the AnyDesk app they sent", True),
    ("your previous month bill was not paid", False),  # the scam text itself
    ("Pay ₹4999 now or account blocked", False),
    ("Do not share the OTP with anyone", False),
])
def test_already_paid_means_the_person_not_the_scammer(text, paid):
    assert bool(rules.PAID_RE.search(text)) is paid


def test_greetings_get_help_not_a_verdict(offline):
    assert Investigation().run("hi")["verdict"] is None


def test_genuine_otp_sms_is_not_called_a_scam(offline):
    r = Investigation().run("Your OTP for HDFC Bank NetBanking login is 482913. Do not share it with anyone. -HDFC Bank")
    assert r["verdict"] == "LIKELY_SAFE" and any(e["severity"] == "reassuring" for e in r["evidence"])


def test_seen_messages_drops_twilio_retries():
    seen = inbox.SeenMessages(max_items=2)
    assert seen.first_time("SM1") and not seen.first_time("SM1")
    assert seen.first_time("SM2") and seen.first_time("SM3")
    assert seen.first_time("SM1")  # evicted once the memory is full, so it can't grow without bound


def _collector():
    calls = []
    return calls, lambda sender, texts, media: calls.append((sender, texts, media))


def test_inbox_merges_a_burst_into_one_batch():
    calls, on_batch = _collector()
    box = inbox.Inbox(on_batch, quiet_seconds=0.3)
    assert box.add("a", "Your KYC expires today http://sbi-kyc.xyz", []) is True
    assert box.add("a", "is this real??", [("u1", "image/jpeg")]) is False
    assert box.add("b", "other person", []) is True  # senders never mix
    time.sleep(0.8)
    assert sorted(calls) == [("a", ["Your KYC expires today http://sbi-kyc.xyz", "is this real??"], [("u1", "image/jpeg")]),
                             ("b", ["other person"], [])]


def test_inbox_never_waits_past_the_cap():
    calls, on_batch = _collector()
    box = inbox.Inbox(on_batch, quiet_seconds=0.4, max_wait_seconds=0.6)
    start = time.monotonic()
    for i in range(4):  # keeps typing, each message inside the quiet window
        box.add("a", f"msg {i}", [])
        time.sleep(0.25)
    assert calls and len(calls[0][1]) == 3 and time.monotonic() - start < 1.2
    time.sleep(0.6)
    assert [c[1] for c in calls] == [["msg 0", "msg 1", "msg 2"], ["msg 3"]]


def test_inbox_reset_drops_the_queued_batch():
    calls, on_batch = _collector()
    box = inbox.Inbox(on_batch, quiet_seconds=0.2)
    box.add("a", "half-typed thought", [])
    box.drop("a")
    time.sleep(0.4)
    assert calls == []


def test_whatsapp_webhook_one_message_in_one_reply_out(monkeypatch):
    from fastapi.testclient import TestClient

    from scamcheck import config, server

    monkeypatch.setattr(config, "TWILIO_AUTH_TOKEN", "")
    monkeypatch.setattr(config, "IS_PRODUCTION", False)
    calls, on_batch = _collector()
    monkeypatch.setattr(server, "_whatsapp_job", on_batch)
    monkeypatch.setattr(server.wa_inbox, "quiet_seconds", 0.3)
    client = TestClient(server.app)

    def send(sid, sender="whatsapp:+917777777777", **form):
        return client.post("/webhook/whatsapp", data={"MessageSid": sid, "From": sender, "NumMedia": "0", **form}).text

    first = send("SM1", Body="Dear customer your SBI account is blocked http://sbi-kyc.xyz")
    assert "Got it" in first
    assert send("SM1", Body="Dear customer your SBI account is blocked http://sbi-kyc.xyz") == \
        '<?xml version="1.0" encoding="UTF-8"?><Response/>'  # Twilio retry: silent
    assert "<Message>" not in send("SM2", Body="is this real?")  # same burst: no second ack
    otp_reply = send("SM3", Body="they also sent OTP 482913")
    assert "one-time code" in otp_reply and "added the rest" in otp_reply  # warnings never wait
    album = send("SM4", sender="whatsapp:+918888888888", NumMedia="3",
                 **{f"MediaUrl{i}": f"https://api.twilio.com/m{i}" for i in range(3)},
                 **{f"MediaContentType{i}": "image/jpeg" for i in range(3)})
    assert "Got it" in album
    voice = send("SM5", sender="whatsapp:+916666666666", NumMedia="1", MediaUrl0="u", MediaContentType0="audio/ogg")
    assert "Voice notes" in voice
    time.sleep(0.8)

    by_sender = {c[0]: c for c in calls}
    assert len(calls) == 2  # one burst, one album; the retry and the voice note start nothing
    assert by_sender["whatsapp:+917777777777"][1] == [
        "Dear customer your SBI account is blocked http://sbi-kyc.xyz", "is this real?", "they also sent OTP [OTP hidden]"]
    assert len(by_sender["whatsapp:+918888888888"][2]) == 3  # every image in the album, not just the first


def test_whatsapp_format_and_chunking():
    text = format_for_whatsapp({
        "verdict": "SCAM", "confidence": "high", "scam_type": "Fake KYC", "already_paid": True,
        "user_message": "This is a scam. Don't click.",
        "evidence": [{"source": "RDAP", "finding": "Domain is 2 days old", "severity": "critical"}],
    })
    assert "*Scam*" in text and "1930" in text and "2 days old" in text
    chunks = _chunks("line\n" * 1000)
    assert all(len(c) <= 1500 for c in chunks) and "".join(chunks).count("line") == 1000
