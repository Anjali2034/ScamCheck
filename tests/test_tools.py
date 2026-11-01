"""Offline tests for the deterministic tools (no API keys or network needed)."""
from scamcheck.agent import TOOLS, format_for_whatsapp
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


def test_tool_schemas_are_strict():
    for t in TOOLS:
        s = t["input_schema"]
        assert t["strict"] and s["additionalProperties"] is False
        assert set(s["required"]) == set(s["properties"])


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
    for k in ("ANTHROPIC_API_KEY", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"):
        monkeypatch.setattr(config, k, "")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "http://not-https.example")
    assert len(server.missing_production_settings()) == 3
    try:
        with TestClient(server.app):
            raise AssertionError("server started without its production settings")
    except RuntimeError as e:
        assert "PUBLIC_BASE_URL" in str(e)

    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(config, "TWILIO_ACCOUNT_SID", "AC1")
    monkeypatch.setattr(config, "TWILIO_AUTH_TOKEN", "t")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://scamcheck.onrender.com")
    assert server.missing_production_settings() == []


def test_whatsapp_format_and_chunking():
    text = format_for_whatsapp({
        "verdict": "SCAM", "confidence": "high", "scam_type": "Fake KYC", "already_paid": True,
        "user_message": "This is a scam. Don't click.",
        "evidence": [{"source": "RDAP", "finding": "Domain is 2 days old", "severity": "critical"}],
    })
    assert "*Scam*" in text and "1930" in text and "2 days old" in text
    chunks = _chunks("line\n" * 1000)
    assert all(len(c) <= 1500 for c in chunks) and "".join(chunks).count("line") == 1000
