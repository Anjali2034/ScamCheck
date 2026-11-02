"""The quota guard: free-tier budgets, fair use, and what people get when a limit is hit."""
import pytest

from scamcheck import agent, config, llm, quota, server, whatsapp
from scamcheck.agent import Investigation, format_for_whatsapp

SCAM = "Dear Customer your SBI YONO account will be BLOCKED today due to incomplete KYC. Update PAN now"
AI_REPLY = {"verdict": "SCAM", "confidence": "high", "scam_type": "Fake KYC", "user_message": "Don't reply.",
            "already_paid": False, "wording_observations": [], "complaint": None}


@pytest.fixture
def fake_groq(monkeypatch):
    """Groq answering with a usage block; `responses` can queue 429s."""
    calls, responses = [], []

    class R:
        def __init__(self, status=200, headers=None, tokens=1200):
            self.status_code, self.headers, self._tokens = status, headers or {}, tokens
            self.ok = status == 200

        def json(self):
            import json
            return {"choices": [{"message": {"content": json.dumps(AI_REPLY)}}], "usage": {"total_tokens": self._tokens}}

    def post(*a, **k):
        calls.append(k["json"])
        return responses.pop(0) if responses else R()

    monkeypatch.setattr(config, "GROQ_API_KEY", "gsk_test")
    monkeypatch.setattr(llm.requests, "post", post)
    monkeypatch.setattr(agent, "_investigate_url", lambda url, emit: {"url": url, "domain": {}, "reputation": None, "sandbox": None})
    return calls, responses, R


def test_tokens_are_counted_from_groqs_answer(fake_groq):
    Investigation().run(SCAM, person="web:a")
    assert quota.status()["ai_tokens_left_today"] == config.AI_DAILY_TOKENS - 1200


def test_daily_ai_budget_keeps_a_reserve_for_people_who_lost_money(fake_groq, monkeypatch):
    monkeypatch.setattr(config, "AI_DAILY_TOKENS", 10_000)
    quota.record_ai_tokens(9_100)  # into the last 10%
    r = Investigation().run(SCAM, person="web:a")
    assert r["checked_by"] == "rules" and r["limited"] == "daily" and r["verdict"]  # still a verdict, no dead end
    assert quota.ai_allowed("web:a", already_paid=True) == (True, "")  # the reserve is theirs
    quota.record_ai_tokens(1_000)
    assert quota.ai_allowed("web:a", already_paid=True) == (False, "daily")


def test_one_person_cant_use_everyones_ai(fake_groq, monkeypatch):
    calls, _, _ = fake_groq
    monkeypatch.setattr(config, "AI_CHECKS_PER_PERSON_PER_DAY", 2)
    for _ in range(3):
        r = Investigation().run(SCAM, person="web:greedy")
    assert len(calls) == 2 and r["limited"] == "person" and r["checked_by"] == "rules"
    assert Investigation().run(SCAM, person="web:other")["checked_by"] == "ai"
    assert quota.ai_allowed("web:greedy", already_paid=True)[0]  # a victim is never cut off from the AI by this


def test_groq_saying_no_for_a_while_pauses_the_ai(fake_groq):
    calls, responses, R = fake_groq
    responses.append(R(429, {"retry-after": "3600"}))
    first = Investigation().run(SCAM, person="web:a")
    second = Investigation().run(SCAM, person="web:b")
    assert first["checked_by"] == "rules" and second["limited"] == "busy"
    assert len(calls) == 1  # the second check didn't wait to be refused
    assert "Quick check: the free AI is busy" in format_for_whatsapp(second)


def test_a_short_429_is_waited_out_once(fake_groq, monkeypatch):
    calls, responses, R = fake_groq
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    responses.append(R(429, {"retry-after": "2"}))
    assert Investigation().run(SCAM, person="web:a")["checked_by"] == "ai" and len(calls) == 2


@pytest.mark.parametrize("raw, expected", [("", 25), ("abc", 25), ("  7 ", 7), ("-3", 0)])
def test_limit_settings_fail_safe(monkeypatch, raw, expected):
    monkeypatch.setenv("X_LIMIT", raw)
    assert config._int("X_LIMIT", 25) == expected


def _client():
    from fastapi.testclient import TestClient
    return TestClient(server.app)


def test_web_flood_gets_a_kind_429_and_other_networks_dont_notice(monkeypatch):
    monkeypatch.setattr(config, "WEB_CHECKS_PER_NETWORK_PER_10_MIN", 2)
    monkeypatch.setattr(server, "_investigate", lambda *a, **k: {"verdict": None, "user_message": "ok", "evidence": []})
    c = _client()
    codes = [c.post("/api/investigate", data={"text": "hello there"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    r = c.post("/api/investigate", data={"text": "hello there"})
    assert "1930" in r.json()["detail"] and "wait a few minutes" in r.json()["detail"]
    assert quota.web_check_allowed("10.9.9.9")


def test_on_render_the_address_comes_from_cloudflare_not_a_typed_header(monkeypatch):
    monkeypatch.setattr(config, "IS_PRODUCTION", True)

    class Req:
        class client:
            host = "10.0.0.7"  # Render's proxy
        headers = {"x-forwarded-for": "1.1.1.1, 49.36.10.20, 172.70.1.1",  # typed, real, a shared proxy
                   "cf-connecting-ip": "49.36.10.20"}  # Cloudflare overwrites this one
    assert server.client_network(Req) == "49.36.10.20"
    Req.headers = {"x-forwarded-for": "1.1.1.1"}  # no Cloudflare header: never trust a typed one
    assert server.client_network(Req) == "10.0.0.7"


@pytest.fixture
def wa(monkeypatch):
    """WhatsApp 'configured', with posts recorded instead of sent."""
    posts = []
    monkeypatch.setattr(config, "WHATSAPP_ACCESS_TOKEN", "EAAtest")
    monkeypatch.setattr(config, "WHATSAPP_PHONE_NUMBER_ID", "123")
    monkeypatch.setattr(whatsapp, "_post", lambda payload: posts.append(payload["text"]["body"]) or True)
    return posts


def test_monthly_whatsapp_allowance_keeps_a_reserve_for_safety_messages(wa, monkeypatch):
    monkeypatch.setattr(config, "WHATSAPP_MONTHLY_MESSAGES", quota.WHATSAPP_RESERVE + 2)
    for i in range(3):
        whatsapp.send("+919000000001", f"reply {i}")
    assert wa == ["reply 0", "reply 1"]  # the third ordinary reply would eat into the reserve
    whatsapp.send("+919000000001", "OTP warning", urgent=True)
    assert wa[-1] == "OTP warning"


def test_out_of_free_replies_says_so_once_with_where_to_go(wa, monkeypatch):
    monkeypatch.setattr(config, "WHATSAPP_MONTHLY_MESSAGES", quota.WHATSAPP_RESERVE)  # nothing left for replies
    monkeypatch.setattr(config, "PUBLIC_URL", "https://scamcheck.onrender.com")
    ran = []
    monkeypatch.setattr(server, "_investigate", lambda *a, **k: ran.append(1))
    for _ in range(3):
        server._whatsapp_job("+919000000001", [SCAM], [])
    assert not ran and len(wa) == 1
    assert "https://scamcheck.onrender.com" in wa[0] and "1930" in wa[0]


def test_daily_checks_per_number_then_one_notice(wa, monkeypatch):
    monkeypatch.setattr(config, "WHATSAPP_CHECKS_PER_NUMBER_PER_DAY", 1)
    monkeypatch.setattr(server, "_investigate", lambda *a, **k: {"verdict": None, "user_message": "checked", "evidence": []})
    for _ in range(3):
        server._whatsapp_job("+919000000002", [SCAM], [])
    assert wa[0] == "checked" and "today's limit" in wa[1] and len(wa) == 2
    server._whatsapp_job("+919000000003", [SCAM], [])  # someone else isn't affected
    assert wa[-1] == "checked"


def test_health_shows_whats_left():
    h = _client().get("/api/health").json()
    assert h["ai_tokens_left_today"] == config.AI_DAILY_TOKENS and h["whatsapp_replies_left_this_month"] > 0
