"""On the web, a conversation is one page visit; the fair share of AI checks belongs to the visitor."""
import json

from fastapi.testclient import TestClient

from scamcheck import agent, llm, server

LOTTERY = "Congratulations! You have won Rs 25 lakh in the KBC lottery. Pay the processing fee of Rs 4999 to claim it."
PHOTOS = "Hi! Here are the photos from Sunday: https://example.org/photos"


def _check(c, text, **ids) -> dict:
    r = c.post("/api/investigate", data={"text": text, **ids})
    return json.loads(r.text.strip().splitlines()[-1])["result"]


def _offline(monkeypatch):
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "")
    monkeypatch.setattr(agent, "_investigate_url", lambda url, emit, me="": {
        "url": url, "domain": {}, "reputation": None, "sandbox": None})


def test_callers_without_an_id_never_share_a_conversation(monkeypatch):
    _offline(monkeypatch)
    c = TestClient(server.app)
    assert _check(c, LOTTERY)["verdict"] in ("SCAM", "LIKELY_SCAM")
    assert _check(c, PHOTOS)["verdict"] == "INCONCLUSIVE"  # not dragged into the lottery conversation


def test_a_follow_up_in_the_same_conversation_still_counts(monkeypatch):
    _offline(monkeypatch)
    c = TestClient(server.app)
    _check(c, LOTTERY, session_id="visit1", visitor_id="me")
    r = _check(c, "I already paid ₹4999 by UPI yesterday", session_id="visit1", visitor_id="me")
    assert r["already_paid"] and r["complaint"]


def test_the_fair_share_of_ai_follows_the_visitor_not_the_visit(monkeypatch):
    _offline(monkeypatch)
    seen = []
    real = server._investigate
    monkeypatch.setattr(server, "_investigate", lambda *a, **k: seen.append(a[7]) or real(*a, **k))
    c = TestClient(server.app)
    _check(c, PHOTOS, session_id="visit1", visitor_id="me")
    _check(c, PHOTOS, session_id="visit2", visitor_id="me")
    assert seen == ["web:me", "web:me"]
