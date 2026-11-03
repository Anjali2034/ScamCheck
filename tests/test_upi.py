"""UPI tricks: accepting a request or entering a PIN sends money out, and nobody official collects by UPI ID."""
import pytest

from scamcheck import llm
from scamcheck.agent import Investigation


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(llm.config, "GROQ_API_KEY", "")


@pytest.mark.parametrize("text", [
    "Is refund.claim@ybl safe? They said they will return my money if I accept the request",
    "Customer care said accept the request from refund.claim@ybl to get your refund",
    "उन्होंने कहा refund.claim@ybl की रिक्वेस्ट स्वीकार करो तो पैसे वापस मिल जाएंगे",
    "Unhone bola refund.claim@ybl ki request accept karo to paise wapas mil jayenge",
])
def test_accept_a_request_to_get_money_back_is_a_scam(text):
    assert Investigation().run(text)["verdict"] in ("SCAM", "LIKELY_SCAM")


@pytest.mark.parametrize("text", [
    "Your SBI KYC expired. Pay Rs 10 to refund.help@ybl now or your account will be blocked today.",
    "आपकी बिजली आज रात काट दी जाएगी। पिछले महीने का बिल अपडेट नहीं हुआ, तुरंत bill.update@ybl पर ₹10 भेजें।",
    "Your parcel is on hold due to incomplete address. Pay redelivery fee Rs 25 to indiapost.help@ybl",
])
def test_official_bodies_never_collect_through_a_upi_id(text):
    r = Investigation().run(text)
    assert r["verdict"] in ("SCAM", "LIKELY_SCAM")
    assert any("UPI ID" in e["finding"] for e in r["evidence"])


@pytest.mark.parametrize("text", [
    "Pay ₹450 to rahul.k@okaxis for dinner, thanks!",
    "Please accept the request for the dinner split, 450 each.",
    "Rent for November: send to landlord.sharma@oksbi by the 5th.",
])
def test_ordinary_upi_payments_arent_flagged(text):
    assert Investigation().run(text)["verdict"] in ("INCONCLUSIVE", "LIKELY_SAFE", "SAFE")


def test_the_ai_is_told_what_kind_of_thing_each_identifier_is():
    inv = Investigation()
    inv.run("Is refund.claim@ybl safe? Call 9876543210")
    prompt = inv._prompt("x", [], "INCONCLUSIVE", False)
    assert "UPI ID: refund.claim@ybl" in prompt and "Phone number: +919876543210" in prompt
