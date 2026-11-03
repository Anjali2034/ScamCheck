"""Short links (bit.ly/…): find where they really go, and judge that."""
import pytest

from scamcheck import agent, config
from scamcheck.agent import Investigation, format_for_whatsapp
from scamcheck.tools import domain, sandbox

FAKE_SBI = "https://sbi-kyc-update.xyz/login"


@pytest.fixture
def web(monkeypatch):
    """The link checks without the network: `redirects` maps a short link to where it goes."""
    redirects = {}
    monkeypatch.setattr(config, "GROQ_API_KEY", "")
    monkeypatch.setattr(agent, "_check_domain", lambda url: {
        **domain.check_brand_impersonation(url),
        "registration": {"status": "ok", "age_days": 4 if "xyz" in url else 4000}})
    monkeypatch.setattr(agent.reputation, "check_url_reputation", lambda url: {"safe_browsing": {"status": "skipped"}})
    monkeypatch.setattr(sandbox, "follow_redirects", lambda url: {
        "status": "ok", "final_url": redirects.get(url, url), "hops": [url] + ([redirects[url]] if url in redirects else [])})
    monkeypatch.setattr(sandbox, "visit_url", lambda url: {
        "status": "ok", "final_url": redirects.get(url, url), "title": "Login", "asks_password": "xyz" in redirects.get(url, url)})
    return redirects


def test_a_short_link_is_judged_by_where_it_really_goes(web):
    web["https://bit.ly/sbi-upd8"] = FAKE_SBI
    r = Investigation().run("Update KYC now: https://bit.ly/sbi-upd8")
    found = " ".join(e["finding"] for e in r["evidence"])
    assert r["verdict"] == "SCAM"
    assert "sbi-kyc-update.xyz is not an official State Bank of India website" in found and "4 days ago" in found
    assert "shortener hides" not in found  # we know where it goes now
    assert r["link_destinations"] == [{"link": "https://bit.ly/sbi-upd8", "goes_to": "sbi-kyc-update.xyz", "official": False}]


def test_the_shortener_itself_is_never_remembered_as_a_scam(web):
    web["https://bit.ly/sbi-upd8"] = FAKE_SBI
    kinds = {(i["kind"], i["value"]) for i in Investigation().run("https://bit.ly/sbi-upd8")["indicators"]}
    assert ("domain", "sbi-kyc-update.xyz") in kinds and ("short_link", "bit.ly/sbi-upd8") in kinds
    assert ("domain", "bit.ly") not in kinds  # or every bit.ly link would look "flagged before"


def test_whatsapp_reply_says_where_it_goes_without_a_tappable_link(web):
    web["https://bit.ly/sbi-upd8"] = FAKE_SBI
    text = format_for_whatsapp(Investigation().run("Update KYC now: https://bit.ly/sbi-upd8"))
    assert "really goes to *sbi-kyc-update[.]xyz*" in text and "sbi-kyc-update.xyz" not in text


def test_a_short_link_to_an_official_site_isnt_held_against_it(web):
    web["https://bit.ly/sale26"] = "https://www.amazon.in/deals"
    r = Investigation().run("Diwali sale https://bit.ly/sale26")
    assert r["verdict"] == "LIKELY_SAFE" and r["link_destinations"][0]["official"]
    assert not [e for e in r["evidence"] if e["severity"] in ("critical", "high", "medium")]


def test_a_page_that_forwards_elsewhere_is_checked_too(web):
    web["https://cheap-offer.top/go"] = FAKE_SBI  # not a shortener: found by the sandbox visit
    r = Investigation().run("Offer: https://cheap-offer.top/go")
    assert r["link_destinations"][0]["goes_to"] == "sbi-kyc-update.xyz"
    assert "State Bank of India" in " ".join(e["finding"] for e in r["evidence"])


class _Resp:
    def __init__(self, status, location=None):
        self.status_code, self.headers = status, {"location": location} if location else {}

    def close(self):
        pass


@pytest.fixture
def hops(monkeypatch):
    chain, public = {}, {"bit.ly", "t.ly", "sbi-kyc-update.xyz"}
    monkeypatch.setattr(sandbox.socket, "getaddrinfo", lambda host, *a: [0] if host in public | {"10.0.0.5"} else (_ for _ in ()).throw(sandbox.socket.gaierror()))
    monkeypatch.setattr(sandbox, "_is_public_host", lambda host: host in public)
    monkeypatch.setattr(sandbox.requests, "get", lambda url, **k: _Resp(*chain.get(url, (200,))))
    return chain


def test_follow_redirects_through_several_hops(hops):
    hops["https://bit.ly/a"] = (301, "https://t.ly/b")
    hops["https://t.ly/b"] = (302, "/c")  # relative redirect
    hops["https://t.ly/c"] = (302, FAKE_SBI)
    r = sandbox.follow_redirects("https://bit.ly/a")
    assert r["status"] == "ok" and r["final_url"] == FAKE_SBI and len(r["hops"]) == 4


def test_follow_redirects_never_goes_inside_a_private_network(hops):
    hops["https://bit.ly/a"] = (302, "http://10.0.0.5/admin")
    r = sandbox.follow_redirects("https://bit.ly/a")
    assert r["status"] == "blocked"


def test_follow_redirects_dead_short_link_and_dead_destination(hops):
    assert sandbox.follow_redirects("https://gone.example/x")["status"] == "dead"
    hops["https://bit.ly/a"] = (302, "https://taken-down.xyz/")
    r = sandbox.follow_redirects("https://bit.ly/a")
    assert r["final_url"] == "https://taken-down.xyz/" and r["destination_down"]


def test_short_link_id():
    assert domain.short_link_id("https://bit.ly/AbC123/?utm=x") == "bit.ly/AbC123"
