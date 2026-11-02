"""Domain intelligence: registration age (RDAP), brand impersonation, URL red flags."""
import json
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import urlsplit

import requests
import tldextract

from scamcheck.config import DATA_DIR, HTTP_TIMEOUT

# Offline public-suffix snapshot bundled with tldextract; no network fetch at runtime.
_tld = tldextract.TLDExtract(suffix_list_urls=())
_BRANDS = json.loads((DATA_DIR / "brands.json").read_text(encoding="utf-8"))

SHORTENERS = frozenset(_BRANDS["shorteners"])

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


def registrable_domain(url_or_host: str) -> str:
    host = urlsplit(url_or_host).hostname if "://" in url_or_host else url_or_host
    ext = _tld(host or "")
    return ext.top_domain_under_public_suffix or (host or "")


def short_link_id(url: str) -> str:
    """'https://bit.ly/abc123?x=1' -> 'bit.ly/abc123': what "seen before" remembers for a short link. The shortener
    itself (bit.ly) is never remembered as a scam, or every bit.ly link would look flagged."""
    parts = urlsplit(url if "://" in url else "http://" + url)
    return (parts.hostname or "") + (parts.path or "").rstrip("/")


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_brand_impersonation(url: str) -> dict:
    parts = urlsplit(url if "://" in url else "http://" + url)
    host = (parts.hostname or "").lower()
    ext = _tld(host)
    reg = ext.top_domain_under_public_suffix or host
    label = ext.domain
    normalised = label.translate(HOMOGLYPHS).replace("-", "")
    full = host.translate(HOMOGLYPHS)
    path = (parts.path or "").lower()

    findings, impersonated = [], None
    for brand in _BRANDS["brands"]:
        official = brand["domains"]
        if reg in official or any(host == d or host.endswith("." + d) for d in official):
            return {"host": host, "registrable_domain": reg, "is_official_domain": True,
                    "brand": brand["name"], "findings": [f"Domain belongs to {brand['name']}."]}
        for kw in brand["keywords"]:
            k = kw.strip("-")
            if k and (k in full.replace("-", "") or k in path):
                where = "path" if k in path and k not in full.replace("-", "") else "domain"
                findings.append(f"Uses '{k}' ({brand['name']}) in the {where} but is not an official {brand['name']} domain.")
                impersonated = impersonated or brand["name"]
                break
        for d in official:
            off_label = _tld(d).domain
            if len(off_label) >= 4 and normalised != off_label:
                dist = _levenshtein(normalised, off_label)
                if dist <= max(1, len(off_label) // 5):
                    findings.append(f"Look-alike of {d} (edit distance {dist}): typosquatting.")
                    impersonated = impersonated or brand["name"]

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("Punycode (internationalised) domain; may use look-alike Unicode characters.")
    if reg in SHORTENERS:
        findings.append("URL shortener hides the real destination.")
    if ext.suffix.split(".")[-1] in _BRANDS["risky_tlds"]:
        findings.append(f".{ext.suffix} is a cheap TLD heavily used for phishing.")
    if host.replace(".", "").isdigit():
        findings.append("Link points to a raw IP address instead of a domain.")
    if host.count(".") >= 4:
        findings.append("Unusually deep subdomain chain, a common trick to hide the real domain.")
    if parts.scheme == "http":
        findings.append("No HTTPS.")
    if "@" in (parts.netloc or ""):
        findings.append("URL contains '@', which can disguise the real host.")
    if any(x in host for x in ("ngrok", "trycloudflare", "web.app", "firebaseapp", "netlify.app", "vercel.app", "github.io", "000webhost", "blogspot", "weebly", "wixsite")):
        findings.append("Hosted on a free/tunnelling platform; real banks never use these.")

    return {"host": host, "registrable_domain": reg, "is_official_domain": False,
            "possible_impersonated_brand": impersonated, "findings": findings}


@lru_cache(maxsize=256)
def domain_age(domain: str) -> dict:
    """Registration date via RDAP (the modern replacement for WHOIS). rdap.org redirects to the right registry."""
    domain = registrable_domain(domain)
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=HTTP_TIMEOUT,
                         headers={"Accept": "application/rdap+json"})
    except requests.RequestException as e:
        return {"domain": domain, "status": "error", "error": str(e)}
    if r.status_code == 404:
        return {"domain": domain, "status": "not_found",
                "note": "No RDAP record. Some ccTLDs (incl. some .in) do not publish RDAP; treat as unknown."}
    if not r.ok:
        return {"domain": domain, "status": "error", "http_status": r.status_code}

    data = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    created = events.get("registration")
    result = {"domain": domain, "status": "ok", "registered": created,
              "expires": events.get("expiration"), "last_changed": events.get("last changed")}
    registrar = next((e for e in data.get("entities", []) if "registrar" in e.get("roles", [])), None)
    if registrar:
        vcard = registrar.get("vcardArray", [None, []])[1]
        result["registrar"] = next((v[3] for v in vcard if v[0] == "fn"), None)
    if created:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - dt).days
        result["age_days"] = age
        if age < 30:
            result["assessment"] = "Registered less than a month ago: very strong phishing signal."
        elif age < 180:
            result["assessment"] = "Registered within the last 6 months: suspicious for anything claiming to be an established brand."
        else:
            result["assessment"] = "Established domain (age alone is not proof of safety)."
    return result
