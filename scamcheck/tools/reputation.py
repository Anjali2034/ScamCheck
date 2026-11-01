"""Third-party URL reputation: Google Safe Browsing and VirusTotal."""
import base64

import requests

from scamcheck.config import HTTP_TIMEOUT, SAFE_BROWSING_KEY, VIRUSTOTAL_KEY
from scamcheck.tools.domain import registrable_domain


def safe_browsing(url: str) -> dict:
    if not SAFE_BROWSING_KEY:
        return {"source": "Google Safe Browsing", "status": "skipped", "reason": "GOOGLE_SAFE_BROWSING_KEY not set"}
    body = {
        "client": {"clientId": "scamcheck", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                          params={"key": SAFE_BROWSING_KEY}, json=body, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        return {"source": "Google Safe Browsing", "status": "error", "error": str(e)}
    matches = r.json().get("matches", [])
    return {
        "source": "Google Safe Browsing",
        "status": "ok",
        "flagged": bool(matches),
        "threat_types": sorted({m["threatType"] for m in matches}),
        "note": "Not being listed does NOT mean safe; new phishing sites take hours or days to be listed.",
    }


def _vt_stats(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    engines = attrs.get("last_analysis_results", {})
    flagged_by = [n for n, v in engines.items() if v.get("category") in ("malicious", "suspicious")][:10]
    return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
            "flagged_by": flagged_by}


def virustotal(url: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"source": "VirusTotal", "status": "skipped", "reason": "VIRUSTOTAL_API_KEY not set"}
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    out = {"source": "VirusTotal", "status": "ok"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            # Never scanned: submit it so the next lookup has data, and fall back to the domain report.
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=HTTP_TIMEOUT)
            out["url_report"] = "URL not previously seen by VirusTotal (submitted for scanning). Brand-new URLs are a mild risk signal."
        elif r.ok:
            out["url_report"] = _vt_stats(r.json()["data"]["attributes"])
        else:
            out["url_report"] = f"HTTP {r.status_code}"

        dom = registrable_domain(url)
        d = requests.get(f"https://www.virustotal.com/api/v3/domains/{dom}", headers=headers, timeout=HTTP_TIMEOUT)
        if d.ok:
            attrs = d.json()["data"]["attributes"]
            out["domain_report"] = {"domain": dom, **_vt_stats(attrs),
                                    "categories": sorted(set(attrs.get("categories", {}).values()))[:5]}
        if r.status_code == 429 or d.status_code == 429:
            out["status"] = "rate_limited"
    except requests.RequestException as e:
        return {"source": "VirusTotal", "status": "error", "error": str(e)}
    return out


def check_url_reputation(url: str) -> dict:
    return {"url": url, "safe_browsing": safe_browsing(url), "virustotal": virustotal(url)}
