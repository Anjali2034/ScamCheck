"""Open a suspicious link in a throwaway headless Chromium and record what it does.

Isolation here: fresh browser context (no cookies/storage), downloads refused, permission
prompts denied, requests to private/loopback addresses blocked (SSRF), hard timeouts.
For production, also run this inside a disposable container or VM.
"""
import ipaddress
import re
import socket
import time
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from scamcheck.config import SCREENSHOT_DIR

NAV_TIMEOUT_MS = 20000
USER_AGENT = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36")


def _is_public_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def visit_url(url: str) -> dict:
    host = urlsplit(url).hostname or ""
    if not host:
        return {"status": "error", "error": "Not a valid URL"}
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        return {"status": "dead", "error": f"{host} does not resolve. The site is down or already taken down "
                                            "(common for phishing links after a few days)."}
    if not _is_public_host(host):
        return {"status": "blocked", "error": f"{host} points to a private/internal address; refusing to visit."}

    redirects, blocked = [], []
    shot_path = SCREENSHOT_DIR / f"{int(time.time() * 1000)}_{re.sub(r'[^a-z0-9]+', '_', host.lower())[:40]}.jpg"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-extensions", "--no-first-run"])
        try:
            ctx = browser.new_context(
                user_agent=USER_AGENT, viewport={"width": 412, "height": 915}, is_mobile=True,
                accept_downloads=False, java_script_enabled=True, permissions=[], locale="en-IN",
            )

            def guard(route):
                h = urlsplit(route.request.url).hostname or ""
                if route.request.url.startswith(("data:", "blob:")) or _is_public_host(h):
                    route.continue_()
                else:
                    blocked.append(route.request.url)
                    route.abort()

            ctx.route("**/*", guard)
            page = ctx.new_page()
            page.on("dialog", lambda d: d.dismiss())
            page.on("framenavigated", lambda f: f == page.main_frame and redirects.append(f.url))

            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                page.wait_for_timeout(2500)  # let JS-rendered phishing kits draw
            except PlaywrightError as e:
                return {"status": "error", "error": str(e).splitlines()[0], "redirect_chain": redirects}

            info = page.evaluate("""() => {
                const inputs = [...document.querySelectorAll('input')].map(i =>
                    ((i.type||'') + ' ' + (i.name||'') + ' ' + (i.placeholder||'') + ' ' + (i.id||'')).toLowerCase());
                const has = re => inputs.some(s => re.test(s));
                return {
                  title: document.title,
                  text: (document.body ? document.body.innerText : '').replace(/\\s+/g,' ').slice(0, 2500),
                  forms: document.forms.length,
                  asks_password: has(/password|mpin|\\bpin\\b|passcode/),
                  asks_otp: has(/otp|one.?time|verification code/),
                  asks_card: has(/card|cvv|expiry|\\bexp\\b/),
                  asks_aadhaar_pan: has(/aadha|pan\\b|pan.?no|pan.?card/),
                  asks_bank_login: has(/user.?id|username|customer.?id|netbanking|account.?n/),
                  external_form_actions: [...document.forms].map(f => f.action).filter(Boolean).slice(0,5),
                  apk_links: [...document.querySelectorAll('a[href]')].map(a => a.href).filter(h => /\\.apk(\\?|$)/i.test(h)).slice(0,5),
                  upi_deeplinks: [...document.querySelectorAll('a[href]')].map(a => a.href).filter(h => /^upi:/i.test(h)).slice(0,5),
                };
            }""")
            page.screenshot(path=str(shot_path), type="jpeg", quality=60, full_page=False)
            return {
                "status": "ok",
                "requested_url": url,
                "final_url": page.url,
                "http_status": resp.status if resp else None,
                "redirect_chain": list(dict.fromkeys(redirects)),
                "blocked_internal_requests": blocked[:5],
                **info,
                "screenshot_path": str(shot_path),
            }
        finally:
            browser.close()
