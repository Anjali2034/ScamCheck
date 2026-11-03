"""End-to-end: the live feed shows strangers' checks only as tool names and a verdict, never their content."""
import asyncio
import os
import subprocess
import sys
import threading
import time

import requests

import meta_hook

os.environ["DEMO_NUMBERS"] = " 919999999999 , +918888888888"
from scamcheck import config, server  # noqa: E402

SECRET = "OTP 482913 for A/c XX4521, Ramesh"
EVENTS = [
    {"type": "status", "message": "Thinking…"},
    {"type": "thinking", "text": SECRET},
    {"type": "tool_call", "name": "extract_indicators", "input": {"text": SECRET}},
    {"type": "tool_result", "name": "extract_indicators", "result": {"echo": SECRET}},
    {"type": "screenshot", "url": "http://x.xyz/?u=" + SECRET, "data": "..."},
    {"type": "text", "text": SECRET},
    {"type": "verdict", "verdict": {"verdict": "SCAM", "scam_type": "Fake KYC", "user_message": SECRET, "evidence": []}},
]
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))


class FakeInvestigation:
    fail = False

    def run(self, text, images, emit, person="", reporter=""):
        if self.fail:
            raise RuntimeError("boom: " + SECRET)
        for e in EVENTS:
            emit(e)
        return {"verdict": "SCAM", "confidence": "high", "scam_type": "Fake KYC", "user_message": "Scam.",
                "evidence": [], "already_paid": False, "complaint": None}


async def pipeline_checks():
    check("DEMO_NUMBERS parses with/without + and spaces",
          config.DEMO_NUMBERS == {"+919999999999", "+918888888888"}, str(config.DEMO_NUMBERS))

    fake = FakeInvestigation()
    server.sessions.get = lambda key: (fake, threading.Lock())
    loop, q = server.feed.subscribe()

    async def run_job(sender):
        await asyncio.to_thread(server._whatsapp_job, sender, [SECRET], [])
        await asyncio.sleep(0.2)
        out = []
        while not q.empty():
            out.append(q.get_nowait())
        return out

    stranger = await run_job("+917777777777")
    check("Stranger: no secret anywhere in the feed", "482913" not in str(stranger) and "Ramesh" not in str(stranger))
    check("Stranger: start event marked private", any(e["type"] == "start" and e.get("private") for e in stranger))
    check("Stranger: tool names still shown", any(e["type"] == "tool_call" and e["name"] == "extract_indicators" for e in stranger))
    check("Stranger: verdict label shown", any(e["type"] == "verdict" and e["verdict"]["verdict"] == "SCAM" for e in stranger))
    check("Stranger: no thinking/text/screenshot/status events",
          not any(e["type"] in ("thinking", "text", "screenshot", "status") for e in stranger))
    check("Stranger: number masked in session label", all(e["session"] == "+91•••••777" for e in stranger),
          str({e["session"] for e in stranger}))

    demo = await run_job("+919999999999")
    check("Demo number: full content streams", SECRET in str(demo) and any(e["type"] == "screenshot" for e in demo))

    fake.fail = True
    failed = await run_job("+917777777777")
    check("Job failure: error shown generically, secret hidden",
          any(e["type"] == "error" for e in failed) and "482913" not in str(failed), str(failed))
    server.feed.unsubscribe((loop, q))


def live_server_checks():
    env = {**os.environ, "DEMO_NUMBERS": "", "GROQ_API_KEY": ""}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", "8765"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:8765"
    try:
        for _ in range(60):
            try:
                requests.get(base + "/api/health", timeout=1)
                break
            except requests.ConnectionError:
                time.sleep(0.5)
        check("Server boots; /api/health responds", requests.get(base + "/api/health").ok)
        check("GET / serves the page", "ScamCheck" in requests.get(base + "/").text)

        check("Webhook: Meta-format message accepted", meta_hook.post(base, "p1", "917777777777", "reset").ok)

        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(base + "/demo")
            page.click("#tab-live")
            page.wait_for_timeout(800)
            # A real stranger's message through the real webhook.
            check("Webhook: real message accepted", meta_hook.post(base, "p2", "917777777777", SECRET).ok)
            # No AI key is needed: the rules give a verdict once the 8 s burst window has passed.
            page.wait_for_selector("#live .ev.verdict", timeout=60000)
            live_text = page.inner_text("#live")
            check("Browser live feed shows the stranger's check, never the secret",
                  "Message hidden" in live_text and "482913" not in live_text and "Ramesh" not in live_text, live_text)

            # Render the redacted event shapes through the page's own JS.
            page.evaluate("""() => {
                const into = document.querySelector('#live');
                renderEvent({type:'start', has_image:true, private:true, session:'+91•••••777'}, into);
                renderEvent({type:'tool_call', name:'check_domain', private:true, session:'+91•••••777'}, into);
                renderEvent({type:'tool_result', name:'check_domain', private:true, session:'+91•••••777'}, into);
                renderEvent({type:'verdict', verdict:{verdict:'SCAM', scam_type:'Fake KYC'}, session:'+91•••••777'}, into);
            }""")
            live_text = page.inner_text("#live")
            check("Browser renders private start as 'Message hidden'", "Message hidden" in live_text, live_text)
            check("Browser renders private tool call with its friendly label",
                  "checking domain age and brand impersonation" in live_text.lower())  # .t is CSS-uppercased
            check("Browser renders verdict in live feed", "SCAM" in live_text and "Fake KYC" in live_text)
            check("No JavaScript errors on the page", not errors, str(errors))
            browser.close()
    finally:
        proc.terminate()


asyncio.run(pipeline_checks())
live_server_checks()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
