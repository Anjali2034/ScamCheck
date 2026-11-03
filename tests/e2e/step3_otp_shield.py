"""End-to-end: OTPs are hidden before anything logs, stores or streams them, and the warning goes out first."""
import atexit
import os
import subprocess
import sys
import threading
import time

import requests

import meta_hook

CODE = "482913"
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


env = {**os.environ, "SCAMCHECK_ENV": "development", "GROQ_API_KEY": "",
       "DEMO_NUMBERS": "+919999999999", "PYTHONUNBUFFERED": "1"}
proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", "8781"], env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
atexit.register(lambda: proc.poll() is None and proc.kill())
server_log = []
threading.Thread(target=lambda: [server_log.append(l) for l in proc.stdout], daemon=True).start()
BASE = "http://127.0.0.1:8781"
for _ in range(360):
    try:
        requests.get(BASE + "/api/health", timeout=1)
        break
    except requests.ConnectionError:
        time.sleep(0.5)

# A live feed listener, to prove the code never reaches spectators either (demo number = full content).
feed = []
def listen():
    with requests.get(BASE + "/api/live", stream=True, timeout=60) as r:
        for line in r.iter_lines():
            feed.append(line.decode("utf-8"))
threading.Thread(target=listen, daemon=True).start()
time.sleep(1)

meta_hook.post(BASE, "o1", "919999999999", f"Your OTP for HDFC Bank NetBanking login is {CODE}. Do not share it. -HDFC Bank")
meta_hook.post(BASE, "o2", "917777777777", f"आपका ओटीपी {CODE} है")
meta_hook.post(BASE, "o3", "915555555555", "Pay ₹4999 now or KYC blocked")
time.sleep(3)  # well inside the 8 s burst window: only immediate warnings can have gone out
first = meta_hook.replies(server_log, "919999999999")
check("WhatsApp: OTP warning sent at once, before the verdict", len(first) == 1 and "You just sent me a one-time code" in first[0], str(first))
check("WhatsApp: the warning never echoes the code", CODE not in "".join(first))
hindi = meta_hook.replies(server_log, "917777777777")
check("WhatsApp: Hindi message gets the Hindi warning", hindi and "कभी किसी को न भेजें" in hindi[0], str(hindi))
check("WhatsApp: no code -> no warning (no false alarm)", meta_hook.replies(server_log, "915555555555") == [])

r = requests.post(BASE + "/api/investigate", data={"text": f"OTP is {CODE}, the agent on call is asking for it", "session_id": "t"})
lines = [l for l in r.text.splitlines() if l.strip()]
check("Web: the warning is the very first event", '"type": "notice"' in lines[0], lines[0][:200])
check("Web: code appears nowhere in the stream", CODE not in r.text)

time.sleep(12)  # the burst window (8 s) passes, then jobs fail (no API key) and log
check("Live feed: demo number's message shown masked", any("[OTP hidden]" in l for l in feed), str(feed)[:300])
check("Live feed: code never streamed", not any(CODE in l for l in feed))
check("Server log: code never logged", not any(CODE in l for l in server_log), "".join(server_log)[-500:])
check("WhatsApp: the verdict follows the warning (2 messages in all)", len(meta_hook.replies(server_log, "919999999999")) == 2)
later = meta_hook.replies(server_log, "915555555555")
check("WhatsApp: no-code message gets just its verdict", len(later) == 1 and "one-time code" not in later[0], str(later))

from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(BASE + "/demo")
    page.get_by_role("button", name="Real OTP forwarded").click()
    page.click("#go")
    page.wait_for_selector("#trace .ev.notice", timeout=60000)
    page.wait_for_selector("#go:not([disabled])", timeout=60000)
    first = page.locator("#trace .ev").first.inner_text()
    check("Browser: warning card is first in the trace", "one-time code" in first and "*" not in first, first)
    check("Browser: code not visible anywhere in the trace", CODE not in page.inner_text("#trace"))
    check("Browser: no JavaScript errors", not errors, str(errors))
    b.close()

proc.kill()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
