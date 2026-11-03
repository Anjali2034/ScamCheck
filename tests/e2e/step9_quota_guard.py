"""End-to-end: the free-tier budgets, against local stand-ins for Groq and Meta with small limits so they're
reached quickly."""
import atexit
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

results = []
PORT, GROQ_PORT, GRAPH_PORT = 8801, 8802, 8803
BASE = f"http://127.0.0.1:{PORT}"
SCAM = "Dear Customer your SBI YONO account will be BLOCKED today due to incomplete KYC. Update PAN now"
TOKENS_PER_CALL = 1200


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


groq_calls, groq_script = [], []  # script: queued (status, headers); otherwise 200


class FakeGroq(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        groq_calls.append(time.monotonic())
        status, headers = groq_script.pop(0) if groq_script else (200, {})
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        answer = {"verdict": "SCAM", "confidence": "high", "scam_type": "Fake KYC", "user_message": "AI: don't reply.",
                  "already_paid": False, "wording_observations": [], "complaint": None}
        self.wfile.write(json.dumps({"choices": [{"message": {"content": json.dumps(answer)}}],
                                     "usage": {"total_tokens": TOKENS_PER_CALL}}).encode() if status == 200 else b"{}")

    def log_message(self, *a):
        pass


sent = []  # (to, body) of every WhatsApp message ScamCheck sent


class FakeGraph(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if body.get("type") == "text":
            sent.append((body["to"], body["text"]["body"]))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"messages": [{"id": "wamid.out"}]}')

    def log_message(self, *a):
        pass


for port, handler in ((GROQ_PORT, FakeGroq), (GRAPH_PORT, FakeGraph)):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

ENV = {**os.environ, "SCAMCHECK_ENV": "development", "GROQ_API_KEY": "gsk_test",
       "GROQ_API_URL": f"http://127.0.0.1:{GROQ_PORT}/v1/chat/completions",
       "SCAMCHECK_AI_DAILY_TOKENS": "5000", "SCAMCHECK_AI_CHECKS_PER_PERSON": "3", "SCAMCHECK_WEB_CHECKS_PER_10_MIN": "40",
       "SCAMCHECK_WHATSAPP_MONTHLY_MESSAGES": "55", "SCAMCHECK_WHATSAPP_CHECKS_PER_DAY": "3",
       "SCAMCHECK_PUBLIC_URL": "https://scamcheck.example", "WHATSAPP_ACCESS_TOKEN": "EAAtest",
       "WHATSAPP_PHONE_NUMBER_ID": "1065403522", "WHATSAPP_APP_SECRET": "", "WHATSAPP_VERIFY_TOKEN": "",
       "WHATSAPP_API_BASE": f"http://127.0.0.1:{GRAPH_PORT}"}


def start(**overrides):
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", str(PORT)],
                            env={**ENV, **overrides}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(lambda: proc.poll() is None and proc.kill())
    for _ in range(360):
        try:
            requests.get(BASE + "/api/health", timeout=1)
            return proc
        except requests.ConnectionError:
            time.sleep(0.5)
    raise SystemExit("server didn't start")


def stop(proc):
    proc.kill()
    proc.wait()


def web(text, sid):
    r = requests.post(BASE + "/api/investigate", data={"text": text, "session_id": sid}, timeout=180)
    if r.status_code != 200:
        return r.status_code, r.json()
    done = next(json.loads(l) for l in r.text.splitlines() if l.strip() and json.loads(l)["type"] == "done")
    return 200, done["result"]


def health():
    return requests.get(BASE + "/api/health").json()


# --- 1. The daily AI budget and fair shares ------------------------------------------------------------------
proc = start()
for i in range(3):
    _, r = web(SCAM, "alice")
check("First 3 checks from one person use the AI", r["checked_by"] == "ai" and len(groq_calls) == 3, str(r)[:200])
_, r = web(SCAM, "alice")
check("4th check that day: rules only ('your share'), every check still ran, Groq not called",
      r["checked_by"] == "rules" and r["limited"] == "person" and r["verdict"] and len(groq_calls) == 3, str(r)[:300])
_, r = web(SCAM, "bob")
check("Someone else still gets the AI", r["checked_by"] == "ai" and len(groq_calls) == 4)
check("Health shows the tokens left today", health()["ai_tokens_left_today"] == 5000 - 4 * TOKENS_PER_CALL, str(health()))
_, r = web(SCAM, "carol")
check("Last 10% of the day's AI: ordinary checks get rules ('used up')", r["limited"] == "daily" and len(groq_calls) == 4)
_, r = web("I already paid ₹500 to them via PhonePe", "carol")
check("...but someone who lost money still gets the AI (reserve)", r["already_paid"] and r["checked_by"] == "ai"
      and len(groq_calls) == 5 and r["complaint"], str(r)[:300])
_, r = web("I already paid ₹900 via GPay", "dave")
check("Budget fully used: even a victim gets rules, with 1930 first", r["checked_by"] == "rules" and "1930" in r["user_message"])

from playwright.sync_api import sync_playwright  # noqa: E402

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={"width": 360, "height": 740}, is_mobile=True)
    page.goto(BASE)
    page.fill("#text", SCAM)
    page.click("#go")
    page.wait_for_selector("#result .verdict h2", timeout=120000)
    note = page.inner_text("#limited") if page.locator("#limited").count() else ""
    check("Public page says honestly why it's a rules-only answer", "used up" in note and "Every check still ran" in note, note)
    b.close()
stop(proc)

# --- 2. Budgets survive a restart; Groq's "come back later" pauses the AI -------------------------------------
proc = start(SCAMCHECK_AI_DAILY_TOKENS="100000")
check("Restart: today's AI usage is remembered", health()["ai_tokens_left_today"] == 100000 - 5 * TOKENS_PER_CALL, str(health()))
groq_script.append((429, {"retry-after": "3600"}))
before = len(groq_calls)
_, r1 = web(SCAM, "erin")
t = time.monotonic()
_, r2 = web(SCAM, "frank")
check("Groq says 'try in an hour': that check falls back to rules", r1["checked_by"] == "rules")
check("...and the next one doesn't even ask (no wait, no wasted call)", r2["limited"] == "busy"
      and len(groq_calls) == before + 1 and time.monotonic() - t < 10, str(r2)[:200])
check("Health shows the AI is paused", health()["ai_paused"] is True)
stop(proc)

# --- 3. Floods from one network -------------------------------------------------------------------------------
proc = start(SCAMCHECK_WEB_CHECKS_PER_10_MIN="5", GROQ_API_KEY="")
codes = [web("hello, is this ok? 9876543210", f"bot{i}")[0] for i in range(6)]  # a bot rotating its session id
check("A flood from one network is stopped (new session ids don't help)", codes == [200] * 5 + [429], str(codes))
status, body = web("hello", "bot9")
check("...with a kind message: wait, safety basics, 1930", status == 429 and "1930" in body["detail"], str(body))
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={"width": 360, "height": 740}, is_mobile=True)
    page.goto(BASE)
    page.fill("#text", SCAM)
    page.click("#go")
    page.wait_for_selector("#result .msg", timeout=30000)
    msg = page.inner_text("#result")
    check("Public page shows that message, not a generic error", "Too many checks from your network" in msg, msg)
    b.close()
stop(proc)

# --- 4. WhatsApp: per-number daily limit and the monthly allowance --------------------------------------------
proc = start(GROQ_API_KEY="")


def whatsapp(mid, sender, body):
    msg = {"id": mid, "from": sender, "type": "text", "text": {"body": body}}
    requests.post(BASE + "/webhook/whatsapp", json={"entry": [{"changes": [{"field": "messages",
                                                    "value": {"messages": [msg]}}]}]})


def to(number):
    return [b for n, b in sent if n == number]


def wait_count(number, n, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end and len(to(number)) < n:
        time.sleep(0.3)
    time.sleep(1)  # and nothing more arrives straight after
    return to(number)


A, B, C = "917000000001", "917000000002", "917000000003"
for i in range(4):  # four separate bursts (each waits out the 8 s quiet window)
    whatsapp(f"a{i}", A, f"{SCAM} #{i}")
    got = wait_count(A, i + 1)
check("WhatsApp: 3 checks a day per number, then one 'today's limit' notice",
      len(got) == 4 and all("Scam" in m for m in got[:3]) and "today's limit" in got[3] and "scamcheck.example" in got[3],
      json.dumps(got)[:400])
whatsapp("a9", A, SCAM)
check("...and after that, silence (no message spent per extra check)", len(wait_count(A, 5, timeout=12)) == 4)
whatsapp("b0", B, SCAM)
got = wait_count(B, 1)
check("Another number is unaffected (5th free message of 5 this month)", len(got) == 1 and "Scam" in got[0])
whatsapp("c0", C, SCAM)
got = wait_count(C, 1)
check("Month's free replies used up: one notice pointing to the web page, with safety basics",
      len(got) == 1 and "used up this month's free WhatsApp replies" in got[0] and "scamcheck.example" in got[0]
      and "1930" in got[0], json.dumps(got))
whatsapp("c1", C, SCAM)
check("...sent once, not on every message", len(wait_count(C, 2, timeout=12)) == 1)
whatsapp("c2", C, "They asked for this code: OTP 482913")
got = wait_count(C, 2)
check("OTP warning still gets through, from the safety reserve", len(got) == 2 and "one-time code" in got[1]
      and "482913" not in got[1], json.dumps(got))
check("Health shows no ordinary replies left this month", health()["whatsapp_replies_left_this_month"] == 0)
stop(proc)

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
