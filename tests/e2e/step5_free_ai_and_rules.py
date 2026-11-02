"""End-to-end checks for step #5 (Groq + one AI call + rules). Run with tests/e2e/run_all.py."""
import atexit
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


# 1. The Anthropic SDK is gone from the import graph.
p = subprocess.run([sys.executable, "-c", "import sys; sys.modules['anthropic'] = None; import scamcheck.server, scamcheck.__main__"],
                   capture_output=True, text=True)
check("Nothing imports the Anthropic SDK any more", p.returncode == 0, p.stderr[-300:])

# 2. The Groq client against a local stand-in for api.groq.com.
script, seen = [], []


class FakeGroq(BaseHTTPRequestHandler):
    def do_POST(self):
        seen.append((json.loads(self.rfile.read(int(self.headers["Content-Length"]))), self.headers.get("Authorization")))
        status, headers, body = script.pop(0)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 8799), FakeGroq)
threading.Thread(target=srv.serve_forever, daemon=True).start()
from scamcheck import config, llm  # noqa: E402

llm.API_URL = "http://127.0.0.1:8799/v1/chat/completions"
config.GROQ_API_KEY = "gsk_test"
ok_body = json.dumps({"choices": [{"message": {"content": json.dumps({"verdict": "SCAM"})}}]})

script[:] = [(200, {}, ok_body)]
out = llm.complete_json("sys", "user")
body, auth = seen[-1]
check("Groq request: right model, JSON mode, low reasoning, bearer key",
      body["model"] == "openai/gpt-oss-120b" and body["response_format"] == {"type": "json_object"}
      and body["reasoning_effort"] == "low" and auth == "Bearer gsk_test" and out == {"verdict": "SCAM"}, str(body)[:300])

script[:] = [(429, {"retry-after": "1"}, "{}"), (200, {}, ok_body)]
t = time.monotonic()
out = llm.complete_json("sys", "user")
check("Per-minute limit (retry-after 1 s): waits once, then succeeds", out == {"verdict": "SCAM"} and time.monotonic() - t >= 1)

script[:] = [(429, {"retry-after": "3600"}, "{}")]
t = time.monotonic()
try:
    llm.complete_json("sys", "user")
    check("Daily limit reached: falls back at once", False)
except llm.AIUnavailable as e:
    check("Daily limit reached: falls back at once, no long wait", "quota" in str(e) and time.monotonic() - t < 3, str(e))

for status, body, label in [(500, "{}", "Groq server error"),
                            (200, json.dumps({"choices": [{"message": {"content": "not json"}}]}), "Garbage answer")]:
    script[:] = [(status, {}, body)]
    try:
        llm.complete_json("sys", "user")
        check(f"{label}: falls back to rules", False)
    except llm.AIUnavailable:
        check(f"{label}: falls back to rules", True)
srv.shutdown()

# 3. The real pipeline: real RDAP, real sandbox browser, real server, no AI key.
env = {**os.environ, "SCAMCHECK_ENV": "development", "GROQ_API_KEY": ""}
proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", "8792"], env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
atexit.register(lambda: proc.poll() is None and proc.kill())
BASE = "http://127.0.0.1:8792"
for _ in range(360):
    try:
        requests.get(BASE + "/api/health", timeout=1)
        break
    except requests.ConnectionError:
        time.sleep(0.5)


def investigate(text, sid):
    t = time.monotonic()
    r = requests.post(BASE + "/api/investigate", data={"text": text, "session_id": sid}, timeout=180)
    events = [json.loads(l) for l in r.text.splitlines() if l.strip()]
    done = next(e for e in events if e["type"] == "done")
    return done["result"], events, time.monotonic() - t


res, ev, secs = investigate("Is this real? https://www.onlinesbi.sbi/", "real1")
check("Real official SBI link -> LIKELY_SAFE", res and res["verdict"] == "LIKELY_SAFE", json.dumps(res)[:400])
check("...and no sandbox visit was wasted on it", not any(e["type"] == "tool_call" and e["name"] == "visit_in_sandbox" for e in ev))
print(f"      ({secs:.1f}s)")

fake = "Dear Customer your SBI YONO account will be BLOCKED today due to incomplete KYC. Update PAN: http://sbi-kyc-update.xyz/login"
res, ev, secs = investigate(fake, "real2")
names = {e["name"] for e in ev if e["type"] == "tool_call"}
check("Fake KYC message -> scam verdict from rules alone", res and res["verdict"] in ("SCAM", "LIKELY_SCAM")
      and res["checked_by"] == "rules", json.dumps(res)[:400])
check("...every check ran (domain, reputation, sandbox, scripts)",
      {"extract_indicators", "check_domain", "check_url_reputation", "visit_in_sandbox", "match_scam_scripts"} <= names, str(names))
check("...the trace says honestly that the AI was unavailable", any("AI unavailable" in e.get("message", "") for e in ev))
check("...a scam reply is readable, with action first", res["user_message"].startswith("This is"), res["user_message"])
print(f"      ({secs:.1f}s; evidence: {[e['finding'][:60] for e in res['evidence']]})")

res, ev, _ = investigate("I already paid ₹4,999 via PhonePe to them", "real2")
check("Follow-up 'I already paid' -> 1930 + complaint draft", res["already_paid"] and res["complaint"]
      and "4,999" in res["complaint"]["complaint_text"] and "1930" in res["user_message"], json.dumps(res)[:400])
done = next(e for e in ev if e["type"] == "done")
check("WhatsApp text for it has the 1930 call to action", "Call 1930 now" in done["whatsapp_text"])

res, _, _ = investigate("hi", "real3")
check("'hi' gets the help text, not a verdict", res["verdict"] is None and "Forward me" in res["user_message"])

from playwright.sync_api import sync_playwright  # noqa: E402
with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(BASE + "/demo")
    page.get_by_role("button", name="Fake KYC").click()
    page.click("#go")
    page.wait_for_selector("#result .verdict h2", timeout=120000)
    check("Browser: verdict card renders from the new pipeline", "SCAM" in page.inner_text("#result .verdict h2"))
    check("Browser: no JavaScript errors", not errors, str(errors))
    b.close()

proc.kill()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
