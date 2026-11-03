"""End-to-end: webhook retries are ignored and a burst of messages gets one reply, with real timing."""
import atexit
import json
import os
import subprocess
import sys
import threading
import time

import requests

import meta_hook

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


env = {**os.environ, "SCAMCHECK_ENV": "development", "GROQ_API_KEY": "",
       "DEMO_NUMBERS": "+919999999999", "PYTHONUNBUFFERED": "1"}
proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", "8791"], env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
atexit.register(lambda: proc.poll() is None and proc.kill())
log = []
threading.Thread(target=lambda: [log.append(l) for l in proc.stdout], daemon=True).start()
BASE = "http://127.0.0.1:8791"
for _ in range(360):
    try:
        requests.get(BASE + "/api/health", timeout=1)
        break
    except requests.ConnectionError:
        time.sleep(0.5)

feed = []
def listen():
    with requests.get(BASE + "/api/live", stream=True, timeout=120) as r:
        for line in r.iter_lines():
            feed.append((time.monotonic(), json.loads(line.decode("utf-8"))))
threading.Thread(target=listen, daemon=True).start()
time.sleep(1)

DEMO = "919999999999"
def send(sid, body, sender=DEMO):
    return meta_hook.post(BASE, sid, sender, body)

check("First message accepted", send("wa1", "Dear customer your SBI account is blocked, update KYC http://sbi-kyc.xyz").ok)
send("wa1", "Dear customer your SBI account is blocked, update KYC http://sbi-kyc.xyz")  # Meta retry
time.sleep(3)
check("No acknowledgement message spent ('typing…' instead), retry ignored", meta_hook.replies(log, DEMO) == [])
send("wa2", "is this real??")
last_sent = time.monotonic()
time.sleep(1)
check("Follow-up 3 s later is silent (same burst)", meta_hook.replies(log, DEMO) == [])

time.sleep(13)
starts = [(t, e) for t, e in feed if e.get("type") == "start" and e.get("session") == "+91•••••999"]
check("Exactly one investigation started for the burst", len(starts) == 1, str(starts))
if starts:
    t, e = starts[0]
    check("It contains both messages, in order", "sbi-kyc.xyz" in e["text"] and e["text"].rstrip().endswith("is this real??"), e["text"])
    check("It waited for the quiet window after the last message (~8 s)", 7 <= t - last_sent <= 11, f"{t - last_sent:.1f}s")
replies = meta_hook.replies(log, DEMO)
check("Exactly one reply was sent to the person", len(replies) == 1, "".join(log)[-600:])

send("wb1", "reset")
meta_hook.post(BASE, "wc1", "916666666666", kind="audio")
time.sleep(2)
check("'reset' still works and is answered", "Started fresh" in meta_hook.replies(log, DEMO)[-1])
check("Voice note alone gets an honest 'not supported' reply",
      any("Voice notes" in r for r in meta_hook.replies(log, "916666666666")))

proc.kill()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
