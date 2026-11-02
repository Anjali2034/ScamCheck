"""Real-process checks for step #2 (webhooks fail closed in production), on Meta's signing since fix #7."""
import atexit
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time

import requests

results = []
BASE = ""
WA = {"WHATSAPP_ACCESS_TOKEN": "EAAtest", "WHATSAPP_PHONE_NUMBER_ID": "123", "WHATSAPP_APP_SECRET": "app-secret",
      "WHATSAPP_VERIFY_TOKEN": "verify-me"}
CLEAR = {k: "" for k in ("GROQ_API_KEY", "SCAMCHECK_ENV", "RENDER", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME", *WA)}
PORT, ALL = [8770], []
atexit.register(lambda: [p.kill() for p in ALL if p.poll() is None])


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


def start(env):
    """Each scenario gets a fresh port, so a leftover server can never answer for the next one."""
    global BASE
    PORT[0] += 1
    BASE = f"http://127.0.0.1:{PORT[0]}"
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", str(PORT[0])],
                         env={**os.environ, **CLEAR, **env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace")
    ALL.append(p)
    return p


def wait_up():
    for _ in range(360):
        try:
            return requests.get(BASE + "/api/health", timeout=1).ok
        except requests.ConnectionError:
            time.sleep(0.5)
    return False


RAW = json.dumps({"entry": [{"changes": [{"value": {"statuses": [{"id": "x", "status": "delivered"}]}}]}]}).encode()


def post(signature=None, body=RAW):
    headers = {"Content-Type": "application/json", **({"X-Hub-Signature-256": signature} if signature else {})}
    return requests.post(BASE + "/webhook/whatsapp", data=body, headers=headers)


# 1. On Render with nothing configured: refuse to start, and say why.
p = start({"RENDER": "true"})
out, _ = p.communicate(timeout=180)
check("Render, no keys: server refuses to start", p.returncode != 0, out[-400:])
check("...and names the missing Groq key", "GROQ_API_KEY" in out, out[-600:])

# 2. Half a WhatsApp setup (token pasted, rest forgotten) is refused too.
p = start({"RENDER": "true", "GROQ_API_KEY": "gsk", "WHATSAPP_ACCESS_TOKEN": "EAAtest"})
out, _ = p.communicate(timeout=180)
check("Production with WhatsApp half set up: refuses, naming what's missing",
      p.returncode != 0 and "WHATSAPP_APP_SECRET" in out and "only partly set up" in out, out[-600:])

# 3. Web-only production (no WhatsApp at all) is a valid deployment.
p = start({"RENDER": "true", "GROQ_API_KEY": "gsk"})
try:
    check("Production, web-only: starts", wait_up())
    check("...and its webhook rejects everything (no app secret to verify with)", post().status_code == 403)
finally:
    p.terminate(); p.communicate()

# 4. Explicit SCAMCHECK_ENV=development beats the platform default (escape hatch for staging).
p = start({"RENDER": "true", "SCAMCHECK_ENV": "development"})
try:
    check("Render + SCAMCHECK_ENV=development: starts", wait_up())
finally:
    p.terminate(); p.communicate()

# 5. Production, fully configured: unsigned, forged and tampered webhooks are rejected.
p = start({"RENDER": "true", "GROQ_API_KEY": "gsk", **WA})
try:
    check("Production, fully configured: starts", wait_up())
    good = "sha256=" + hmac.new(b"app-secret", RAW, hashlib.sha256).hexdigest()
    check("Production: unsigned webhook -> 403", post().status_code == 403)
    check("Production: forged signature -> 403", post("sha256=" + "0" * 64).status_code == 403)
    check("Production: valid signature on a tampered body -> 403", post(good, RAW + b" ").status_code == 403)
    check("Production: correctly signed webhook -> 200", post(good).status_code == 200)
finally:
    p.terminate(); p.communicate()

# 6. Local dev, no WhatsApp secret: still easy to test, with a visible warning.
p = start({})
try:
    check("Local dev: server starts without any keys", wait_up())
    check("Local dev: unsigned webhook accepted for testing", post().status_code == 200)
finally:
    p.terminate()
    out, _ = p.communicate()
check("Local dev: startup warns that signatures are off", "NOT checked" in out, out[-400:])

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
