"""End-to-end: WhatsApp via Meta's Cloud API, against a local stand-in for graph.facebook.com, with real signatures,
real OCR and real link checks."""
import atexit
import hashlib
import hmac
import io
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from PIL import Image, ImageDraw, ImageFont

results = []
SECRET, TOKEN, PHONE_ID, VERIFY = "app-secret-123", "EAAtest", "1065403522", "scamcheck-2026"
ALLOWED = {"917777777777", "918888888888"}  # numbers "registered" on the test number


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


def png(lines):
    font = ImageFont.truetype("arial.ttf", 30)
    img = Image.new("RGB", (720, 140 + 54 * len(lines)), (255, 255, 255))
    for i, line in enumerate(lines):
        ImageDraw.Draw(img).text((40, 50 + 54 * i), line, fill=(17, 27, 33), font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


SCREENSHOT = png(["Dear Customer, your SBI YONO", "account will be BLOCKED today.", "Update PAN: http://sbi-kyc-update.xyz"])
graph_log = []  # every call ScamCheck made to "Meta"


class FakeGraph(BaseHTTPRequestHandler):
    def _reply(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else json.dumps(body).encode())

    def do_GET(self):
        authed = self.headers.get("Authorization") == f"Bearer {TOKEN}"
        graph_log.append(("GET", self.path, None, authed))
        if self.path.startswith("/v26.0/media"):
            return self._reply(200, {"url": f"http://127.0.0.1:8798/file{self.path}", "mime_type": "image/png"})
        if self.path.startswith("/file"):
            return self._reply(200 if authed else 401, SCREENSHOT if authed else b"", "image/png")
        self._reply(404, {})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        graph_log.append(("POST", self.path, body, self.headers.get("Authorization") == f"Bearer {TOKEN}"))
        if body.get("to") and body["to"] not in ALLOWED:  # how the real test number behaves
            return self._reply(400, {"error": {"code": 131030, "message": "Recipient phone number not in allowed list"}})
        self._reply(200, {"messages": [{"id": "wamid.out"}]})

    def log_message(self, *a):
        pass


graph = ThreadingHTTPServer(("127.0.0.1", 8798), FakeGraph)
threading.Thread(target=graph.serve_forever, daemon=True).start()

env = {**os.environ, "SCAMCHECK_ENV": "development", "GROQ_API_KEY": "", "WHATSAPP_ACCESS_TOKEN": TOKEN,
       "WHATSAPP_PHONE_NUMBER_ID": PHONE_ID, "WHATSAPP_APP_SECRET": SECRET, "WHATSAPP_VERIFY_TOKEN": VERIFY,
       "WHATSAPP_API_BASE": "http://127.0.0.1:8798", "PYTHONUNBUFFERED": "1"}
proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", "8797"], env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
atexit.register(lambda: proc.poll() is None and proc.kill())
server_log = []
threading.Thread(target=lambda: [server_log.append(l) for l in proc.stdout], daemon=True).start()
BASE = "http://127.0.0.1:8797"
for _ in range(360):
    try:
        requests.get(BASE + "/api/health", timeout=1)
        break
    except requests.ConnectionError:
        time.sleep(0.5)


def webhook(*messages, sign=True):
    raw = json.dumps({"object": "whatsapp_business_account", "entry": [{"changes": [{"field": "messages",
                      "value": {"messaging_product": "whatsapp", "messages": list(messages)}}]}]}).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest() if sign else ""
    return requests.post(BASE + "/webhook/whatsapp", data=raw, headers={"Content-Type": "application/json",
                                                                         "X-Hub-Signature-256": sig})


def text_msg(mid, body, sender="917777777777"):
    return {"id": mid, "from": sender, "type": "text", "text": {"body": body}}


def sends_to(number, since=0):
    return [b for m, p, b, _ in graph_log[since:] if m == "POST" and b.get("to") == number]


def wait_for(cond, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.3)
    return False


# Meta's dashboard handshake
r = requests.get(BASE + "/webhook/whatsapp", params={"hub.mode": "subscribe", "hub.verify_token": VERIFY, "hub.challenge": "8675309"})
check("Meta's webhook handshake returns the challenge", r.status_code == 200 and r.text == "8675309", r.text)
check("Unsigned webhook is rejected (403)", webhook(text_msg("x0", "hi"), sign=False).status_code == 403)

# 1. A scam text: typing indicator, then exactly one verdict message
mark = len(graph_log)
t = time.monotonic()
r = webhook(text_msg("wamid.1", "Dear Customer your SBI account will be BLOCKED today. Update KYC: http://sbi-kyc-update.xyz/login"))
check("Signed webhook answered fast with 200", r.status_code == 200 and time.monotonic() - t < 2)
check("Blue ticks + 'typing…' sent right away", wait_for(lambda: any(
    b and b.get("status") == "read" and b.get("message_id") == "wamid.1" and b.get("typing_indicator") for _, _, b, _ in graph_log[mark:]), 5))
check("Exactly one verdict message, after the burst window", wait_for(lambda: sends_to("917777777777", mark)) and
      len(sends_to("917777777777", mark)) == 1)
reply = sends_to("917777777777", mark)[0]
body = reply["text"]["body"]
check("...it's a scam verdict", "Scam" in body, body[:200])
check("...the scam link is defanged, never tappable", "sbi-kyc-update.xyz" not in body and "sbi-kyc-update[.]xyz" in body, body)
check("...with link previews switched off", reply["text"]["preview_url"] is False)
check("...every Graph call carried the access token", all(a for *_, a in graph_log))

# 2. Follow-up after paying: verdict + complaint draft, both defanged
mark = len(graph_log)
webhook(text_msg("wamid.2", "I already paid ₹4,999 via PhonePe"))
check("Paid follow-up -> verdict and complaint draft (2 messages)",
      wait_for(lambda: len(sends_to("917777777777", mark)) == 2, 30))
v, c = [m["text"]["body"] for m in sends_to("917777777777", mark)]
check("...verdict says call 1930", "1930" in v)
check("...complaint has the amount, defanged link and the 'type them normally' note",
      "4,999" in c and "sbi-kyc-update[.]xyz" in c and "type them normally" in c, c[:300])

# 3. A screenshot sent as WhatsApp media: downloaded with the token, read by OCR, judged
mark = len(graph_log)
webhook({"id": "wamid.3", "from": "918888888888", "type": "image", "image": {"id": "media42", "mime_type": "image/png"}})
check("Screenshot: media fetched from Meta with the token, then read and judged",
      wait_for(lambda: sends_to("918888888888", mark), 40) and "Scam" in sends_to("918888888888", mark)[0]["text"]["body"])
check("...media URL lookup and download both happened",
      any(m == "GET" and p == "/v26.0/media42" for m, p, *_ in graph_log[mark:])
      and any(m == "GET" and p.startswith("/file") for m, p, *_ in graph_log[mark:]))

# 4. An OTP: the warning goes out immediately, before the verdict
mark = len(graph_log)
webhook(text_msg("wamid.4", "Your OTP for HDFC Bank login is 482913. Do not share it.", sender="918888888888"))
check("OTP: warning sent within 3 s (before the 8 s burst window)", wait_for(lambda: sends_to("918888888888", mark), 3))
check("...and the code never left the server",
      wait_for(lambda: len(sends_to("918888888888", mark)) == 2, 30) and "482913" not in json.dumps(graph_log[mark:]))

# 5. Someone not registered on the test number: no crash, logged clearly
mark = len(graph_log)
webhook(text_msg("wamid.5", "Is this real? http://sbi-kyc-update.xyz", sender="919999999999"))
check("Unregistered number: reply attempt fails cleanly and is logged",
      wait_for(lambda: any("131030" in l for l in server_log), 30) and proc.poll() is None)

graph.shutdown()
proc.kill()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
