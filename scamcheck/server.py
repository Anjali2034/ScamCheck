"""HTTP server: web demo with a live agent trace, plus the Twilio WhatsApp webhook.

Run:  uvicorn scamcheck.server:app --reload --port 8000
"""
import asyncio
import json
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from xml.sax.saxutils import escape

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse

from scamcheck import config, inbox, otp_shield, whatsapp
from scamcheck.agent import Investigation, format_for_whatsapp


def missing_production_settings() -> list[str]:
    """Settings a public deployment can't run safely without, each with what goes wrong if it's missing."""
    missing = []
    if not config.GROQ_API_KEY:
        missing.append("GROQ_API_KEY (free at console.groq.com): every verdict would fall back to rules only")
    if not (config.TWILIO_ACCOUNT_SID and config.TWILIO_AUTH_TOKEN):
        missing.append("TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN: replies can't be sent and webhooks can't be verified")
    if not config.PUBLIC_BASE_URL.startswith("https://"):
        missing.append("PUBLIC_BASE_URL (https://...): Twilio signatures are computed on the public URL, "
                       "so without it every real message is rejected")
    return missing


@asynccontextmanager
async def lifespan(_app):
    if config.IS_PRODUCTION:
        if missing := missing_production_settings():
            raise RuntimeError("ScamCheck won't start in production without:\n  - " + "\n  - ".join(missing))
    elif not config.TWILIO_AUTH_TOKEN:
        print("[scamcheck] Development mode: WhatsApp webhook signatures are NOT checked (no TWILIO_AUTH_TOKEN). "
              "Deploys on Render/Railway switch to production automatically; elsewhere set SCAMCHECK_ENV=production.")
    yield


app = FastAPI(title="ScamCheck", lifespan=lifespan)
STATIC = Path(__file__).parent / "static"
SESSION_TTL = 30 * 60


class Sessions:
    """Per-user conversations, so a follow-up like 'I already paid' keeps context."""

    def __init__(self):
        self._items: dict[str, tuple[Investigation, threading.Lock, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> tuple[Investigation, threading.Lock]:
        now = time.time()
        with self._lock:
            for k in [k for k, (_, _, t) in self._items.items() if now - t > SESSION_TTL]:
                del self._items[k]
            inv, lock, _ = self._items.get(key) or (Investigation(), threading.Lock(), now)
            self._items[key] = (inv, lock, now)
            return inv, lock

    def reset(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)


class LiveFeed:
    """Fan out every agent event (web and WhatsApp) to anyone watching /api/live."""

    def __init__(self):
        self._subs: set[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = set()

    def publish(self, event: dict) -> None:
        for loop, q in list(self._subs):
            loop.call_soon_threadsafe(q.put_nowait, event)

    def subscribe(self) -> tuple[asyncio.AbstractEventLoop, asyncio.Queue]:
        sub = (asyncio.get_running_loop(), asyncio.Queue())
        self._subs.add(sub)
        return sub

    def unsubscribe(self, sub) -> None:
        self._subs.discard(sub)


sessions = Sessions()
feed = LiveFeed()

RESET_WORDS = {"reset", "new", "start", "restart", "/new"}


def _mask(phone: str) -> str:
    digits = phone.replace("whatsapp:", "")
    return digits[:3] + "•••••" + digits[-3:]


def redact_for_feed(e: dict) -> dict | None:
    """What strangers may see of someone else's check: its shape, never its content.

    Forwarded messages carry names, account numbers and live OTPs, and the model's reasoning, tool inputs,
    page screenshots and error text all quote them. So only tool names and the final verdict get through.
    """
    match e["type"]:
        case "start":
            return {"type": "start", "has_image": e["has_image"], "private": True}
        case "tool_call" | "tool_result":
            return {"type": e["type"], "name": e["name"], "private": True}
        case "verdict":
            v = e["verdict"]
            return {"type": "verdict", "verdict": {"verdict": v["verdict"], "scam_type": v["scam_type"]}}
        case "error":
            return {"type": "error", "message": "A check hit an error.", "private": True}
    return None  # thinking, text, screenshots, status


def _investigate(key: str, label: str, text: str, images: list, emit, public: bool = False) -> dict:
    """Run one turn of a conversation. Only `public` sessions (demo numbers) stream their content to the live feed."""
    inv, lock = sessions.get(key)

    def publish(e):
        e = e if public else redact_for_feed(e)
        if e:
            feed.publish({**e, "session": label})

    def both(e):
        emit(e)
        publish(e)

    publish({"type": "start", "text": text[:500], "has_image": bool(images)})
    with lock:
        return inv.run(text=text, images=images, emit=both)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/investigate")
async def investigate(text: str = Form(""), session_id: str = Form("web"), image: UploadFile | None = File(None)):
    img = None
    if image and image.filename:
        data = await image.read()
        if len(data) > 5 * 1024 * 1024:
            raise HTTPException(413, "Image too large (max 5 MB)")
        img = (data, image.content_type or "image/jpeg")
    if not text.strip() and not img:
        raise HTTPException(400, "Send some text or an image")
    text, hidden_codes = otp_shield.mask_otps(text)  # before anything can log, store or stream it

    loop = asyncio.get_running_loop()
    q: asyncio.Queue = asyncio.Queue()
    emit = lambda e: loop.call_soon_threadsafe(q.put_nowait, e)

    async def worker():
        if hidden_codes:
            emit({"type": "notice", "message": otp_shield.warning(text)})
        try:
            result = await asyncio.to_thread(_investigate, f"web:{session_id}", "web", text, [img] if img else [], emit)
            emit({"type": "done", "result": result, "whatsapp_text": format_for_whatsapp(result)})
        except Exception as e:
            emit({"type": "error", "message": str(e)})
            emit({"type": "done", "result": None})

    task = asyncio.create_task(worker())

    async def stream():
        while True:
            e = await q.get()
            yield json.dumps(e, ensure_ascii=False, default=str) + "\n"
            if e["type"] == "done":
                break
        await task

    return StreamingResponse(stream(), media_type="application/x-ndjson")


@app.post("/api/reset")
def reset(session_id: str = Form("web")):
    sessions.reset(f"web:{session_id}")
    return {"ok": True}


@app.get("/api/live")
async def live(request: Request):
    sub = feed.subscribe()

    async def stream():
        try:
            yield json.dumps({"type": "status", "message": "Connected to live feed"}) + "\n"
            while not await request.is_disconnected():
                try:
                    e = await asyncio.wait_for(sub[1].get(), timeout=15)
                    yield json.dumps(e, ensure_ascii=False, default=str) + "\n"
                except asyncio.TimeoutError:
                    yield json.dumps({"type": "ping"}) + "\n"
        finally:
            feed.unsubscribe(sub)

    return StreamingResponse(stream(), media_type="application/x-ndjson")


@app.get("/api/health")
def health():
    return {
        "model": config.MODEL,
        "safe_browsing": bool(config.SAFE_BROWSING_KEY),
        "virustotal": bool(config.VIRUSTOTAL_KEY),
        "whatsapp": whatsapp.is_configured(),
    }


def _twiml(text: str) -> Response:
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{escape(text)}</Message></Response>',
                    media_type="application/xml")


def _twiml_empty() -> Response:
    return Response('<?xml version="1.0" encoding="UTF-8"?><Response/>', media_type="application/xml")


def _whatsapp_job(sender: str, texts: list[str], media: list[inbox.Media]) -> None:
    """Investigate everything one person sent in a burst, as one message, and send one reply."""
    try:
        text = "\n\n".join(texts)
        images = [whatsapp.download_media(url) for url, kind in media if kind.startswith("image/")]
        result = _investigate(f"wa:{sender}", _mask(sender), text, images, lambda e: None,
                              public=sender in config.DEMO_NUMBERS)
        whatsapp.send(sender, format_for_whatsapp(result))
        if result.get("complaint"):
            whatsapp.send(sender, "📝 *Your complaint draft* (copy into cybercrime.gov.in):\n\n"
                          + result["complaint"]["complaint_text"])
    except Exception as e:
        print(f"[whatsapp job failed] {_mask(sender)}: {e!r}")
        feed.publish({"type": "error", "session": _mask(sender), "message": "A check hit an error.", "private": True})
        whatsapp.send(sender, "Sorry, the check failed. Don't click links or share OTPs meanwhile. If you've paid, call 1930 now.")


seen_messages = inbox.SeenMessages()
wa_inbox = inbox.Inbox(lambda sender, texts, media: _whatsapp_job(sender, texts, media))

ACK = ("🔍 Got it. I'm checking the links, numbers and wording and will reply in about a minute.\n"
       "Have more? Send it in the next few seconds (another screenshot, the number that called you) "
       "and I'll check it all together.\n"
       "Meanwhile: don't click the link, pay, or share any OTP.")


@app.post("/webhook/whatsapp")
async def whatsapp_webhook(request: Request):
    form = dict(await request.form())
    public_url = (config.PUBLIC_BASE_URL.rstrip("/") + request.url.path) if config.PUBLIC_BASE_URL else str(request.url)
    if not whatsapp.verify_signature(public_url, form, request.headers.get("X-Twilio-Signature", "")):
        raise HTTPException(403, "Invalid Twilio signature")
    sid = form.get("MessageSid", "")
    if sid and not seen_messages.first_time(sid):
        return _twiml_empty()  # Twilio retrying a message we already have

    sender = form.get("From", "")
    body, hidden_codes = otp_shield.mask_otps((form.get("Body") or "").strip())  # before anything can log or store it
    if body.lower() in RESET_WORDS:
        wa_inbox.drop(sender)
        sessions.reset(f"wa:{sender}")
        return _twiml("Started fresh. Forward me any suspicious message, link, screenshot, UPI ID or number.")

    media = [(form.get(f"MediaUrl{i}", ""), form.get(f"MediaContentType{i}", ""))  # an album carries up to 10
             for i in range(int(form.get("NumMedia", "0") or 0))]
    if not body and not media:
        return _twiml("Forward me a suspicious SMS, link, screenshot, UPI ID or phone number and I'll investigate it.")
    if not body and not any(kind.startswith("image/") for _, kind in media):
        return _twiml("I can check text, links and screenshots. Voice notes, videos and documents aren't supported "
                      "yet, so please forward the message text or send a screenshot.")

    # Twilio expects a reply within 15 s; investigations take longer, so acknowledge now and send the verdict later.
    first_in_burst = wa_inbox.add(sender, body, media)
    if hidden_codes:  # the warning always goes out at once: it matters more than the verdict, and right now
        then = ("🔍 Now checking the rest of the message. I'll reply in about a minute." if first_in_burst
                else "I've added the rest of this message to my check.")
        return _twiml(otp_shield.warning(body) + "\n\n" + then)
    return _twiml(ACK) if first_in_burst else _twiml_empty()
