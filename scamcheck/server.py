"""HTTP server: the web checker with a live trace, plus the WhatsApp (Meta Cloud API) webhook.

Run:  uvicorn scamcheck.server:app --reload --port 8000
"""
import asyncio
import hmac
import json
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse

from scamcheck import config, inbox, otp_shield, quota, whatsapp
from scamcheck.agent import Investigation, format_for_whatsapp

WHATSAPP_SETTINGS = ("WHATSAPP_ACCESS_TOKEN", "WHATSAPP_PHONE_NUMBER_ID", "WHATSAPP_APP_SECRET", "WHATSAPP_VERIFY_TOKEN")


def missing_production_settings() -> list[str]:
    """Settings a public deployment can't run safely without, each with what goes wrong if it's missing."""
    missing = []
    if not config.GROQ_API_KEY:
        missing.append("GROQ_API_KEY (free at console.groq.com): every verdict would fall back to rules only")
    # WhatsApp is optional (the web page is the public channel), but half a setup fails silently on real messages.
    unset = [k for k in WHATSAPP_SETTINGS if not getattr(config, k)]
    if 0 < len(unset) < len(WHATSAPP_SETTINGS):
        missing.append(", ".join(unset) + ": WhatsApp is only partly set up, so replies would fail or webhooks "
                                          "couldn't be verified. Set all four, or none for web-only.")
    return missing


@asynccontextmanager
async def lifespan(_app):
    if config.IS_PRODUCTION:
        if missing := missing_production_settings():
            raise RuntimeError("ScamCheck won't start in production without:\n  - " + "\n  - ".join(missing))
    elif not config.WHATSAPP_APP_SECRET:
        print("[scamcheck] Development mode: WhatsApp webhook signatures are NOT checked (no WHATSAPP_APP_SECRET). "
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
    return phone[:3] + "•••••" + phone[-3:]


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


def _investigate(key: str, label: str, text: str, images: list, emit, public: bool = False, reporter: str = "",
                 person: str = "") -> dict:
    """Run one turn of conversation `key`. `person` (default: the conversation) gets the fair share of AI checks.
    Only `public` sessions (demo numbers) stream their content to the live feed."""
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
        return inv.run(text=text, images=images, emit=both, person=person or key, reporter=reporter)


def client_network(request: Request) -> str:
    """The address a check came from. On Render, Cloudflare writes CF-Connecting-IP on every request and overwrites
    whatever the sender typed. X-Forwarded-For isn't used: Cloudflare only appends to it, so its first entry is
    whatever the sender typed, and its last is a proxy that many people share."""
    if config.IS_PRODUCTION and (cf := request.headers.get("cf-connecting-ip", "").strip()):
        return cf
    return request.client.host if request.client else "unknown"


BUSY = ("Too many checks from your network right now. Please wait a few minutes and try again. Meanwhile: don't "
        "click links, don't pay, and never share an OTP or PIN. If you've lost money, call 1930 now.")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/demo")
def demo():
    """The developer view: every check as it runs, plus the live feed of all channels."""
    return FileResponse(STATIC / "demo.html")


@app.post("/api/investigate")
async def investigate(request: Request, text: str = Form(""), session_id: str = Form(""), visitor_id: str = Form(""),
                      image: UploadFile | None = File(None)):
    network = client_network(request)
    if not quota.web_check_allowed(network):
        raise HTTPException(429, BUSY)
    img = None
    if image and image.filename:
        data = await image.read()
        if len(data) > 5 * 1024 * 1024:
            raise HTTPException(413, "Image too large (max 5 MB)")
        img = (data, image.content_type or "image/jpeg")
    if not text.strip() and not img:
        raise HTTPException(400, "Send some text or an image")
    text, hidden_codes = otp_shield.mask_otps(text)  # before anything can log, store or stream it
    # No id means no follow-ups: never one shared conversation that every id-less caller would land in.
    convo = session_id[:64] or uuid.uuid4().hex

    loop = asyncio.get_running_loop()
    q: asyncio.Queue = asyncio.Queue()
    emit = lambda e: loop.call_soon_threadsafe(q.put_nowait, e)

    async def worker():
        if hidden_codes:
            emit({"type": "notice", "message": otp_shield.warning(text)})
        try:
            result = await asyncio.to_thread(_investigate, f"web:{convo}", "web", text, [img] if img else [], emit,
                                          False, f"net:{network}", f"web:{visitor_id[:64] or convo}")
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
def reset(session_id: str = Form("")):
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
        **quota.status(),
    }


COMPLAINT_HEADER = ("📝 *Your complaint draft* (copy into cybercrime.gov.in). Links are written like example[.]com "
                    "so they can't be tapped by mistake; type them normally when you file.\n\n")


def _web_page() -> str:
    return f"the ScamCheck web page: {config.PUBLIC_URL}" if config.PUBLIC_URL else "the ScamCheck web page"


SAFETY_BASICS = "Meanwhile: don't click links, don't pay, and never share an OTP or PIN. If you've lost money, call 1930 now."


def _over_whatsapp_limits(sender: str) -> bool:
    """Out of free replies this month, or this number has had today's checks: say so once, with what to do instead."""
    if quota.whatsapp_replies_left() <= 0:
        if quota.first_notice(f"wa_month:{sender}", monthly=True):
            whatsapp.send(sender, f"ScamCheck has used up this month's free WhatsApp replies. Please check messages on "
                                  f"{_web_page()}. {SAFETY_BASICS}", urgent=True)
        return True
    if not quota.whatsapp_check_allowed(sender):
        if quota.first_notice(f"wa_day:{sender}"):
            whatsapp.send(sender, f"You've reached today's limit of checks on WhatsApp. Try again tomorrow, or use "
                                  f"{_web_page()}. {SAFETY_BASICS}")
        return True
    return False


def _whatsapp_job(sender: str, texts: list[str], media: list[inbox.Media]) -> None:
    """Investigate everything one person sent in a burst, as one message, and send one reply."""
    if _over_whatsapp_limits(sender):
        return
    try:
        images = [whatsapp.download_media(media_id) for media_id, kind in media if kind.startswith("image/")]
        result = _investigate(f"wa:{sender}", _mask(sender), "\n\n".join(texts), images, lambda e: None,
                              public=sender in config.DEMO_NUMBERS)
        whatsapp.send(sender, format_for_whatsapp(result))
        if result.get("complaint"):
            whatsapp.send(sender, COMPLAINT_HEADER + format_for_whatsapp(result, complaint=True))
    except Exception as e:
        print(f"[whatsapp job failed] {_mask(sender)}: {e!r}")
        feed.publish({"type": "error", "session": _mask(sender), "message": "A check hit an error.", "private": True})
        whatsapp.send(sender, "Sorry, the check failed. Don't click links or share OTPs meanwhile. If you've paid, call 1930 now.")


seen_messages = inbox.SeenMessages()
wa_inbox = inbox.Inbox(lambda sender, texts, media: _whatsapp_job(sender, texts, media))


def _handle_whatsapp_message(m: dict) -> None:
    """One incoming message. Runs after the webhook has already answered Meta with 200."""
    sender = m["sender"]
    whatsapp.mark_read_and_typing(m["id"])  # blue ticks + "typing…" instead of an acknowledgement message
    body, hidden_codes = otp_shield.mask_otps(m["text"].strip())  # before anything can log or store it
    if body.lower() in RESET_WORDS:
        wa_inbox.drop(sender)
        sessions.reset(f"wa:{sender}")
        whatsapp.send(sender, "Started fresh. Forward me any suspicious message, link, screenshot, UPI ID or number.")
        return
    images = [x for x in m["media"] if x[1].startswith("image/")]
    if not body and not images:
        whatsapp.send(sender, "I can check text, links and screenshots. Voice notes, videos and documents aren't "
                              "supported yet, so please forward the message text or send a screenshot."
                      if m["media"] else
                      "Forward me a suspicious SMS, link, screenshot, UPI ID or phone number and I'll check it.")
        return
    if hidden_codes:  # worth one extra message: they may be on the phone with the scammer right now
        whatsapp.send(sender, otp_shield.warning(body), urgent=True)
    wa_inbox.add(sender, body, images)


@app.get("/webhook/whatsapp")
def whatsapp_verify(mode: str = Query("", alias="hub.mode"), token: str = Query("", alias="hub.verify_token"),
                    challenge: str = Query("", alias="hub.challenge")):
    """Meta's one-time check when you save the webhook URL in the app dashboard."""
    if mode == "subscribe" and config.WHATSAPP_VERIFY_TOKEN and hmac.compare_digest(token, config.WHATSAPP_VERIFY_TOKEN):
        return PlainTextResponse(challenge)
    raise HTTPException(403, "Verify token doesn't match WHATSAPP_VERIFY_TOKEN")


@app.post("/webhook/whatsapp")
async def whatsapp_webhook(request: Request, background: BackgroundTasks):
    raw = await request.body()
    if not whatsapp.verify_signature(raw, request.headers.get("X-Hub-Signature-256", "")):
        raise HTTPException(403, "Invalid signature")
    try:
        payload = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Not JSON") from None
    for m in whatsapp.incoming(payload):
        if m["id"] and not seen_messages.first_time(m["id"]):
            continue  # Meta retrying a delivery we already have
        background.add_task(_handle_whatsapp_message, m)
    return {"ok": True}  # answer fast: Meta retries anything slow, for up to 36 hours
