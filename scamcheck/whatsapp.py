"""WhatsApp via Meta's Cloud API (free test number): verify webhooks, read incoming messages, download media,
show "typing…", send replies. Replies inside the 24-hour customer-service window are free service messages.
"""
import hashlib
import hmac

import requests

from scamcheck import config, quota

MAX_BODY = 4000  # the Cloud API caps a text message at 4,096 characters
HANDLED_TYPES = {"text", "image", "audio", "video", "document", "interactive", "button"}  # not reactions or stickers
_MEDIA_TYPES = ("image", "audio", "video", "document")


def _api() -> str:
    return f"{config.WHATSAPP_API_BASE}/{config.WHATSAPP_API_VERSION}"


def _auth() -> dict:
    return {"Authorization": f"Bearer {config.WHATSAPP_ACCESS_TOKEN}"}


def is_configured() -> bool:
    return bool(config.WHATSAPP_ACCESS_TOKEN and config.WHATSAPP_PHONE_NUMBER_ID)


def verify_signature(raw_body: bytes, header: str) -> bool:
    """Meta signs each webhook body with the app secret (X-Hub-Signature-256: sha256=<hex HMAC>)."""
    if not config.WHATSAPP_APP_SECRET:
        return not config.IS_PRODUCTION  # unsigned requests are only for local testing, never on a public server
    expected = "sha256=" + hmac.new(config.WHATSAPP_APP_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header or "")


def incoming(payload: dict) -> list[dict]:
    """Flatten a webhook into messages: {id, sender, kind, text, media: [(media id, mime type)]}.

    Delivery receipts, reactions ("👍" to a verdict) and stickers are dropped: answering them would only spend
    the free message allowance and annoy the person.
    """
    out = []
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            for m in (change.get("value") or {}).get("messages") or []:
                kind = m.get("type", "")
                if kind not in HANDLED_TYPES:
                    continue
                text, media = (m.get("text") or {}).get("body", ""), []
                if kind in _MEDIA_TYPES:
                    obj = m.get(kind) or {}
                    media.append((obj.get("id", ""), obj.get("mime_type", "")))
                    text = obj.get("caption", "")
                elif kind == "button":
                    text = (m.get("button") or {}).get("text", "")
                elif kind == "interactive":
                    reply = (m.get("interactive") or {})
                    text = (reply.get("button_reply") or reply.get("list_reply") or {}).get("title", "")
                out.append({"id": m.get("id", ""), "sender": "+" + str(m.get("from", "")).lstrip("+"),
                            "kind": kind, "text": text, "media": media})
    return out


def _post(payload: dict) -> bool:
    try:
        r = requests.post(f"{_api()}/{config.WHATSAPP_PHONE_NUMBER_ID}/messages", json=payload, headers=_auth(), timeout=15)
    except requests.RequestException as e:
        print(f"[whatsapp] request failed: {e}")
        return False
    if not r.ok:  # e.g. 131030: the test number may only message the (up to 5) numbers registered in the dashboard
        print(f"[whatsapp] {r.status_code}: {r.text[:300]}")
    return r.ok


def mark_read_and_typing(message_id: str) -> None:
    """Blue ticks plus "typing…" until the reply (max 25 s). Not a message, so it doesn't use the free allowance."""
    if is_configured() and message_id:
        _post({"messaging_product": "whatsapp", "status": "read", "message_id": message_id,
               "typing_indicator": {"type": "text"}})


def download_media(media_id: str) -> tuple[bytes, str]:
    meta = requests.get(f"{_api()}/{media_id}", headers=_auth(), timeout=15)
    meta.raise_for_status()
    info = meta.json()
    r = requests.get(info["url"], headers=_auth(), timeout=30)
    r.raise_for_status()
    return r.content, info.get("mime_type") or r.headers.get("Content-Type", "image/jpeg").split(";")[0]


def _chunks(text: str) -> list[str]:
    out, cur = [], ""
    for para in text.split("\n"):
        while len(para) > MAX_BODY:
            out.append(para[:MAX_BODY])
            para = para[MAX_BODY:]
        if len(cur) + len(para) + 1 > MAX_BODY:
            out.append(cur)
            cur = ""
        cur = f"{cur}\n{para}" if cur else para
    if cur:
        out.append(cur)
    return out


def send(to: str, text: str, urgent: bool = False) -> None:
    """`urgent` (OTP warnings, the "out of free replies" notice) may use the small reserve kept back each month."""
    if not is_configured():
        print(f"[whatsapp not configured] reply to {to}:\n{text}")
        return
    for part in _chunks(text):
        if not quota.take_whatsapp_message(urgent):
            print("[whatsapp] this month's free messages are used up; not sending")
            return
        # preview_url off: a link preview would fetch the scam page and show its logo, making it look legitimate.
        _post({"messaging_product": "whatsapp", "to": to.lstrip("+"), "type": "text",
               "text": {"body": part, "preview_url": False}})
