"""Twilio WhatsApp glue: verify webhooks, download forwarded media, send replies."""
import requests
from twilio.request_validator import RequestValidator
from twilio.rest import Client

from scamcheck import config

MAX_BODY = 1500  # WhatsApp via Twilio caps a message at 1600 characters


def is_configured() -> bool:
    return bool(config.TWILIO_ACCOUNT_SID and config.TWILIO_AUTH_TOKEN)


def verify_signature(url: str, form: dict, signature: str) -> bool:
    if not config.TWILIO_AUTH_TOKEN:
        return not config.IS_PRODUCTION  # unsigned requests are only for local testing, never on a public server
    return RequestValidator(config.TWILIO_AUTH_TOKEN).validate(url, form, signature)


def download_media(url: str) -> tuple[bytes, str]:
    r = requests.get(url, auth=(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN), timeout=20)
    r.raise_for_status()
    return r.content, r.headers.get("Content-Type", "image/jpeg").split(";")[0]


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


def send(to: str, text: str) -> None:
    if not is_configured():
        print(f"[whatsapp not configured] reply to {to}:\n{text}")
        return
    client = Client(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN)
    for part in _chunks(text):
        client.messages.create(from_=config.TWILIO_WHATSAPP_FROM, to=to, body=part)
