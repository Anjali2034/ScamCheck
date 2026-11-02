"""Shared by the end-to-end scripts: post Meta-style WhatsApp webhooks and read the replies ScamCheck 'sent'.

With WhatsApp unconfigured, whatsapp.send prints "[whatsapp not configured] reply to <number>:" then the text.
"""
import requests

MARK = "[whatsapp not configured] reply to "


def post(base, mid, sender, body="", kind="text", media=None):
    msg = {"id": mid, "from": sender, "type": kind}
    if kind == "text":
        msg["text"] = {"body": body}
    else:
        msg[kind] = media or {"id": "m1", "mime_type": "audio/ogg"}
    payload = {"entry": [{"changes": [{"field": "messages", "value": {"messages": [msg]}}]}]}
    return requests.post(base + "/webhook/whatsapp", json=payload)


def replies(log_lines, number):
    """Every reply sent to +<number>, in order."""
    out = []
    for chunk in "".join(log_lines).split(MARK)[1:]:
        to, _, text = chunk.partition(":\n")
        if to.strip() == "+" + number.lstrip("+"):
            out.append(text)
    return out
