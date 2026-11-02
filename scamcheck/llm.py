"""The one AI call per check: Groq's free tier, via its OpenAI-compatible HTTP API (no SDK needed).

Groq states it does not train on customer data, which matters because people forward personal bank messages.
"""
import json
import time

import requests

from scamcheck import config, quota

API_URL = config.GROQ_API_URL


class AIUnavailable(Exception):
    """No key, quota exhausted, timeout or a bad answer. The caller falls back to rules; the person still gets a reply."""


def complete_json(system: str, user: str, max_tokens: int = 1500) -> dict:
    if not config.GROQ_API_KEY:
        raise AIUnavailable("GROQ_API_KEY not set")
    body = {
        "model": config.MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
        "max_completion_tokens": max_tokens,
        "reasoning_effort": "low",  # reasoning tokens count against the free per-minute budget
    }
    for attempt in range(2):
        try:
            r = requests.post(API_URL, json=body, timeout=30, headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"})
        except requests.RequestException as e:
            raise AIUnavailable(f"network: {e}") from None
        if r.status_code == 429:
            try:
                wait = float(r.headers.get("retry-after") or 60)
            except ValueError:
                wait = 60
            if attempt == 0 and wait <= 10:  # a per-minute limit clears quickly; worth one short wait
                time.sleep(wait)
                continue
            quota.pause_ai(wait)  # e.g. the daily limit: later checks go straight to rules instead of waiting to be refused
            raise AIUnavailable("free quota reached")
        if not r.ok:
            raise AIUnavailable(f"HTTP {r.status_code}")
        try:
            data = r.json()
            quota.record_ai_tokens(int((data.get("usage") or {}).get("total_tokens") or 0))
            return json.loads(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, ValueError) as e:
            raise AIUnavailable(f"unreadable answer: {e}") from None
    raise AIUnavailable("free quota reached")
