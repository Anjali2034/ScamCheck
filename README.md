# 🛡️ ScamCheck

An AI agent that investigates suspicious messages for people in India. Forward it an SMS, link, screenshot, UPI ID or phone number on WhatsApp. It picks its own tools, collects evidence and replies with a verdict and the reasons for it. If you've already paid, it tells you to call **1930** and drafts your **cybercrime.gov.in** complaint.

> Indians lost about ₹22,495 crore to cyber fraud in 2025, up 24% on 2024, mostly through investment scams. There have been 38 lakh+ complaints since 2021.

## What the agent can do

| Tool | What it checks | Needs |
|---|---|---|
| `extract_indicators` | Links, UPI IDs (+ whether the PSP handle is real), phone numbers, emails, Telegram/wa.me handles, ₹ amounts | none |
| `check_domain` | Brand impersonation of ~30 Indian banks, UPI apps, govt sites and couriers (keyword, typosquat and homoglyph checks), shorteners, risky TLDs, punycode, free hosting, **domain age via RDAP** | none |
| `check_url_reputation` | Google Safe Browsing + VirusTotal (URL and domain reports) | free API keys |
| `visit_in_sandbox` | Opens the link in a throwaway headless phone browser (Playwright): redirect chain, final URL, whether it asks for password/OTP/card/Aadhaar, APK downloads, **screenshot that Claude looks at** | none |
| `match_scam_scripts` | 10 known scripts: digital arrest, task scam, fake KYC, investment, electricity cut-off, courier, KBC lottery, UPI refund/collect, sextortion, loan apps (English + Hinglish cues) | none |
| `analyse_phone_number` | Foreign numbers posing as Indian agencies, scam-compound regions, 140-series | none |
| `check_indicator_history` | Whether this UPI ID/number/domain appeared in earlier ScamCheck verdicts (local SQLite) | none |
| `draft_cybercrime_complaint` | NCRP-format complaint with [FILL IN] gaps + urgent steps (1930, bank freeze) | none |
| `submit_verdict` | Structured verdict: SCAM / LIKELY_SCAM / SUSPICIOUS / LIKELY_SAFE / SAFE / INCONCLUSIVE, with evidence and severity | none |

Claude (`claude-opus-5-5`) decides which tools to run and in what order, runs independent checks in parallel, reads screenshots (including a screenshot the user forwards) and writes the reply in the user's own language.

## Quick start

```powershell
cd "C:\Users\anjal\OneDrive\Desktop\New project"
.\.venv\Scripts\Activate.ps1          # already created, with deps + Chromium installed
copy .env.example .env                # then put your ANTHROPIC_API_KEY in .env
uvicorn scamcheck.server:app --reload --port 8000
```

Open http://localhost:8000, click a sample message, and watch the trace.

If you're setting up from scratch: `python -m venv .venv`, `pip install -r requirements.txt`, `python -m playwright install chromium`.

**CLI:** `python -m scamcheck "Your SBI KYC expired, update at http://sbi-kyc.xyz"` (add `--image screenshot.png` for images). It stays open for follow-ups like "I already paid ₹4,999".

**Tests:** `pytest` runs 9 offline tests. They need no API keys.

## Hooking up WhatsApp (Twilio sandbox, free)

1. Create a Twilio account, then go to **Messaging → Try it out → Send a WhatsApp message**. From your phone, send the join code to the sandbox number.
2. Put `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` in `.env`.
3. Expose your server: `ngrok http 8000`, then set `PUBLIC_BASE_URL=https://<your-id>.ngrok-free.app` in `.env` (used to verify Twilio's signature). Restart uvicorn.
4. In the sandbox settings, set **"When a message comes in"** to `https://<your-id>.ngrok-free.app/webhook/whatsapp` (POST).
5. Forward a scam message to the sandbox number. You get an instant "Investigating…" reply, then the verdict about a minute later. Send `reset` to start a new conversation.

**Demo tip:** open the **Live feed** tab on the web page. Every investigation streams there, so an audience can watch the agent work while you use your phone. For privacy, strangers' checks show only which tools ran and the verdict. To show your own checks in full (message, reasoning, screenshots), put your number in `DEMO_NUMBERS` in `.env`.

## Getting the free API keys

- **Claude:** https://console.anthropic.com → API keys
- **Google Safe Browsing:** create a Google Cloud project, enable the "Safe Browsing API", then create an API key
- **VirusTotal:** sign up, then go to profile → API key (free tier: 4 requests/min)

Any key you leave out is skipped. The agent is told the check was skipped, so it won't treat a missing check as a clean result.

## Architecture

```
WhatsApp ──Twilio──▶ /webhook/whatsapp ─┐  (acks in <15 s, replies async)
Web UI ──────────▶ /api/investigate ────┼─▶ Investigation (per-user session, 30 min)
                    /api/live ◀── events┘        │  Claude tool-use loop
                                                 ▼
             extract · domain/RDAP · Safe Browsing/VirusTotal · Playwright sandbox
             scam scripts · phone · history (SQLite) · complaint draft · verdict
```

- `scamcheck/agent.py`: system prompt, tool schemas (strict), the agent loop, WhatsApp formatting
- `scamcheck/tools/`: one file per capability
- `scamcheck/data/`: brand domains and scam-script patterns. These are plain JSON, so you can grow them without code changes.
- `scamcheck/server.py`: FastAPI app, sessions, live feed, Twilio webhook
- `runtime/`: screenshots + SQLite history (git-ignored)

## Safety notes

- Forwarded messages and web pages are treated as **untrusted** (the prompt guards against injection, and page text is labeled).
- The sandbox uses a fresh context and blocks downloads, permissions and requests to private/loopback IPs (SSRF), with hard timeouts. **For a public deployment, run the browser in a disposable container too.**
- On Render, Railway or Fly (or with `SCAMCHECK_ENV=production`), the server won't start without its Anthropic key, Twilio credentials and an https `PUBLIC_BASE_URL`, and it rejects any webhook without a valid Twilio signature. Unsigned webhooks are accepted only when running locally, so you can test with curl.
- **OTP shield.** People often forward a real OTP SMS to ask whether it's genuine. ScamCheck hides the code (OTPs, UPI PINs, MPINs) the moment a message arrives, before anything is logged, stored, streamed or sent to Claude. The person's first reply is a warning: never share a code, not even with ScamCheck, and if someone asked for it, it's a scam. Amounts, phone numbers, dates and postal PIN codes are left alone, because they're evidence.
- ScamCheck never submits complaints and never asks for OTPs, PINs or passwords. It only drafts the complaint for the user to file.
- Verdicts are advice, not certainty. When in doubt, the reply errs toward caution.

## Ideas for next steps

- Hindi voice-note input (WhatsApp audio → speech-to-text)
- Seed `check_indicator_history` with public data (e.g. the government's Chakshu reports, if an export becomes available)
- An eval set of labeled real/fake messages to measure accuracy
- Deploy to Render/Railway with a Dockerfile; move to the Meta WhatsApp Cloud API for production
