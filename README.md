# 🛡️ ScamCheck

A free scam checker for India. Paste a suspicious SMS, WhatsApp message, link, UPI ID or phone number, or add a screenshot, and ScamCheck runs real checks on it. In a few seconds it replies with a verdict, the evidence behind it, and what to do next, in English, Hindi or Hinglish. If you've already paid, it tells you to call **1930** and drafts your **cybercrime.gov.in** complaint.

**[Try it live](https://scamcheck-h6pe.onrender.com)** · [Developer view](https://scamcheck-h6pe.onrender.com/demo) · [Service status](https://scamcheck-h6pe.onrender.com/api/health) · [Testing guide](docs/TESTING.md)

Indians lost ₹22,495 crore to cyber fraud in 2025, across 28 lakh recorded cases, 24% more cases than in 2024 ([ThePrint](https://theprint.in/india/cybercrime-saw-24-spike-in-2025-indians-lost-rs-22495-crore-mainly-in-investment-scams/2859930/)). Most of these scams follow a handful of known scripts that can be checked automatically.

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Testing](#testing)
- [Deployment](#deployment)
- [Free-tier limits](#free-tier-limits)
- [Security and privacy](#security-and-privacy)
- [Project structure](#project-structure)

## Features

- **Evidence-based verdicts.** Six levels, from *Scam* to *Safe*, each with its reasons. The AI can make a verdict stricter than the checks, never softer.
- **Link investigation.** Detects brand impersonation and look-alike domains, checks domain age (RDAP), opens the page in an isolated phone browser and screenshots it, and follows short links (bit.ly and others) to their real destination.
- **Ten known Indian scam scripts.** Digital arrest, fake KYC, task jobs, investment groups, electricity cut-off, courier fees, KBC lottery, UPI refund tricks, sextortion and loan apps, recognised equally in English, Hindi and Hinglish.
- **Screenshots.** Text is read on the server (Tesseract, English and Hindi, dark mode included), so the image is never sent to a third party.
- **OTP shield.** One-time codes, UPI PINs and MPINs are hidden the moment a message arrives, before anything logs, stores or sends them.
- **"Already paid" help.** A tap-to-call 1930 card and a pre-filled cybercrime.gov.in complaint to copy.
- **Seen before.** Links, numbers and UPI IDs from scam verdicts are remembered, counted once per person, to warn the next person who checks them.
- **Two channels.** A mobile-first web page and WhatsApp (Meta Cloud API).
- **Free to run.** Every service is on a free tier, and the app stays inside each quota by design.

## How it works

1. **Checks run in parallel, in code:**

| Check | What it does | Needs |
|---|---|---|
| `extract_indicators` | Pulls out links, UPI IDs (and whether the handle is a real bank or app), phone numbers, emails, Telegram/wa.me handles and ₹ amounts | none |
| `check_domain` | Brand impersonation of ~30 Indian banks, UPI apps, government sites and couriers (keywords, typosquats, homoglyphs), risky TLDs, punycode, free hosting, and domain age via RDAP | none |
| `follow_redirects` | Where a short link really goes, asked server by server over plain HTTP (no page code runs, private addresses refused). The destination then gets every website check too | none |
| `visit_in_sandbox` | Opens the link in a throwaway headless phone browser (Playwright): redirect chain, final URL, whether it asks for a password, OTP, card or Aadhaar, APK downloads, and a screenshot | none |
| `check_url_reputation` | Google Safe Browsing and VirusTotal | free API keys |
| `match_scam_scripts` | The ten scam scripts above, as weighted cues in English, Hindi and Hinglish, tolerant of OCR errors in Hindi | none |
| `analyse_phone_number` | Foreign numbers posing as Indian agencies, scam-compound regions, the 140 telemarketing series | none |
| `check_indicator_history` | How many *other people* got a scam verdict for this UPI ID, number or domain | none |
| `read_screenshot` | OCR of uploaded screenshots, with OTPs masked before anything else sees the text | Tesseract |

2. **Rules grade the evidence** (critical, high, medium, low, reassuring) into a verdict: SCAM, LIKELY_SCAM, SUSPICIOUS, INCONCLUSIVE, LIKELY_SAFE or SAFE ([rules.py](scamcheck/rules.py)). With no reassuring evidence, an unknown link is *inconclusive*, never *safe*.
3. **One AI call** (`openai/gpt-oss-120b` on Groq) reads the message and the evidence, then writes a short, calm reply in the person's language. It can add up to two observations about the wording, but the evidence sets the floor: a scam text saying "this message is verified safe" can't talk the verdict down.
4. **If the person has paid**, the reply leads with *call 1930* and drafts a complaint with `[FILL IN]` markers for what only they know.

When the free AI quota runs out, the rule-based verdict and reply answer instead, so every check still gets a reply.

```
WhatsApp ──Meta────▶ /webhook/whatsapp ─┐  signed, retries dropped, bursts merged, replies async
Web page ────────▶ /api/investigate ────┼─▶ Investigation (one per conversation)
                    /api/live ◀── events┘        │
                                                 ▼
     screenshots ──▶ on-server OCR ──▶ OTP shield ──▶ text
     parallel checks: extract · domain/RDAP · redirects · reputation · sandbox · scripts · phone · history
                                                 ▼
     rules: graded evidence + verdict ──▶ one Groq call (reply + wording) ──▶ verdict ≥ evidence floor
                                                 ▼
                                complaint draft if paid · history record
```

## Tech stack

| Area | Choice |
|---|---|
| Server | Python 3.12+, FastAPI, Uvicorn |
| AI | Groq free tier (`openai/gpt-oss-120b`), plain HTTP, one call per check |
| Link sandbox | Playwright (headless Chromium) |
| OCR | Tesseract (English and Hindi) |
| Storage | SQLite |
| Messaging | WhatsApp Cloud API (Meta) |
| Front end | One HTML file, no framework or build step |
| Hosting | Docker on Render's free plan |

## Getting started

### Prerequisites

- Python 3.12 or newer
- Optional: [Tesseract](https://github.com/UB-Mannheim/tesseract/wiki) for screenshots (`winget install UB-Mannheim.TesseractOCR` on Windows, `apt install tesseract-ocr tesseract-ocr-hin` on Linux). For Hindi on Windows, put [`hin.traineddata`](https://github.com/tesseract-ocr/tessdata/raw/main/hin.traineddata) and `eng.traineddata` in `runtime/tessdata/`.

### Install and run

```powershell
git clone https://github.com/Anjali2034/ScamCheck.git
cd ScamCheck
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m playwright install chromium
copy .env.example .env      # optional: add a free GROQ_API_KEY
uvicorn scamcheck.server:app --reload --port 8000
```

| URL | What it is |
|---|---|
| http://localhost:8000 | The public page: paste a message or add a screenshot, get a verdict and next steps |
| http://localhost:8000/demo | Developer view: sample messages, every check's raw result as it runs, and a live feed of all channels |
| http://localhost:8000/api/health | What's configured and how much of today's free AI is left |

With no keys at all, everything still runs on the rules alone.

**Command line:** `python -m scamcheck "Your SBI KYC expired, update at http://sbi-kyc.xyz"` (add `--image screenshot.png` for a screenshot). It stays open for follow-ups like "I already paid ₹4,999".

### Configuration

All keys are optional and free. A check whose key is missing is skipped, and a skipped check never counts as a clean result. See [.env.example](.env.example) for every setting.

| Key | Where to get it |
|---|---|
| `GROQ_API_KEY` | https://console.groq.com/keys (no card). About 1,000 requests and 200K tokens a day. Groq states it doesn't train on customer data. |
| `GOOGLE_SAFE_BROWSING_KEY` | A Google Cloud project with the Safe Browsing API enabled |
| `VIRUSTOTAL_API_KEY` | virustotal.com → profile → API key (4 requests a minute) |
| `WHATSAPP_*` | See [WhatsApp](#whatsapp) |

### WhatsApp

Meta gives every developer app a free test number that can reply to up to five registered numbers, with no SIM needed.

1. At [developers.facebook.com](https://developers.facebook.com), create an app (**Other → Business**) and add **WhatsApp**.
2. In **WhatsApp → API Setup**, register the numbers that may use it.
3. Fill in the four `WHATSAPP_*` values in `.env` and restart the server.
4. Expose the server: `cloudflared tunnel --url http://localhost:8000` prints a public `https://….trycloudflare.com` URL.
5. In **WhatsApp → Configuration → Webhook**, set the callback URL to `<that URL>/webhook/whatsapp`, enter your `WHATSAPP_VERIFY_TOKEN`, then subscribe to **messages**.

Each conversation gets blue ticks and "typing…", then one reply. Messages sent within a few seconds of each other are checked together. Send `reset` to start over. Replies never contain a tappable scam link: domains are written as `sbi-kyc[.]xyz` and link previews are off.

## Testing

```powershell
pytest                            # unit tests: offline, no keys, under a minute
python tests\e2e\run_all.py       # end-to-end: real server, browser, sandbox and RDAP (needs internet)
python tests\e2e\run_all.py 3 8   # selected end-to-end suites
```

- **Unit tests** cover the rules, scam scripts in all three languages, the OTP shield, history, quotas, short links and conversations.
- **End-to-end suites** (nine) each start their own server with a throwaway database, then drive it over HTTP, a phone-sized browser and Meta-style webhooks. Groq and Meta are replaced by local stand-ins, so results don't depend on any quota. `GROQ_LIVE=1` adds one check against the real Groq API.
- **Manual testing:** [docs/TESTING.md](docs/TESTING.md) is a step-by-step script for trying it as a user would.

## Deployment

The [Dockerfile](Dockerfile) builds one image containing the app, Chromium for the sandbox and Tesseract with Hindi. [render.yaml](render.yaml) describes a free Render web service in Singapore, the closest region to India.

1. Sign in at [render.com](https://render.com) with GitHub (no card needed).
2. **New → Blueprint**, pick this repository and enter `GROQ_API_KEY`. Leave the WhatsApp fields empty for web only.
3. After the first build, open `https://<your-app>.onrender.com`.
4. Optional: a free [cron-job.org](https://cron-job.org) job that opens `/api/health` every 10 minutes keeps the service awake.

Render's free plan has 512 MB of memory and a tenth of a CPU. To fit, only one sandbox browser runs at a time (peak around 210 MB), and a link that waits more than 25 s is skipped with a note. The disk is wiped on each deploy, which resets the history and the usage counters.

## Free-tier limits

[quota.py](scamcheck/quota.py) keeps ScamCheck inside every free tier. Past a soft limit, every check still runs and only the AI is skipped, and the reply says so.

| Limit | Default | Why |
|---|---|---|
| AI tokens per day | 180,000 | Under Groq's 200K a day, about 150 checks. The last 10% is kept for people who have lost money. |
| AI checks per person per day | 25 | One person can't use up everyone's AI. Someone who has lost money is never cut off. |
| Web checks per network per 10 min | 30 | Stops floods with a polite 429 that still lists the safety basics and 1930. Generous because mobile carriers put many phones behind one address. |
| WhatsApp messages per month | 950 | Under Meta's 1,000 free service messages. The last 50 are kept for OTP warnings and a one-time "use the web page" notice. |
| WhatsApp checks per number per day | 40 | Then one notice, and nothing more that day. |

If Groq rate-limits for more than a few seconds, the AI pauses for as long as Groq asks. Every limit can be changed in `.env`.

## Security and privacy

- **Untrusted input.** Forwarded messages and web pages are treated as untrusted: the prompt says so, page text is labelled, and the evidence floor means injected text can't lower a verdict.
- **Sandbox isolation.** A fresh browser context with downloads, permissions and private-network requests (SSRF) blocked, and hard timeouts. In Docker it runs as a non-root user.
- **Production safeguards.** The server refuses to start without its Groq key or with WhatsApp only partly configured, and rejects any webhook without a valid Meta signature.
- **Minimal data.** Messages and screenshots aren't stored. Sandbox screenshots are deleted after they're shown. "Seen before" stores only scam indicators, and stores people as a keyed hash. The public live feed shows strangers' checks only as tool names and a verdict.
- **No automated actions.** ScamCheck never asks for OTPs, PINs or passwords, and never submits a complaint; it only drafts one.
- **Advice, not certainty.** Verdicts can be wrong. When in doubt, the reply leans toward caution.

## Project structure

```
scamcheck/
├── server.py        FastAPI app: web API, live feed, WhatsApp webhook, sessions
├── agent.py         The investigation: parallel checks, the AI call, the evidence floor, complaints
├── rules.py         Graded evidence, verdicts, rule-based replies, language detection
├── llm.py           Groq client (plain HTTP)
├── quota.py         Free-tier budgets and flood limits
├── ocr.py           Screenshot OCR
├── otp_shield.py    OTP and PIN masking
├── inbox.py         Webhook retry dedupe and message-burst merging
├── whatsapp.py      Meta Cloud API: signatures, parsing, media, sending
├── config.py        Settings from environment variables
├── tools/           One module per check (domain, sandbox, reputation, scripts, extract, history, complaint)
├── data/            Brand domains and scam-script patterns (JSON, editable without code changes)
└── static/          The public page and the developer view
tests/               Unit tests, plus end-to-end suites in tests/e2e/
docs/TESTING.md      Manual testing script
```
