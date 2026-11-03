# 🛡️ ScamCheck

A free scam checker for people in India. Send it a suspicious SMS, screenshot, link, UPI ID or phone number. It runs a set of real checks in under a few seconds and replies with a verdict, the evidence behind it and what to do. If you've already paid, it tells you to call **1930** and drafts your **cybercrime.gov.in** complaint.

> Indians lost about ₹22,495 crore to cyber fraud in 2025, up 24% on 2024, mostly through investment scams. There have been 38 lakh+ complaints since 2021.

**Runs entirely on free tiers.** One AI call per check (Groq's free tier). When the free quota runs out, a rule-based verdict still answers, so nobody is left without a reply.

## How a check works

1. **Code runs every check in parallel**, with no AI involved:

| Check | What it looks at | Needs |
|---|---|---|
| `read_screenshot` | Reads the text in screenshots (English + Hindi) with Tesseract **on the server**, so the image is never sent anywhere or saved. Dark-mode screenshots are inverted first; OTPs in the image are masked before anything else sees the text. | Tesseract |
| `extract_indicators` | Links, UPI IDs (+ whether the PSP handle is real), phone numbers, emails, Telegram/wa.me handles, ₹ amounts | none |
| `check_domain` | Brand impersonation of ~30 Indian banks, UPI apps, govt sites and couriers (keyword, typosquat and homoglyph checks), shorteners, risky TLDs, punycode, free hosting, **domain age via RDAP** | none |
| `follow_redirects` | Where a short link (bit.ly, tinyurl, cutt.ly… 20 shorteners) really goes, by asking each server in turn (plain HTTP, nothing on the page runs, private addresses refused). The real destination then gets every website check too, and the reply says *"This link really goes to …"*. Pages that forward elsewhere by script are caught by the sandbox visit. "Seen before" remembers the destination and the exact short link, never the shortener itself. | none |
| `check_url_reputation` | Google Safe Browsing + VirusTotal (URL and domain reports) | free API keys |
| `visit_in_sandbox` | Opens the link in a throwaway headless phone browser (Playwright): redirect chain, final URL, whether it asks for password/OTP/card/Aadhaar, APK downloads, screenshot. Skipped for official bank domains. | none |
| `match_scam_scripts` | 10 known scripts: digital arrest, task scam, fake KYC, investment, electricity cut-off, courier, KBC lottery, UPI refund/collect, sextortion, loan apps (English, Hindi and Hinglish cues, tested to give the same answer in all three) | none |
| `analyse_phone_number` | Foreign numbers posing as Indian agencies, scam-compound regions, 140-series | none |
| `check_indicator_history` | How many *other people* got a scam verdict for this UPI ID, number or domain (local SQLite). Each person counts once however often they check, nobody's own checks count against them, and a check that only looks bad because of earlier reports doesn't add one, so a wrong verdict can't snowball. One other person is a hint; two or more is strong. People are stored as a keyed hash. | none |

2. **Rules grade the evidence** (critical / high / medium / low / reassuring) and reach a verdict: SCAM, LIKELY_SCAM, SUSPICIOUS, INCONCLUSIVE, LIKELY_SAFE or SAFE ([rules.py](scamcheck/rules.py)).
3. **One AI call** (`openai/gpt-oss-120b` on Groq) reads the message and the evidence, then writes a calm reply in the person's own language (English, Hindi, Hinglish…). It can add up to two wording observations and fills in the complaint draft. **The AI can make a verdict stricter but never softer than the hard evidence**: a fake bank domain can't be talked into "safe" by a message saying "this is verified safe". It can warn, but only checks can reassure.
4. If the person says they've paid, shared an OTP or installed an app, the reply leads with **call 1930**, and a [FILL IN]-marked complaint is drafted for cybercrime.gov.in.

## Quick start

```powershell
cd ScamCheck
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt; python -m playwright install chromium
copy .env.example .env                # optional: add a free GROQ_API_KEY
uvicorn scamcheck.server:app --reload --port 8000
```

Open http://localhost:8000 for the **public page**, the one real users get: paste a message or add a screenshot and get a plain verdict, what to do, and, if they've paid, a tap-to-call 1930 button and a complaint to copy. It's mobile-first, in English or Hindi (the verdict follows the language the message was written in, Hinglish included), and works in dark mode.

Open http://localhost:8000/demo for the **developer view**: sample messages, every check's raw result as it runs, and the live feed. With no keys at all, everything still works on rules alone.

**Screenshots** need Tesseract (free). On Windows: `winget install UB-Mannheim.TesseractOCR`; ScamCheck finds it in `C:\Program Files\Tesseract-OCR`. For Hindi, put `eng.traineddata` and [`hin.traineddata`](https://github.com/tesseract-ocr/tessdata/raw/main/hin.traineddata) in `runtime/tessdata/`. On Linux: `apt install tesseract-ocr tesseract-ocr-hin`. Without Tesseract, a screenshot gets a polite "please paste the text instead".

**CLI:** `python -m scamcheck "Your SBI KYC expired, update at http://sbi-kyc.xyz"` (add `--image screenshot.png` for a screenshot). It stays open for follow-ups like "I already paid ₹4,999".

**Tests:** `pytest` runs the offline test suite. It needs no API keys or network.

**End-to-end:** `python tests/e2e/run_all.py` runs one suite per build step (165 checks) against a real server, a real phone-sized browser, the sandbox and live RDAP lookups, so it needs internet and Playwright's Chromium. Run a few with `run_all.py 3 8`. None of them call the real AI (step 9 uses a local stand-in for Groq), so results don't depend on the free quota; `GROQ_LIVE=1` adds one check against the real Groq API. Test runs use a throwaway history database, set via `SCAMCHECK_DB`.

## Hooking up WhatsApp (Meta's free test number)

No phone number or SIM needed: Meta gives every developer app a free WhatsApp test number. It can reply to up to 5 numbers you register, which suits demos; the public channel is the web page. Since 1 October 2026 each number gets 1,000 free replies a month, and ScamCheck uses one per check (the "typing…" indicator replaces an acknowledgement message, and it isn't a message).

1. At [developers.facebook.com](https://developers.facebook.com), create an app (**Other → Business**) and add the **WhatsApp** product.
2. In **WhatsApp → API Setup**, add your own WhatsApp number (and up to 4 others) as recipients.
3. Fill in the four `WHATSAPP_*` values in `.env` (see `.env.example` for where each one is), then restart uvicorn.
4. Make your laptop reachable: `cloudflared tunnel --url http://localhost:8000` (free, no account) prints an `https://….trycloudflare.com` URL.
5. In **WhatsApp → Configuration → Webhook**, set the callback URL to `https://….trycloudflare.com/webhook/whatsapp`, type your `WHATSAPP_VERIFY_TOKEN`, click **Verify and save**, then subscribe to the **messages** field.
6. Message the test number. You'll see blue ticks and "typing…", then one verdict. Anything you send in the next few seconds (a follow-up question, more screenshots) is checked together with it. Meta's retries are ignored, as are 👍 reactions and stickers. Send `reset` to start a new conversation.

Replies never contain a tappable scam link (they're written as `sbi-kyc[.]xyz`) and link previews are off, so a warning can't become a one-tap way back to the scam.

**Demo tip:** open the **Live feed** tab at `/demo`. Every investigation streams there, so an audience can watch the checks run while you use your phone. For privacy, strangers' checks show only which tools ran and the verdict. To show your own checks in full (message, screenshots, results), put your number in `DEMO_NUMBERS` in `.env`.

## Deploying free on Render

The [Dockerfile](Dockerfile) builds one image with the app, Chromium for the sandbox and Tesseract with Hindi. [render.yaml](render.yaml) describes a free web service in Render's Singapore region, the closest to India.

1. Sign in at [render.com](https://render.com) with GitHub. No card is needed for the free plan.
2. **New → Blueprint**, pick this repository, and paste `GROQ_API_KEY` when asked. Leave the WhatsApp fields empty for web-only. The server refuses to start in production without the Groq key, or with WhatsApp only partly set up.
3. Wait for the first build (several minutes: the image is large). Open `https://<your-app>.onrender.com`.
4. **Keep it awake (optional):** a free [cron-job.org](https://cron-job.org) job that opens `/api/health` every 10 minutes. Without it, the first visitor after 15 quiet minutes waits about a minute (the page says "Starting up…"). Always on uses about 744 of the workspace's 750 free hours a month, so it leaves almost nothing for a second free service.

**What the free plan means in practice:** 512 MB of memory and a tenth of a CPU, so a check with a link takes longer than on a laptop. To fit, only one sandbox browser runs at a time (measured peak ≈ 210 MB of the app's own memory, whatever the load); a link that waits more than 25 s is skipped and the check says so. The disk is wiped on every redeploy, which resets the "seen before" history and the budget counters. Sandbox screenshots are deleted as soon as they've been shown.

## Getting the free API keys

All optional; each one you leave out is skipped, and a skipped check never counts as a clean result.

- **Groq** (the AI): https://console.groq.com/keys. Free, no card. Free tier: about 30 requests/min, 1,000/day, 8K tokens/min, 200K tokens/day, which is roughly 50 checks a day. Groq states it doesn't train on customer data. (Gemini's free tier was ruled out: Google uses free-tier prompts for training and human review, and people forward personal bank messages here.)
- **Google Safe Browsing:** create a Google Cloud project, enable the "Safe Browsing API", then create an API key.
- **VirusTotal:** sign up, then go to profile → API key (free tier: 4 requests/min, non-commercial use).

## Staying free (quota guard)

Every free tier has a ceiling, and [quota.py](scamcheck/quota.py) keeps ScamCheck under each one. **Nobody hits a dead end:** past a soft limit every check still runs and only the AI is skipped, and the reply says so honestly ("today's free AI checks are used up, so this answer comes from the rule-based checks").

| Limit | Default | Why |
|---|---|---|
| AI tokens per day | 180,000 | Groq's free tier allows 200K/day. A check uses about 1,200 tokens, so that's roughly 150 AI checks a day. **The last 10% is kept for people who say they've lost money**, because the AI fills in their complaint. |
| AI checks per person per day | 25 | One person can't use up everyone's AI. Someone who has lost money is never cut off by this. |
| Web checks per network per 10 min | 30 | Stops floods (a bot, a stuck script) with a kind 429 that still gives safety basics and 1930. Generous on purpose: Jio and Airtel put thousands of phones behind one address (CGNAT). New session ids don't reset it. |
| WhatsApp messages per month | 950 | Meta gives 1,000 free service messages a month per number. The last 50 are kept for OTP warnings and a one-time "out of free replies, use the web page" notice. |
| WhatsApp checks per number per day | 40 | Then one "today's limit" notice and silence, so extra messages don't spend the allowance. |

When Groq answers "too many requests" for longer than a few seconds, the AI is paused for as long as Groq asks, so later checks go straight to rules instead of waiting to be refused. Counts live in the same SQLite file as the history, so a restart doesn't reset them; on Render's free disk a redeploy does, and Groq's own limit is the backstop. `/api/health` shows what's left today. Every limit can be changed in `.env` (see `.env.example`); a typo keeps the default rather than switching the limit off.

## Architecture

```
WhatsApp ──Meta────▶ /webhook/whatsapp ─┐  (signed, dedupes retries, merges bursts, replies async)
Web UI ──────────▶ /api/investigate ────┼─▶ Investigation (per-person session, 30 min)
                    /api/live ◀── events┘        │
                                                 ▼
     screenshots ──▶ on-server OCR ──▶ OTP shield ──▶ text
     parallel checks: extract · domain/RDAP · Safe Browsing/VirusTotal · Playwright sandbox
                      scam scripts · phone · history (SQLite)
                                                 ▼
     rules: graded evidence + verdict ──▶ one Groq call (reply + wording) ──▶ verdict ≥ evidence floor
                                                 ▼
                                complaint draft if paid · history record
```

- `scamcheck/agent.py`: runs the checks in parallel, makes the one AI call, enforces the evidence floor, drafts complaints, formats for WhatsApp
- `scamcheck/rules.py`: graded evidence, verdicts, the floor, rule-based replies (English + Hindi), "already paid" detection
- `scamcheck/llm.py`: the Groq client (plain HTTP, no SDK); any failure means "fall back to rules"
- `scamcheck/tools/`: one file per check
- `scamcheck/ocr.py`: screenshot text via Tesseract (dark-mode inversion, upscaling, size cap, timeout)
- `scamcheck/otp_shield.py`, `scamcheck/inbox.py`: OTP masking; retry dedupe and burst merging
- `scamcheck/data/`: brand domains and scam-script patterns. These are plain JSON, so you can grow them without code changes.
- `scamcheck/server.py`: FastAPI app, sessions, live feed, WhatsApp webhook
- `scamcheck/whatsapp.py`: Meta Cloud API: signature check, message parsing, media download, typing indicator, sending
- `runtime/`: screenshots + SQLite history (git-ignored)

## Safety notes

- Forwarded messages and web pages are treated as **untrusted**: the prompt says so, page text is labelled, and the evidence floor means injected text can't lower a verdict that the checks support.
- The sandbox uses a fresh context and blocks downloads, permissions and requests to private/loopback IPs (SSRF), with hard timeouts. **For a public deployment, run the browser in a disposable container too.**
- On Render, Railway or Fly (or with `SCAMCHECK_ENV=production`), the server won't start without its Groq key or with WhatsApp only partly configured, and it rejects any webhook without a valid Meta signature (`X-Hub-Signature-256`). Unsigned webhooks are accepted only when running locally, so you can test with curl.
- **OTP shield.** People often forward a real OTP SMS to ask whether it's genuine. ScamCheck hides the code (OTPs, UPI PINs, MPINs) the moment a message arrives, before anything is logged, stored, streamed or sent to the AI. The person's first reply is a warning: never share a code, not even with ScamCheck, and if someone asked for it, it's a scam. Amounts, phone numbers, dates and postal PIN codes are left alone, because they're evidence.
- ScamCheck never submits complaints and never asks for OTPs, PINs or passwords. It only drafts the complaint for the user to file.
- Verdicts are advice, not certainty. When in doubt, the reply errs toward caution.

## Ideas for next steps

- Hindi voice-note input (Groq's free Whisper → text)
- Seed `check_indicator_history` with public data (e.g. the government's Chakshu reports, if an export becomes available)
- An eval set of labeled real/fake messages to measure accuracy
- A free hosted database (e.g. a free Postgres tier) so history and budgets survive redeploys
