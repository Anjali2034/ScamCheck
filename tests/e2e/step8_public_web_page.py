"""End-to-end checks for step #8 (public mobile web page): a real server, a real phone-sized browser. Run with tests/e2e/run_all.py."""
import atexit
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests
from PIL import Image, ImageDraw, ImageFont

results = []
SCRATCH = Path(tempfile.mkdtemp(prefix="scamcheck-e2e-"))
KYC = "Dear Customer your SBI YONO account will be BLOCKED today due to incomplete KYC. Update PAN: http://sbi-kyc-update.xyz/login"
HINDI = "प्रिय ग्राहक, आपका बिजली कनेक्शन आज रात 9 बजे काट दिया जाएगा। तुरंत 9876543210 पर कॉल करें।"
HINGLISH = "Congratulations! Aapne 25 lakh ki KBC lottery jeeti hai. Prize lene ke liye 5000 rs processing fee bhejo"


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


def start(port, env):
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", str(port)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(lambda: proc.poll() is None and proc.kill())
    for _ in range(360):
        try:
            requests.get(f"http://127.0.0.1:{port}/api/health", timeout=1)
            break
        except requests.ConnectionError:
            time.sleep(0.5)
    return proc


# A long phone screenshot saved as a big PNG (> 5 MB): the page must shrink it before uploading.
font = ImageFont.truetype("arial.ttf", 44)
big = Image.new("RGB", (1440, 6000), (255, 255, 255))
d = ImageDraw.Draw(big)
for i, line in enumerate(["Dear Customer, your SBI YONO", "account will be BLOCKED today.", "Update PAN: http://sbi-kyc-update.xyz"]):
    d.text((60, 80 + 70 * i), line, fill=(17, 27, 33), font=font)
rnd = random.Random(1)
px = big.load()
for y in range(400, 6000):  # photo-like noise below the message makes the PNG big
    for x in range(0, 1440, 2):
        g = 200 + rnd.randrange(56)
        px[x, y] = (g, g - rnd.randrange(30), g)
BIG = SCRATCH / "big_screenshot.png"
big.save(BIG)
(SCRATCH / "notes.txt").write_text("not an image")

env = {**os.environ, "SCAMCHECK_ENV": "development", "GROQ_API_KEY": ""}  # rules only: deterministic
proc = start(8798, env)
BASE = "http://127.0.0.1:8798"

check("GET / serves the public page", "Is this a scam?" in requests.get(BASE + "/").text)
check("GET /demo still serves the developer console", "Live feed" in requests.get(BASE + "/demo").text)
check(f"Big test screenshot really is over 5 MB ({BIG.stat().st_size / 1e6:.1f} MB)", BIG.stat().st_size > 5 * 1024 * 1024)

from playwright.sync_api import sync_playwright  # noqa: E402


def no_sideways_scroll(page):
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def submit(page, text):
    page.fill("#text", text)
    page.click("#go")
    page.wait_for_selector("#result .verdict h2, #result .msg, #result .card", timeout=150000)


with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 360, "height": 740}, is_mobile=True, has_touch=True, locale="en-IN",
                        permissions=["clipboard-read", "clipboard-write"])
    page = ctx.new_page()
    errors, requests_seen = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.on("request", lambda r: requests_seen.append(r.url))
    page.goto(BASE)

    check("Small phone (360 px): nothing scrolls sideways", no_sideways_scroll(page))
    small = page.evaluate("""[...document.querySelectorAll('button, a.btn')].filter(b => b.offsetParent)
        .filter(b => b.getBoundingClientRect().height < 40).map(b => b.textContent)""")
    check("Every visible button is big enough to tap (>= 40 px)", not small, str(small))

    page.click("#go")
    check("Empty check: says what to do, sends nothing", page.is_visible("#formerr")
          and "Paste a message" in page.inner_text("#formerr") and not any("/api/investigate" in u for u in requests_seen))

    # Fake KYC link: the full happy path.
    page.fill("#text", KYC)
    page.click("#go")
    page.wait_for_selector("#progress li", timeout=20000)
    check("While checking: progress shows plain-language steps", "Finding links" in page.inner_text("#progress"))
    check("While checking: the button can't be pressed twice", page.is_disabled("#go"))
    page.wait_for_selector("#result .verdict h2", timeout=150000)
    head = page.inner_text("#result .verdict h2")
    check("Verdict heading is plain words, not a code", head in ("This is a scam", "Very likely a scam"), head)
    check("Focus moves to the verdict (screen readers announce it)", page.evaluate("document.activeElement.id") == "vh")
    card = page.inner_text("#result").lower()
    check("'What to do' comes before 'Why'", 0 < card.find("what to do") < card.find("why"), card[:300])
    check("Why: names the fake SBI website", "not an official state bank of india website" in card)
    check("Why: at most 4 reasons up front, the rest folded", page.locator("#result .verdict > .why li").count() <= 4
          and (page.locator("#result .verdict > details .why li").count() > 0) == ("more reasons" in card))
    check("Developer details are folded away", not page.is_visible("#result .checks"))
    page.click("#result summary >> text=How we checked")
    how = page.inner_text("#result .checks")
    check("'How we checked' lists the checks in plain words", "Opening the link safely" in how and "Checking who owns the website" in how, how)
    check("No raw JSON on the public page", "{" not in page.inner_text("body"))
    check("Textbox is cleared for the next message", page.input_value("#text") == "")
    check("With a verdict on screen: still no sideways scroll", no_sideways_scroll(page))

    # "I already paid" follow-up keeps the conversation and gets the 1930 card plus a complaint.
    page.click("#paid")
    check("'I already paid' pre-fills the box and explains what to add",
          page.input_value("#text") == "I already paid ₹" and page.is_visible("#paid-hint"))
    page.type("#text", "4,999 via PhonePe at 3 pm")
    page.click("#go")
    page.wait_for_selector("#result a.call", timeout=150000)
    check("Paid: big 'Call 1930 now' button comes first and dials 1930",
          page.get_attribute("#result a.call", "href") == "tel:1930"
          and page.evaluate("document.querySelector('#result').firstElementChild.contains(document.querySelector('a.call'))"))
    check("Paid: complaint has the amount and the scam website", "4,999" in page.inner_text("#complaint")
          and "sbi-kyc-update" in page.inner_text("#complaint"))
    page.click("#copy")
    clip = page.evaluate("navigator.clipboard.readText()")
    check("Copy complaint puts it on the clipboard", "4,999" in clip and page.inner_text("#copy") == "✓ Copied")
    check("Paid: no 'I already paid' button any more", page.locator("#paid").count() == 0)

    page.click("#again")
    check("'Check something else' clears the screen and focuses the box",
          page.inner_text("#result") == "" and page.evaluate("document.activeElement.id") == "text")
    submit(page, "I already paid ₹200")
    check("...and really starts a new conversation (old scam forgotten)", "sbi-kyc-update" not in (
        page.inner_text("#complaint") if page.locator("#complaint").count() else ""))
    page.click("#again")

    # The verdict speaks the person's language.
    submit(page, HINDI)
    head = page.inner_text("#result .verdict h2")
    check("Hindi message: Hindi verdict heading", head in ("यह धोखा है", "लगभग पक्का धोखा"), head)
    page.click("#again")
    submit(page, HINGLISH)
    head = page.inner_text("#result .verdict h2")
    check("Hinglish message: Hinglish verdict heading", head in ("Yeh scam hai", "Lagbhag pakka scam"), head)
    check("Hinglish message: Hinglish advice (rules)", "mat bhejiye" in page.inner_text("#result .todo"))

    # Page language toggle; remembered on reload; the verdict on screen re-renders.
    page.click("#lang")
    check("Hindi toggle: page chrome in Hindi", page.inner_text("h1") == "क्या यह धोखा है?" and "क्या करें" in page.inner_text("#result"))
    check("...the verdict heading keeps the message's language", page.inner_text("#result .verdict h2") in ("Yeh scam hai", "Lagbhag pakka scam"))
    page.reload()
    check("...remembered after reload", page.inner_text("h1") == "क्या यह धोखा है?")
    page.click("#lang")
    page.click("#again") if page.locator("#again").count() else None

    # OTP: warned first, the code never shows.
    submit(page, "Your OTP for HDFC Bank NetBanking login is 482913. Do not share it with anyone. -HDFC Bank")
    check("OTP message: warning shown above the verdict", page.is_visible("#notice") and "one-time code" in page.inner_text("#notice"))
    check("OTP message: the code appears nowhere on the page", "482913" not in page.content())
    page.click("#again")

    submit(page, "hi")
    check("'hi' gets the help text, not a verdict", "Forward me" in page.inner_text("#result") and page.locator("#result .verdict").count() == 0)
    page.click("#again") if page.locator("#again").count() else page.evaluate("startOver()")

    # Screenshots.
    page.set_input_files("#image", str(SCRATCH / "notes.txt"))
    check("Non-image file: friendly message, nothing attached", "isn't an image" in page.inner_text("#formerr") and not page.is_visible("#thumb"))
    page.set_input_files("#image", str(BIG))
    page.wait_for_selector("#thumb:not([hidden])", timeout=20000)
    check("Big screenshot is shrunk in the browser (under 5 MB)", page.evaluate("image.size") < 5 * 1024 * 1024,
          str(page.evaluate("image.size")))
    page.click("#unshot")
    check("'Remove' takes the screenshot off", not page.is_visible("#thumb"))
    page.set_input_files("#image", str(BIG))
    page.wait_for_selector("#thumb:not([hidden])", timeout=20000)
    page.click("#go")
    page.wait_for_selector("#result .verdict h2, #result .msg", timeout=150000)
    check("Screenshot-only check: read on the server and judged a scam",
          page.locator("#result .verdict.bad").count() == 1, page.inner_text("#result")[:300])
    page.click("#again")

    # When things go wrong.
    page.route("**/api/investigate", lambda r: r.abort())
    submit(page, KYC)
    check("Offline: friendly message, button usable again", "Check your internet" in page.inner_text("#result") and not page.is_disabled("#go"))
    page.unroute("**/api/investigate")
    errors = [e for e in errors if "ERR_FAILED" not in e]  # the abort we just caused

    def slow(route):
        time.sleep(7)
        route.continue_()
    page.route("**/api/investigate", slow)
    page.fill("#text", KYC)
    page.click("#go")
    page.wait_for_selector("text=Starting up", timeout=10000)
    check("Sleeping free server: says it's starting up instead of looking frozen", True)
    page.wait_for_selector("#result .verdict h2", timeout=150000)
    check("...and the verdict still arrives", page.locator("#result .verdict h2").count() == 1)
    page.unroute("**/api/investigate")

    # A live page: the sandbox screenshot is shown so the person never has to open the link.
    page.click("#again")
    submit(page, "Is this genuine? https://example.com/login")
    check("Shows what the link opens (sandbox screenshot), so they needn't tap it",
          page.locator("#result .shot img").count() == 1 and page.evaluate(
              "document.querySelector('#result .shot img').naturalWidth > 100"), page.inner_text("#result")[:300])

    check("No JavaScript or console errors", not errors, str(errors))
    ctx.close()

    # Dark mode and a larger phone.
    ctx = b.new_context(viewport={"width": 412, "height": 915}, color_scheme="dark", is_mobile=True)
    page = ctx.new_page()
    page.goto(BASE)
    bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    check("Dark mode: dark background", bg == "rgb(15, 18, 22)", bg)
    submit(page, KYC)
    check("Dark mode: verdict renders", page.locator("#result .verdict.bad").count() == 1)
    page.screenshot(path=str(SCRATCH / "fix8_dark.png"), full_page=True)
    ctx.close()

    # Phone language Hindi: the page opens in Hindi.
    ctx = b.new_context(viewport={"width": 360, "height": 740}, locale="hi-IN")
    page = ctx.new_page()
    page.goto(BASE)
    check("Phone set to Hindi: page opens in Hindi", page.inner_text("h1") == "क्या यह धोखा है?")
    ctx.close()
    b.close()
proc.kill()

# One run with the real AI, to see the page with a live reply.
if os.getenv("GROQ_LIVE") == "1":
    proc = start(8799, {**os.environ, "SCAMCHECK_ENV": "development"})
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page(viewport={"width": 360, "height": 740}, is_mobile=True)
        page.goto("http://127.0.0.1:8799")
        submit(page, HINGLISH)
        check("Live AI: Hinglish heading and Hinglish advice", page.inner_text("#result .verdict h2") in ("Yeh scam hai", "Lagbhag pakka scam"),
              page.inner_text("#result")[:400])
        print("      advice:", page.inner_text("#result .todo"))
        page.screenshot(path=str(SCRATCH / "fix8_live.png"), full_page=True)
        b.close()
    proc.kill()

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
