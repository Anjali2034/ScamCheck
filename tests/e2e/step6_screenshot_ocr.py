"""End-to-end: screenshot OCR (English, Hindi, dark mode) through the real server and a real browser upload."""
import atexit
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests
from PIL import Image, ImageDraw, ImageFont

results = []
SCRATCH = Path(tempfile.mkdtemp(prefix="scamcheck-e2e-"))


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))


def screenshot(path, lines, dark=False):
    font = ImageFont.truetype("arial.ttf", 30)
    img = Image.new("RGB", (720, 140 + 54 * len(lines)), (11, 20, 26) if dark else (255, 255, 255))  # WhatsApp dark bg
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((20, 30, 700, 70 + 54 * len(lines)), 18, fill=(31, 44, 52) if dark else (220, 248, 198))
    for i, line in enumerate(lines):
        d.text((40, 50 + 54 * i), line, fill=(233, 237, 239) if dark else (17, 27, 33), font=font)
    img.save(path)
    return path


kyc = screenshot(SCRATCH / "kyc_dark.png", ["Dear Customer, your SBI YONO", "account will be BLOCKED today.",
                                            "Update PAN: http://sbi-kyc-update.xyz"], dark=True)
otp = screenshot(SCRATCH / "otp.png", ["Your OTP for HDFC Bank NetBanking", "login is 482913. Do not share",
                                       "it with anyone. -HDFC Bank"])

repo = Path(__file__).resolve().parents[2]
runtime_before = {p for p in (repo / "runtime").rglob("*") if p.is_file()}
env = {**os.environ, "SCAMCHECK_ENV": "development", "GROQ_API_KEY": ""}
proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "scamcheck.server:app", "--port", "8793"], env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
atexit.register(lambda: proc.poll() is None and proc.kill())
BASE = "http://127.0.0.1:8793"
for _ in range(360):
    try:
        requests.get(BASE + "/api/health", timeout=1)
        break
    except requests.ConnectionError:
        time.sleep(0.5)

from playwright.sync_api import sync_playwright  # noqa: E402

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={"width": 412, "height": 915})  # a phone
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(BASE + "/demo")

    t = time.monotonic()
    page.set_input_files("#image", str(kyc))
    page.click("#go")
    page.wait_for_selector("#result .verdict h2", timeout=120000)
    secs = time.monotonic() - t
    trace = page.inner_text("#trace").lower()
    check("Dark-mode WhatsApp screenshot, no typed text -> read on the server", "reading the screenshot" in trace)
    check("...and caught as a scam", "SCAM" in page.inner_text("#result .verdict h2"), page.inner_text("#result")[:300])
    check("...with the fake SBI domain in the evidence", "not an official state bank of india" in page.inner_text("#result").lower())
    print(f"      ({secs:.1f}s end to end)")

    page.click("#reset")
    page.set_input_files("#image", str(otp))
    page.click("#go")
    page.wait_for_selector("#result .verdict", timeout=120000)
    # text_content includes collapsed <details> (raw tool results); the page's own <script> holds a sample with this code.
    whole = page.locator("#trace").text_content() + page.locator("#result").text_content()
    check("OTP screenshot: warning card shown in the trace", page.locator("#trace .ev.notice").count() == 1)
    check("OTP screenshot: the code appears nowhere on the page", "482913" not in whole)
    check("OTP screenshot: WhatsApp preview leads with the warning",
          page.inner_text("#result .wa").lstrip().startswith("🔐"), page.inner_text("#result .wa")[:120])
    check("No JavaScript errors", not errors, str(errors))
    b.close()

runtime_after = {p for p in (repo / "runtime").rglob("*") if p.is_file()}
new_files = [str(p.relative_to(repo)) for p in runtime_after - runtime_before]
check("Uploaded screenshots were never written to disk", not any(f.endswith(".png") for f in new_files)
      and all("screenshots" in f for f in new_files), str(new_files))

proc.kill()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
