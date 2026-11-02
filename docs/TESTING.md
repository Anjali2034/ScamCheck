# Testing ScamCheck yourself

A hands-on script for trying ScamCheck the way a real person would. It takes about 30 minutes. Each test says what to do, what you should see, and what to notice. Note anything that feels slow, confusing or unkind, not just what's broken: that's how the next fixes get chosen.

## 1. Start it on your laptop (2 minutes)

In PowerShell:

```powershell
cd C:\dev\ScamCheck
.\.venv\Scripts\Activate.ps1
$env:SCAMCHECK_DB = "runtime\manual-test.db"    # a fresh history, just for this session
uvicorn scamcheck.server:app --port 8000
```

Leave that window open and go to **http://localhost:8000**. To stop, press `Ctrl+C`. To start over with an empty "seen before" history, stop the server and delete `runtime\manual-test.db`.

**Why the separate database?** ScamCheck remembers links, numbers and UPI IDs from earlier scam verdicts. If you check the same message ten times, it later says "flagged in 10 earlier checks", which makes later results stricter than a real user would see.

**On your phone (same Wi-Fi):** start it with `uvicorn scamcheck.server:app --host 0.0.0.0 --port 8000`, run `ipconfig` to find the laptop's IPv4 address (like `192.168.1.5`), and open `http://192.168.1.5:8000` on the phone. If Windows asks about the firewall, allow **private networks** only. You can also test the live site, https://scamcheck-h6pe.onrender.com, but it only has what's been pushed.

## 2. Test like a user

Copy each message into the box and tap **Check it**. Times are from a laptop. On the live site, a check with a link takes about 12 seconds.

| # | Paste this | You should see | Notice |
|---|---|---|---|
| 1 | `Dear customer your SBI KYC expired. Update now at http://sbi-kyc-update.xyz or account will be blocked today` | Red **scam** card. Reasons include the fake SBI domain. "What to do" says don't click. A screenshot of what the link opens. | Does the first line tell you what to do without scrolling? |
| 2 | `Your Amazon order #402-1234567 has been delivered. Track it at https://www.amazon.in/your-orders` | Green **safe**. The link is recognised as Amazon's. | Does a genuine message feel reassuring, not alarming? |
| 3 | `Hi! Here are the photos from Sunday: https://example.org/photos` | Grey **can't confirm** (INCONCLUSIVE). It should never say "safe" just because nothing bad was found. | Is the advice proportionate? It may still say "block the sender", which is heavy for a friend's link. |
| 4 | `Check this out https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.org%2F&status_code=302` | "🔗 This link really goes to **example.org**". | The link is a stand-in for a bit.ly link. Make a real bit.ly link to a harmless page and try that too. |
| 5 | `Badhai ho! Aap ne KBC lottery mein 25 lakh jeete hain. Prize lene ke liye 4999 processing fee bhejiye 9876543210 par` | **Scam**, with the reply in Hinglish. | Does the reply's language match how the message was written? |
| 6 | `आपके आधार कार्ड से मनी लॉन्ड्रिंग केस दर्ज हुआ है। CBI अधिकारी से तुरंत वीडियो कॉल पर बात करें वरना आपको डिजिटल अरेस्ट किया जाएगा।` | Reply in Hindi. Recognised as digital arrest. | Known issue: this gets only **suspicious**, while the same scam in English gets **likely scam**. |
| 7 | `Dear consumer your electricity power will be disconnected tonight at 9.30 pm because your previous month bill was not updated. Please contact our electricity officer immediately 9123456780` | **Scam**, recognised as the electricity cut-off scam. | Look at the small scam-type line. Known issue: it can show a code like `utility_scams` instead of plain words. |
| 8 | `Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank` | A warning first: never share a code. The code is hidden as `[OTP hidden]` everywhere. | Is the warning clear without being scary? |
| 9 | `Is refund.claim@ybl safe? They said they will return my money if I accept the request` | It should say "scam": accepting a UPI request sends money, it never receives it. | Known issue: this currently says **can't confirm** and calls the UPI ID "the email". |
| 10 | Just a number: `+44 7911 123456` | Notes that it's a foreign number. | Does a bare number get a useful answer? |

### The "I already paid" journey

1. Check message 1 again.
2. Tap **I already paid or shared a code**. The box fills with "I already paid ₹". Add `4999 by UPI yesterday` and tap **Check it**.
3. You should see a red **📞 Call 1930 now** card at the top, then a complaint ready to copy. **Copy complaint** should show "✓ Copied". Paste it into Notepad: the `[FILL IN]` parts are what the person still has to add.
4. On a phone, tapping the call button should open the dialler with 1930 (don't call).

Notice: if you'd just lost money, is the first thing you see the right thing?

### Screenshots

1. Make a screenshot of message 1 or 7. You can type it into WhatsApp or Notes and screenshot it. Try one in **dark mode** too.
2. Tap **🖼️ Add screenshot**, check the preview, then tap **Check it**. Try one with no text, and one with Hindi text.
3. Also try a photo taken with the camera, a PDF (it should say it isn't an image) and a very large image (the page shrinks it).

### The page itself

- **हिंदी / English** toggle: does everything switch? Does the choice stick after a refresh?
- **Empty box:** tap Check it with nothing pasted. You should get a gentle hint, not an error.
- **Double tap:** tap Check it twice quickly. It should run only once.
- **Check something else:** does it clear cleanly and put the cursor back in the box?
- **Offline:** turn the Wi-Fi off and check something. You should get a "Couldn't reach ScamCheck" message, not a frozen spinner.
- **Dark mode, small phone, large text size** (phone settings): does anything overlap or get cut off?
- **Back button** after a result: does it behave the way you'd expect?
- **Long message:** paste a whole page of text.
- **While waiting:** do the progress lines make sense to someone who isn't technical?

## 3. The developer view

Go to **http://localhost:8000/demo**. It shows sample messages, every check's raw result as it runs, and the **Live feed** tab. Open the feed in a second tab, check something on the main page, and watch it appear. Other people's checks show only the verdict and which checks ran, never the message.

`http://localhost:8000/api/health` shows what's configured and how much of today's free AI is left.

## 4. The automated tests

These are what a reviewer would run:

```powershell
pytest                          # 100 offline tests, about 1 minute, no internet needed
python tests\e2e\run_all.py     # 165 checks against a real server and browser, about 10 minutes, needs internet
python tests\e2e\run_all.py 8   # just one suite (8 = the public page)
```

All should pass. A failure prints which check failed and why.

## 5. Writing down what you find

One line per finding is enough:

```
#3 | phone | "block the sender" feels too harsh for a friend's link | annoying
Paid journey | laptop | took 9 s and nothing moved for 5 s | felt broken
```

Include the test number, the device, what happened, and how it felt. "Felt broken", "confusing" or "annoying" is useful even without a reason.
