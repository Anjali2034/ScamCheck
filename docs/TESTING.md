# Testing ScamCheck yourself

A hands-on script for trying ScamCheck the way a real person would. The full run takes about 45 minutes; sections 2 and 3 alone take about 20. Each test says what to do, what you should see, and what to notice.

Write down anything that feels slow, confusing, scary or unkind, not just what's broken. That's how the next fixes get chosen.

## 0. Before you start: things to keep in mind

- **The AI words every reply a little differently.** Judge the *verdict* (the coloured heading) and whether the advice fits. Don't judge the exact sentences: running the same message twice gives two phrasings. Only report the wording if it's wrong, scary or in the wrong language.
- **Never open a link from a scam message yourself,** not even a test one. ScamCheck opens it in a throwaway browser and shows you a screenshot; that's the point.
- **Don't call or pay any number or UPI ID** in the samples. They're made up, but a made-up number can belong to a real person.
- **Use made-up details.** OTPs are hidden automatically, but there's no need to paste your real account number, Aadhaar or a real OTP.
- **30 checks per 10 minutes per network.** After that you'll see "Too many checks from your network". That's the flood guard working, not a bug. Wait 10 minutes, or restart the local server, which resets it.
- **About 150 AI checks a day** come free from Groq. If you see "Today's free AI checks are used up", the answer came from the rules alone. That's expected, and everything else should still work.
- **Local vs live.** Your laptop runs whatever code is on disk. The live site, https://scamcheck-h6pe.onrender.com, only has what's been pushed, and it's slower: links take about 12 s instead of 5–8 s, and the first check after a deploy takes up to a minute.
- **Each person counts once for "seen before".** If you check the same scam ten times, it's still one report, and your own reports are never shown back to you. To see "1 other person who checked … got a scam result", the second check has to come from a different network (see section 5).

## 1. Start it on your laptop (2 minutes)

In PowerShell:

```powershell
cd C:\dev\ScamCheck
.\.venv\Scripts\Activate.ps1
$env:SCAMCHECK_DB = "runtime\manual-test.db"    # a fresh history, just for this session
uvicorn scamcheck.server:app --port 8000
```

Leave that window open and go to **http://localhost:8000**. You should see "Is this a scam?", a text box and a **Check it** button.

- **To stop:** press `Ctrl+C` in the PowerShell window.
- **To start completely fresh** (empty history and limits): stop the server, delete `runtime\manual-test.db`, and start it again.
- **If `uvicorn` isn't found,** the `Activate.ps1` line didn't run. Run it again and look for `(.venv)` at the start of the prompt.
- **If the port is busy,** use `--port 8001` and open http://localhost:8001.

## 2. The core checks

Copy each message into the box, tap **Check it**, then tap **Check something else** before the next one. That button starts a fresh conversation, as a new visitor would get.

| # | Paste this | You should see | Notice |
|---|---|---|---|
| 1 | `Dear customer your SBI KYC expired. Update now at http://sbi-kyc-update.xyz or account will be blocked today` | Red **scam** heading. Reasons include the fake SBI website. A screenshot of what the link opens. "What to do" says don't click. | Can you tell what to do without scrolling? |
| 2 | `Your Amazon order #402-1234567 has been delivered. Track it at https://www.amazon.in/your-orders` | Green **safe**. The link is recognised as Amazon's own. | Does a genuine message feel reassuring, not alarming? |
| 3 | `Hi! Here are the photos from Sunday: https://example.org/photos` | Grey **Couldn't tell for sure**. Calm advice like "check with the sender on a number you already have". **No** "block" or "report". | Is it proportionate? It must never say "safe" just because nothing bad was found. |
| 4 | `Check this out https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.org%2F&status_code=302` | "🔗 This link really goes to **example.org**". | It stands in for a bit.ly link. Make a real bit.ly link to a harmless page and try that too. |
| 5 | `Badhai ho! Aap ne KBC lottery mein 25 lakh jeete hain. Prize lene ke liye 4999 processing fee bhejiye 9876543210 par` | **Scam** heading and reply in Hinglish (Hindi in English letters). Scam type: "Lottery / KBC / gift prize". | Does the reply sound like the message? |
| 6 | `आपके आधार कार्ड से मनी लॉन्ड्रिंग केस दर्ज हुआ है। CBI अधिकारी से तुरंत वीडियो कॉल पर बात करें वरना आपको डिजिटल अरेस्ट किया जाएगा।` | Hindi heading, at least **लगभग पक्का धोखा** (very likely a scam). Scam type in Hindi: "डिजिटल अरेस्ट / नकली पुलिस या एजेंसी". | Same strength as the English version in #7a? |
| 7a | `This is CBI officer. A money laundering case is registered on your Aadhaar. Join video call immediately or you will be under digital arrest. Do not tell anyone.` | **Very likely a scam** or stronger. | Compare with #6: the same scam should get the same answer. |
| 7b | `Dear consumer your electricity power will be disconnected tonight at 9.30 pm because your previous month bill was not updated. Please contact our electricity officer immediately 9123456780` | **Very likely a scam** or stronger. Scam type in plain words: "Electricity / gas bill disconnection", never a code like `utility_scams`. | Is the scam-type line readable? |
| 8 | `Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank` | A warning on top: never share a code. The code shows as `[OTP hidden]` everywhere. | Is the warning clear without being scary? |
| 9 | `Is refund.claim@ybl safe? They said they will return my money if I accept the request` | **Very likely a scam**. A reason says accepting a request *sends* money. The reply says "UPI ID", never "email". | Would someone who doesn't know how UPI works understand why? |
| 10 | `Your SBI KYC expired. Pay Rs 10 to refund.help@ybl now or your account will be blocked today.` | **Very likely a scam**. A reason says banks never collect money through a UPI ID sent in a message. | |
| 11 | `Pay ₹450 to rahul.k@okaxis for dinner, thanks!` | **Couldn't tell for sure**, with calm advice. **No** "block", "report" or "cybercrime". | This is the most common real message. Does the reply treat your friend like a friend? |
| 12 | `Maine galti se tumhe 500 bhej diye, wapas bhej dena please.` | **Couldn't tell for sure** or **suspicious**, and never "call 1930": nobody here has lost money. | It's genuine, but it's also how a known scam opens, so a gentle warning is fine. Now try `Maine galti se scammer ko 5000 bhej diye, wapas kaise milenge?`: that person *has* lost money and must get the call-1930 card. |
| 13 | `शादी का वीडियो परिवार वालों को भेज दो, सब देखना चाहते हैं।` | **Couldn't tell for sure**, nothing alarming. | An ordinary Hindi message must not trip the scam patterns. |
| 14 | Just a number: `+44 7911 123456` | Notes that it's a UK number, and that Indian banks and agencies don't contact people from foreign numbers. | Does a bare number get a useful answer? |

**The same scam in three languages.** For a quick consistency check, the file `tests\test_languages.py` has each of the 10 scam types written in English, Hindi and Hinglish. Paste a few: all three versions of each should get the same heading.

## 3. Journeys

### "I already paid"

1. Check message 1 again.
2. Tap **I already paid or shared a code**. The box fills with "I already paid ₹". Add `4999 by UPI yesterday` and tap **Check it**.
3. You should see:
   - A red **📞 Call 1930 now** card at the top.
   - Below it, a complaint ready to copy. Tap **Copy complaint**: it should say "✓ Copied". Paste it into Notepad. The `[FILL IN]` parts are what the person still has to add.
4. On a phone, tapping the call button should open the dialler with 1930 already in it. Don't call.

Notice: if you'd just lost money, is the first thing you see the right thing?

### A victim with nothing to paste

1. Tap **Check something else**, type `Mere paise kat gaye` and tap **Check it**. You should see the red **📞 Call 1930 now** card, the heading **Abhi kadam uthaiye**, and a complaint draft. Try `I got scammed` and `मेरे पैसे चले गए` as well.
2. Now try `I never shared my OTP` and `Your money will be deducted today`. Neither should show the 1930 card: nobody has lost anything.

### A fresh start every time

1. Check message 6 (Hindi).
2. **Reload the page** (F5), paste message 3 and check it. It must get the grey "Couldn't tell for sure" in English, with no trace of the Hindi scam.
3. Check message 1, then tap **Check something else** and check message 11. The second result must stand on its own.

### Checking the same thing again

1. Check message 10 three times.
2. All three should give the same verdict, and none should say "1 other person who checked it…": your own checks never count against you.

### Screenshots

1. Make a screenshot of message 1 or 7b. Type it into WhatsApp or Notes and screenshot it. Make one in **dark mode** too.
2. Tap **🖼️ Add screenshot**, check the preview appears, then tap **Check it**.
3. Try these too:

| Try | Expected |
|---|---|
| A screenshot of Hindi text (message 6) | Read and judged in Hindi |
| A screenshot with no text (a photo of your desk) | A polite "couldn't read any text, please paste it" |
| A PDF or other file | "That file isn't an image" |
| A very large photo straight from the camera | It's shrunk on the phone first, then checked |

## 4. The page itself

Go through each of these:

- [ ] **हिंदी / English** toggle (top right): does everything switch? Reload: does the choice stick?
- [ ] **Empty box:** tap **Check it** with nothing pasted. You should get a gentle hint, not an error.
- [ ] **Double tap:** tap **Check it** twice quickly. It should run only once; the button says "Checking…".
- [ ] **📋 Paste** button: does it paste, or ask you to long-press if the browser blocks it?
- [ ] **While waiting:** do the progress lines make sense to someone who isn't technical? Does anything move within a second?
- [ ] **Offline:** turn the Wi-Fi off and check something. You should see "Couldn't reach ScamCheck", not a frozen spinner.
- [ ] **Long message:** paste a whole page of text. Does it cope?
- [ ] **Looks:** dark mode, a small phone, the phone's largest text size. Does anything overlap or get cut off?
- [ ] **Back button** after a result: does it do what you'd expect?
- [ ] **More reasons / How we checked:** do they open and close, and make sense?

## 5. On your phone, and on the live site

**Your laptop's server, from your phone** (same Wi-Fi):

1. Start the server with `uvicorn scamcheck.server:app --host 0.0.0.0 --port 8000`.
2. Run `ipconfig` and find the laptop's **IPv4 Address**, for example `192.168.1.5`.
3. Open `http://192.168.1.5:8000` on the phone. If Windows asks about the firewall, allow **private networks** only.

**The live site:** open https://scamcheck-h6pe.onrender.com on your phone. Try the core checks and the "I already paid" journey with your thumb, the way a real user would.

**"Seen before" by another person:** this needs two different networks.

1. On the **live site**, check message 10 from your laptop on Wi-Fi.
2. Check `Someone asked me to pay refund.help@ybl, is it ok?` from your phone on **mobile data**, not Wi-Fi.
3. The phone should show a reason like "1 other person who checked refund.help@ybl on ScamCheck got a scam result."

Note that every deploy wipes the live history.

## 6. The developer view

- **http://localhost:8000/demo** shows sample messages, every check's raw result as it runs, and a **Live feed** tab. Open the feed in a second tab, check something on the main page, and watch it appear. Other people's checks show only the verdict and which checks ran, never the message.
- **http://localhost:8000/api/health** shows what's configured and how much of today's free AI is left.

## 7. The automated tests

These are what a reviewer would run:

```powershell
pytest                          # offline unit tests, under a minute, no internet needed
python tests\e2e\run_all.py     # end-to-end suites against a real server and browser, about 10 minutes, needs internet
python tests\e2e\run_all.py 8   # just one suite (8 = the public page)
```

All of them should pass. A failure prints which check failed and why.

## 8. Writing down what you find

One line per finding is enough:

```
#11 | phone | reply said "verify with your bank", odd for a dinner bill | confusing
Paid journey | live site | nothing moved for 6 s after tapping Check it | felt broken
```

Include the test number, the device, what happened, and how it felt. "Felt broken", "confusing" or "annoying" is useful even without a reason. Note the time too if something was slow.
