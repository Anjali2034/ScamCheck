"""The same scam gets the same answer whether it's written in English, Hindi or Hinglish."""
import pytest

from scamcheck import rules
from scamcheck.tools import scripts

# The same message three ways, as scammers actually write them. Each must match the same script just as strongly.
SAME_SCAM = {
    "digital_arrest": (
        "This is CBI officer. A money laundering case is registered on your Aadhaar. Join video call immediately or you "
        "will be under digital arrest. Do not tell anyone.",
        "मैं सीबीआई अधिकारी बोल रहा हूँ। आपके आधार कार्ड से मनी लॉन्ड्रिंग केस दर्ज हुआ है। तुरंत वीडियो कॉल पर जुड़ें "
        "वरना आपको डिजिटल अरेस्ट किया जाएगा। किसी को मत बताना।",
        "Main CBI officer bol raha hu. Aapke Aadhaar se money laundering case darj hua hai. Turant video call pe aao "
        "warna digital arrest hoga. Kisi ko mat batana.",
    ),
    "task_scam": (
        "Part time job offer! Like YouTube videos and earn Rs 3000 daily. Complete the prepaid task to unlock "
        "commission. Contact HR on Telegram.",
        "पार्ट टाइम जॉब! यूट्यूब वीडियो लाइक करें और रोज़ ₹3000 कमाएं। कमीशन पाने के लिए प्रीपेड टास्क पूरा करें। "
        "एचआर से टेलीग्राम पर संपर्क करें।",
        "Ghar baithe part time job! YouTube videos like karo aur roz Rs 3000 kamao. Commission ke liye prepaid task "
        "complete karo. HR se Telegram pe baat karo.",
    ),
    "fake_kyc": (
        "Dear customer, your SBI KYC has expired. Your account will be blocked today. Update your PAN now and share the "
        "OTP with our officer.",
        "प्रिय ग्राहक, आपका एसबीआई केवाईसी समाप्त हो गया है। आपका खाता आज बंद हो जाएगा। अभी पैन अपडेट करें और ओटीपी "
        "हमारे अधिकारी को बताएं।",
        "Dear customer, aapka SBI KYC expire ho gaya hai. Aapka account aaj band ho jayega. Abhi PAN update karo aur OTP "
        "hamare officer ko batao.",
    ),
    "investment_scam": (
        "Join our VIP stock tips group. Guaranteed returns of 30% monthly. To withdraw your profit, pay the tax first.",
        "हमारे वीआईपी स्टॉक टिप्स ग्रुप से जुड़ें। हर महीने 30% गारंटीड रिटर्न। मुनाफ़ा निकालने के लिए पहले टैक्स भरें।",
        "Hamare VIP stock tips group join karo. Har mahine 30% guaranteed return. Profit withdraw karne ke liye pehle "
        "tax bharo.",
    ),
    "utility_disconnection": (
        "Dear consumer, your electricity will be disconnected tonight at 9.30 pm because your previous month bill was "
        "not updated. Contact our electricity officer 9123456780.",
        "प्रिय उपभोक्ता, आपकी बिजली आज रात 9.30 बजे काट दी जाएगी क्योंकि पिछले महीने का बिल अपडेट नहीं हुआ है। "
        "हमारे बिजली अधिकारी से संपर्क करें 9123456780।",
        "Priya upbhokta, aapki bijli aaj raat 9.30 baje kat jayegi kyunki pichle mahine ka bill update nahi hua. "
        "Electricity officer ko call karo 9123456780.",
    ),
    "courier_customs": (
        "India Post: your parcel is on hold due to incomplete address. Pay the redelivery fee of Rs 25 to release it.",
        "इंडिया पोस्ट: अधूरे पते के कारण आपका पार्सल रुका हुआ है। इसे छुड़ाने के लिए ₹25 री-डिलीवरी फीस भरें।",
        "India Post: aapka parcel incomplete address ki wajah se hold pe hai. Redelivery fee Rs 25 bharo.",
    ),
    "lottery_prize": (
        "Congratulations! You have won Rs 25 lakh in the KBC lottery. Pay the processing fee of Rs 4999 to claim your "
        "prize.",
        "बधाई हो! आपने केबीसी लॉटरी में 25 लाख रुपये जीते हैं। इनाम पाने के लिए ₹4999 प्रोसेसिंग फीस भेजें।",
        "Badhai ho! Aap ne KBC lottery mein 25 lakh jeete hain. Prize lene ke liye 4999 processing fee bhejiye.",
    ),
    "upi_refund_collect": (
        "Sir I sent Rs 5000 to you by mistake. I have sent a collect request for the refund, please approve it and "
        "enter your UPI PIN to receive it back.",
        "सर मैंने गलती से आपको ₹5000 भेज दिए। रिफंड के लिए रिक्वेस्ट भेजी है, उसे अप्रूव करें और पैसे वापस पाने के लिए "
        "अपना यूपीआई पिन डालें।",
        "Sir maine galti se aapko 5000 bhej diye. Refund ke liye request bheji hai, approve karo aur paise wapas paane "
        "ke liye UPI PIN daalo.",
    ),
    "sextortion": (
        "We have recorded your private video. Pay Rs 20000 or we will make it viral and send it to your family.",
        "हमने आपका प्राइवेट वीडियो रिकॉर्ड किया है। ₹20000 दो वरना इसे वायरल कर देंगे और आपके परिवार को भेज देंगे।",
        "Humne aapka private video record kiya hai. 20000 do warna video viral kar denge aur family ko bhej denge.",
    ),
    "loan_app": (
        "Your pre-approved loan of Rs 2 lakh is ready. Instant loan without documents. Pay the processing fee of Rs 999 "
        "to get the money.",
        "आपका ₹2 लाख का प्री-अप्रूव्ड लोन तैयार है। बिना दस्तावेज़ के तुरंत लोन। पैसा पाने के लिए ₹999 लोन प्रोसेसिंग फीस भरें।",
        "Aapka 2 lakh ka pre-approved loan ready hai. Bina documents ke instant loan. Paisa paane ke liye 999 loan "
        "processing fee bharo.",
    ),
}
LANGS = ("English", "Hindi", "Hinglish")
RANK = {"weak": 0, "moderate": 1, "strong": 2}


def _match(text: str, script_id: str) -> dict | None:
    return next((m for m in scripts.match_scam_scripts(text)["matches"] if m["id"] == script_id), None)


@pytest.mark.parametrize("script_id", SAME_SCAM)
def test_every_language_is_recognised_as_the_same_scam(script_id):
    for lang, text in zip(LANGS, SAME_SCAM[script_id]):
        assert _match(text, script_id), f"{lang} version of {script_id} not recognised"


@pytest.mark.parametrize("script_id", SAME_SCAM)
def test_hindi_and_hinglish_are_never_weaker_than_english(script_id):
    strengths = {lang: (_match(t, script_id) or {}).get("strength") for lang, t in zip(LANGS, SAME_SCAM[script_id])}
    english = RANK[strengths["English"]]
    assert all(RANK.get(s, -1) >= english for s in strengths.values()), strengths


@pytest.mark.parametrize("script_id", SAME_SCAM)
def test_the_reply_is_in_the_language_it_was_written_in(script_id):
    assert [rules.language(t) for t in SAME_SCAM[script_id]] == list(LANGS)


@pytest.mark.parametrize("text", [
    "मेरा पार्सल कल आ जाएगा, इंडिया पोस्ट वाले ने फ़ोन किया था।",          # a real delivery update
    "बिजली का बिल 1240 रुपये आया है, कल भर दूँगा।",                         # a real bill
    "आज रात 9 बजे वीडियो कॉल करेंगे, सबको बता देना।",                      # a family video call
    "Kal se part time job shuru, office Sector 18 mein hai.",              # a real job
    "Please send the video to the family group, everyone wants to see the wedding.",
    "शादी का वीडियो परिवार वालों को भेज दो, सब देखना चाहते हैं।",
    "I took a loan to get a new bike, EMI starts next month.",
    "Pay the school fee by Friday or the late fine applies.",
])
def test_ordinary_messages_arent_called_scams(text):
    assert scripts.match_scam_scripts(text)["matches"] == []


def test_a_mistaken_transfer_is_only_a_gentle_hint():
    # Genuine, but it's also how the fake "sent by mistake, please return it" scam opens; "check your bank app
    # first" is fair advice, a scam verdict isn't.
    for text in ("Maine galti se tumhe 500 bhej diye, wapas bhej dena please.", "I sent you Rs 500 by mistake, please return it."):
        assert all(m["strength"] == "weak" for m in scripts.match_scam_scripts(text)["matches"])


def test_a_video_going_viral_isnt_blackmail():
    for text in ("Our dance video went viral!", "हमारा वीडियो वायरल हो गया!", "Apna video viral ho gaya yaar"):
        assert scripts.match_scam_scripts(text)["matches"] == []


@pytest.mark.parametrize("script_id", SAME_SCAM)
def test_the_classic_version_of_each_scam_is_recognised_strongly(script_id):
    assert [(_match(t, script_id) or {}).get("strength") for t in SAME_SCAM[script_id]] == ["strong"] * 3
