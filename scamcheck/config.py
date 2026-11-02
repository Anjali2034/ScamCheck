import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = Path(__file__).resolve().parent / "data"
RUNTIME_DIR = ROOT / "runtime"
SCREENSHOT_DIR = RUNTIME_DIR / "screenshots"
DB_PATH = Path(os.getenv("SCAMCHECK_DB") or RUNTIME_DIR / "scamcheck.db")  # the "seen before" history
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

def is_production(env=os.environ) -> bool:
    """Every mistake lands on the safe side: only an explicit 'development' (or running locally) relaxes security."""
    value = (env.get("SCAMCHECK_ENV") or "").strip().lower()  # blank counts as unset (common in hosting dashboards)
    if not value:
        # Hosting platforms set these on every deploy, so forgetting SCAMCHECK_ENV can't leave a public server open.
        return any(env.get(v) for v in ("RENDER", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME"))
    return value not in ("development", "dev")  # 'prod', 'staging', typos: all protected


IS_PRODUCTION = is_production()

# Free tier, no card: https://console.groq.com/keys. Without a key, verdicts come from rules alone.
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
MODEL = os.getenv("SCAMCHECK_MODEL", "openai/gpt-oss-120b")
GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")  # overridden only by end-to-end tests


def _int(name: str, default: int) -> int:
    """A limit from the environment. A typo or blank keeps the default rather than turning the limit off."""
    try:
        return max(0, int(os.getenv(name, "").strip()))
    except ValueError:
        return default


# Free-tier budgets (see quota.py). Defaults leave headroom under Groq's 200K tokens/day and Meta's 1,000 free
# service messages/month per number.
AI_DAILY_TOKENS = _int("SCAMCHECK_AI_DAILY_TOKENS", 180_000)
AI_CHECKS_PER_PERSON_PER_DAY = _int("SCAMCHECK_AI_CHECKS_PER_PERSON", 25)
WEB_CHECKS_PER_NETWORK_PER_10_MIN = _int("SCAMCHECK_WEB_CHECKS_PER_10_MIN", 30)
WHATSAPP_MONTHLY_MESSAGES = _int("SCAMCHECK_WHATSAPP_MONTHLY_MESSAGES", 950)
WHATSAPP_CHECKS_PER_NUMBER_PER_DAY = _int("SCAMCHECK_WHATSAPP_CHECKS_PER_DAY", 40)
# Where people go when WhatsApp is out of free replies. Render sets RENDER_EXTERNAL_URL itself.
PUBLIC_URL = (os.getenv("SCAMCHECK_PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").rstrip("/")

# Screenshot OCR (Tesseract, free, on this machine). Docker installs it system-wide; on Windows it isn't on PATH.
_WINDOWS_TESSERACT = Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")
TESSERACT_CMD = os.getenv("TESSERACT_CMD") or (str(_WINDOWS_TESSERACT) if _WINDOWS_TESSERACT.exists() else "tesseract")
TESSDATA_DIR = RUNTIME_DIR / "tessdata"  # optional local language data (e.g. Hindi) when the system install lacks it

SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# WhatsApp Cloud API (Meta, free). The test number can reply to up to 5 numbers registered in the Meta dashboard.
# All four are needed together; with none, ScamCheck runs web-only.
WHATSAPP_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_APP_SECRET = os.getenv("WHATSAPP_APP_SECRET", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_API_VERSION = os.getenv("WHATSAPP_API_VERSION", "v26.0")
WHATSAPP_API_BASE = os.getenv("WHATSAPP_API_BASE", "https://graph.facebook.com")  # overridden only by end-to-end tests
# Only these WhatsApp numbers show their full investigation (message text, reasoning, screenshots) in the
# public live feed. Everyone else appears there as tool names and a verdict only.
DEMO_NUMBERS = {"+" + n.strip().lstrip("+") for n in os.getenv("DEMO_NUMBERS", "").split(",") if n.strip()}

HTTP_TIMEOUT = 12
