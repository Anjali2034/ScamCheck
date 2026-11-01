import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = Path(__file__).resolve().parent / "data"
RUNTIME_DIR = ROOT / "runtime"
SCREENSHOT_DIR = RUNTIME_DIR / "screenshots"
DB_PATH = RUNTIME_DIR / "scamcheck.db"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

def is_production(env=os.environ) -> bool:
    """Every mistake lands on the safe side: only an explicit 'development' (or running locally) relaxes security."""
    value = (env.get("SCAMCHECK_ENV") or "").strip().lower()  # blank counts as unset (common in hosting dashboards)
    if not value:
        # Hosting platforms set these on every deploy, so forgetting SCAMCHECK_ENV can't leave a public server open.
        return any(env.get(v) for v in ("RENDER", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME"))
    return value not in ("development", "dev")  # 'prod', 'staging', typos: all protected


IS_PRODUCTION = is_production()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = os.getenv("SCAMCHECK_MODEL", "claude-opus-5-5")
EFFORT = os.getenv("SCAMCHECK_EFFORT", "medium")
MAX_AGENT_TURNS = int(os.getenv("SCAMCHECK_MAX_TURNS", "12"))

SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "")  # e.g. https://abcd.ngrok-free.app
# Only these WhatsApp numbers show their full investigation (message text, reasoning, screenshots) in the
# public live feed. Everyone else appears there as tool names and a verdict only.
DEMO_NUMBERS = {"whatsapp:+" + n.strip().lstrip("+") for n in os.getenv("DEMO_NUMBERS", "").split(",") if n.strip()}

HTTP_TIMEOUT = 12
