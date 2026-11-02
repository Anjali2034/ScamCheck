"""Read the text out of a screenshot, on this server (Tesseract: free, and the image never leaves the machine).

Images are only held in memory for the read; they are never saved or sent anywhere.
"""
import io
import os
import re
from functools import lru_cache

import pytesseract
from PIL import Image, ImageOps, ImageStat, UnidentifiedImageError

from scamcheck import config

pytesseract.pytesseract.tesseract_cmd = config.TESSERACT_CMD
MIN_CHARS = 15            # less than this is a photo, a sticker or noise, not a message
MAX_SIDE = 3000           # phone screenshots fit; bigger images are shrunk so a 512 MB server can't be flooded
TIMEOUT_SECONDS = 20


@lru_cache(maxsize=1)
def _languages() -> str:
    """'eng+hin' when Hindi data exists, 'eng' otherwise, '' when Tesseract isn't installed."""
    if (config.TESSDATA_DIR / "eng.traineddata").exists():
        # An env var, not --tessdata-dir: on Windows pytesseract passes that flag's quotes through literally.
        os.environ["TESSDATA_PREFIX"] = str(config.TESSDATA_DIR)
    try:
        langs = set(pytesseract.get_languages())
    except (pytesseract.TesseractNotFoundError, pytesseract.TesseractError, OSError):
        return ""
    return "eng+hin" if "hin" in langs else "eng" if "eng" in langs else ""


def available() -> bool:
    return bool(_languages())


def _prepare(img: Image.Image) -> Image.Image:
    img = ImageOps.exif_transpose(img).convert("L")
    if max(img.size) > MAX_SIDE:
        img.thumbnail((MAX_SIDE, MAX_SIDE))
    if ImageStat.Stat(img).mean[0] < 110:
        img = ImageOps.invert(img)  # dark mode (light text on a dark background) reads badly as-is
    if img.width < 1000:
        img = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)  # small screenshots: Tesseract likes ~30 px text
    return ImageOps.autocontrast(img)


def read_text(data: bytes) -> dict:
    """{"status": ok | no_text | unreadable | unavailable, "text": ...}"""
    langs = _languages()
    if not langs:
        return {"status": "unavailable", "text": ""}
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        text = pytesseract.image_to_string(_prepare(img), lang=langs, timeout=TIMEOUT_SECONDS)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, RuntimeError, pytesseract.TesseractError):
        return {"status": "unreadable", "text": ""}
    text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    text = re.sub(r"[ \t]{2,}", " ", text)
    return {"status": "ok" if len(text) >= MIN_CHARS else "no_text", "text": text, "languages": langs}
