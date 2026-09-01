"""
ocr_service.py
----------------
Extracts text from screenshots so the same NLP/URL pipeline that handles
pasted messages can run on scam screenshots too (docs: "Screenshot /
Message / URL / QR -> Understand -> Investigate -> Score -> Explain").

Engine: Tesseract via pytesseract (already installed in this environment).

Honest limitation, stated up front rather than silently degraded: this
sandbox only has the English tessdata installed (no network access to fetch
tam.traineddata). The code always *requests* 'eng+tam' first so that on a
real deployment (`apt install tesseract-ocr-tam`) Tamil-script screenshots
work with zero code changes -- it detects the missing language pack and
falls back to English-only, and reports which happened in the result so the
UI can be upfront about it instead of pretending Tamil OCR ran.
"""

from __future__ import annotations
from dataclasses import dataclass, field

import pytesseract
from PIL import Image


def _available_languages() -> set[str]:
    try:
        return set(pytesseract.get_languages(config=""))
    except Exception:
        return {"eng"}


AVAILABLE_LANGS = _available_languages()


@dataclass
class OcrResult:
    text: str = ""
    requested_lang: str = "eng+tam"
    used_lang: str = "eng"
    tamil_available: bool = False
    confidence_note: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class OcrService:
    def __init__(self):
        self.tamil_available = "tam" in AVAILABLE_LANGS

    def extract_text(self, image_path: str) -> OcrResult:
        used_lang = "eng+tam" if self.tamil_available else "eng"
        try:
            img = Image.open(image_path)
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            text = pytesseract.image_to_string(img, lang=used_lang)
            note = (
                "Tamil + English OCR" if self.tamil_available
                else "English-only OCR (Tamil OCR language pack not installed in this "
                     "environment -- install tesseract-ocr-tam to enable; pipeline "
                     "already requests 'eng+tam' and will use it automatically once present)"
            )
            return OcrResult(
                text=text.strip(),
                used_lang=used_lang,
                tamil_available=self.tamil_available,
                confidence_note=note,
            )
        except Exception as e:
            return OcrResult(error=str(e), used_lang=used_lang, tamil_available=self.tamil_available)


if __name__ == "__main__":
    svc = OcrService()
    print("Tamil tessdata available:", svc.tamil_available)
    print("Languages installed:", AVAILABLE_LANGS)
