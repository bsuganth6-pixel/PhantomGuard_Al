"""
language_detector.py
---------------------
Deterministic language identification for PhantomGuard AI.

Design choice: script-range detection instead of a statistical language-ID
model. This is intentional, not a shortcut -- the product's stated design
principle is that detection signals should be explainable and should not
depend on a black-box model. Unicode block membership is 100% inspectable:
you can always point at *which characters* triggered a language call.

MVP scope: Tamil + English (see docs). The TAMIL_RANGES / registration
pattern below is built so adding Hindi (Devanagari), Telugu, or Malayalam
later is a ~5-line change, not a rewrite.
"""

from __future__ import annotations
from dataclasses import dataclass, field

# (start, end) inclusive Unicode code point ranges per script.
SCRIPT_RANGES = {
    "ta": [(0x0B80, 0x0BFF)],   # Tamil
    "hi": [(0x0900, 0x097F)],   # Devanagari (Hindi) -- stretch, detection only
    "te": [(0x0C00, 0x0C7F)],   # Telugu -- stretch, detection only
    "ml": [(0x0D00, 0x0D7F)],   # Malayalam -- stretch, detection only
}

LANGUAGE_NAMES = {
    "ta": "Tamil",
    "en": "English",
    "hi": "Hindi",
    "te": "Telugu",
    "ml": "Malayalam",
    "mixed": "Code-mixed",
    "unknown": "Unknown",
}


@dataclass
class LanguageResult:
    primary: str                     # ISO-ish code: 'ta', 'en', 'mixed', 'unknown'
    primary_name: str                # Human-readable name
    scripts_detected: list = field(default_factory=list)   # e.g. ['ta', 'en']
    script_char_counts: dict = field(default_factory=dict) # e.g. {'ta': 42, 'en': 18}
    confidence: float = 0.0          # 0-1, share of primary script among letter chars
    is_code_mixed: bool = False

    def to_dict(self) -> dict:
        return {
            "primary": self.primary,
            "primary_name": self.primary_name,
            "scripts_detected": self.scripts_detected,
            "script_char_counts": self.script_char_counts,
            "confidence": round(self.confidence, 3),
            "is_code_mixed": self.is_code_mixed,
        }


def _script_of_char(ch: str) -> str | None:
    cp = ord(ch)
    for lang, ranges in SCRIPT_RANGES.items():
        for start, end in ranges:
            if start <= cp <= end:
                return lang
    if ch.isascii() and ch.isalpha():
        return "en"
    return None


def detect_language(text: str) -> LanguageResult:
    """
    Detect the language(s) present in `text` by script.

    Returns a LanguageResult. If two or more scripts each account for
    >= CODE_MIX_THRESHOLD of letter characters, primary is 'mixed' and
    both scripts are listed in scripts_detected -- this matters for
    PhantomGuard because scam messages routinely interleave Tamil framing
    with English loanwords ("KYC update seiyavum", "OTP kudukka vendaam").
    """
    CODE_MIX_THRESHOLD = 0.15

    counts: dict[str, int] = {}
    if not text or not text.strip():
        return LanguageResult(primary="unknown", primary_name=LANGUAGE_NAMES["unknown"])

    for ch in text:
        lang = _script_of_char(ch)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1

    total = sum(counts.values())
    if total == 0:
        return LanguageResult(primary="unknown", primary_name=LANGUAGE_NAMES["unknown"])

    ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    top_lang, top_count = ordered[0]
    confidence = top_count / total

    scripts_detected = [lang for lang, c in ordered if (c / total) >= CODE_MIX_THRESHOLD]
    is_code_mixed = len(scripts_detected) > 1

    primary = "mixed" if is_code_mixed else top_lang

    return LanguageResult(
        primary=primary,
        primary_name=LANGUAGE_NAMES.get(primary, primary),
        scripts_detected=scripts_detected,
        script_char_counts=counts,
        confidence=confidence,
        is_code_mixed=is_code_mixed,
    )


if __name__ == "__main__":
    samples = [
        "உங்கள் வங்கி கணக்கு முடக்கப்படும். KYC update செய்ய இந்த link-ஐ click செய்யவும்.",
        "Your account will be blocked. Click here to verify KYC immediately.",
        "Hello, how are you today?",
    ]
    for s in samples:
        r = detect_language(s)
        print(f"{s[:50]!r:55} -> {r.primary_name} (confidence={r.confidence:.2f}, mixed={r.is_code_mixed})")
