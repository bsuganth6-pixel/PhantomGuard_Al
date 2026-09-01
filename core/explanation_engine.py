"""
explanation_engine.py
------------------------
Turns detected signals into the human-facing explanation: what was found,
why it matters, and what to do -- in English always, and in Tamil when the
input was Tamil/code-mixed. Template-based and deterministic on purpose
(see docs' design principle: generative AI, if used at all, only phrases
an already-decided verdict -- it never decides the verdict). That means
this module has zero hallucination risk: every sentence it produces is
built from evidence the other modules already found and can point to.
"""

from __future__ import annotations
from dataclasses import dataclass, field

# Minimal, deliberately-scoped Tamil phrase templates (see keywords_ta.json
# comment -- same "starter set, needs native-speaker review" caveat applies).
TA_TEMPLATES = {
    "critical_or_high": "\u26a0\ufe0f இது ஒரு மோசடி செய்தியாக இருக்கலாம். "
                         "இணைப்பைத் திறக்க வேண்டாம். OTP, PIN அல்லது கடவுச்சொல் கொடுக்க வேண்டாம்.",
    "suspicious": "\u26a0\ufe0f இந்த செய்தியில் சந்தேகத்திற்குரிய அம்சங்கள் உள்ளன. "
                  "எச்சரிக்கையாக இருங்கள், சரிபார்க்காமல் தகவல் பகிர வேண்டாம்.",
    "low": "இந்த செய்தியில் சில அசாதாரண அம்சங்கள் உள்ளன. கவனமாக இருங்கள்.",
    "safe": "இந்த செய்தியில் குறிப்பிடத்தக்க அபாய அறிகுறிகள் இல்லை.",
}

ACTIONS_BY_LEVEL = {
    "CRITICAL": [
        "Do not click the link or open any attachment",
        "Do not enter your OTP, PIN, password, or card details anywhere from this message",
        "Do not make any payment referenced in this message",
        "Verify only through the official app or website you already trust, typed in yourself",
        "Report this message using the Report Scam option",
    ],
    "HIGH": [
        "Do not click the link",
        "Do not share OTP, PIN, or banking details",
        "Verify through the official app or website directly",
        "Consider reporting this message",
    ],
    "SUSPICIOUS": [
        "Treat this message with caution",
        "Do not share sensitive information without verifying independently",
        "If in doubt, contact the organization directly using a number from their official website",
    ],
    "LOW": [
        "No immediate danger detected, but stay alert",
        "Avoid clicking unfamiliar links out of habit",
    ],
    "SAFE": [
        "No action needed based on the indicators PhantomGuard checks",
    ],
}


@dataclass
class Explanation:
    headline: str
    evidence_bullets: list = field(default_factory=list)
    recommended_actions: list = field(default_factory=list)
    tamil_summary: str | None = None
    english_summary: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class ExplanationEngine:
    def build(
        self,
        risk_breakdown,          # RiskBreakdown
        scam_classification,     # ClassificationResult
        language_result,         # LanguageResult
    ) -> Explanation:
        level = risk_breakdown.risk_level
        score = risk_breakdown.total_score

        headline = f"{score}/100 \u2014 {level}"

        actions = ACTIONS_BY_LEVEL.get(level, ACTIONS_BY_LEVEL["SAFE"])

        english_summary = (
            f"{risk_breakdown.risk_level_description} "
            f"Classified as: {scam_classification.category_label}."
            if level != "SAFE"
            else risk_breakdown.risk_level_description
        )

        tamil_summary = None
        wants_tamil = language_result and language_result.primary in ("ta", "mixed")
        if wants_tamil:
            if level in ("CRITICAL", "HIGH"):
                tamil_summary = TA_TEMPLATES["critical_or_high"]
            elif level == "SUSPICIOUS":
                tamil_summary = TA_TEMPLATES["suspicious"]
            elif level == "LOW":
                tamil_summary = TA_TEMPLATES["low"]
            else:
                tamil_summary = TA_TEMPLATES["safe"]

        return Explanation(
            headline=headline,
            evidence_bullets=list(risk_breakdown.evidence),
            recommended_actions=actions,
            tamil_summary=tamil_summary,
            english_summary=english_summary,
        )
