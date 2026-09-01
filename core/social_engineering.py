"""
social_engineering.py
----------------------
Detects psychological-manipulation signals in a message: urgency, fear,
authority impersonation, credential/OTP requests, reward bait, etc.

This is the "don't just detect malicious URLs, detect manipulation" layer
called for in the product docs. Matching is deterministic keyword/phrase
matching over EN + TA lists (data/keywords_en.json, data/keywords_ta.json)
run in parallel over the same raw text, so code-mixed messages
("KYC update seiyavum") get hits from both matchers.
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

CATEGORY_LABELS = {
    "urgency": "Urgency",
    "account_threat": "Account Threat",
    "reward_bait": "Reward / Prize Bait",
    "authority_impersonation": "Authority Impersonation",
    "otp_request": "OTP Request",
    "credential_request": "Credential Request",
    "kyc_request": "KYC / Verification Request",
    "payment_request": "Payment Request",
    "job_scam": "Job Offer Bait",
    "lottery_scam": "Lottery / Prize Claim",
    "investment_scam": "Investment Promise",
    "delivery_scam": "Delivery / Courier Pretext",
    "romance_scam": "Romance / Trust Bait",
    "fear_threat": "Fear / Threat",
    "bank_finance": "Banking / Finance Mention",
}


def _load_json(name: str) -> dict:
    with open(DATA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def _compile_en(keywords_en: dict) -> dict:
    """Word-boundary regex per category for English (ASCII) phrases."""
    compiled = {}
    for category, phrases in keywords_en.items():
        if category.startswith("_"):
            continue
        patterns = [re.escape(p) for p in phrases]
        # \b works fine for ASCII phrases; phrases may contain spaces/apostrophes.
        compiled[category] = re.compile(r"(?<![a-z0-9])(" + "|".join(patterns) + r")(?![a-z0-9])",
                                         re.IGNORECASE)
    return compiled


@dataclass
class SocialEngineeringResult:
    categories_detected: list = field(default_factory=list)   # ['urgency', 'kyc_request', ...]
    matches: dict = field(default_factory=dict)                # category -> [matched phrases]
    score_0_100: int = 0
    label_summary: list = field(default_factory=list)          # human labels, for UI chips

    def to_dict(self) -> dict:
        return {
            "categories_detected": self.categories_detected,
            "matches": self.matches,
            "score_0_100": self.score_0_100,
            "label_summary": self.label_summary,
        }


class SocialEngineeringDetector:
    """
    Loads EN + TA keyword taxonomies once and reuses them across scans.
    Instantiate once per process (the Flask app does this at startup).
    """

    # Tier 1: the message is asking for something dangerous *right now*
    # (credentials, money, urgent account action).
    CRITICAL_CATEGORIES = {
        "otp_request", "credential_request", "payment_request",
        "account_threat", "kyc_request",
    }
    # Tier 2: recognized scam archetypes -- specific enough patterns that
    # matching one is meaningful evidence on its own, even without an
    # explicit credential/payment ask in the same message.
    ARCHETYPE_CATEGORIES = {
        "job_scam", "investment_scam", "lottery_scam", "delivery_scam",
        "government_impersonation", "romance_scam", "reward_bait",
        "authority_impersonation",
    }
    # Tier 3: supporting context -- real signal, but weak/ambiguous alone
    # (e.g. "urgent" shows up in plenty of legitimate messages too).
    # Everything else in the taxonomy falls here by default.

    def _tier_value(self, category: str) -> int:
        if category in self.CRITICAL_CATEGORIES:
            return 34
        if category in self.ARCHETYPE_CATEGORIES:
            return 30
        return 14

    def __init__(self):
        self.keywords_en = _load_json("keywords_en.json")
        self.keywords_ta = _load_json("keywords_ta.json")
        self._en_patterns = _compile_en(self.keywords_en)

    def _match_tamil(self, text: str) -> dict:
        hits = {}
        for category, phrases in self.keywords_ta.items():
            if category.startswith("_"):
                continue
            found = [p for p in phrases if p in text]
            if found:
                hits.setdefault(category, []).extend(found)
        return hits

    def _match_english(self, text: str) -> dict:
        hits = {}
        for category, pattern in self._en_patterns.items():
            found = pattern.findall(text)
            if found:
                # normalize case for display
                hits.setdefault(category, []).extend(sorted(set(m.lower() for m in found)))
        return hits

    def analyze(self, text: str) -> SocialEngineeringResult:
        if not text or not text.strip():
            return SocialEngineeringResult()

        en_hits = self._match_english(text)
        ta_hits = self._match_tamil(text)

        matches: dict[str, list[str]] = {}
        for src in (en_hits, ta_hits):
            for cat, phrases in src.items():
                matches.setdefault(cat, [])
                for p in phrases:
                    if p not in matches[cat]:
                        matches[cat].append(p)

        categories_detected = sorted(matches.keys())

        # Scoring: each detected category contributes at its tier value
        # (see CRITICAL_CATEGORIES / ARCHETYPE_CATEGORIES above).
        raw = sum(self._tier_value(cat) for cat in categories_detected)
        score = min(100, raw)

        label_summary = [CATEGORY_LABELS.get(c, c) for c in categories_detected]

        return SocialEngineeringResult(
            categories_detected=categories_detected,
            matches=matches,
            score_0_100=score,
            label_summary=label_summary,
        )


if __name__ == "__main__":
    det = SocialEngineeringDetector()
    samples = [
        "உங்கள் வங்கி கணக்கு முடக்கப்படும். KYC update செய்ய இந்த link-ஐ click செய்யவும்.",
        "Congratulations! You have won \u20b950,000. Pay \u20b9499 processing fee to claim your prize.",
        "Hey, are we still on for lunch tomorrow?",
    ]
    for s in samples:
        r = det.analyze(s)
        print(f"\n{s}")
        print(f"  categories: {r.label_summary}")
        print(f"  score: {r.score_0_100}")
