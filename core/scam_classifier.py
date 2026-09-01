"""
scam_classifier.py
--------------------
Names the *kind* of scam ("KYC / Banking Phishing" rather than a bare
"phishing" verdict) by voting the social-engineering categories already
detected against data/scam_categories.json. Deterministic and inspectable:
the category with the most matching signals wins; ties broken by priority.
"""

from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass
class ClassificationResult:
    category_id: str
    category_label: str
    matched_signal_count: int

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class ScamClassifier:
    def __init__(self):
        with open(DATA_DIR / "scam_categories.json", encoding="utf-8") as f:
            self.categories = json.load(f)["categories"]

    def classify(self, detected_se_categories: list[str], url_signals: dict | None = None) -> ClassificationResult:
        """
        detected_se_categories: e.g. ['urgency', 'kyc_request', 'account_threat']
                                 from SocialEngineeringResult.categories_detected
        url_signals: optional dict, currently used only to nudge toward
                     'credential_phishing' when a credential-style URL path
                     was found even without a keyword hit.
        """
        detected_set = set(detected_se_categories)
        best = None
        best_votes = -1

        for cat in self.categories:
            votes = len(detected_set.intersection(cat["signals"]))
            if votes > best_votes or (votes == best_votes and best is not None and cat["priority"] < best["priority"]):
                if votes > 0 or best is None:
                    best = cat
                    best_votes = votes

        if best is None or best_votes == 0:
            if url_signals and url_signals.get("credential_path_hit"):
                for cat in self.categories:
                    if cat["id"] == "credential_phishing":
                        return ClassificationResult(cat["id"], cat["label"], 0)
            fallback = next(c for c in self.categories if c["id"] == "generic_phishing")
            return ClassificationResult(fallback["id"], fallback["label"], 0)

        return ClassificationResult(best["id"], best["label"], best_votes)


if __name__ == "__main__":
    clf = ScamClassifier()
    tests = [
        ["account_threat", "kyc_request", "bank_finance"],
        ["job_scam"],
        ["reward_bait", "payment_request"],
        [],
    ]
    for t in tests:
        r = clf.classify(t)
        print(f"{t} -> {r.category_label} ({r.matched_signal_count} signals)")
