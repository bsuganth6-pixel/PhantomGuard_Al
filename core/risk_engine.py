"""
risk_engine.py
----------------
Combines URL, social-engineering, and reputation signals into a single
explainable 0-100 risk score. This is the module the whole product's
credibility rests on, so the design constraint from the docs is enforced
literally in code, not just in the pitch: the score is a weighted sum of
*inspectable* sub-scores. No generative-AI call sits anywhere in this file.
An LLM may later be used to phrase the explanation in explanation_engine.py,
but it never computes or adjusts this number.

Weights (configurable, not claimed to be validated -- see docs):
    URL / Domain Intelligence   30%
    Social Engineering          25%
    Scam Language Patterns      20%   (approximated here by SE score again,
                                        see note below)
    Credential / Payment Request 15%  (approximated by presence of
                                        high-weight SE categories)
    Reputation / Local Intel    10%
"""

from __future__ import annotations
from dataclasses import dataclass, field

RISK_LEVELS = [
    (0, 24, "SAFE", "No significant indicators detected."),
    (25, 49, "LOW", "Some suspicious characteristics."),
    (50, 74, "SUSPICIOUS", "Multiple risk indicators."),
    (75, 89, "HIGH", "Strong evidence of scam/phishing behavior."),
    (90, 100, "CRITICAL", "Multiple strong indicators with likely malicious intent."),
]

WEIGHTS = {
    "url_domain": 0.30,
    "social_engineering": 0.25,
    "scam_language": 0.20,
    "credential_payment": 0.15,
    "reputation": 0.10,
}

CREDENTIAL_PAYMENT_SE_CATEGORIES = {
    "otp_request", "credential_request", "payment_request", "kyc_request",
    "job_scam", "investment_scam", "lottery_scam", "delivery_scam",
}


def risk_level_for(score: int) -> tuple[str, str]:
    for lo, hi, label, desc in RISK_LEVELS:
        if lo <= score <= hi:
            return label, desc
    return "SAFE", RISK_LEVELS[0][3]


@dataclass
class RiskBreakdown:
    total_score: int
    risk_level: str
    risk_level_description: str
    sub_scores: dict = field(default_factory=dict)     # component -> 0-100
    weighted_contributions: dict = field(default_factory=dict)  # component -> points contributed
    evidence: list = field(default_factory=list)        # flat, ordered list of evidence strings

    def to_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "risk_level": self.risk_level,
            "risk_level_description": self.risk_level_description,
            "sub_scores": self.sub_scores,
            "weighted_contributions": {k: round(v, 1) for k, v in self.weighted_contributions.items()},
            "evidence": self.evidence,
        }


class RiskEngine:
    def __init__(self, weights: dict | None = None):
        self.weights = weights or WEIGHTS

    def score(
        self,
        url_findings: list | None,       # list[UrlFinding]
        se_result,                        # SocialEngineeringResult
    ) -> RiskBreakdown:
        url_findings = url_findings or []
        known_scam_domain_hit = any(getattr(f, "known_scam_domain", False) for f in url_findings)
        no_url_present = len(url_findings) == 0

        # --- URL / Domain sub-score: worst (max) offending URL wins ---
        url_score = max((f.score_0_100 for f in url_findings), default=0)

        # --- Social engineering sub-score, straight from the detector ---
        se_score = se_result.score_0_100 if se_result else 0

        # --- Scam language patterns: reuse SE score as a proxy signal.
        # (A dedicated statistical scam-language classifier is future work;
        # documented honestly here rather than faked with a second model.)
        scam_language_score = se_score

        # --- Credential / payment request: binary-ish based on high-weight
        # SE categories actually firing, independent of overall SE score.
        credential_categories_hit = (
            set(se_result.categories_detected) & CREDENTIAL_PAYMENT_SE_CATEGORIES
            if se_result else set()
        )
        credential_payment_score = min(100, len(credential_categories_hit) * 60)

        # --- Reputation: local threat-intel hit is the strongest signal we
        # can produce offline; otherwise derive a small score from whether
        # any URL already looked bad on its own merits.
        if known_scam_domain_hit:
            reputation_score = 100
        else:
            reputation_score = min(60, url_score // 2) if url_score else 0

        sub_scores = {
            "url_domain": url_score,
            "social_engineering": se_score,
            "scam_language": scam_language_score,
            "credential_payment": credential_payment_score,
            "reputation": reputation_score,
        }

        # --- Weight redistribution when there's no URL to analyze ---
        # A fixed 40% of the weight budget (url_domain 30% + reputation 10%)
        # sits on signals that are structurally zero for a message with no
        # link at all -- a phone-style OTP-social-engineering text or a job/
        # investment scam pitched in pure prose. Rather than let that silently
        # cap every URL-less scam's ceiling near ~60, redistribute those two
        # weights proportionally across the three message-based signals when
        # there is genuinely no URL to judge (not merely a URL that scored
        # 0 -- that *is* a meaningful "this link looks clean" signal and
        # keeps its normal weight).
        active_weights = dict(self.weights)
        if no_url_present:
            freed = active_weights.pop("url_domain") + active_weights.pop("reputation")
            recipients = ["social_engineering", "scam_language", "credential_payment"]
            recipient_total = sum(self.weights[k] for k in recipients)
            for k in recipients:
                active_weights[k] = self.weights[k] + freed * (self.weights[k] / recipient_total)
            active_weights.setdefault("url_domain", 0.0)
            active_weights.setdefault("reputation", 0.0)

        weighted = {k: sub_scores[k] * active_weights.get(k, 0.0) for k in self.weights}
        base_total = sum(weighted.values())

        # --- Corroboration bonus ---
        # Real fraud-scoring systems treat independently-agreeing evidence
        # families as more-than-additively suspicious: a phishing URL *and*
        # manipulative message language *and* a reputation hit each on their
        # own could be noise, but three unrelated signals all pointing the
        # same way rarely is. Count how many signal *families* independently
        # cleared a "meaningfully suspicious" bar (>=50) and add a bonus per
        # corroborating family beyond the first. This is a deliberate,
        # documented non-linearity -- not a per-example fudge factor.
        strong_families = sum(1 for s in (url_score, se_score, reputation_score) if s >= 50)
        corroboration_bonus = max(0, strong_families - 1) * 8

        total = round(base_total + corroboration_bonus)

        # --- Escalation floor ---
        # Weighted averaging can under-state risk when ONE signal family is
        # overwhelming but the others are quiet -- e.g. a near-certain
        # malicious URL (IP-based + impersonating a named brand) paired with
        # a terse message that happens not to match any keyword phrase
        # verbatim. A url_domain or social_engineering score this extreme is
        # already strong evidence on its own; don't let five-way averaging
        # cut it by more than ~20%. This only engages when a single family
        # is very high (>=85) -- it has no effect on moderate/ambiguous
        # scores, so it doesn't reopen the false-positive door.
        strongest_single_signal = max(url_score, se_score)
        if strongest_single_signal >= 85:
            total = max(total, round(strongest_single_signal * 0.8))

        total = max(0, min(100, total))

        level, desc = risk_level_for(total)

        evidence: list[str] = []
        for f in url_findings:
            evidence.extend(f.evidence)
        if se_result:
            evidence.extend(f"Detected: {label}" for label in se_result.label_summary)

        return RiskBreakdown(
            total_score=total,
            risk_level=level,
            risk_level_description=desc,
            sub_scores=sub_scores,
            weighted_contributions=weighted,
            evidence=evidence,
        )


if __name__ == "__main__":
    from url_analyzer import UrlAnalyzer
    from social_engineering import SocialEngineeringDetector

    text = "உங்கள் வங்கி கணக்கு முடக்கப்படும். KYC update செய்ய இந்த link-ஐ click செய்யவும் https://sbi-kyc-security-update.example.com/login"
    urls = UrlAnalyzer().analyze_text(text)
    se = SocialEngineeringDetector().analyze(text)
    breakdown = RiskEngine().score(urls, se)
    print(f"Score: {breakdown.total_score}/100 -- {breakdown.risk_level}")
    print(f"Sub-scores: {breakdown.sub_scores}")
    print("Evidence:")
    for e in breakdown.evidence:
        print("  -", e)
