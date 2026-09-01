"""
test_modules.py
------------------
Fast, dependency-free unit tests for individual core modules (as opposed
to test_known_answer.py, which tests the full pipeline end to end). Uses
plain assert + a tiny runner so it works with zero extra packages -- this
sandbox has no network access to install pytest, and there's no reason
these need it anyway.

Run: python3 tests/test_modules.py
"""

from __future__ import annotations
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.language_detector import detect_language
from core.url_analyzer import UrlAnalyzer, extract_urls
from core.social_engineering import SocialEngineeringDetector
from core.scam_classifier import ScamClassifier
from core.risk_engine import RiskEngine, risk_level_for


_PASS, _FAIL = [], []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        _PASS.append(name)
    else:
        _FAIL.append(f"{name}  {detail}")


# ---- language_detector ----

def test_language_detector():
    r = detect_language("Hello, how are you?")
    check("lang: pure English -> en", r.primary == "en", f"got {r.primary}")

    r = detect_language("உங்கள் கணக்கு பாதுகாப்பானது")
    check("lang: pure Tamil -> ta", r.primary == "ta", f"got {r.primary}")

    r = detect_language("KYC update செய்ய இந்த link-ஐ click செய்யவும்")
    check("lang: code-mixed -> mixed", r.primary == "mixed", f"got {r.primary}")

    r = detect_language("")
    check("lang: empty -> unknown", r.primary == "unknown", f"got {r.primary}")


# ---- url_analyzer ----

def test_url_extraction():
    urls = extract_urls("Check this out: https://example.com/path and also www.test.org")
    check("extract: finds two urls", len(urls) == 2, f"got {urls}")

    urls = extract_urls("No links in this sentence at all.")
    check("extract: no false positives on plain text", len(urls) == 0, f"got {urls}")


def test_url_scoring():
    az = UrlAnalyzer()

    f = az.analyze_one("https://www.google.com", "just checking search results")
    check("url: legit domain scores 0", f.score_0_100 == 0, f"got {f.score_0_100}")

    f = az.analyze_one("https://icici-secure-login.net/verify", "ICICI security alert, verify now")
    check("url: brand-padded fake domain flagged", f.brand_domain_mismatch is True)
    check("url: brand-padded fake domain scores high", f.score_0_100 >= 70, f"got {f.score_0_100}")

    f = az.analyze_one("https://sbi.co.in/login", "SBI account login")
    check("url: real-looking bank domain not flagged", f.brand_domain_mismatch is False)

    f = az.analyze_one("http://10.0.0.5/login", "HDFC account verify")
    check("url: IP-based url flagged as ip_based", f.is_ip_based is True)
    check("url: IP + brand mention flagged as mismatch", f.brand_domain_mismatch is True)


# ---- social_engineering ----

def test_social_engineering():
    se = SocialEngineeringDetector()

    r = se.analyze("Hey, are we still on for lunch tomorrow?")
    check("se: casual message has zero categories", len(r.categories_detected) == 0, f"got {r.categories_detected}")
    check("se: casual message scores 0", r.score_0_100 == 0, f"got {r.score_0_100}")

    r = se.analyze("Your account will be blocked. Share the OTP immediately to avoid suspension.")
    check("se: otp_request detected", "otp_request" in r.categories_detected)
    check("se: account_threat detected", "account_threat" in r.categories_detected)

    r = se.analyze("உங்கள் வங்கி கணக்கு முடக்கப்படும்")
    check("se: tamil account_threat detected", "account_threat" in r.categories_detected, f"got {r.categories_detected}")


# ---- scam_classifier ----

def test_scam_classifier():
    clf = ScamClassifier()

    r = clf.classify(["account_threat", "kyc_request", "bank_finance"])
    check("classify: kyc phishing labeled correctly", r.category_id == "kyc_banking_phishing", f"got {r.category_id}")

    r = clf.classify([])
    check("classify: no signals -> generic fallback", r.category_id == "generic_phishing", f"got {r.category_id}")


# ---- risk_engine ----

def test_risk_level_bands():
    check("risk band: 0 -> SAFE", risk_level_for(0)[0] == "SAFE")
    check("risk band: 24 -> SAFE (upper bound)", risk_level_for(24)[0] == "SAFE")
    check("risk band: 25 -> LOW (lower bound)", risk_level_for(25)[0] == "LOW")
    check("risk band: 74 -> SUSPICIOUS (upper bound)", risk_level_for(74)[0] == "SUSPICIOUS")
    check("risk band: 90 -> CRITICAL (lower bound)", risk_level_for(90)[0] == "CRITICAL")
    check("risk band: 100 -> CRITICAL", risk_level_for(100)[0] == "CRITICAL")


def test_risk_engine_no_url_no_se():
    r = RiskEngine().score([], SocialEngineeringDetector().analyze(""))
    check("risk: empty input scores 0", r.total_score == 0, f"got {r.total_score}")


def run_all():
    tests = [
        test_language_detector, test_url_extraction, test_url_scoring,
        test_social_engineering, test_scam_classifier, test_risk_level_bands,
        test_risk_engine_no_url_no_se,
    ]
    for t in tests:
        try:
            t()
        except Exception as e:
            _FAIL.append(f"{t.__name__} raised {e!r}")
            traceback.print_exc()

    print("=" * 70)
    print(f"MODULE TESTS: {len(_PASS)} passed, {len(_FAIL)} failed")
    print("=" * 70)
    if _FAIL:
        print("FAILURES:")
        for f in _FAIL:
            print("  -", f)
    return len(_FAIL) == 0


if __name__ == "__main__":
    ok = run_all()
    sys.exit(0 if ok else 1)
