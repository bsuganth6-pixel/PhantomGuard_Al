"""
test_data_generator.py
------------------------
Synthetic known-answer generator, following the same methodology used
across the rest of the Phantom Security toolkit: generate N precisely
labeled examples, then assert exact recall and zero false positives
programmatically -- no eyeballing.

Each generated example carries:
    text            the message to feed the pipeline
    label           'scam' | 'safe'
    category        scam sub-type, or 'legitimate' for safe examples
    min_expected_level   for scams: the minimum RISK_LEVELS label the
                         engine must reach (e.g. 'SUSPICIOUS') for this
                         to count as a correct detection
    lang            'en' | 'ta' | 'mixed' -- for breaking down results
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class LabeledExample:
    text: str
    label: str            # 'scam' | 'safe'
    category: str
    min_expected_level: str | None
    lang: str


# Risk-level ordering, for "did we reach at least X" comparisons.
LEVEL_ORDER = ["SAFE", "LOW", "SUSPICIOUS", "HIGH", "CRITICAL"]


def level_at_least(actual: str, minimum: str) -> bool:
    return LEVEL_ORDER.index(actual) >= LEVEL_ORDER.index(minimum)


# ---------------------------------------------------------------- SCAMS ---

_SCAM_EXAMPLES: list[LabeledExample] = [
    # --- KYC / Banking phishing (English) ---
    LabeledExample(
        "Dear customer, your SBI account will be blocked within 24 hours. "
        "Update your KYC immediately at https://sbi-kyc-security-update.example.com/login",
        "scam", "kyc_banking_phishing", "HIGH", "en"),
    LabeledExample(
        "URGENT: Your HDFC Bank account has been suspended. Verify your account now: "
        "https://hdfc-verify-account.com/secure/login",
        "scam", "kyc_banking_phishing", "HIGH", "en"),
    LabeledExample(
        "Your ICICI net banking will be deactivated today. Click https://icici-secure-login.net/verify "
        "and enter your password to continue using your account.",
        "scam", "kyc_banking_phishing", "HIGH", "en"),

    # --- KYC / Banking phishing (Tamil / code-mixed) ---
    LabeledExample(
        "உங்கள் வங்கி கணக்கு முடக்கப்படும். KYC update செய்ய இந்த link-ஐ click செய்யவும் "
        "https://sbi-kyc-security-update.example.com/login",
        "scam", "kyc_banking_phishing", "HIGH", "mixed"),
    LabeledExample(
        "உங்கள் Paytm கணக்கு இன்றே முடக்கப்படும். KYC புதுப்பிக்க https://paytm-kyc-update.com "
        "பார்வையிடவும்.",
        "scam", "kyc_banking_phishing", "SUSPICIOUS", "mixed"),

    # --- Credential / OTP phishing ---
    LabeledExample(
        "Your bank has detected suspicious login. Share the OTP sent to your phone immediately "
        "to secure your account, or it will be locked.",
        "scam", "credential_phishing", "SUSPICIOUS", "en"),
    LabeledExample(
        "Security alert: enter your net banking password and CVV to verify your identity within "
        "12 hours to avoid account suspension.",
        "scam", "credential_phishing", "HIGH", "en"),

    # --- UPI / payment scam ---
    LabeledExample(
        "Congratulations! You have won Rs 50,000 in the lucky draw. Pay Rs 499 processing fee "
        "to claim your prize now: http://amazon-prize-claim.com/pay",
        "scam", "lottery_scam", "HIGH", "en"),
    LabeledExample(
        "You are a lucky winner! Claim your cashback reward by paying a small activation fee "
        "immediately.",
        "scam", "lottery_scam", "SUSPICIOUS", "en"),

    # --- Job scam ---
    LabeledExample(
        "Work from home job offer! Earn Rs 5000 per day, no experience required, hiring now. "
        "Pay a refundable registration fee to start immediately.",
        "scam", "job_scam", "SUSPICIOUS", "en"),
    LabeledExample(
        "Part time job available, data entry job, daily payout, no experience required. "
        "Limited seats, act now, hiring now.",
        "scam", "job_scam", "LOW", "en"),

    # --- Investment scam ---
    LabeledExample(
        "Guaranteed returns of 30% every month! Double your money in 60 days, risk free "
        "investment opportunity. Act now, limited time offer.",
        "scam", "investment_scam", "SUSPICIOUS", "en"),

    # --- Delivery / courier scam ---
    LabeledExample(
        "Your parcel is on hold at customs. Pay customs duty of Rs 350 immediately to release "
        "your shipment: http://indiapost-parcel-hold.com/pay",
        "scam", "delivery_scam", "HIGH", "en"),
    LabeledExample(
        "Delivery failed, your package is on hold. Reschedule your delivery and pay a small "
        "fee to avoid your parcel being returned.",
        "scam", "delivery_scam", "LOW", "en"),

    # --- Government impersonation ---
    LabeledExample(
        "This is Income Tax Department. Legal action and court notice will be issued against "
        "you within 24 hours unless you pay the pending amount immediately.",
        "scam", "government_impersonation", "SUSPICIOUS", "en"),

    # --- IP-based credential phishing URL, no keyword bait beyond a link ---
    LabeledExample(
        "Bank of Baroda account update pending, verify now: http://192.168.4.55/verify",
        "scam", "kyc_banking_phishing", "HIGH", "en"),
]


# ---------------------------------------------------------------- SAFE ----

_SAFE_EXAMPLES: list[LabeledExample] = [
    LabeledExample("Hey, are we still on for lunch tomorrow? Let me know!", "safe", "legitimate", None, "en"),
    LabeledExample("Please login to your account at https://www.onlinesbi.sbi to check your balance.",
                    "safe", "legitimate", None, "en"),
    LabeledExample("Here is your weekly newsletter with the latest tech news and product updates.",
                    "safe", "legitimate", None, "en"),
    LabeledExample("Reminder: your dentist appointment is scheduled for Monday at 10 AM.",
                    "safe", "legitimate", None, "en"),
    LabeledExample("Thanks for the great presentation today, the team really enjoyed it!",
                    "safe", "legitimate", None, "en"),
    LabeledExample("Your Amazon order #402-1193822 has shipped and will arrive on Thursday. "
                    "Track it at https://www.amazon.in/orders", "safe", "legitimate", None, "en"),
    LabeledExample("இன்று மாலை நீங்கள் வீட்டிற்கு வருகிறீர்களா? சாப்பாடு தயார் செய்கிறேன்.",
                    "safe", "legitimate", None, "ta"),
    LabeledExample("Your OTP for logging into your own banking app you just requested is 482913. "
                    "Do not share this with anyone.", "safe", "legitimate", None, "en"),
    LabeledExample("Team meeting moved to 3 PM today, conference room B. See you all there.",
                    "safe", "legitimate", None, "en"),
    LabeledExample("Congratulations on your promotion! Well deserved, the whole team is proud of you.",
                    "safe", "legitimate", None, "en"),
    LabeledExample("Your electricity bill of Rs 1,240 for this month is now available to view on "
                    "the official state electricity board portal.", "safe", "legitimate", None, "en"),
    LabeledExample("இந்த வார இறுதியில் கோயிலுக்கு செல்லலாமா? நேரம் சொல்லுங்கள்.",
                    "safe", "legitimate", None, "ta"),
]


def generate_dataset() -> list[LabeledExample]:
    return list(_SCAM_EXAMPLES) + list(_SAFE_EXAMPLES)


def dataset_summary() -> dict:
    data = generate_dataset()
    return {
        "total": len(data),
        "scam": sum(1 for d in data if d.label == "scam"),
        "safe": sum(1 for d in data if d.label == "safe"),
        "scam_categories": sorted({d.category for d in data if d.label == "scam"}),
        "languages": sorted({d.lang for d in data}),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(dataset_summary(), indent=2))
