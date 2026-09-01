"""
url_analyzer.py
-----------------
Lexical + structural URL/domain intelligence. No live network calls (an MVP
that depends on reaching arbitrary attacker-controlled URLs server-side is
both slow and unsafe -- see docs: "do not actually visit arbitrary malicious
websites server-side without proper isolation"). Everything here is static
analysis of the URL string itself, plus a lookup against the local demo
threat dataset in data/threat_patterns.json.

Explicitly encodes the "HTTPS is not a safety signal" point from the docs:
scheme is reported but never reduces the risk score.
"""

from __future__ import annotations
import json
import re
import difflib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
URL_RE = re.compile(r"""(https?://[^\s<>"']+|www\.[^\s<>"']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"']*)?)""",
                     re.IGNORECASE)


def _load_json(name: str) -> dict:
    with open(DATA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def extract_urls(text: str) -> list[str]:
    """Pull URL-looking substrings out of free text (messages, OCR output)."""
    if not text:
        return []
    found = URL_RE.findall(text)
    # de-dupe, preserve order
    seen = set()
    out = []
    for u in found:
        u = u.rstrip(".,;:!?)")
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


@dataclass
class UrlFinding:
    url: str
    scheme: str
    domain: str
    is_ip_based: bool = False
    is_shortener: bool = False
    has_suspicious_tld: bool = False
    subdomain_count: int = 0
    hyphen_count: int = 0
    url_length: int = 0
    has_at_symbol: bool = False
    has_encoded_chars: bool = False
    credential_path_hit: bool = False
    known_scam_domain: bool = False
    mentioned_brand: str | None = None       # brand text found elsewhere in the message
    brand_domain_mismatch: bool = False
    evidence: list = field(default_factory=list)
    score_0_100: int = 0

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        return d


class UrlAnalyzer:
    def __init__(self):
        self.threat = _load_json("threat_patterns.json")
        self.brands = _load_json("brands.json")
        self._all_brands = sorted(
            {b for group in self.brands.values() if isinstance(group, list) for b in group},
            key=len, reverse=True,
        )

    # Suffixes where the registrable domain is the last 3 labels, not 2
    # (naive list -- no network access to a full public-suffix list in this env).
    _TWO_PART_SUFFIXES = {
        "co.in", "com.in", "net.in", "org.in", "gov.in", "co.uk", "org.uk",
        "com.au", "co.jp", "co.nz",
    }

    def _registrable_domain(self, domain: str) -> str:
        labels = domain.split(".")
        if len(labels) <= 2:
            return domain
        last_two = ".".join(labels[-2:])
        last_three = ".".join(labels[-3:])
        if last_two in self._TWO_PART_SUFFIXES and len(labels) >= 3:
            return last_three
        return last_two

    def _find_mentioned_brand(self, context_text: str) -> str | None:
        if not context_text:
            return None
        lowered = context_text.lower()
        for brand in self._all_brands:
            if brand in lowered:
                return brand
        return None

    def analyze_one(self, url: str, context_text: str = "") -> UrlFinding:
        raw = url if "://" in url else f"http://{url}"
        parsed = urlparse(raw)
        domain = parsed.netloc.split("@")[-1].split(":")[0].lower()
        finding = UrlFinding(
            url=url,
            scheme=parsed.scheme or "unknown",
            domain=domain,
            url_length=len(url),
        )

        finding.is_ip_based = bool(IP_RE.match(domain))
        if finding.is_ip_based:
            finding.evidence.append("URL uses a raw IP address instead of a domain name")

        finding.is_shortener = any(s in domain for s in self.threat["url_shorteners"])
        if finding.is_shortener:
            finding.evidence.append(f"Uses a URL-shortening service ({domain}), destination is hidden")

        finding.has_suspicious_tld = any(domain.endswith(t) for t in self.threat["suspicious_tlds"])
        if finding.has_suspicious_tld:
            finding.evidence.append(f"Domain uses a TLD commonly abused for scam sites ({domain.split('.')[-1]})")

        registrable = self._registrable_domain(domain)
        registrable_label_count = len(registrable.split("."))
        total_label_count = len(domain.split("."))
        finding.subdomain_count = max(0, total_label_count - registrable_label_count)
        if finding.subdomain_count >= 3:
            finding.evidence.append(f"Unusually many subdomains ({finding.subdomain_count})")

        finding.hyphen_count = domain.count("-")
        if finding.hyphen_count >= 2:
            finding.evidence.append(f"Multiple hyphens in domain ({finding.hyphen_count}), common brand-spoofing pattern")

        finding.has_at_symbol = "@" in url
        if finding.has_at_symbol:
            finding.evidence.append("Contains '@' -- text before '@' is decorative, browser navigates past it")

        finding.has_encoded_chars = "%" in url and bool(re.search(r"%[0-9a-fA-F]{2}", url))
        if finding.has_encoded_chars:
            finding.evidence.append("Contains percent-encoded characters, can hide the real target")

        path_lower = parsed.path.lower()
        finding.credential_path_hit = any(seg in path_lower for seg in self.threat["credential_page_paths"])
        if finding.credential_path_hit and (finding.hyphen_count or finding.subdomain_count):
            finding.evidence.append("Path suggests a login/verification page on a non-standard domain")

        finding.known_scam_domain = domain in self.threat["known_scam_domains"]
        if finding.known_scam_domain:
            finding.evidence.append("Matches a domain in the local known-scam list")

        mentioned = self._find_mentioned_brand(context_text)
        finding.mentioned_brand = mentioned
        if mentioned:
            if finding.is_ip_based:
                # An IP address is categorically never a brand's legitimate
                # domain -- skip the ratio heuristic entirely, it's meant
                # for comparing text, not numeric octets.
                finding.brand_domain_mismatch = True
                finding.evidence.append(
                    f"Message references '{mentioned.upper()}' but the link is a raw IP address, "
                    f"not {mentioned}'s domain"
                )
            else:
                brand_token = mentioned.replace(" ", "")
                registrable = self._registrable_domain(domain)
                registrable_core = registrable.split(".")[0].replace("-", "")
                registrable_tld = registrable.split(".")[-1] if "." in registrable else ""
                full_domain_core = domain.replace("-", "").replace(".", "")

                # Legitimate iff either:
                #   (a) the brand IS (or owns) the TLD -- e.g. a branded gTLD
                #       like onlinesbi.sbi, or
                #   (b) the brand accounts for a *majority* of the registrable
                #       core, i.e. this reads as "brand + short legit suffix"
                #       (hdfcbank.com) rather than "brand + padding" (icici-
                #       secure-login.net, amazon-prize-claim.com).
                brand_is_tld = registrable_tld == brand_token
                coverage = (len(brand_token) / len(registrable_core)) if registrable_core else 0
                looks_legit = brand_is_tld or coverage >= 0.5

                if looks_legit:
                    pass
                elif brand_token in full_domain_core:
                    finding.brand_domain_mismatch = True
                    finding.evidence.append(
                        f"'{mentioned.upper()}' appears in the domain but diluted by other words -- "
                        f"the actual registered domain is '{registrable}', not {mentioned}'s real site"
                    )
                else:
                    finding.brand_domain_mismatch = True
                    finding.evidence.append(
                        f"Message references '{mentioned.upper()}' but the domain ({domain}) does not match"
                    )

        finding.score_0_100 = self._score(finding)
        return finding

    @staticmethod
    def _score(f: UrlFinding) -> int:
        score = 0
        if f.known_scam_domain:
            score += 60
        if f.brand_domain_mismatch:
            score += 50
        if f.is_ip_based:
            score += 30
        if f.has_suspicious_tld:
            score += 20
        if f.is_shortener:
            score += 15
        if f.hyphen_count >= 2:
            score += 12
        if f.subdomain_count >= 3:
            score += 10
        if f.has_at_symbol:
            score += 20
        if f.has_encoded_chars:
            score += 10
        if f.credential_path_hit and (f.hyphen_count or f.subdomain_count):
            score += 15
        return min(100, score)

    def analyze_text(self, text: str) -> list[UrlFinding]:
        """Find and analyze every URL in a block of text (message/OCR output)."""
        urls = extract_urls(text)
        return [self.analyze_one(u, context_text=text) for u in urls]


if __name__ == "__main__":
    az = UrlAnalyzer()
    tests = [
        ("https://sbi-kyc-security-update.example.com/login",
         "Your SBI account needs KYC verification, click https://sbi-kyc-security-update.example.com/login"),
        ("https://www.google.com", "Just a normal search"),
        ("http://192.168.4.55/verify", "Bank of Baroda account update: http://192.168.4.55/verify"),
    ]
    for url, ctx in tests:
        f = az.analyze_one(url, ctx)
        print(f"\n{url}")
        print(f"  score={f.score_0_100} mismatch={f.brand_domain_mismatch} evidence={f.evidence}")
