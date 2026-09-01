"""
pipeline.py
------------
The single orchestration point: Input -> Understand -> Analyze -> Score ->
Explain, matching the workflow in the product docs. web/app.py calls
ScanPipeline.scan_text() / scan_image() / scan_qr() -- detection logic
lives only here, not duplicated in route handlers.
"""

from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field

from core.language_detector import detect_language
from core.social_engineering import SocialEngineeringDetector
from core.url_analyzer import UrlAnalyzer, extract_urls
from core.scam_classifier import ScamClassifier
from core.risk_engine import RiskEngine
from core.explanation_engine import ExplanationEngine
from core.ocr_service import OcrService
from core.qr_analyzer import QrAnalyzer


@dataclass
class ScanResult:
    scan_id: str
    input_type: str                 # 'text' | 'url' | 'screenshot' | 'qr'
    raw_input_preview: str
    extracted_text: str
    language: dict
    urls: list
    social_engineering: dict
    scam_category: dict
    risk: dict
    explanation: dict
    ocr_note: str | None = None
    qr_payload: dict | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "input_type": self.input_type,
            "raw_input_preview": self.raw_input_preview,
            "extracted_text": self.extracted_text,
            "language": self.language,
            "urls": self.urls,
            "social_engineering": self.social_engineering,
            "scam_category": self.scam_category,
            "risk": self.risk,
            "explanation": self.explanation,
            "ocr_note": self.ocr_note,
            "qr_payload": self.qr_payload,
            "timestamp": self.timestamp,
        }


class ScanPipeline:
    """Instantiate once (loads keyword/threat data from disk once) and reuse."""

    def __init__(self):
        self.se_detector = SocialEngineeringDetector()
        self.url_analyzer = UrlAnalyzer()
        self.classifier = ScamClassifier()
        self.risk_engine = RiskEngine()
        self.explainer = ExplanationEngine()
        self.ocr = OcrService()
        self.qr = QrAnalyzer()

    def _run_text_pipeline(self, text: str, input_type: str, raw_preview: str,
                            ocr_note: str | None = None, qr_payload: dict | None = None) -> ScanResult:
        lang = detect_language(text)
        url_findings = self.url_analyzer.analyze_text(text)
        se_result = self.se_detector.analyze(text)
        classification = self.classifier.classify(
            se_result.categories_detected,
            url_signals={"credential_path_hit": any(f.credential_path_hit for f in url_findings)},
        )
        risk = self.risk_engine.score(url_findings, se_result)
        explanation = self.explainer.build(risk, classification, lang)

        return ScanResult(
            scan_id=str(uuid.uuid4())[:8],
            input_type=input_type,
            raw_input_preview=raw_preview[:280],
            extracted_text=text,
            language=lang.to_dict(),
            urls=[f.to_dict() for f in url_findings],
            social_engineering=se_result.to_dict(),
            scam_category=classification.to_dict(),
            risk=risk.to_dict(),
            explanation=explanation.to_dict(),
            ocr_note=ocr_note,
            qr_payload=qr_payload,
        )

    def scan_text(self, text: str) -> ScanResult:
        input_type = "url" if (extract_urls(text) and len(text.strip()) == len(extract_urls(text)[0])) else "text"
        return self._run_text_pipeline(text, input_type, raw_preview=text)

    def scan_screenshot(self, image_path: str) -> ScanResult:
        ocr_result = self.ocr.extract_text(image_path)
        if ocr_result.error:
            text = ""
            note = f"OCR failed: {ocr_result.error}"
        else:
            text = ocr_result.text
            note = ocr_result.confidence_note
        return self._run_text_pipeline(
            text, "screenshot", raw_preview=f"[screenshot] {text[:200]}", ocr_note=note,
        )

    def scan_qr(self, image_path: str) -> ScanResult:
        qr_result = self.qr.decode(image_path)
        if not qr_result.found:
            text = ""
        elif qr_result.payload_type == "upi":
            payee = qr_result.upi_fields.get("pa", "unknown")
            amount = qr_result.upi_fields.get("am", "unspecified")
            text = f"UPI payment request to {payee} for amount {amount}. {qr_result.raw_payload}"
        else:
            text = qr_result.raw_payload
        return self._run_text_pipeline(
            text, "qr", raw_preview=f"[QR] {qr_result.raw_payload[:200]}",
            qr_payload=qr_result.to_dict(),
        )
