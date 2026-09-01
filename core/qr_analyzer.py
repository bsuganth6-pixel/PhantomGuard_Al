"""
qr_analyzer.py
----------------
Decodes QR codes from an uploaded image and hands the payload back to the
caller so it can flow through the same URL/text analysis pipeline (docs:
"QR detected -> Decode -> URL / UPI data -> Analyze").

Engine: cv2.QRCodeDetector (OpenCV, already installed) -- no extra system
package needed, unlike pyzbar/libzbar which are not installed and can't be
fetched in this network-disabled environment.

Also does a first-pass classification of the payload: plain URL, UPI deep
link (upi://pay?...), or opaque text -- because a "scan to get a refund" QR
that actually opens a UPI *payment* intent (pa=<receiver> instead of a
refund) is a distinct, common scam pattern worth calling out by itself.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

import cv2
import numpy as np
from PIL import Image


@dataclass
class QrResult:
    found: bool = False
    raw_payload: str = ""
    payload_type: str = "none"     # 'url' | 'upi' | 'text' | 'none'
    upi_fields: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class QrAnalyzer:
    def __init__(self):
        self._detector = cv2.QRCodeDetector()

    def decode(self, image_path: str) -> QrResult:
        try:
            pil_img = Image.open(image_path).convert("RGB")
            arr = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
        except Exception as e:
            return QrResult(error=f"Could not read image: {e}")

        try:
            data, points, _ = self._detector.detectAndDecode(arr)
        except Exception as e:
            return QrResult(error=f"QR decode failed: {e}")

        if not data:
            return QrResult(found=False)

        result = QrResult(found=True, raw_payload=data)

        if data.lower().startswith("upi://"):
            result.payload_type = "upi"
            parsed = urlparse(data)
            fields = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            result.upi_fields = fields
        elif data.lower().startswith(("http://", "https://")):
            result.payload_type = "url"
        else:
            result.payload_type = "text"

        return result


if __name__ == "__main__":
    # Self-test: generate a QR with cv2's encoder (needs a white quiet-zone
    # border + upscaling for the detector to read it back reliably) and
    # confirm the round trip works end to end.
    enc = cv2.QRCodeEncoder_create()
    modules = enc.encode("https://secure-sbi-verify.com/refund")
    border, scale = 4, 10
    h, w = modules.shape
    bordered = np.full((h + 2 * border, w + 2 * border), 255, dtype=np.uint8)
    bordered[border:border + h, border:border + w] = modules
    upscaled = cv2.resize(bordered, ((w + 2 * border) * scale, (h + 2 * border) * scale),
                           interpolation=cv2.INTER_NEAREST)
    cv2.imwrite("/tmp/test_qr.png", upscaled)

    r = QrAnalyzer().decode("/tmp/test_qr.png")
    print(r.to_dict())
