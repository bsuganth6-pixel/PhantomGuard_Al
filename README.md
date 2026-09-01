# PhantomGuard AI

**Regional-Language Phishing & Scam Defense Platform**
*Understand the Scam. Explain the Risk. Stop the Attack.*

Built for Omnikon National Hackathon 2026 — Problem Statement `Omni_CyberTech_1`
(Regional-Language Phishing Detection) — by **Phantom Security**.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Live demo:** _TODO — add deployed URL here before Round 2 submission
(also add it to this repo's GitHub "About" section, per the Round 2 rules).
See "Deployment" below for the fastest path to a public URL._

## Team & Contributions

| Member | Contribution |
|---|---|
| Suganth B | _TODO — fill in_ |
| Aadhithiya B | _TODO — fill in_ |

*(Team name: Phantom Security. Fill in the specifics above before
submission — the rules require "a clear list of all team members and
their contributions," and a placeholder won't satisfy that.)*

---

## What this is

PhantomGuard AI accepts a message, URL, screenshot, or QR code; understands
it in Tamil or English (including code-mixed text); analyzes technical and
social-engineering indicators; and returns an **explainable 0–100 risk
score** with evidence and a recommended action — in the user's own language.

It does **not** just output `phishing: true/false`. Every score comes with
a reason a non-technical user can read and act on.

```
Input                                    Output
─────                                    ──────
"உங்கள் வங்கி கணக்கு முடக்கப்படும்.        92/100 — CRITICAL
KYC update செய்ய இந்த link-ஐ              KYC / Banking Phishing
click செய்யவும்"                          ⚠️ இது மோசடி செய்தியாக இருக்கலாம்.
+ https://sbi-kyc-security-update...      OTP/PIN/password கொடுக்க வேண்டாம்.
```

## Try it

```bash
pip install -r requirements.txt --break-system-packages
python3 web/app.py                    # web UI on http://localhost:5000

python3 tests/test_known_answer.py    # known-answer test suite
```

## Architecture

Deterministic, layered, and inspectable — no single generative-AI call is
ever the whole product (see *Design principle* below).

```
INPUT              Message · URL · Screenshot · QR
  │
UNDERSTAND          language_detector.py (Unicode-range script detection)
  │                 ocr_service.py (Tesseract)
  │                 qr_analyzer.py (OpenCV QRCodeDetector)
  ▼
ANALYZE             social_engineering.py (bilingual keyword/pattern match)
  │                 url_analyzer.py (lexical + brand/domain-mismatch)
  ▼
CLASSIFY            scam_classifier.py (rule-based category voting)
  │
SCORE               risk_engine.py (weighted, explainable 0–100)
  │
EXPLAIN             explanation_engine.py (template-based, EN + TA)
  │
PROTECT             Flask UI — warning, evidence, recommended action
```

`web/app.py` calls straight into `core/pipeline.py` for every scan — the
Flask routes are thin; all detection logic lives in `core/`, not in route
handlers, so the pipeline stays testable and reusable on its own.

### Why the UI is white/red, not a dark cyberpunk theme

The target user is explicitly non-technical — elderly users, first-time
digital-service users, people reading a scam message in a language security
tooling doesn't usually speak to them in. A dark, neon, "hacker tool"
aesthetic (however much it fits Phantom Security's usual brand) reads as
intimidating or untrustworthy to that audience, and doesn't map to any
intuitive safety signal. The UI instead uses a clean white background with
a red/orange/yellow/green traffic-light system for risk levels — closer to
a banking app's fraud alert or an antivirus dashboard than a security
researcher's tool, because the person using this screen needs to trust it
at a glance, not be impressed by it.

### Design principle: the risk score never depends solely on generative AI

Every signal in `risk_engine.py` is a plain, auditable number derived from
rules you can read in the source. There's no LLM call anywhere in the
scoring path. `explanation_engine.py` is template-based for the same
reason — the multilingual explanation is assembled from evidence the other
modules already found, never invented. This means: zero hallucination risk
in the verdict, and every decision is explainable by pointing at the exact
line of code (or JSON evidence array) that produced it.

## Why Flask, not the FastAPI/Next.js in the pitch deck

The Phase 1 idea submission describes the target production stack
(Next.js/React + FastAPI). This MVP is built as **Flask + a shared core/
package** instead. It's what's actually buildable and demoable end to
end in one sitting, and the detection logic underneath is framework-agnostic:
porting `core/` to FastAPI later is a routing-layer change, not a rewrite.

## Known-answer test results

Following the same QA methodology as the rest of the toolkit: synthetic
labeled examples, exact recall and false-positive rate asserted
programmatically, not eyeballed.

```
$ python3 tests/test_known_answer.py

Dataset:  28 examples (16 scam, 12 safe)
Recall on scam set:      93.8%  (target 90%)  PASS
False positive rate:      0.0%  (target 0.0%) PASS
```

**Zero false positives is the hard constraint** — a system that cries wolf
on legitimate bank emails loses user trust faster than one that misses an
occasional scam. The one recall miss (an investment-scam example landing
in LOW instead of SUSPICIOUS) is left in deliberately rather than tuned
away — see the note in `tests/test_known_answer.py` about not overfitting
the scoring formula to a 28-example dataset. Expanding the labeled set is
the highest-value next step; see Roadmap.

Module-level tests (`tests/test_modules.py`, no pytest dependency needed):
26/26 passing.

## Honest limitations (documented, not hidden)

- **Tamil OCR**: `tesseract-ocr-tam` isn't installed in the build sandbox
  (no network access to fetch it). `core/ocr_service.py` already requests
  `eng+tam` and will use it automatically the moment the language pack is
  present (`apt install tesseract-ocr-tam`) — English-only OCR runs today,
  and the result JSON says so explicitly rather than silently degrading.
- **Tamil keyword lists** (`data/keywords_ta.json`) are a deliberately
  small v0 seed set, not a validated NLP resource — flagged in the file's
  own `_comment` field as needing native-speaker review before production
  weight. This matches the phased "Tamil + English first, expand
  iteratively" rollout in the idea submission.
- **Brand/domain-mismatch detection** is a heuristic (registrable-domain +
  brand-coverage-ratio check), not a lookup against brands' real registered
  domains — PhantomGuard doesn't have a verified brand→domain map. It's
  tuned against known phishing patterns (brand name padded with
  security-theater or bait words) and validated in `tests/test_modules.py`.
- **QR decoding** uses OpenCV's built-in detector (no `pyzbar`/`libzbar`
  system package available offline) — fully functional for standard QR
  codes, see `core/qr_analyzer.py`.
- **Reputation signal** is a small local curated dataset
  (`data/threat_patterns.json`), not a live threat-intelligence feed — by
  design, so the product still works with no internet connection during a
  demo (or in the field, for a user with a bad connection).

## Risk scoring

```
0–24    SAFE         No significant indicators detected
25–49   LOW          Some suspicious characteristics
50–74   SUSPICIOUS   Multiple risk indicators
75–89   HIGH         Strong evidence of scam/phishing behavior
90–100  CRITICAL     Multiple strong indicators, likely malicious
```

Starting weights (configurable — see `core/risk_engine.py`):
URL/Domain 30% · Social Engineering 25% · Scam Language 20% ·
Credential/Payment 15% · Reputation 10% — plus two documented
non-linear adjustments: a **corroboration bonus** when independent
signal families agree, and an **escalation floor** so one overwhelming
signal (e.g. a near-certain malicious URL) isn't diluted by averaging
against an otherwise-quiet message. Both are explained in code comments
at the point they're applied, not hidden in a magic number.

## Privacy

No OTPs, passwords, or PINs are ever requested or stored. Uploaded
screenshots/QR images are processed in a temp file and deleted immediately
after analysis (`web/app.py`) — only a short text preview (280 chars) of
the *extracted* content is kept in scan history, never the image itself.

## Project layout

```
phantomguard-ai/
├── core/                  Shared detection pipeline (used by web/app.py)
│   ├── language_detector.py
│   ├── social_engineering.py
│   ├── url_analyzer.py
│   ├── ocr_service.py
│   ├── qr_analyzer.py
│   ├── scam_classifier.py
│   ├── risk_engine.py
│   ├── explanation_engine.py
│   ├── pipeline.py        Orchestrates the above
│   └── database.py        SQLite scan history
├── data/                  Keyword taxonomies, brand list, local threat dataset
├── web/                   Flask app (clean white/red professional UI)
│   ├── app.py
│   ├── templates/
│   └── static/{css,js}/
├── tests/
│   ├── test_data_generator.py   Known-answer synthetic dataset
│   ├── test_known_answer.py     Full-pipeline recall/FPR suite
│   └── test_modules.py          Fast per-module unit tests
└── requirements.txt
```

## Roadmap (must-have vs stretch, from the Phase 1 submission)

**Shipped in this MVP:** text + URL analysis, Tamil/English (code-mixed)
support, explainable 0–100 risk scoring, screenshot OCR, QR decoding, scam
categorization, scan history + dashboard stats, Flask web UI.

**Stretch (not in this pass):** Hindi/Telugu/Malayalam, community threat
trends dashboard, browser extension, voice input, live external threat-intel
integration, transformer-based classifier upgrade path.

## Deployment

A live deployed URL is required for Round 2. Fastest paths, using the
included `Dockerfile` (installs Tesseract + Tamil OCR support, serves via
`gunicorn` instead of the Flask dev server):

- **Render** — New → Web Service → connect this repo → Render detects the
  `Dockerfile` automatically. Free tier works for a demo.
- **Railway** — New Project → Deploy from GitHub repo → Railway builds the
  `Dockerfile` automatically.
- **Fly.io** — `fly launch` in the repo root detects the `Dockerfile` and
  provisions a free-tier instance.

All three give you a public HTTPS URL in a few minutes. Whichever you use,
paste the URL into the "Live demo" line at the top of this README **and**
into the GitHub repo's "About" section — the Round 2 rules require both.

Local production-mode test before deploying:
```bash
docker build -t phantomguard-ai .
docker run -p 8000:8000 phantomguard-ai
```

## Third-Party Attribution

| Dependency | Purpose | License |
|---|---|---|
| [Flask](https://flask.palletsprojects.com/) | Web framework | BSD-3-Clause |
| [Pillow](https://python-pillow.org/) | Image handling | MIT-CMU |
| [pytesseract](https://github.com/madmaze/pytesseract) | Python wrapper for Tesseract OCR | Apache 2.0 |
| [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) | OCR engine (system binary, not bundled) | Apache 2.0 |
| [OpenCV](https://opencv.org/) (`opencv-python-headless`) | QR code detection/decoding | Apache 2.0 |
| [NumPy](https://numpy.org/) | Array operations for image data | BSD-3-Clause |
| [Gunicorn](https://gunicorn.org/) | Production WSGI server | MIT |
| [Inter](https://fonts.google.com/specimen/Inter) / [Lexend](https://fonts.google.com/specimen/Lexend) | UI fonts, via Google Fonts | SIL Open Font License |

No proprietary datasets or third-party threat-intelligence APIs are used —
`data/threat_patterns.json`, `data/brands.json`, and `data/keywords_*.json`
are original, hand-curated for this project (see each file's own
`_comment` field for scope/limitations).

## Governance

- [LICENSE](LICENSE) — MIT
- [SECURITY.md](SECURITY.md) — data handling and vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant v2.1

---

*Phantom Security — detection-first, not exploitation.*
