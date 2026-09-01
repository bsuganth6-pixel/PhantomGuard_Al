# Contributing to PhantomGuard AI

Thanks for your interest in improving PhantomGuard AI. This is a hackathon
MVP (Omnikon National Hackathon 2026, Problem Statement `Omni_CyberTech_1`)
built by Phantom Security — contributions that push it toward a real,
usable product are welcome.

## Ground rule

PhantomGuard is **detection-first, never exploitation**. Contributions that
add or facilitate credential harvesting, spam/phishing generation, attacks
against the sites the tool flags, or anything that could be repurposed as
an offensive tool will not be accepted, regardless of stated intent.

## Getting set up

```bash
git clone <this-repo-url>
cd phantomguard-ai
pip install -r requirements.txt --break-system-packages
python3 web/app.py          # http://localhost:5000
```

System dependency (not pip-installable): Tesseract OCR.
```bash
sudo apt install tesseract-ocr tesseract-ocr-tam   # tam = Tamil OCR support
```

## Before you open a PR

1. **Run the test suites** — both must stay green:
   ```bash
   python3 tests/test_modules.py        # fast per-module unit tests
   python3 tests/test_known_answer.py   # full-pipeline recall / false-positive suite
   ```
2. **Zero false positives is non-negotiable.** If your change touches
   `core/risk_engine.py`, `core/social_engineering.py`, or
   `core/url_analyzer.py`, re-run `test_known_answer.py` and confirm the
   false-positive rate is still 0.0% before opening a PR. A recall
   improvement that costs a false positive is not an improvement — see the
   reasoning in `tests/test_known_answer.py`.
3. **Add known-answer examples for new patterns.** If you're adding
   detection for a new scam pattern (a language, a category, a keyword
   set), add labeled examples to `tests/test_data_generator.py` — the
   suite runs against real synthetic data, not by inspection.
4. **Keep detection logic in `core/`.** `web/app.py` should stay a thin
   routing layer that calls into `core/pipeline.py`. Don't duplicate
   detection logic in a route handler.

## Where things live

See the "Project layout" section of `README.md` for the module map.
Short version: one file per concern in `core/` (language detection, URL
analysis, social engineering, OCR, QR, classification, scoring,
explanation), a shared `pipeline.py` that orchestrates them, and `web/`
for the Flask UI on top.

## Extending the Tamil keyword lists

`data/keywords_ta.json` is explicitly a v0 starter set (see its own
`_comment` field) — it needs native-speaker review, not just more entries
added by pattern-matching English phrases into Tamil. If you're a Tamil
speaker and want to help here, that's one of the highest-value
contributions this project can take. Please include example scam messages
(real or representative) alongside any keyword additions so reviewers can
verify the phrase actually appears in that context.

## Code style

Standard library first — this project deliberately avoids adding a
dependency where `difflib`, `sqlite3`, or a plain regex already does the
job (see the "Why Flask, not FastAPI/Next.js" note in the README for the
same philosophy applied to framework choice). If you're tempted to add a
new package, check whether the standard library already covers it.

## Reporting bugs

Open a GitHub issue with the input that triggered the bug (redact anything
personally sensitive first) and the actual vs. expected risk score/level.
For security vulnerabilities, see `SECURITY.md` instead of a public issue.
