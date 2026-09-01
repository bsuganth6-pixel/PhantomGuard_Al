# Security Policy

PhantomGuard AI processes user-submitted content (messages, URLs,
screenshots, QR codes) to detect phishing and scam attempts. This document
describes exactly what happens to that data, honestly and at the level of
what the code actually does — not aspirational claims.

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting: open this repository's
**Security** tab → **Report a vulnerability**. This reaches maintainers
privately without a public issue disclosing the problem before a fix ships.

Do not open a public GitHub issue for a security vulnerability.

We aim to acknowledge reports within 5 business days. This is a hackathon
MVP maintained by a small team, not a funded security team with an SLA —
please factor that into expectations.

## Data We Collect

| Data | Stored? | Where | Retention |
|---|---|---|---|
| Scanned message/URL text | Yes | Local SQLite (`data/phantomguard.db`) | Until manually deleted |
| Screenshot / QR image file | **No** | Processed in a temp file, deleted immediately after OCR/decode (`os.unlink` in `web/app.py`) | Not retained |
| Extracted OCR text from a screenshot | Yes (as scan text) | Local SQLite | Until manually deleted |
| Risk analysis result (score, category, evidence) | Yes | Local SQLite | Until manually deleted |
| User accounts, names, emails, phone numbers | **No** | — | — |

**Important nuance:** if a scanned message *itself* contains something
sensitive — e.g. a scam text quoting "your OTP is 1234" back at the user —
that text becomes part of the stored scan record, because it's the content
being analyzed. PhantomGuard does not attempt to detect and redact
OTP-shaped numbers from what it stores. If you deploy this beyond a demo,
consider a redaction pass or a retention/auto-delete policy before storing
scan text long-term.

## Data We Never Ask For

PhantomGuard AI never requests a user's real OTP, password, PIN, CVV, or
banking credentials as part of its own operation — it is a checker, not a
form that collects them. This is enforced by there being no such input
field anywhere in the app, not by a filter (there's nothing to filter
against, because it's never asked for).

## Network Behavior

Analysis is fully local: language detection, social-engineering pattern
matching, URL/domain heuristics, scam classification, and risk scoring run
with **no outbound network calls or third-party API requests**. The
"reputation" signal uses a local curated dataset
(`data/threat_patterns.json`), not a live external service — see the README
"Honest limitations" section for why that's a deliberate choice, not a gap.

The only network activity is the browser loading Google Fonts (Inter,
Lexend) from `fonts.googleapis.com` when a user visits the web UI.

## Known Limitations (MVP, not production-hardened)

- The bundled Flask dev server (`python3 web/app.py`) is explicitly **not**
  for production use — see the `Dockerfile` for a production setup using
  `gunicorn` instead.
- No authentication/authorization layer exists — anyone with access to the
  deployed URL can submit scans and read the local scan-history endpoints.
  Do not deploy this with sensitive shared data on a public URL without
  adding auth first.
- No rate limiting is implemented; a public deployment should add it
  (e.g. `flask-limiter`) to prevent abuse of the OCR/QR upload endpoints.
- SQLite is used for simplicity (see README's tech-stack rationale) — fine
  for a demo/small deployment, not for concurrent multi-instance scaling.
- Dependencies (`requirements.txt`) are pinned to specific versions; run
  `pip list --outdated` periodically and update for security patches.

## Responsible Use

PhantomGuard AI is built detection-first: it identifies and explains risk,
it does not exploit anything. If you extend this project, please keep that
principle — no feature that could be repurposed to actually harvest
credentials, send phishing messages, or attack the sites it flags.
