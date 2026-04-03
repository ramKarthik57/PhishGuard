<div align="center">

# PhishGuard

### AI-Powered Phishing Detection & Response Tool

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0+-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**PhishGuard** combines a 17-rule heuristic engine with a logistic regression ML classifier to detect phishing URLs and social-engineering email content in real-time.

</div>

---

## Features

| Capability | Description |
|---|---|
| **URL Analysis** | Length, entropy, IP detection, subdomain depth, suspicious TLDs, special characters |
| **Keyword Detection** | Flags phishing lures: `login`, `verify`, `secure`, `bank`, `update`, + 14 more |
| **Email Body Scanning** | Detects urgency phrases, PII requests, generic greetings, embedded URL clusters |
| **ML Classification** | Self-training Logistic Regression on synthetic data (zero external datasets needed) |
| **VirusTotal Integration** | Optional API enrichment for real-world reputation data |
| **Risk Scoring** | 0-100 score with LOW / MEDIUM / HIGH classification |
| **Actionable Output** | `allow` / `caution` / `block` recommendations per scan |

---

## Project Structure

```
PhishGuard/
├── app.py                  # Flask web application & API
├── detector.py             # Core detection engine (rules + ML blend)
├── model.py                # Logistic regression classifier
├── utils.py                # Feature extraction, data structures, helpers
├── virustotal.py           # VirusTotal v3 API integration
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── templates/
│   └── index.html          # Web UI template
├── static/
│   ├── css/
│   │   └── style.css       # Dark-theme design system
│   └── js/
│       └── app.js          # Frontend logic & animations
├── artifacts/              # Auto-generated ML model files
│   ├── phishguard_model.pkl
│   └── phishguard_scaler.pkl
└── logs/
    └── phishguard.log      # Runtime logs
```

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/PhishGuard.git
cd PhishGuard
pip install -r requirements.txt
```

### 2. Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

> The ML model auto-trains on first launch (takes ~2 seconds). Subsequent runs load the saved model instantly.

### 3. (Optional) Enable VirusTotal

```bash
set VIRUSTOTAL_API_KEY=your_api_key_here   # Windows
export VIRUSTOTAL_API_KEY=your_api_key_here # Linux/Mac

python app.py
```

Get a free API key at [virustotal.com](https://www.virustotal.com/gui/join-us).

---

## Usage

### Web UI

1. Enter a suspicious URL in the input field
2. Optionally paste email body content for deeper analysis
3. Click **Analyze Threat**
4. Review the risk score, triggered rules, and recommended action

Use the **Quick Test** chips to instantly demo with pre-loaded examples.

### Python API (Programmatic)

```python
from detector import PhishGuardDetector

detector = PhishGuardDetector(enable_ml=True)

# Analyze a URL
result = detector.analyze("http://secure-login.suspicious-bank.xyz/verify")
print(result.to_dict())

# Analyze URL + email body
result = detector.analyze(
    url="http://192.168.1.1/@admin/login/verify",
    email_body="URGENT: confirm your identity within 24 hours."
)
print(f"Score: {result.risk_score}, Level: {result.risk_level.value}, Action: {result.action}")
```

### REST API

```bash
curl -X POST http://127.0.0.1:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-bank-login.xyz/verify", "email_body": "Click here immediately!"}'
```

**Response:**
```json
{
  "url": "http://suspicious-bank-login.xyz/verify",
  "risk_score": 78,
  "risk_level": "HIGH",
  "triggered_rules": [
    "Suspicious keywords detected (login, verify, secure...)",
    "Suspicious TLD (.xyz, .top, .click...)",
    "Missing HTTPS"
  ],
  "action": "block",
  "email_flags": [
    "Urgency phrases detected: immediately, click here"
  ],
  "virustotal": null,
  "fingerprint": "a1b2c3d4e5f6...",
  "timestamp": "2026-04-03T15:55:00"
}
```

---

## Example Inputs & Outputs

### Safe URL

| Field | Value |
|---|---|
| **Input** | `https://www.google.com/search?q=python` |
| **Score** | 0 |
| **Level** | LOW |
| **Rules** | None triggered |
| **Action** | `allow` |

### Suspicious URL + Email

| Field | Value |
|---|---|
| **Input** | `http://secure-login-verify.update-bank.xyz/account/confirm?id=8a3f` |
| **Email** | *"Dear Customer, your account will be suspended. Click here to verify immediately."* |
| **Score** | 95 |
| **Level** | HIGH |
| **Rules** | Excessive dashes, Suspicious keywords, Suspicious TLD, Missing HTTPS, High entropy |
| **Email Flags** | Urgency phrases, Generic greeting |
| **Action** | `block` |

### Malicious URL + Email

| Field | Value |
|---|---|
| **Input** | `http://192.168.1.1/@admin/login/verify-credential/update.html?token=abc123` |
| **Email** | *"URGENT: confirm your identity within 24 hours or your credit card will be locked out."* |
| **Score** | 100 |
| **Level** | HIGH |
| **Rules** | IP address as domain, @ symbol, Suspicious keywords, Missing HTTPS, Digits in domain |
| **Email Flags** | Urgency phrases, Requests sensitive data (credit card) |
| **Action** | `block` |

---

## Architecture

```
                    ┌───────────────┐
                    │   Flask UI    │
                    │   (app.py)    │
                    └──────┬────────┘
                           │ POST /analyze
                    ┌──────▼────────┐
                    │   Detector    │
                    │ (detector.py) │
                    └──┬────────┬───┘
               ┌───────▼──┐  ┌─▼──────────┐
               │ Rule      │  │ ML Model   │
               │ Engine    │  │ (model.py) │
               │ (17 rules)│  │ LogReg     │
               └───────┬───┘  └─┬──────────┘
                       │ 60%    │ 40%
                    ┌──▼────────▼───┐
                    │ Blended Score │
                    │   (0 - 100)   │
                    └───────────────┘
```

The detector blends **60% rule engine** + **40% ML probability** for the final score:

- **0 – 29** → `LOW` → `allow`
- **30 – 59** → `MEDIUM` → `caution`
- **60 – 100** → `HIGH` → `block`

---

## Detection Rules (17)

| # | Rule | Weight | Trigger |
|---|---|---|---|
| 1 | Long URL | 10 | Length > 75 chars |
| 2 | Very Long URL | 8 | Length > 120 chars |
| 3 | IP Address | 25 | IP instead of domain |
| 4 | @ Symbol | 20 | `@` in URL |
| 5 | Double-Slash Redirect | 15 | `//` in path |
| 6 | Excessive Dashes | 12 | ≥ 3 dashes |
| 7 | Excessive Subdomains | 18 | ≥ 3 subdomain levels |
| 8 | Suspicious Keywords | 8-30 | login, verify, secure... |
| 9 | Suspicious TLD | 15 | .xyz, .top, .click... |
| 10 | No HTTPS | 8 | Missing TLS |
| 11 | High Entropy | 10 | Shannon entropy > 4.0 |
| 12 | Many Dots | 10 | ≥ 5 dots in netloc |
| 13 | Digits in Domain | 8 | ≥ 4 digits |
| 14 | Hex Encoding | 12 | ≥ 3 percent-encoded chars |
| 15 | URL Shortener | 10 | Known shortener domain |
| 16 | Deep Path | 7 | ≥ 5 path segments |
| 17 | Special Char Ratio | 10 | > 45% non-alpha chars |

---

## Tech Stack

- **Python 3.10+**
- **Flask** — Web framework & REST API
- **scikit-learn** — Logistic Regression classifier
- **tldextract** — Robust domain/subdomain parsing
- **NumPy** — Numerical feature vectors
- **requests** — HTTP client (VirusTotal API)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
