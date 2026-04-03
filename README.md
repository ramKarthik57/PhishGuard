<div align="center">

# PhishGuard 🛡️

### Enterprise-Grade AI-Powered Phishing Detection & Response

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Helm-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Swagger](https://img.shields.io/badge/API-Swagger-85EA2D?logo=swagger&logoColor=white)](http://localhost:5000/apidocs)

**PhishGuard** is a multi-layered security platform that identifies phishing threats using heuristic rule engines, **Random Forest** machine learning, and context-aware brand spoofing detection.

</div>

---

## 📸 Platform Overview

### Analysis Dashboard
![Analysis Dashboard](docs/screenshots/dashboard.png)
*Real-time threat assessment with Explainable AI (XAI) breakdown and triggered rule alerts.*

### Security Operations Center (SOC)
![SOC Monitor](docs/screenshots/soc_monitor.png)
*Centralized telemetry, threat level tracking, and persistent event logging.*

### Phishing Awareness Simulator
![Interactive Quiz](docs/screenshots/quiz_mode.png)
*Gamified training module to educate users on identifying sophisticated phishing attempts.*

---

## 🏗️ Architecture

```mermaid
graph TD
    A[User Request / Browser Extension] --> B[Flask API Gateway]
    B --> C[PhishGuard Detector]
    C --> D[Heuristic Rule Engine]
    C --> E[RF ML Classifier]
    C --> F[Brand Spoofing Engine]
    C --> G[Threat Intel Service]
    G --> H[(VirusTotal API)]
    C --> I[Explainability Layer]
    I --> J[JSON / SOC Logs]
    I --> K[Prometheus Metrics]
    I --> L[Interactive Dashboard]
```

---

## 🚀 Quick Start

### 🐳 Docker (Recommended)
```bash
git clone https://github.com/yourusername/PhishGuard.git
cd PhishGuard

# Launch with Docker Compose
docker-compose up --build -d
```
Access at **http://localhost:5000**

### 🐍 Local Installation (Manual)
1. **Setup Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. **Configuration:**
   Set your API keys:
   ```bash
   export PHISHGUARD_API_KEY="YOUR-SECURE-KEY"
   export VIRUSTOTAL_API_KEY="YOUR-VT-KEY"
   ```
3. **Run Platform:**
   ```bash
   python app.py
   ```

---

## 🔐 Developer & Enterprise APIs

PhishGuard provides a fully documented REST API secured by `X-API-Key` authentication.

- **Interactive API Docs:** [http://localhost:5000/apidocs](http://localhost:5000/apidocs)
- **Monitoring:** [http://localhost:5000/metrics](http://localhost:5000/metrics) (Prometheus format)

### Example Analysis Request
```bash
curl -X POST http://localhost:5000/analyze \
     -H "Content-Type: application/json" \
     -H "X-API-Key: YOUR-SECURE-KEY" \
     -d '{"url": "http://secure-login.paypa1.xyz/"}'
```

---

## 📊 Performance & Robustness
The platform includes an automated **Adversarial Testing Suite** to ensure detection of:
- **Unicode/Homoglyph Attacks** (Cyrillic character substitution)
- **Punycode/IDN Obfuscation** 
- **URL Padding & Hex-Encoding**

Run validation tests:
```bash
python -m pytest tests/test_adversarial.py
```

---

## ⚖️ License
MIT License. Developed for enterprise security research and phishing awareness.
