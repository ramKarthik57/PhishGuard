"""
PhishGuard - Flask Web Application (v2)
SOC-style dashboard with advanced API endpoints.
"""

import os
import uuid
import logging
from datetime import datetime

from flask import Flask, render_template, request, jsonify, session

from config import config
from detector import PhishGuardDetector
from utils import url_fingerprint
from virustotal import check_virustotal
from services.behavior_tracker import BehaviorTracker
from services.soc_logger import SOCLogger
from services.phish_simulator import PhishingSimulator

# ======================================================================
# Logging
# ======================================================================

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "phishguard.log"), encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("phishguard.app")

# ======================================================================
# App & Services
# ======================================================================

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY

# Initialize all services
detector = PhishGuardDetector(enable_ml=True)
behavior_tracker = BehaviorTracker()
soc = SOCLogger()
simulator = PhishingSimulator()

# Scan history (in-memory)
scan_history: list[dict] = []

logger.info("PhishGuard v2 initialized with all services.")


# ======================================================================
# Helpers
# ======================================================================

def get_session_id() -> str:
    if "sid" not in session:
        session["sid"] = str(uuid.uuid4())
    return session["sid"]


# ======================================================================
# Page Routes
# ======================================================================

@app.route("/")
def index():
    return render_template("index.html")


# ======================================================================
# API: Core Analysis
# ======================================================================

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL is required."}), 400

    email_body = (data.get("email_body") or "").strip() or None
    sid = get_session_id()

    logger.info("Analyzing URL: %s (session: %s)", url, sid[:8])

    # Full analysis pipeline
    result = detector.analyze(
        url=url,
        email_body=email_body,
        session_id=sid,
        behavior_tracker=behavior_tracker,
        soc_logger=soc,
    )

    # VirusTotal enrichment (best-effort)
    try:
        vt = check_virustotal(url)
        result["virustotal"] = vt
    except Exception:
        result["virustotal"] = None

    # Metadata
    result["timestamp"] = datetime.now().isoformat()

    # History
    scan_history.insert(0, result)
    if len(scan_history) > 100:
        scan_history.pop()

    return jsonify(result)


# ======================================================================
# API: SOC Dashboard
# ======================================================================

@app.route("/api/soc/events")
def soc_events():
    severity = request.args.get("severity")
    limit = int(request.args.get("limit", 30))
    return jsonify(soc.get_events(limit=limit, severity=severity))


@app.route("/api/soc/threat-level")
def soc_threat_level():
    return jsonify(soc.get_threat_level())


@app.route("/api/soc/stats")
def soc_stats():
    return jsonify(soc.get_stats())


# ======================================================================
# API: Phishing Simulator
# ======================================================================

@app.route("/api/simulate", methods=["POST"])
def simulate():
    data = request.get_json(silent=True) or {}
    difficulty = data.get("difficulty", "medium")
    count = min(int(data.get("count", 3)), 10)

    samples = simulator.generate(difficulty=difficulty, count=count)
    return jsonify([s.to_dict() for s in samples])


# ======================================================================
# API: History & Session
# ======================================================================

@app.route("/history")
def history():
    return jsonify(scan_history[:20])


@app.route("/api/session")
def session_info():
    sid = get_session_id()
    summary = behavior_tracker.get_session_summary(sid)
    return jsonify(summary or {"session_id": sid, "total_scans": 0})


# ======================================================================
# API: Adaptive Scoring Snapshot
# ======================================================================

@app.route("/api/adaptive/snapshot")
def adaptive_snapshot():
    return jsonify(detector.adaptive.get_snapshot())


# ======================================================================
# API: Anomaly Baseline
# ======================================================================

@app.route("/api/anomaly/baseline")
def anomaly_baseline():
    return jsonify(detector.anomaly.get_baseline_summary())


# ======================================================================
# Entry Point
# ======================================================================

if __name__ == "__main__":
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)
