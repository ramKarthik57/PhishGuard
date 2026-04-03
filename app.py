"""
PhishGuard - Flask Web Application (v2)
SOC-style dashboard with advanced API endpoints.
"""

import os
import uuid
import logging
from datetime import datetime

from flask import Flask, render_template, request, jsonify, session, Response, abort
from functools import wraps

from config import config
from detector import PhishGuardDetector
from utils import url_fingerprint
from virustotal import check_virustotal
from services.behavior_tracker import BehaviorTracker
from services.soc_logger import SOCLogger
from services.phish_simulator import PhishingSimulator
from services.training_quiz import TrainingQuizEngine

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from pythonjsonlogger import jsonlogger
from flasgger import Swagger, swag_from

# ======================================================================
# Logging
# ======================================================================

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Application Logging (Structured JSON)
logHandler = logging.FileHandler(os.path.join(LOG_DIR, "phishguard.log"), encoding="utf-8")
formatter = jsonlogger.JsonFormatter('%(asctime)s %(name)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)

# Remove predefined handlers and add the JSON one
logging.getLogger().handlers = []
logging.getLogger().addHandler(logHandler)
logging.getLogger().setLevel(getattr(logging, config.LOG_LEVEL))

logger = logging.getLogger("phishguard.app")

# Prometheus Metrics
SCAN_COUNTER = Counter("phishguard_scans_total", "Total URLs scanned", ["risk_level"])
API_REQUEST_COUNTER = Counter("phishguard_api_requests_total", "Total API Requests", ["endpoint"])
SCAN_LATENCY = Histogram("phishguard_scan_latency_seconds", "Scan processing time")

# ======================================================================
# App & Services
# ======================================================================

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config['SWAGGER'] = {
    'title': 'PhishGuard API',
    'uiversion': 3,
    'openapi': '3.0.0'
}
swagger = Swagger(app)

# Security: Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# API Authentication configuration
config.API_KEY = os.environ.get("PHISHGUARD_API_KEY", "TEST-KEY")

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow requests originating directly from the local UI without strict API Key checks
        # in a real environment this would be more secure.
        if request.headers.get("X-API-Key") and request.headers.get("X-API-Key") == config.API_KEY:
            return f(*args, **kwargs)
        # Fallback to check if it's the web UI local
        if request.remote_addr == '127.0.0.1' and request.headers.get("X-API-Key") == "TEST-KEY":
             return f(*args, **kwargs)
        abort(401, description="Invalid or missing X-API-Key header.")
    return decorated_function

# Initialize all services
detector = PhishGuardDetector(enable_ml=True)
behavior_tracker = BehaviorTracker()
soc = SOCLogger()
simulator = PhishingSimulator()
quiz_engine = TrainingQuizEngine()

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
@SCAN_LATENCY.time()
@limiter.limit("10 per minute")
@require_api_key
def analyze():
    """
    Analyze a URL and optional email body for phishing indicators.
    ---
    tags:
      - Core Analysis
    security:
      - ApiKeyAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              url:
                type: string
                description: The target URL to analyze
              email_body:
                type: string
                description: Optional email context
              extension_metadata:
                type: object
                description: Context parsed directly from browser DOM
    responses:
      200:
        description: Successful scan results
        content:
          application/json:
            schema:
              type: object
              properties:
                risk_score:
                  type: integer
                risk_level:
                  type: string
                action:
                  type: string
    """
    API_REQUEST_COUNTER.labels(endpoint="/analyze").inc()
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL is required."}), 400

    email_body = (data.get("email_body") or "").strip() or None
    ext_metadata = data.get("extension_metadata")
    sid = get_session_id()

    logger.info("Analyzing URL: %s (session: %s)", url, sid[:8])

    # Full analysis pipeline
    result = detector.analyze(
        url=url,
        email_body=email_body,
        session_id=sid,
        behavior_tracker=behavior_tracker,
        soc_logger=soc,
        extension_metadata=ext_metadata,
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

    SCAN_COUNTER.labels(risk_level=result["risk_level"]).inc()

    return jsonify(result)


# ======================================================================
# API: SOC Dashboard
# ======================================================================

@app.route("/api/soc/events")
@require_api_key
def soc_events():
    severity = request.args.get("severity")
    limit = int(request.args.get("limit", 30))
    return jsonify(soc.get_events(limit=limit, severity=severity))


@app.route("/api/soc/threat-level")
@require_api_key
def soc_threat_level():
    return jsonify(soc.get_threat_level())


@app.route("/api/soc/stats")
@require_api_key
def soc_stats():
    return jsonify(soc.get_stats())


# ======================================================================
# API: Phishing Simulator
# ======================================================================

@app.route("/metrics")
def metrics():
    """Prometheus metrics scraping endpoint."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


@app.route("/api/simulate", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def simulate():
    """
    Generate synthetic phishing examples for testing or training.
    ---
    tags:
      - Simulation
    security:
      - ApiKeyAuth: []
    requestBody:
      required: false
      content:
        application/json:
          schema:
            type: object
            properties:
              difficulty:
                type: string
                enum: [easy, medium, hard]
              count:
                type: integer
    responses:
      200:
        description: Array of generated samples
    """
    API_REQUEST_COUNTER.labels(endpoint="/api/simulate").inc()
    data = request.get_json(silent=True) or {}
    difficulty = data.get("difficulty", "medium")
    count = min(int(data.get("count", 3)), 10)

    samples = simulator.generate(difficulty=difficulty, count=count)
    return jsonify([s.to_dict() for s in samples])


# ======================================================================
# API: Training Quiz Mode
# ======================================================================

@app.route("/api/quiz/generate", methods=["GET"])
@require_api_key
def quiz_generate():
    difficulty = request.args.get("difficulty", "mixed")
    count = int(request.args.get("count", 5))
    challenges = quiz_engine.generate_quiz(difficulty, count)
    return jsonify([c.to_dict() for c in challenges])


@app.route("/api/quiz/evaluate", methods=["POST"])
@require_api_key
def quiz_evaluate():
    data = request.get_json(silent=True) or {}
    cid = data.get("challenge_id")
    answer = data.get("answer")
    sid = get_session_id()

    if cid is None or not answer:
        return jsonify({"error": "Missing parameters"}), 400

    result = quiz_engine.evaluate(int(cid), answer)
    if not result:
        return jsonify({"error": "Invalid challenge ID"}), 404

    score_data = quiz_engine.update_session_score(sid, result.is_correct)
    resp = result.to_dict()
    resp["session_score"] = score_data
    return jsonify(resp)


# ======================================================================
# API: History & Session
# ======================================================================

@app.route("/history")
def history():
    return jsonify(scan_history[:20])


@app.route("/api/session")
@require_api_key
def session_info():
    sid = get_session_id()
    summary = behavior_tracker.get_session_summary(sid)
    return jsonify(summary or {"session_id": sid, "total_scans": 0})


# ======================================================================
# API: Adaptive Scoring Snapshot
# ======================================================================

@app.route("/api/adaptive/snapshot")
@require_api_key
def adaptive_snapshot():
    return jsonify(detector.adaptive.get_snapshot())


# ======================================================================
# API: Anomaly Baseline
# ======================================================================

@app.route("/api/anomaly/baseline")
@require_api_key
def anomaly_baseline():
    return jsonify(detector.anomaly.get_baseline_summary())


# ======================================================================
# Entry Point
# ======================================================================

if __name__ == "__main__":
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)
