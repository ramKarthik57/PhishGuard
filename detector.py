"""
PhishGuard - Core Detection Engine (v2)
Integrates rule engine, ML classifier, threat intelligence,
anomaly detection, adaptive scoring, behavior tracking,
brand spoofing, and explainable AI into a unified analysis pipeline.
"""

import logging
from typing import Optional, Dict, Any, List

from config import config
from utils import (
    AnalysisResult,
    RiskLevel,
    URLFeatures,
    extract_features,
    features_to_vector,
    analyze_email_body,
    normalize_url,
    url_fingerprint,
)
from model import PhishingClassifier
from services.threat_intel import ThreatIntelService
from services.adaptive_scoring import AdaptiveScoringEngine
from services.anomaly_detector import AnomalyDetector
from services.explainability import ExplainabilityEngine
from services.brand_spoof import BrandSpoofDetector # ADDED: Brand Spoofing

logger = logging.getLogger("phishguard.detector")


# ======================================================================
# Rule Definitions
# ======================================================================

RULES: Dict[str, Dict[str, Any]] = {
    "long_url": {
        "check": lambda f: f.url_length > 75,
        "base_weight": 10,
        "label": "URL length > 75 characters",
    },
    "very_long_url": {
        "check": lambda f: f.url_length > 120,
        "base_weight": 8,
        "label": "URL length > 120 characters (highly suspicious)",
    },
    "ip_address": {
        "check": lambda f: f.has_ip_address,
        "base_weight": 25,
        "label": "IP address used instead of domain name",
    },
    "at_symbol": {
        "check": lambda f: f.has_at_symbol,
        "base_weight": 20,
        "label": "'@' symbol in URL (potential redirect trick)",
    },
    "double_slash_redirect": {
        "check": lambda f: f.has_double_slash_redirect,
        "base_weight": 15,
        "label": "Double-slash redirect in path",
    },
    "excessive_dashes": {
        "check": lambda f: f.dash_count >= 3,
        "base_weight": 12,
        "label": "Excessive dashes in URL (>=3)",
    },
    "excessive_subdomains": {
        "check": lambda f: f.subdomain_count >= 3,
        "base_weight": 18,
        "label": "Excessive subdomains (>=3 levels)",
    },
    "suspicious_keywords": {
        "check": lambda f: f.suspicious_keyword_count >= 1,
        "base_weight": 15,
        "label": "Suspicious keywords detected (login, verify, secure...)",
        "dynamic_weight": lambda f: min(f.suspicious_keyword_count * 8, 30),
    },
    "suspicious_tld": {
        "check": lambda f: f.suspicious_tld,
        "base_weight": 15,
        "label": "Suspicious TLD (.xyz, .top, .click...)",
    },
    "no_https": {
        "check": lambda f: not f.has_https,
        "base_weight": 8,
        "label": "Missing HTTPS",
    },
    "high_entropy": {
        "check": lambda f: f.entropy > 4.0,
        "base_weight": 10,
        "label": "High domain entropy (randomised characters)",
    },
    "many_dots": {
        "check": lambda f: f.dot_count >= 5,
        "base_weight": 10,
        "label": "Excessive dots in netloc (>=5)",
    },
    "digits_in_domain": {
        "check": lambda f: f.digit_count_in_domain >= 4,
        "base_weight": 8,
        "label": "Many digits in domain name",
    },
    "hex_encoded": {
        "check": lambda f: f.hex_encoded_chars >= 3,
        "base_weight": 12,
        "label": "Heavy percent-encoding in URL",
    },
    "url_shortener": {
        "check": lambda f: f.is_shortened,
        "base_weight": 10,
        "label": "URL shortener detected (could mask destination)",
    },
    "deep_path": {
        "check": lambda f: f.path_depth >= 5,
        "base_weight": 7,
        "label": "Deeply nested path (>=5 segments)",
    },
    "high_special_char_ratio": {
        "check": lambda f: f.special_char_ratio > 0.45,
        "base_weight": 10,
        "label": "High ratio of special characters",
    },
}


# ======================================================================
# Scoring Helpers
# ======================================================================

def _classify_risk(score: int) -> RiskLevel:
    if score > config.scoring.MEDIUM_CEILING:
        return RiskLevel.HIGH
    if score > config.scoring.LOW_CEILING:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _recommend_action(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: "allow",
        RiskLevel.MEDIUM: "caution",
        RiskLevel.HIGH: "block",
    }[level]


# ======================================================================
# Main Detector
# ======================================================================

class PhishGuardDetector:
    """
    Stateless detector with integrated services.
    Instantiate once at app startup; call analyze() per URL.
    """

    def __init__(self, enable_ml: bool = True):
        # Core
        self._ml: Optional[PhishingClassifier] = None
        self._ml_enabled = enable_ml

        # Services
        self.threat_intel = ThreatIntelService()
        self.adaptive = AdaptiveScoringEngine()
        self.anomaly = AnomalyDetector()
        self.explainer = ExplainabilityEngine()
        self.brand_spoof = BrandSpoofDetector() # ADDED: Brand spoof detector

        # Scan counter for adaptive weight updates
        self._scan_count = 0
        self._ADAPT_INTERVAL = 10

        # Register rules into adaptive engine
        for rule_id, rule in RULES.items():
            self.adaptive.register_rule(rule_id, rule["base_weight"])

        # Load ML model
        if enable_ml:
            self._try_load_model()

        logger.info("PhishGuard Detector v2 initialized with all services (including Brand Spoofing).")

    def _try_load_model(self) -> None:
        clf = PhishingClassifier()
        if clf.load():
            self._ml = clf
            logger.info("ML model loaded successfully.")
        else:
            logger.info("No pre-trained model found. Training now...")
            metrics = clf.train()
            clf.save()
            self._ml = clf
            logger.info("ML model trained (accuracy %.2f%%).", metrics["accuracy"] * 100)

    # ──────────────────────────────────────────────
    # Core Analysis Pipeline
    # ──────────────────────────────────────────────

    def analyze(
        self,
        url: str,
        email_body: Optional[str] = None,
        session_id: Optional[str] = None,
        behavior_tracker=None,
        soc_logger=None,
        extension_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full analysis pipeline:
        1. Feature extraction
        2. Rule engine (with adaptive weights)
        3. ML classification
        4. Threat intelligence
        5. Anomaly detection
        6. Email analysis
        7. Brand Spoofing / Context analysis
        8. Behavior tracking
        9. Score blending
        10. Explainability report
        11. SOC logging
        """
        features: URLFeatures = extract_features(url)
        triggered_rules: List[str] = []
        triggered_ids: List[str] = []

        # ── 1. Rule Engine (adaptive weights) ──
        rule_score: float = 0.0
        for rule_id, rule in RULES.items():
            if rule["check"](features):
                # Use adaptive weight if available, else base
                if "dynamic_weight" in rule:
                    weight = rule["dynamic_weight"](features)
                else:
                    weight = self.adaptive.get_weight(rule_id)
                rule_score += weight
                triggered_rules.append(rule["label"])
                triggered_ids.append(rule_id)

        # ── 2. ML Classification ──
        ml_score: float = 0.0
        if self._ml_enabled and self._ml and self._ml.is_ready:
            vec = features_to_vector(features)
            ml_score = self._ml.predict_proba(vec) * 100  # scale to 0-100

        # ── 3. Threat Intelligence ──
        intel_report = self.threat_intel.analyze(url)
        intel_score = intel_report.intel_risk_score

        # ── 4. Anomaly Detection ──
        anomaly_result = self.anomaly.detect(features)
        anomaly_score = anomaly_result["anomaly_score"]
        self.anomaly.update_baseline(features)

        # ── 5. Email Analysis ──
        email_flags: List[str] = []
        email_bonus = 0
        if email_body:
            email_flags = analyze_email_body(email_body)
            email_bonus = len(email_flags) * 5

        # ── 6. Brand Spoofing (Context-Aware) ──
        from urllib.parse import urlparse
        spoof_report = self.brand_spoof.analyze(urlparse(url).netloc, url)
        spoof_bonus = spoof_report.context_bonus

        if spoof_report.is_spoofing:
             triggered_rules.extend(spoof_report.details)
             triggered_ids.append("brand_spoofing")

        # ── 6.5 Live Page Scanning (Extension) ──
        page_bonus = 0
        if extension_metadata:
            ext_meta = extension_metadata
            if ext_meta.get("insecure_password_field"):
                page_bonus += 35
                triggered_rules.append("Insecure password field detected (HTTP + Password Form)")
                triggered_ids.append("insecure_password_form")
            
            # Penalize forms posting to external sources
            ext_forms = ext_meta.get("external_forms_count", 0)
            if ext_forms > 0:
                page_bonus += 15
                triggered_rules.append(f"Forms sending data to external domains ({ext_forms} found)")
                triggered_ids.append("external_form_action")

        # ── 7. Weighted Score Blending ──
        blended = (
            rule_score * config.scoring.RULE_WEIGHT +
            ml_score * config.scoring.ML_WEIGHT +
            intel_score * config.scoring.INTEL_WEIGHT +
            anomaly_score * config.scoring.ANOMALY_WEIGHT +
            email_bonus +
            spoof_bonus +
            page_bonus
        )

        # ── 8. Behavior Tracking ──
        behavior_data = None
        if behavior_tracker and session_id:
            # Preliminary score for behavior check
            prelim_score = max(0, min(100, int(round(blended))))
            prelim_level = _classify_risk(prelim_score).value
            behavior_data = behavior_tracker.record_scan(
                session_id, url, prelim_score, prelim_level,
            )
            blended += behavior_data.get("escalation_bonus", 0)

        # ── 9. Final Score ──
        final_score = max(0, min(100, int(round(blended))))
        level = _classify_risk(final_score)
        action = _recommend_action(level)

        # ── 10. Record for adaptive learning ──
        is_high = level == RiskLevel.HIGH
        for rid in triggered_ids:
            if rid != "brand_spoofing": # Don't adapt the brand spoofing rule weight directly in the old engine
                 self.adaptive.record_fire(rid, is_high)
        self._scan_count += 1
        if self._scan_count % self._ADAPT_INTERVAL == 0:
            self.adaptive.update_weights()

        # ── 11. Explainability ──
        explanation = self.explainer.explain(
            url=url,
            risk_score=final_score,
            risk_level=level.value,
            action=action,
            triggered_rules=triggered_rules,
            rule_ids=triggered_ids,
            email_flags=email_flags,
            threat_intel=intel_report.to_dict(),
            anomalies=anomaly_result.get("anomalies", []),
            behavior=behavior_data,
        )

        # ── 12. SOC Logging ──
        if soc_logger:
            soc_logger.log_scan(url, final_score, level.value, action)
            if anomaly_result.get("anomalies"):
                soc_logger.log_anomaly(url, anomaly_result["anomalies"])
            if spoof_report.is_spoofing:
                 soc_logger.log_event(
                     "WARNING",
                     f"Brand Spoofing: {spoof_report.matched_brand}",
                     "|".join(spoof_report.details)
                 )

        # ── Build Response ──
        result = {
            "url": normalize_url(url),
            "risk_score": final_score,
            "risk_level": level.value,
            "triggered_rules": triggered_rules,
            "action": action,
            "email_flags": email_flags if email_flags else None,
            "fingerprint": url_fingerprint(url),
            # Advanced sections
            "threat_intel": intel_report.to_dict(),
            "anomaly": {
                "score": anomaly_score,
                "anomalies": anomaly_result.get("anomalies", []),
                "is_active": anomaly_result.get("is_active", False),
            },
            "brand_spoofing": spoof_report.to_dict(), # ADDED
            "behavior": behavior_data,
            "explanation": explanation,
            "scoring_breakdown": {
                "rule_engine": round(rule_score * config.scoring.RULE_WEIGHT, 1),
                "ml_classifier": round(ml_score * config.scoring.ML_WEIGHT, 1),
                "threat_intel": round(intel_score * config.scoring.INTEL_WEIGHT, 1),
                "anomaly": round(anomaly_score * config.scoring.ANOMALY_WEIGHT, 1),
                "email_bonus": email_bonus,
                "context_bonus": spoof_bonus,
                "page_bonus": page_bonus,
                "behavior_bonus": behavior_data.get("escalation_bonus", 0) if behavior_data else 0,
            },
        }

        logger.info(
            "Analysis | %s | score=%d level=%s action=%s [R:%.0f ML:%.0f TI:%.0f AN:%.0f SP:%.0f PG:%.0f]",
            url, final_score, level.value, action,
            rule_score, ml_score, intel_score, anomaly_score, spoof_bonus, page_bonus
        )
        return result


# ======================================================================
# CLI Quick-Test
# ======================================================================

if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    detector = PhishGuardDetector(enable_ml=True)

    test_cases = [
        {"url": "https://www.google.com/search?q=phishing+detection", "email": None},
        {
            "url": "http://secure-login-verify.update-bank.xyz/account/confirm?id=8a3f",
            "email": "Dear Customer, your account will be suspended. Click here to verify immediately.",
        },
        {
            "url": "http://192.168.1.1/@admin/login/verify-credential/update.html?token=abc123",
            "email": "URGENT: confirm your identity within 24 hours or your credit card will be locked out.",
        },
        {
             "url": "https://paypa1.com/login",
             "email": "Verify your identity"
        }
    ]

    print("\n" + "=" * 64)
    print("  PhishGuard v2.1 - Advanced Detection Engine Test")
    print("=" * 64)

    for i, tc in enumerate(test_cases, 1):
        result = detector.analyze(tc["url"], tc.get("email"))
        print(f"\n-- Test #{i} {'-' * 48}")
        print(f"  URL:    {result['url']}")
        print(f"  Score:  {result['risk_score']} ({result['risk_level']})")
        print(f"  Action: {result['action']}")
        print(f"  Rules:  {len(result['triggered_rules'])} triggered")
        print(f"  Intel:  rep={result['threat_intel']['reputation_score']} "
              f"blacklisted={result['threat_intel']['is_blacklisted']}")
        bd = result['scoring_breakdown']
        print(f"  Blend:  Rule={bd['rule_engine']} ML={bd['ml_classifier']} "
              f"TI={bd['threat_intel']} AN={bd['anomaly']} SP={bd['context_bonus']}")
        print(f"  Confidence: {result['explanation']['confidence']['percentage']}% "
              f"({result['explanation']['confidence']['label']})")
        if result['brand_spoofing']['is_spoofing']:
            print(f"  Spoofed: {result['brand_spoofing']['matched_brand']} ({result['brand_spoofing']['spoof_type']})")

    print("\n" + "=" * 64)
