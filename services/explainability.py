"""
PhishGuard - Explainable AI Security Engine
Generates human-readable, chain-of-reasoning explanations
for every phishing detection, making the AI auditable and transparent.
"""

import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger("phishguard.explain")


class ExplainabilityEngine:
    """
    Produces structured, human-readable explanations of how
    PhishGuard arrived at its risk assessment.
    Provides: narrative summary, evidence chain, confidence breakdown,
    and plain-English reasoning per rule.
    """

    # Human-readable explanations per rule
    RULE_EXPLANATIONS: Dict[str, str] = {
        "long_url": (
            "Phishing URLs are often extremely long to hide the real destination "
            "behind layers of subdirectories, query parameters, and encoded characters."
        ),
        "very_long_url": (
            "URLs exceeding 120 characters are a strong phishing signal. Legitimate "
            "services rarely need URLs this long."
        ),
        "ip_address": (
            "Using an IP address instead of a domain name is highly suspicious. "
            "Legitimate organizations always host content on named domains."
        ),
        "at_symbol": (
            "The '@' symbol in a URL causes the browser to ignore everything before it, "
            "making the displayed URL misleading. This is a classic redirect attack."
        ),
        "double_slash_redirect": (
            "A double-slash (//) in the URL path can trigger an open redirect, "
            "sending the user to a completely different malicious server."
        ),
        "excessive_dashes": (
            "Multiple hyphens suggest the domain is trying to mimic a legitimate brand "
            "(e.g., 'secure-login-bank-verify.xyz')."
        ),
        "excessive_subdomains": (
            "Deeply nested subdomains (a.b.c.evil.com) are used to make the URL "
            "appear legitimate at first glance while the actual domain is malicious."
        ),
        "suspicious_keywords": (
            "Words like 'login', 'verify', 'secure', and 'bank' are planted to "
            "create a false sense of legitimacy and urgency."
        ),
        "suspicious_tld": (
            "This domain uses a TLD (.xyz, .top, .click, etc.) commonly abused "
            "by phishing operators due to cheap or free registration."
        ),
        "no_https": (
            "Legitimate sites use HTTPS to encrypt data. A phishing site skipping "
            "HTTPS indicates either a hastily deployed attack or intent to intercept data."
        ),
        "high_entropy": (
            "The domain has high character randomness, suggesting it was algorithmically "
            "generated rather than chosen by a human — a hallmark of disposable phishing domains."
        ),
        "many_dots": (
            "Excessive dots in the hostname indicate deeply nested subdomains, "
            "a technique used to obscure the real domain in the URL bar."
        ),
        "digits_in_domain": (
            "Many digits in the domain name suggest automated generation "
            "or an attempt to mimic an IP address within a domain."
        ),
        "hex_encoded": (
            "Heavy use of percent-encoding (%XX) obscures the true URL content, "
            "often hiding malicious paths or parameters from security filters."
        ),
        "url_shortener": (
            "URL shorteners mask the true destination. While not inherently malicious, "
            "they are frequently weaponized to bypass link preview protections."
        ),
        "deep_path": (
            "A deeply nested path suggests the attacker is hosting phishing pages "
            "inside compromised directories of a legitimate server."
        ),
        "high_special_char_ratio": (
            "A high ratio of special characters to letters is unusual for legitimate URLs "
            "and may indicate obfuscation or encoding attacks."
        ),
    }

    def explain(
        self,
        url: str,
        risk_score: int,
        risk_level: str,
        action: str,
        triggered_rules: List[str],
        rule_ids: List[str],
        email_flags: List[str],
        threat_intel: Optional[Dict] = None,
        anomalies: Optional[List[Dict]] = None,
        behavior: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Generate a complete explainability report.
        """
        explanation = {
            "summary": self._build_summary(url, risk_score, risk_level, action),
            "confidence": self._compute_confidence(risk_score, len(triggered_rules), threat_intel),
            "evidence_chain": self._build_evidence_chain(
                rule_ids, triggered_rules, email_flags,
                threat_intel, anomalies, behavior,
            ),
            "reasoning": self._build_reasoning(rule_ids),
            "recommendation_rationale": self._explain_action(action, risk_score),
        }

        return explanation

    def _build_summary(self, url: str, score: int, level: str, action: str) -> str:
        if score <= 10:
            return (
                f"This URL appears safe. No significant phishing indicators were detected. "
                f"The analysis engine found no evidence of malicious intent."
            )
        elif score <= 40:
            return (
                f"This URL shows some minor risk indicators (score: {score}/100). "
                f"While not definitively malicious, exercise caution when interacting."
            )
        elif score <= 70:
            return (
                f"This URL exhibits multiple phishing characteristics (score: {score}/100). "
                f"Several indicators suggest this could be a phishing attempt. "
                f"Avoid entering any personal information."
            )
        else:
            return (
                f"HIGH THREAT: This URL is very likely a phishing attack (score: {score}/100). "
                f"Multiple strong indicators confirm malicious intent. "
                f"Do not interact with this URL under any circumstances."
            )

    def _compute_confidence(
        self, score: int, rule_count: int, threat_intel: Optional[Dict]
    ) -> Dict[str, Any]:
        # Confidence based on evidence convergence
        signals = 0
        if rule_count > 0:
            signals += 1
        if rule_count >= 3:
            signals += 1
        if threat_intel and threat_intel.get("is_blacklisted"):
            signals += 2
        if threat_intel and threat_intel.get("reputation_score", 1.0) < 0.4:
            signals += 1

        confidence_pct = min(98, 40 + signals * 12 + min(rule_count * 5, 25))

        return {
            "percentage": confidence_pct,
            "label": "High" if confidence_pct >= 80 else "Medium" if confidence_pct >= 55 else "Low",
            "converging_signals": signals,
            "note": (
                "High confidence: multiple independent signals agree."
                if signals >= 3
                else "Moderate confidence: some indicators present but not fully corroborated."
                if signals >= 1
                else "Low confidence: insufficient signals for a definitive assessment."
            ),
        }

    def _build_evidence_chain(
        self,
        rule_ids: List[str],
        triggered_rules: List[str],
        email_flags: List[str],
        threat_intel: Optional[Dict],
        anomalies: Optional[List[Dict]],
        behavior: Optional[Dict],
    ) -> List[Dict]:
        chain = []

        for i, (rid, label) in enumerate(zip(rule_ids, triggered_rules)):
            chain.append({
                "step": i + 1,
                "source": "Rule Engine",
                "indicator": label,
                "detail": self.RULE_EXPLANATIONS.get(rid, ""),
                "severity": "high" if rid in ("ip_address", "at_symbol", "suspicious_keywords") else "medium",
            })

        if email_flags:
            for flag in email_flags:
                chain.append({
                    "step": len(chain) + 1,
                    "source": "Email Analyzer",
                    "indicator": flag,
                    "detail": "Social engineering pattern detected in email body.",
                    "severity": "medium",
                })

        if threat_intel:
            for tag in threat_intel.get("threat_tags", []):
                chain.append({
                    "step": len(chain) + 1,
                    "source": "Threat Intelligence",
                    "indicator": tag,
                    "detail": f"Domain reputation: {threat_intel.get('reputation_score', 'N/A')}",
                    "severity": "high" if threat_intel.get("is_blacklisted") else "medium",
                })

        if anomalies:
            for a in anomalies:
                chain.append({
                    "step": len(chain) + 1,
                    "source": "Anomaly Detector",
                    "indicator": f"{a['feature']} is {a['direction']} normal (z={a['z_score']})",
                    "detail": f"Value: {a['value']} vs mean: {a['mean']} (std: {a['std_dev']})",
                    "severity": "low",
                })

        if behavior and behavior.get("behavior_flags"):
            for bf in behavior["behavior_flags"]:
                chain.append({
                    "step": len(chain) + 1,
                    "source": "Behavior Analysis",
                    "indicator": bf,
                    "detail": "User scanning pattern raised additional concerns.",
                    "severity": "medium",
                })

        return chain

    def _build_reasoning(self, rule_ids: List[str]) -> List[Dict]:
        return [
            {"rule": rid, "explanation": self.RULE_EXPLANATIONS.get(rid, "No explanation available.")}
            for rid in rule_ids
            if rid in self.RULE_EXPLANATIONS
        ]

    def _explain_action(self, action: str, score: int) -> str:
        explanations = {
            "allow": (
                "The analysis found no significant indicators of phishing. "
                "This URL can be accessed normally, but always remain vigilant."
            ),
            "caution": (
                f"With a risk score of {score}, this URL warrants caution. "
                "Verify the sender and destination before entering any credentials. "
                "Consider contacting the organization directly through official channels."
            ),
            "block": (
                f"With a risk score of {score}, this URL should be blocked. "
                "Multiple indicators confirm this is likely a phishing attempt. "
                "Report this URL to your IT security team and do not interact with it."
            ),
        }
        return explanations.get(action, "")
