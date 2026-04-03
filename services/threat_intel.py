"""
PhishGuard - Threat Intelligence Service
Simulates real-time threat feeds: domain reputation, blacklist checks,
domain age estimation, and IP geolocation risk.
"""

import hashlib
import logging
import time
import re
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract

from config import config

logger = logging.getLogger("phishguard.threat_intel")


@dataclass
class ThreatReport:
    """Structured threat intelligence report for a single URL."""
    domain: str = ""
    is_blacklisted: bool = False
    blacklist_source: Optional[str] = None
    reputation_score: float = 1.0       # 0.0 (malicious) to 1.0 (clean)
    domain_age_days: int = -1           # -1 = unknown
    is_young_domain: bool = False
    ip_reputation: float = 1.0
    threat_tags: List[str] = field(default_factory=list)
    intel_risk_score: int = 0           # 0-100 contribution

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "is_blacklisted": self.is_blacklisted,
            "blacklist_source": self.blacklist_source,
            "reputation_score": round(self.reputation_score, 2),
            "domain_age_days": self.domain_age_days,
            "is_young_domain": self.is_young_domain,
            "threat_tags": self.threat_tags,
            "intel_risk_score": self.intel_risk_score,
        }


# ── Simulated Threat Databases ──────────────────────

_BLACKLISTED_DOMAINS: Dict[str, str] = {
    "malware-download.xyz":    "PhishTank",
    "phishing-site.top":       "OpenPhish",
    "credential-steal.club":   "URLhaus",
    "fake-bank-login.gq":     "APWG",
    "secure-update.ml":        "Google Safe Browsing",
    "account-verify.cf":       "PhishTank",
    "paypal-secure.tk":        "OpenPhish",
    "banking-alert.ga":        "URLhaus",
}

_KNOWN_GOOD_DOMAINS: set = {
    "google.com", "github.com", "microsoft.com", "amazon.com",
    "apple.com", "wikipedia.org", "stackoverflow.com", "python.org",
    "linkedin.com", "twitter.com", "facebook.com", "youtube.com",
    "reddit.com", "netflix.com", "spotify.com", "dropbox.com",
    "cloudflare.com", "mozilla.org", "ubuntu.com", "debian.org",
}

_HIGH_RISK_TLDS: set = {
    "xyz", "top", "club", "click", "buzz", "icu", "gq",
    "ml", "cf", "tk", "ga", "work", "loan",
}


class ThreatIntelService:
    """
    Simulated threat intelligence engine.
    In production, replace _simulate_* methods with real API calls
    (VirusTotal, AbuseIPDB, Shodan, etc.).
    """

    def __init__(self):
        self._query_cache: Dict[str, ThreatReport] = {}
        self._cache_ttl = 300  # 5 min

    def analyze(self, url: str) -> ThreatReport:
        """Run full threat intelligence analysis on a URL."""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        extracted = tldextract.extract(url)
        domain = extracted.top_domain_under_public_suffix or parsed.netloc
        tld = extracted.suffix

        # Cache check
        cache_key = hashlib.md5(domain.encode()).hexdigest()
        if cache_key in self._query_cache:
            logger.debug("ThreatIntel cache hit: %s", domain)
            return self._query_cache[cache_key]

        report = ThreatReport(domain=domain)

        # 1. Blacklist check
        self._check_blacklist(report, domain)

        # 2. Domain reputation scoring
        self._score_reputation(report, domain, tld)

        # 3. Domain age estimation
        self._estimate_domain_age(report, domain)

        # 4. IP reputation (if applicable)
        self._check_ip_reputation(report, parsed.netloc)

        # 5. Compute composite intel risk score
        self._compute_intel_score(report)

        self._query_cache[cache_key] = report
        logger.info(
            "ThreatIntel | %s | blacklisted=%s reputation=%.2f age=%dd score=%d",
            domain, report.is_blacklisted, report.reputation_score,
            report.domain_age_days, report.intel_risk_score,
        )
        return report

    def _check_blacklist(self, report: ThreatReport, domain: str) -> None:
        for bl_domain, source in _BLACKLISTED_DOMAINS.items():
            if bl_domain in domain:
                report.is_blacklisted = True
                report.blacklist_source = source
                report.threat_tags.append(f"Blacklisted by {source}")
                return

    def _score_reputation(self, report: ThreatReport, domain: str, tld: str) -> None:
        if domain in _KNOWN_GOOD_DOMAINS:
            report.reputation_score = 0.95
            return

        score = 0.7  # neutral baseline

        # TLD risk
        if tld in _HIGH_RISK_TLDS:
            score -= 0.25
            report.threat_tags.append("High-risk TLD")

        # Blacklist penalty
        if report.is_blacklisted:
            score -= 0.4

        # Domain entropy / randomness
        alpha_chars = sum(c.isalpha() for c in domain.split(".")[0])
        digit_chars = sum(c.isdigit() for c in domain.split(".")[0])
        if digit_chars > alpha_chars:
            score -= 0.15
            report.threat_tags.append("Domain looks auto-generated")

        # Excessive hyphens
        if domain.count("-") >= 3:
            score -= 0.1
            report.threat_tags.append("Excessive hyphens in domain")

        report.reputation_score = max(0.0, min(1.0, score))

        if report.reputation_score < config.threat_intel.REPUTATION_LOW_THRESHOLD:
            report.threat_tags.append("Low reputation domain")

    def _estimate_domain_age(self, report: ThreatReport, domain: str) -> None:
        """Simulate domain age. In production, use WHOIS or SecurityTrails."""
        if domain in _KNOWN_GOOD_DOMAINS:
            report.domain_age_days = 5000 + hash(domain) % 3000
            return

        # Deterministic "random" age based on domain hash
        h = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        simulated_age = h % 400  # 0-399 days

        report.domain_age_days = simulated_age
        if simulated_age < config.threat_intel.YOUNG_DOMAIN_DAYS:
            report.is_young_domain = True
            report.threat_tags.append(f"Young domain ({simulated_age} days)")

    def _check_ip_reputation(self, report: ThreatReport, netloc: str) -> None:
        ip_match = re.match(r"^(\d{1,3}\.){3}\d{1,3}", netloc)
        if ip_match:
            report.ip_reputation = 0.2
            report.threat_tags.append("IP address used as hostname")

    def _compute_intel_score(self, report: ThreatReport) -> None:
        score = 0

        if report.is_blacklisted:
            score += config.threat_intel.BLACKLIST_SCORE

        if report.is_young_domain:
            score += config.threat_intel.YOUNG_DOMAIN_SCORE

        # Low reputation contribution
        if report.reputation_score < 0.5:
            score += int((0.5 - report.reputation_score) * 40)

        # IP as hostname
        if report.ip_reputation < 0.5:
            score += 15

        report.intel_risk_score = min(100, score)
