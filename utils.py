"""
PhishGuard — Utility Module
URL feature extraction, sanitization, and helper functions for phishing analysis.
"""

import re
import math
import hashlib
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

import tldextract


# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "verify", "secure", "bank", "update", "account", "confirm",
    "password", "signin", "authenticate", "wallet", "paypal", "suspend",
    "alert", "expire", "unlock", "credential", "billing", "invoice",
]

SUSPICIOUS_TLDS: List[str] = [
    ".xyz", ".top", ".club", ".work", ".click", ".loan", ".gq",
    ".ml", ".cf", ".tk", ".ga", ".buzz", ".icu",
]

LEGITIMATE_SHORTENERS: List[str] = [
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
]

IP_PATTERN = re.compile(
    r"^(?:https?://)?(\d{1,3}\.){3}\d{1,3}"
)

HEX_ENCODED_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")

HOMOGLYPH_MAP: Dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a",
}


# ──────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────

class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class URLFeatures:
    """Extracted numerical/boolean features from a URL."""
    url_length: int = 0
    domain_length: int = 0
    subdomain_count: int = 0
    path_depth: int = 0
    has_ip_address: bool = False
    has_at_symbol: bool = False
    has_double_slash_redirect: bool = False
    dash_count: int = 0
    dot_count: int = 0
    digit_count_in_domain: int = 0
    has_https: bool = False
    query_param_count: int = 0
    suspicious_keyword_count: int = 0
    suspicious_tld: bool = False
    is_shortened: bool = False
    entropy: float = 0.0
    hex_encoded_chars: int = 0
    special_char_ratio: float = 0.0
    is_punycode: bool = False


@dataclass
class AnalysisResult:
    """Final phishing analysis output."""
    url: str
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    triggered_rules: List[str] = field(default_factory=list)
    action: str = "allow"
    features: Optional[URLFeatures] = None
    email_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "triggered_rules": self.triggered_rules,
            "action": self.action,
            "email_flags": self.email_flags if self.email_flags else None,
        }


# ──────────────────────────────────────────────
# URL Feature Extraction
# ──────────────────────────────────────────────

def normalize_url(raw_url: str) -> str:
    """Normalize URL: add scheme if missing, lowercase, decode percent-encoding."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return unquote(url).lower()


def compute_entropy(text: str) -> float:
    """Shannon entropy of a string — higher values suggest randomness."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def extract_features(raw_url: str) -> URLFeatures:
    """
    Parse a URL and extract all numerical/boolean features
    used by both the rule engine and the ML model.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = extracted.top_domain_under_public_suffix or parsed.netloc
    subdomain = extracted.subdomain
    path = parsed.path or ""

    feats = URLFeatures()
    feats.url_length = len(url)
    feats.domain_length = len(domain)
    feats.subdomain_count = len(subdomain.split(".")) if subdomain else 0
    feats.path_depth = len([seg for seg in path.split("/") if seg])
    feats.has_ip_address = bool(IP_PATTERN.match(url))
    feats.has_at_symbol = "@" in url
    feats.has_double_slash_redirect = "//" in path
    feats.dash_count = url.count("-")
    feats.dot_count = parsed.netloc.count(".")
    feats.digit_count_in_domain = sum(c.isdigit() for c in domain)
    feats.has_https = parsed.scheme == "https"
    feats.query_param_count = len(parse_qs(parsed.query))
    feats.suspicious_keyword_count = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in url
    )
    feats.suspicious_tld = any(
        domain.endswith(tld) for tld in SUSPICIOUS_TLDS
    )
    feats.is_shortened = any(
        shortener in parsed.netloc for shortener in LEGITIMATE_SHORTENERS
    )
    feats.entropy = compute_entropy(parsed.netloc)
    feats.hex_encoded_chars = len(HEX_ENCODED_PATTERN.findall(raw_url))
    feats.is_punycode = parsed.netloc.startswith("xn--") or ".xn--" in parsed.netloc

    alpha = sum(c.isalpha() for c in url)
    feats.special_char_ratio = (
        1 - (alpha / len(url)) if len(url) > 0 else 0.0
    )

    return feats


def features_to_vector(feats: URLFeatures) -> List[float]:
    """Convert URLFeatures to a flat numerical vector for ML input."""
    return [
        feats.url_length,
        feats.domain_length,
        feats.subdomain_count,
        feats.path_depth,
        float(feats.has_ip_address),
        float(feats.has_at_symbol),
        float(feats.has_double_slash_redirect),
        feats.dash_count,
        feats.dot_count,
        feats.digit_count_in_domain,
        float(feats.has_https),
        feats.query_param_count,
        feats.suspicious_keyword_count,
        float(feats.suspicious_tld),
        float(feats.is_shortened),
        feats.entropy,
        feats.hex_encoded_chars,
        feats.special_char_ratio,
        float(feats.is_punycode),
    ]


# ──────────────────────────────────────────────
# Email Body Analysis
# ──────────────────────────────────────────────

_URGENCY_PHRASES: List[str] = [
    "act now", "immediately", "urgent", "within 24 hours",
    "your account will be", "suspended", "unauthorized",
    "click here", "verify your", "confirm your identity",
    "limited time", "expire", "locked out",
]


def analyze_email_body(text: str) -> List[str]:
    """
    Scan email body text for social-engineering red-flags.
    Returns a list of triggered flag descriptions.
    """
    if not text:
        return []

    lower = text.lower()
    flags: List[str] = []

    # Urgency / social-engineering phrases
    matched = [p for p in _URGENCY_PHRASES if p in lower]
    if matched:
        flags.append(f"Urgency phrases detected: {', '.join(matched)}")

    # Mismatched display text vs. href (raw heuristic on plain text)
    url_count = len(re.findall(r"https?://\S+", lower))
    if url_count >= 3:
        flags.append(f"Multiple URLs embedded in body ({url_count})")

    # Personal data requests
    pii_keywords = ["ssn", "social security", "credit card", "cvv", "pin"]
    pii_hits = [k for k in pii_keywords if k in lower]
    if pii_hits:
        flags.append(f"Requests sensitive data: {', '.join(pii_hits)}")

    # Generic greeting (no personalization)
    if re.search(r"^(dear user|dear customer|dear valued)", lower):
        flags.append("Generic greeting — no personalization")

    return flags


# ──────────────────────────────────────────────
# Hashing Utility (for caching / audit logs)
# ──────────────────────────────────────────────

def url_fingerprint(url: str) -> str:
    """SHA-256 digest of the normalized URL — useful for dedup and logging."""
    return hashlib.sha256(normalize_url(url).encode()).hexdigest()
