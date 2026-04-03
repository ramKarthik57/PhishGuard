"""
PhishGuard - Centralized Configuration
All thresholds, weights, and feature flags in one place.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class ScoringConfig:
    """Thresholds for risk classification."""
    LOW_CEILING: int = 29
    MEDIUM_CEILING: int = 59
    RULE_WEIGHT: float = 0.50       # rule engine contribution
    ML_WEIGHT: float = 0.25         # ML classifier contribution
    INTEL_WEIGHT: float = 0.15      # threat intelligence contribution
    ANOMALY_WEIGHT: float = 0.10    # anomaly detector contribution


@dataclass(frozen=True)
class BehaviorConfig:
    """User behavior tracking thresholds."""
    ESCALATION_WINDOW_SEC: int = 300        # 5-minute sliding window
    MAX_RISKY_SCANS_BEFORE_BOOST: int = 3   # trigger escalation after N risky scans
    ESCALATION_BONUS: int = 10              # extra points added per escalation
    SESSION_TTL_SEC: int = 1800             # 30-min session expiry


@dataclass(frozen=True)
class AnomalyConfig:
    """Anomaly detection parameters."""
    Z_SCORE_THRESHOLD: float = 2.5     # flag features > 2.5 std devs
    MIN_SAMPLES: int = 20             # need N samples before detection activates
    ANOMALY_SCORE_CAP: int = 25       # max score contribution from anomaly engine


@dataclass(frozen=True)
class ThreatIntelConfig:
    """Threat intelligence simulation settings."""
    BLACKLIST_SCORE: int = 40          # score for known-bad domains
    YOUNG_DOMAIN_DAYS: int = 30       # domains < 30 days old are suspicious
    YOUNG_DOMAIN_SCORE: int = 15
    REPUTATION_LOW_THRESHOLD: float = 0.3


@dataclass(frozen=True)
class SimulatorConfig:
    """Phishing simulation generator settings."""
    DIFFICULTY_LEVELS: List[str] = ("easy", "medium", "hard")
    MAX_GENERATED: int = 10


@dataclass(frozen=True)
class SOCConfig:
    """SOC dashboard and alerting."""
    MAX_EVENTS: int = 200
    MAX_ALERTS: int = 50
    CRITICAL_THRESHOLD: int = 80       # score >= 80 triggers CRITICAL alert
    WARNING_THRESHOLD: int = 40        # score >= 40 triggers WARNING alert


@dataclass
class AppConfig:
    """Root configuration object."""
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    behavior: BehaviorConfig = field(default_factory=BehaviorConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    simulator: SimulatorConfig = field(default_factory=SimulatorConfig)
    soc: SOCConfig = field(default_factory=SOCConfig)

    # Flask
    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", "phishguard-dev-key")
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "1") == "1"
    HOST: str = "127.0.0.1"
    PORT: int = 5000

    # VirusTotal
    VT_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")

    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")


# Global singleton
config = AppConfig()
