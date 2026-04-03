"""
PhishGuard - SOC Event Logger & Alert Manager
Provides a security operations center (SOC) style event feed,
alert generation, and threat level monitoring.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from config import config

logger = logging.getLogger("phishguard.soc")


class AlertSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class SOCEvent:
    """A single security event in the SOC feed."""
    event_id: int
    timestamp: float
    event_type: str          # scan, alert, escalation, system
    severity: AlertSeverity
    title: str
    detail: str
    url: Optional[str] = None
    risk_score: Optional[int] = None
    source: str = "PhishGuard"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "url": self.url,
            "risk_score": self.risk_score,
            "source": self.source,
        }


class SOCLogger:
    """
    SOC-style logging and alerting system.
    Maintains an event feed, generates alerts on high-risk detections,
    and tracks global threat level based on recent activity.
    """

    def __init__(self):
        self._events: List[SOCEvent] = []
        self._event_counter: int = 0
        self._alert_count: Dict[str, int] = defaultdict(int)  # severity -> count

        # Boot event
        self._emit("system", AlertSeverity.INFO, "PhishGuard Engine Started",
                    "Detection engine initialized. All services operational.")

    def _emit(
        self,
        event_type: str,
        severity: AlertSeverity,
        title: str,
        detail: str,
        url: Optional[str] = None,
        risk_score: Optional[int] = None,
    ) -> SOCEvent:
        self._event_counter += 1
        event = SOCEvent(
            event_id=self._event_counter,
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            title=title,
            detail=detail,
            url=url,
            risk_score=risk_score,
        )
        self._events.append(event)
        self._alert_count[severity.value] += 1

        # Enforce max events
        if len(self._events) > config.soc.MAX_EVENTS:
            self._events.pop(0)

        logger.log(
            logging.CRITICAL if severity == AlertSeverity.CRITICAL
            else logging.WARNING if severity == AlertSeverity.WARNING
            else logging.INFO,
            "SOC [%s] %s | %s", severity.value, title, detail,
        )
        return event

    def log_scan(self, url: str, score: int, level: str, action: str) -> SOCEvent:
        """Log a scan event and emit alerts if warranted."""
        if score >= config.soc.CRITICAL_THRESHOLD:
            return self._emit(
                "alert", AlertSeverity.CRITICAL,
                f"CRITICAL THREAT DETECTED (Score: {score})",
                f"URL flagged as {level}. Action: {action}. Immediate attention required.",
                url=url, risk_score=score,
            )
        elif score >= config.soc.WARNING_THRESHOLD:
            return self._emit(
                "alert", AlertSeverity.WARNING,
                f"Suspicious URL Detected (Score: {score})",
                f"URL shows phishing indicators. Level: {level}. Action: {action}.",
                url=url, risk_score=score,
            )
        else:
            return self._emit(
                "scan", AlertSeverity.INFO,
                f"URL Scanned (Score: {score})",
                f"URL analyzed. Risk level: {level}. No immediate threat.",
                url=url, risk_score=score,
            )

    def log_escalation(self, session_id: str, level: int) -> SOCEvent:
        return self._emit(
            "escalation", AlertSeverity.WARNING,
            f"Behavior Escalation (Level {level})",
            f"Session {session_id[:8]}... triggered behavior escalation to level {level}.",
        )

    def log_anomaly(self, url: str, anomalies: List[Dict]) -> SOCEvent:
        features = ", ".join(a["feature"] for a in anomalies[:3])
        return self._emit(
            "alert", AlertSeverity.WARNING,
            f"Anomalous URL Pattern Detected",
            f"Statistical anomalies in: {features}",
            url=url,
        )

    def get_events(self, limit: int = 30, severity: Optional[str] = None) -> List[Dict]:
        events = self._events
        if severity:
            events = [e for e in events if e.severity.value == severity]
        return [e.to_dict() for e in reversed(events[-limit:])]

    def get_threat_level(self) -> Dict[str, Any]:
        """Compute global threat level from recent events."""
        window = time.time() - 600  # last 10 minutes
        recent = [e for e in self._events if e.timestamp > window]

        critical = sum(1 for e in recent if e.severity == AlertSeverity.CRITICAL)
        warnings = sum(1 for e in recent if e.severity == AlertSeverity.WARNING)

        if critical >= 3:
            level, label = 4, "SEVERE"
        elif critical >= 1:
            level, label = 3, "HIGH"
        elif warnings >= 3:
            level, label = 2, "ELEVATED"
        elif warnings >= 1:
            level, label = 1, "GUARDED"
        else:
            level, label = 0, "NORMAL"

        return {
            "level": level,
            "label": label,
            "critical_events": critical,
            "warning_events": warnings,
            "total_recent": len(recent),
            "total_all_time": len(self._events),
            "alert_breakdown": dict(self._alert_count),
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_events": len(self._events),
            "alert_breakdown": dict(self._alert_count),
            "threat_level": self.get_threat_level(),
        }
