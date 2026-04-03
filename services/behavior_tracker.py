"""
PhishGuard - User Behavior Tracking Service
Monitors scan patterns per session to detect repeated risky behavior.
Escalates risk scores for users who repeatedly scan suspicious URLs.
"""

import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from config import config

logger = logging.getLogger("phishguard.behavior")


@dataclass
class ScanEvent:
    """A single scan event in a user session."""
    url: str
    risk_score: int
    risk_level: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class UserSession:
    """Tracks all scan events for a single user/session."""
    session_id: str
    scans: List[ScanEvent] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    escalation_level: int = 0

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > config.behavior.SESSION_TTL_SEC

    @property
    def total_scans(self) -> int:
        return len(self.scans)

    @property
    def risky_scans_in_window(self) -> int:
        cutoff = time.time() - config.behavior.ESCALATION_WINDOW_SEC
        return sum(
            1 for s in self.scans
            if s.timestamp > cutoff and s.risk_score >= 40
        )

    @property
    def avg_risk(self) -> float:
        if not self.scans:
            return 0.0
        return sum(s.risk_score for s in self.scans) / len(self.scans)


class BehaviorTracker:
    """
    Tracks user behavior across scan sessions.
    If a user repeatedly scans high-risk URLs, their risk score
    gets an escalation bonus — indicating potential compromise
    or an insider threat investigation.
    """

    def __init__(self):
        self._sessions: Dict[str, UserSession] = {}

    def get_or_create_session(self, session_id: str) -> UserSession:
        if session_id in self._sessions:
            session = self._sessions[session_id]
            if session.is_expired:
                logger.debug("Session expired, creating new: %s", session_id)
                session = UserSession(session_id=session_id)
                self._sessions[session_id] = session
            return session

        session = UserSession(session_id=session_id)
        self._sessions[session_id] = session
        return session

    def record_scan(self, session_id: str, url: str, risk_score: int, risk_level: str) -> Dict:
        """
        Record a scan and return behavior analysis:
        - escalation_bonus: extra points to add to the score
        - behavior_flags: list of behavioral warnings
        """
        session = self.get_or_create_session(session_id)
        event = ScanEvent(url=url, risk_score=risk_score, risk_level=risk_level)
        session.scans.append(event)

        bonus = 0
        flags: List[str] = []

        # Check for repeated risky scans
        risky_count = session.risky_scans_in_window
        if risky_count >= config.behavior.MAX_RISKY_SCANS_BEFORE_BOOST:
            session.escalation_level = min(session.escalation_level + 1, 5)
            bonus = session.escalation_level * config.behavior.ESCALATION_BONUS
            flags.append(
                f"Repeated risky scans detected ({risky_count} in {config.behavior.ESCALATION_WINDOW_SEC}s window) "
                f"- escalation level {session.escalation_level}"
            )
            logger.warning(
                "Behavior escalation | session=%s level=%d risky_scans=%d",
                session_id, session.escalation_level, risky_count,
            )

        # High average risk
        if session.total_scans >= 3 and session.avg_risk > 55:
            flags.append(f"Session average risk is elevated ({session.avg_risk:.0f}/100)")

        # Rapid scanning
        if session.total_scans >= 5:
            recent = session.scans[-5:]
            time_span = recent[-1].timestamp - recent[0].timestamp
            if time_span < 30:  # 5 scans in under 30 seconds
                flags.append("Rapid-fire scanning detected (possible automated tool)")
                bonus += 5

        return {
            "escalation_bonus": bonus,
            "escalation_level": session.escalation_level,
            "behavior_flags": flags,
            "session_stats": {
                "total_scans": session.total_scans,
                "avg_risk": round(session.avg_risk, 1),
                "risky_in_window": risky_count,
            },
        }

    def get_session_summary(self, session_id: str) -> Optional[Dict]:
        session = self._sessions.get(session_id)
        if not session:
            return None
        return {
            "session_id": session_id,
            "total_scans": session.total_scans,
            "avg_risk": round(session.avg_risk, 1),
            "escalation_level": session.escalation_level,
            "recent_scans": [
                {"url": s.url, "score": s.risk_score, "level": s.risk_level}
                for s in session.scans[-10:]
            ],
        }

    def cleanup_expired(self) -> int:
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)
