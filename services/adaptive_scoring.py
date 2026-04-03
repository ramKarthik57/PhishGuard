"""
PhishGuard - Adaptive Scoring Engine
Dynamically adjusts rule weights based on recent threat patterns.
Rules that fire frequently on confirmed threats get boosted;
rules that rarely fire decay toward their baseline.
"""

import time
import logging
from typing import Dict, List
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("phishguard.adaptive")


@dataclass
class RuleStats:
    """Tracks how often a rule fires and its current dynamic weight."""
    base_weight: float = 10.0
    current_weight: float = 10.0
    fire_count: int = 0
    high_risk_fires: int = 0  # times it fired on HIGH-risk URLs
    last_fired: float = 0.0

    @property
    def effectiveness_ratio(self) -> float:
        if self.fire_count == 0:
            return 0.0
        return self.high_risk_fires / self.fire_count


class AdaptiveScoringEngine:
    """
    Learns from scan results to adjust rule weights dynamically.
    - Rules that correlate with HIGH risk get a weight boost.
    - Rules that fire indiscriminately (noise) get dampened.
    - All weights decay toward baseline over time.
    """

    BOOST_FACTOR = 1.3        # max multiplier for effective rules
    DAMPEN_FACTOR = 0.8       # min multiplier for noisy rules
    DECAY_RATE = 0.02         # per-update decay toward baseline
    MIN_OBSERVATIONS = 5      # need N fires before adjusting

    def __init__(self):
        self._rules: Dict[str, RuleStats] = {}
        self._update_count: int = 0

    def register_rule(self, rule_id: str, base_weight: float) -> None:
        """Register a rule with its baseline weight."""
        if rule_id not in self._rules:
            self._rules[rule_id] = RuleStats(
                base_weight=base_weight,
                current_weight=base_weight,
            )

    def get_weight(self, rule_id: str) -> float:
        """Return the current adaptive weight for a rule."""
        if rule_id in self._rules:
            return self._rules[rule_id].current_weight
        return 10.0  # fallback

    def record_fire(self, rule_id: str, was_high_risk: bool) -> None:
        """Record that a rule fired during analysis."""
        if rule_id not in self._rules:
            return
        stats = self._rules[rule_id]
        stats.fire_count += 1
        stats.last_fired = time.time()
        if was_high_risk:
            stats.high_risk_fires += 1

    def update_weights(self) -> Dict[str, float]:
        """
        Recalculate all rule weights based on accumulated stats.
        Call periodically (e.g., every 10 scans).
        """
        self._update_count += 1
        adjustments: Dict[str, float] = {}

        for rule_id, stats in self._rules.items():
            if stats.fire_count < self.MIN_OBSERVATIONS:
                continue

            ratio = stats.effectiveness_ratio

            if ratio > 0.7:
                # Highly effective — boost
                multiplier = 1.0 + (ratio - 0.7) * (self.BOOST_FACTOR - 1.0) / 0.3
            elif ratio < 0.2:
                # Noisy — dampen
                multiplier = self.DAMPEN_FACTOR + ratio * (1.0 - self.DAMPEN_FACTOR) / 0.2
            else:
                multiplier = 1.0

            # Apply with decay toward baseline
            new_weight = stats.base_weight * multiplier
            stats.current_weight = (
                stats.current_weight * (1 - self.DECAY_RATE) +
                new_weight * self.DECAY_RATE
            )
            adjustments[rule_id] = round(stats.current_weight, 2)

        logger.info("Adaptive weights updated (cycle %d): %d rules adjusted", self._update_count, len(adjustments))
        return adjustments

    def get_snapshot(self) -> List[Dict]:
        """Return current state of all rules for the dashboard."""
        return [
            {
                "rule_id": rid,
                "base_weight": round(s.base_weight, 1),
                "current_weight": round(s.current_weight, 1),
                "fire_count": s.fire_count,
                "effectiveness": round(s.effectiveness_ratio * 100, 1),
                "trend": "boosted" if s.current_weight > s.base_weight * 1.05
                         else "dampened" if s.current_weight < s.base_weight * 0.95
                         else "stable",
            }
            for rid, s in self._rules.items()
        ]
