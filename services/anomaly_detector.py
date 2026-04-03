"""
PhishGuard - Anomaly Detection Engine
Statistical anomaly detection using z-score analysis on URL features.
Flags URLs whose features deviate significantly from the observed baseline.
"""

import math
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from config import config
from utils import URLFeatures

logger = logging.getLogger("phishguard.anomaly")


@dataclass
class FeatureStats:
    """Running mean/variance for a single feature (Welford's algorithm)."""
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    @property
    def variance(self) -> float:
        return self.m2 / self.count if self.count > 1 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance) if self.variance > 0 else 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2


class AnomalyDetector:
    """
    Maintains running statistics of URL features across all scans.
    For each new URL, computes z-scores for every feature and flags
    those that deviate beyond the configured threshold.
    """

    TRACKED_FEATURES = [
        "url_length", "domain_length", "subdomain_count", "path_depth",
        "dash_count", "dot_count", "digit_count_in_domain",
        "query_param_count", "suspicious_keyword_count",
        "entropy", "hex_encoded_chars", "special_char_ratio",
    ]

    def __init__(self):
        self._stats: Dict[str, FeatureStats] = {
            f: FeatureStats() for f in self.TRACKED_FEATURES
        }
        self._total_samples: int = 0

    def update_baseline(self, features: URLFeatures) -> None:
        """Incorporate a new sample into the running statistics."""
        for feat_name in self.TRACKED_FEATURES:
            value = float(getattr(features, feat_name, 0))
            self._stats[feat_name].update(value)
        self._total_samples += 1

    def detect(self, features: URLFeatures) -> Dict:
        """
        Analyze a URL's features for anomalies.
        Returns:
            anomaly_score: 0-25 (capped by config)
            anomalies: list of flagged features with z-scores
            is_active: whether anomaly detection has enough data
        """
        if self._total_samples < config.anomaly.MIN_SAMPLES:
            return {
                "anomaly_score": 0,
                "anomalies": [],
                "is_active": False,
                "samples_needed": config.anomaly.MIN_SAMPLES - self._total_samples,
            }

        anomalies: List[Dict] = []
        total_z = 0.0

        for feat_name in self.TRACKED_FEATURES:
            value = float(getattr(features, feat_name, 0))
            stats = self._stats[feat_name]

            if stats.std_dev < 0.001:
                continue

            z_score = abs(value - stats.mean) / stats.std_dev

            if z_score >= config.anomaly.Z_SCORE_THRESHOLD:
                anomalies.append({
                    "feature": feat_name,
                    "value": round(value, 3),
                    "mean": round(stats.mean, 3),
                    "std_dev": round(stats.std_dev, 3),
                    "z_score": round(z_score, 2),
                    "direction": "above" if value > stats.mean else "below",
                })
                total_z += z_score

        # Compute anomaly score (scaled, capped)
        raw = (total_z / len(self.TRACKED_FEATURES)) * 20 if anomalies else 0
        anomaly_score = min(int(raw), config.anomaly.ANOMALY_SCORE_CAP)

        return {
            "anomaly_score": anomaly_score,
            "anomalies": anomalies,
            "is_active": True,
            "total_samples": self._total_samples,
        }

    def get_baseline_summary(self) -> List[Dict]:
        """Return current baseline statistics for the dashboard."""
        return [
            {
                "feature": name,
                "mean": round(stats.mean, 2),
                "std_dev": round(stats.std_dev, 2),
                "samples": stats.count,
            }
            for name, stats in self._stats.items()
            if stats.count > 0
        ]
