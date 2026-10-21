"""
Feature Extraction for Security Event Stream
Extracts numeric and normalized features from structured and semi-structured event streams.
"""

import math
import numpy as np
from typing import Dict, Any, List

SUSPICIOUS_GEO = {"RU": 0.8, "KP": 0.95, "CN": 0.75, "IR": 0.85, "TOR_EXIT_NODE": 1.0}
HIGH_RISK_KEYWORDS = ["injection", "escalation", "zero-day", "rce", "ransomware", "exfil", "shadow", "unauthorized"]


class FeatureExtractor:
    """Extracts a normalized feature vector from a log event dictionary."""

    FEATURE_NAMES = [
        "failure_count_norm",
        "is_admin_action",
        "sensitive_target",
        "http_error_flag",
        "hour_sin",
        "hour_cos",
        "geo_risk_weight",
        "anomaly_indicator",
        "keyword_threat_count",
        "payload_size_norm",
    ]

    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Transforms a single event into a 1D numpy feature vector."""
        failure_count = float(event.get("failure_count", 0))
        failure_norm = min(failure_count / 20.0, 1.0)

        is_admin = 1.0 if event.get("is_admin_action", 0) else 0.0
        sensitive = 1.0 if event.get("sensitive_target", 0) else 0.0

        status = event.get("http_status", 200)
        http_error = 1.0 if status >= 400 else 0.0

        hour = float(event.get("hour_of_day", 12))
        hour_sin = math.sin(2 * math.pi * hour / 24.0)
        hour_cos = math.cos(2 * math.pi * hour / 24.0)

        geo = event.get("geo_country", "IN")
        geo_risk = SUSPICIOUS_GEO.get(geo, 0.1)

        anomaly = float(event.get("anomaly_indicator", 0.1))

        # Text keyword threat analysis over action + resource
        action_text = (event.get("action", "") + " " + event.get("resource", "")).lower()
        keyword_hits = sum(1 for kw in HIGH_RISK_KEYWORDS if kw in action_text)
        keyword_threat_norm = min(keyword_hits / 3.0, 1.0)

        # Payload size heuristic
        payload = event.get("payload", {})
        payload_str = str(payload)
        payload_size_norm = min(len(payload_str) / 1000.0, 1.0)

        features = [
            failure_norm,
            is_admin,
            sensitive,
            http_error,
            hour_sin,
            hour_cos,
            geo_risk,
            anomaly,
            keyword_threat_norm,
            payload_size_norm,
        ]
        return np.array(features, dtype=np.float32)

    def extract_batch(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Transforms a batch of events into a 2D numpy array [N, num_features]."""
        matrix = [self.extract_features(e) for e in events]
        return np.array(matrix, dtype=np.float32)
