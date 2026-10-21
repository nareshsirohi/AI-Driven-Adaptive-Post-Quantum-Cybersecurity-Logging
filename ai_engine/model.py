"""
AI Threat & Risk Classifier
Performs real-time threat detection and assigns risk tier (Low, Medium, High, Critical)
along with continuous risk score and confidence. Includes fail-safe fallbacks.
"""

import time
import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple
from config import RiskLevel, MODELS_DIR, CONFIDENCE_THRESHOLD, FAILSAFE_RISK_FLOOR
from ai_engine.feature_extractor import FeatureExtractor

TIER_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
TIER_MAP = {i: tier for i, tier in enumerate(TIER_ORDER)}
INVERSE_TIER_MAP = {tier.value: i for i, tier in enumerate(TIER_ORDER)}


class AIRiskClassifier:
    """Production AI inference engine for log stream risk assessment."""

    def __init__(self, model_path: str = None):
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.model_path = model_path or (MODELS_DIR / "risk_classifier.joblib")
        self._load_or_train()

    def _load_or_train(self):
        """Loads trained weights from disk if available, else will trigger training."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None
        if self.model is None:
            self._train_default_model()

    def _train_default_model(self):
        """Quick bootstrap training using synthetic samples to ensure immediate operational readiness."""
        from sklearn.ensemble import RandomForestClassifier
        from data.generator import EventStreamGenerator

        gen = EventStreamGenerator(seed=1337)
        train_events = gen.generate_batch(1200)

        X = self.feature_extractor.extract_batch(train_events)
        y = np.array([INVERSE_TIER_MAP[e["ground_truth_risk"]] for e in train_events])

        clf = RandomForestClassifier(n_estimators=75, max_depth=12, random_state=42)
        clf.fit(X, y)
        self.model = clf
        joblib.dump(self.model, self.model_path)

    def infer(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Infers risk class, risk score, and confidence for a single event e.
        Returns:
            dict containing:
            - risk_level: RiskLevel (LOW, MEDIUM, HIGH, CRITICAL)
            - risk_score: float [0.0, 1.0]
            - confidence: float [0.0, 1.0]
            - latency_ms: float
            - failsafe_triggered: bool
            - probabilities: dict
        """
        start_time = time.perf_counter()
        failsafe_triggered = False

        try:
            feat_vec = self.feature_extractor.extract_features(event).reshape(1, -1)
            probs = self.model.predict_proba(feat_vec)[0]

            # Ensure 4 classes are represented in probs
            if len(probs) < 4:
                full_probs = np.zeros(4)
                for idx, cls_id in enumerate(self.model.classes_):
                    full_probs[cls_id] = probs[idx]
                probs = full_probs

            pred_class_idx = int(np.argmax(probs))
            confidence = float(probs[pred_class_idx])

            # Calculate continuous risk score
            # s = 0.05*P(L) + 0.35*P(M) + 0.75*P(H) + 0.98*P(C)
            risk_score = float(0.05 * probs[0] + 0.35 * probs[1] + 0.75 * probs[2] + 0.98 * probs[3])

            risk_level = TIER_MAP[pred_class_idx]

            # Section V-A Invariant: Check confidence floor
            if confidence < CONFIDENCE_THRESHOLD:
                # If model is uncertain, fail safe to HIGH risk protection
                if pred_class_idx < 2:  # Was LOW or MEDIUM
                    risk_level = FAILSAFE_RISK_FLOOR
                    failsafe_triggered = True

        except Exception as e:
            # Complete fail-safe default if error occurs
            risk_level = FAILSAFE_RISK_FLOOR
            risk_score = 0.85
            confidence = 0.50
            failsafe_triggered = True
            probs = np.array([0.0, 0.0, 0.85, 0.15])

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "risk_level": risk_level,
            "risk_score": round(risk_score, 4),
            "confidence": round(confidence, 4),
            "latency_ms": round(latency_ms, 3),
            "failsafe_triggered": failsafe_triggered,
            "probabilities": {
                tier.value: round(float(p), 4) for tier, p in zip(TIER_ORDER, probs)
            }
        }
