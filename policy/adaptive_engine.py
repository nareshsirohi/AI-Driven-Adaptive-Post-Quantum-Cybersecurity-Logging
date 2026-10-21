"""
Adaptive Security Decision Module
Maps AI threat inference (risk tier rho, score s, confidence c) to dynamic cryptographic
and distributed ledger policies according to Table III and Algorithm 1.
"""

from typing import Dict, Any, Tuple
from config import RiskLevel, CryptoOp, POLICY_MATRIX, CONFIDENCE_THRESHOLD, FAILSAFE_RISK_FLOOR


class AdaptiveSecurityPolicyEngine:
    """Enforces dynamic policy mapping and invariants across all event streams."""

    def __init__(self):
        self.policy_matrix = POLICY_MATRIX

    def evaluate_policy(self, risk_level: RiskLevel, risk_score: float, confidence: float) -> Dict[str, Any]:
        """
        Executes decision policy pi(rho, s) -> (crypto_op, priority, dlt_batching).
        Enforces Section V-A policy invariants and fail-safe rules.
        """
        failsafe_applied = False
        effective_risk = risk_level

        # Invariant 1: If confidence is lower than floor, fail safe to HIGH
        if confidence < CONFIDENCE_THRESHOLD and effective_risk in [RiskLevel.LOW, RiskLevel.MEDIUM]:
            effective_risk = FAILSAFE_RISK_FLOOR
            failsafe_applied = True

        policy_spec = self.policy_matrix[effective_risk]

        # Determine priority and commit behavior
        priority_level = policy_spec["dlt_priority"]
        is_pqc = policy_spec["pqc_signature"]
        signature_algo = policy_spec["signature_algo"]
        kem_algo = policy_spec["kem_algo"]
        require_encryption = policy_spec["require_payload_encryption"]

        # Auditor policy description
        if effective_risk == RiskLevel.LOW:
            rationale = "Low threat score: Canonical SHA-256 hash + HMAC audit tag, batched DLT commitment to minimize overhead."
        elif effective_risk == RiskLevel.MEDIUM:
            rationale = "Medium threat score: Canonical hash + NIST FIPS 204 ML-DSA-44 post-quantum signature on metadata."
        elif effective_risk == RiskLevel.HIGH:
            rationale = "High threat score: Enhanced provenance hash + ML-DSA-65 signature + ML-KEM-768 hybrid payload encryption."
        else:  # CRITICAL
            rationale = "Critical zero-day / exploit severity: Maximum assurance NIST FIPS 205 SLH-DSA signature + ML-KEM-1024 encryption + expedited non-batched DLT commit."

        if failsafe_applied:
            rationale = f"[FAILSAFE ENGAGED] Confidence ({confidence:.2f}) below threshold ({CONFIDENCE_THRESHOLD}): " + rationale

        return {
            "effective_risk_level": effective_risk,
            "original_risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": confidence,
            "failsafe_applied": failsafe_applied,
            "crypto_op": signature_algo.value,
            "kem_op": kem_algo.value if kem_algo else None,
            "is_pqc": is_pqc,
            "dlt_priority": priority_level,
            "batch_window_seconds": policy_spec["batch_window_seconds"],
            "require_payload_encryption": require_encryption,
            "policy_rationale": rationale
        }
