"""
Pipeline Orchestrator: Implements Algorithm 1 (AdaptivePQLog)
Coordinates Preprocessing, AI Risk Scoring, Dynamic PQC Policy, Payload Storage, and DLT Commitment.
"""

import time
import datetime
from typing import Dict, Any, Tuple
from config import RiskLevel, CryptoOp
from data.canonicalizer import canonicalize_json, compute_canonical_hash
from ai_engine.model import AIRiskClassifier
from policy.adaptive_engine import AdaptiveSecurityPolicyEngine
from crypto.engine import CryptoEngine
from ledger.offchain_store import OffChainStore
from ledger.dlt_network import PermissionedDLTNetwork


class AdaptiveLoggingPipeline:
    """
    Main orchestration engine implementing Algorithm 1: AdaptivePQLog(e).
    """

    def __init__(
        self,
        ai_model: AIRiskClassifier = None,
        policy_engine: AdaptiveSecurityPolicyEngine = None,
        crypto_engine: CryptoEngine = None,
        offchain_store: OffChainStore = None,
        dlt_network: PermissionedDLTNetwork = None,
    ):
        self.ai = ai_model or AIRiskClassifier()
        self.policy = policy_engine or AdaptiveSecurityPolicyEngine()
        self.crypto = crypto_engine or CryptoEngine()
        self.store = offchain_store or OffChainStore()
        self.ledger = dlt_network or PermissionedDLTNetwork()

        # Cumulative telemetry counters
        self.total_processed = 0
        self.risk_counts = {tier.value: 0 for tier in RiskLevel}
        self.total_e2e_latency_ms = 0.0

    def process_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes Algorithm 1: AdaptivePQLog(e).
        Returns full telemetry packet including verification record R, timing metrics, and off-chain pointer.
        """
        t_pipeline_start = time.perf_counter()

        # Step 1: Preprocess(e)
        event_id = raw_event.get("event_id")
        timestamp_now = raw_event.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Step 2: (rho, s) <- M.Infer(e')
        ai_result = self.ai.infer(raw_event)
        risk_level = ai_result["risk_level"]
        risk_score = ai_result["risk_score"]
        confidence = ai_result["confidence"]

        # Step 3: (op, prio) <- pi(rho, s)
        decision = self.policy.evaluate_policy(risk_level, risk_score, confidence)
        effective_risk = decision["effective_risk_level"]
        crypto_op = decision["crypto_op"]
        priority = decision["dlt_priority"]

        # Step 4: h <- H(Canonicalize(e'))
        event_hash = compute_canonical_hash(raw_event, algorithm="sha256")

        # Step 5: meta <- (id(e'), t_now, rho, op, h)
        metadata = {
            "event_id": event_id,
            "timestamp": timestamp_now,
            "risk_level": effective_risk.value,
            "crypto_op": crypto_op,
            "event_hash": event_hash,
            "source_ip": raw_event.get("source_ip", "UNKNOWN"),
            "event_type": raw_event.get("event_type", "GENERIC_EVENT"),
        }

        # Step 6-9: Sign metadata (PQC or Lightweight MAC)
        sig_result = self.crypto.sign_metadata(effective_risk, metadata)
        signature = sig_result["signature_hex"]
        public_key = sig_result["public_key_hex"]

        # Step 10-12: Payload Confidentiality with ML-KEM + AES-256-GCM & Off-Chain Storage
        payload_to_store, is_encrypted, enc_time_ms = self.crypto.secure_offchain_payload(
            effective_risk,
            raw_event
        )
        ptr = self.store.put(event_id, payload_to_store)

        # Step 13: R <- (meta, sigma, ptr)
        record_R = {
            "event_id": event_id,
            "timestamp": timestamp_now,
            "risk_level": effective_risk.value,
            "crypto_op": crypto_op,
            "event_hash": event_hash,
            "signature": signature,
            "public_key": public_key,
            "payload_ptr": ptr,
            "is_encrypted": is_encrypted,
        }

        # Step 14: L.Commit(R, priority = prio)
        committed_block = self.ledger.commit_record(record_R, priority=priority)

        # Step 15: emit metrics
        e2e_latency_ms = (time.perf_counter() - t_pipeline_start) * 1000.0

        # Update telemetry
        self.total_processed += 1
        self.risk_counts[effective_risk.value] += 1
        self.total_e2e_latency_ms += e2e_latency_ms

        return {
            "record": record_R,
            "committed_block": committed_block.index if committed_block else None,
            "dlt_status": "COMMITTED" if committed_block else "QUEUED_IN_MEMPOOL",
            "ai_inference": {
                "inferred_risk": risk_level.value,
                "effective_risk": effective_risk.value,
                "risk_score": risk_score,
                "confidence": confidence,
                "ai_latency_ms": ai_result["latency_ms"],
                "failsafe_triggered": decision["failsafe_applied"],
            },
            "security_decision": decision,
            "cryptography": {
                "algorithm": sig_result["algorithm"],
                "is_pqc": sig_result["is_pqc"],
                "signature_size_bytes": sig_result["signature_size_bytes"],
                "sign_time_ms": sig_result["sign_time_ms"],
                "is_payload_encrypted": is_encrypted,
                "encryption_time_ms": enc_time_ms,
            },
            "storage": {
                "on_chain_record_bytes": len(canonicalize_json(record_R)),
                "off_chain_bytes": len(canonicalize_json(payload_to_store)),
                "pointer": ptr,
            },
            "metrics": {
                "e2e_latency_ms": round(e2e_latency_ms, 3),
            }
        }
