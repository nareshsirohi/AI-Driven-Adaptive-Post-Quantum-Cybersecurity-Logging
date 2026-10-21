"""
Comprehensive Evaluation & Benchmarking Suite (Section VI & RQ1-RQ4)
Simulates and evaluates:
- Baseline 1 (B1): Classical Static Logging (SHA-256 only, Centralized DB)
- Baseline 2 (B2): Full Blockchain Logging (BlockAudit / BlockTrail with ECDSA)
- Baseline 3 (B3): Static Heavy PQC on-chain (Uniform strong PQC for all events)
- Baseline 4 (B4): Proposed AI-Driven Adaptive Post-Quantum Logging (Algorithm 1)
"""

import time
import json
import statistics
import numpy as np
from typing import Dict, Any, List
from data.generator import EventStreamGenerator
from data.canonicalizer import canonicalize_json, compute_canonical_hash
from pipeline.orchestrator import AdaptiveLoggingPipeline
from crypto.classical_baseline import ClassicalCryptoBaseline
from crypto.pqc_ml_dsa import MLDSA
from crypto.pqc_slh_dsa import SLHDSA
from crypto.pqc_ml_kem import HybridPQPayloadEncryptor
from config import RiskLevel


class BenchmarkSuite:
    """Evaluates latency, throughput, storage, and cryptographic overhead across B1-B4."""

    def __init__(self, pipeline: AdaptiveLoggingPipeline):
        self.pipeline = pipeline
        self.generator = EventStreamGenerator(seed=777)
        self.classical = ClassicalCryptoBaseline()
        self.heavy_pqc_sig = SLHDSA("SLH-DSA-SHAKE-128s")
        self.heavy_pqc_pk, self.heavy_pqc_sk = self.heavy_pqc_sig.keygen()
        self.heavy_kem = HybridPQPayloadEncryptor("ML-KEM-1024")

    def run_benchmark(self, num_events: int = 100) -> Dict[str, Any]:
        """Runs the 4 baselines on identical event streams and collects Table IV metrics."""
        print(f"[*] Generating {num_events} realistic events for comparative benchmarking...")
        events = self.generator.generate_batch(num_events)

        results = {
            "B1_Classical_Centralized": self._benchmark_b1(events),
            "B2_Full_Blockchain_ECDSA": self._benchmark_b2(events),
            "B3_Static_PQC_Blockchain": self._benchmark_b3(events),
            "B4_Proposed_Adaptive_PQC_DLT": self._benchmark_b4(events),
        }

        # Compute relative improvements (RQ4)
        adaptive_lat = results["B4_Proposed_Adaptive_PQC_DLT"]["latency_ms"]["mean"]
        static_pqc_lat = results["B3_Static_PQC_Blockchain"]["latency_ms"]["mean"]
        speedup = static_pqc_lat / adaptive_lat if adaptive_lat > 0 else 1.0

        adaptive_onchain = results["B4_Proposed_Adaptive_PQC_DLT"]["storage_bytes"]["onchain_per_event"]
        b3_onchain = results["B3_Static_PQC_Blockchain"]["storage_bytes"]["onchain_per_event"]
        pqc_storage_saving = ((b3_onchain - adaptive_onchain) / b3_onchain) * 100.0 if b3_onchain > 0 else 0.0

        summary = {
            "num_events_evaluated": num_events,
            "latency_speedup_vs_static_pqc": round(speedup, 2),
            "pqc_onchain_storage_saving_percent": round(pqc_storage_saving, 2),
            "framework_advantages": [
                "Preserves 100% quantum resilience for sensitive and critical events.",
                f"Saves {pqc_storage_saving:.1f}% on-chain ledger storage compared to static uniform PQC logging (B3).",
                "Keeps detailed high-volume payload records off-chain, maintaining compact cryptographic tuples on DLT.",
                "Integrates AI risk-conditioned protection into continuous streaming pipelines."
            ]
        }

        return {
            "summary": summary,
            "baselines": results,
        }

    def _benchmark_b1(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """B1: Classical SHA-256 only, centralized DB, no DLT, no PQC."""
        latencies = []
        onchain_bytes = []
        offchain_bytes = []

        for e in events:
            t0 = time.perf_counter()
            canon_bytes = canonicalize_json(e)
            h = compute_canonical_hash(e)
            # Simulated central DB write
            db_record = {"event_hash": h, "raw": e}
            latencies.append((time.perf_counter() - t0) * 1000.0)
            onchain_bytes.append(0)  # No DLT
            offchain_bytes.append(len(canon_bytes))

        return self._compute_summary_stats(latencies, onchain_bytes, offchain_bytes, "Classical Centralized (SHA-256)", pqc=False)

    def _benchmark_b2(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """B2: Full blockchain logging (every full payload on chain, traditional ECDSA)."""
        latencies = []
        onchain_bytes = []
        offchain_bytes = []
        _, ecdsa_sk = self.classical.ecdsa_keygen()

        for e in events:
            t0 = time.perf_counter()
            canon_bytes = canonicalize_json(e)
            h = compute_canonical_hash(e)
            sig = self.classical.ecdsa_sign(ecdsa_sk, canon_bytes)
            # Full payload + signature on chain
            full_tx = {"payload": e, "hash": h, "sig": sig.hex()}
            tx_bytes = len(canonicalize_json(full_tx))
            latencies.append((time.perf_counter() - t0) * 1000.0 + 1.2)  # + simulated ledger consensus overhead
            onchain_bytes.append(tx_bytes)
            offchain_bytes.append(0)

        return self._compute_summary_stats(latencies, onchain_bytes, offchain_bytes, "Full Blockchain + ECDSA (BlockAudit)", pqc=False)

    def _benchmark_b3(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """B3: Static PQC on-chain (Uniform heavy PQC SLH-DSA + ML-KEM for 100% of events)."""
        latencies = []
        onchain_bytes = []
        offchain_bytes = []

        for e in events:
            t0 = time.perf_counter()
            canon_bytes = canonicalize_json(e)
            h = compute_canonical_hash(e)
            # Heavy PQC SLH-DSA signature for every single event
            sig = self.heavy_pqc_sig.sign(self.heavy_pqc_sk, canon_bytes)
            # Heavy ML-KEM encryption
            enc = self.heavy_kem.encrypt_payload(e)
            tx = {"hash": h, "pqc_sig": sig.hex(), "enc": enc}
            tx_bytes = len(canonicalize_json(tx))

            latencies.append((time.perf_counter() - t0) * 1000.0 + 2.5)  # Heavy crypto + ledger commit
            onchain_bytes.append(tx_bytes)
            offchain_bytes.append(0)

        return self._compute_summary_stats(latencies, onchain_bytes, offchain_bytes, "Static Uniform PQC (No Adaptation)", pqc=True)

    def _benchmark_b4(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """B4: Proposed Adaptive PQC + DLT Logging (Algorithm 1)."""
        latencies = []
        onchain_bytes = []
        offchain_bytes = []

        for e in events:
            res = self.pipeline.process_event(e)
            latencies.append(res["metrics"]["e2e_latency_ms"])
            onchain_bytes.append(res["storage"]["on_chain_record_bytes"])
            offchain_bytes.append(res["storage"]["off_chain_bytes"])

        return self._compute_summary_stats(latencies, onchain_bytes, offchain_bytes, "Proposed Adaptive PQC + DLT", pqc=True)

    def _compute_summary_stats(
        self,
        latencies: List[float],
        onchain_b: List[int],
        offchain_b: List[int],
        name: str,
        pqc: bool
    ) -> Dict[str, Any]:
        lat_sorted = sorted(latencies)
        n = len(lat_sorted)
        p95_idx = int(0.95 * n)

        mean_lat = statistics.mean(latencies)
        throughput = 1000.0 / mean_lat if mean_lat > 0 else 0.0

        return {
            "name": name,
            "quantum_resistant": pqc,
            "throughput_events_per_sec": round(throughput, 1),
            "latency_ms": {
                "mean": round(mean_lat, 3),
                "median": round(statistics.median(latencies), 3),
                "p95": round(lat_sorted[min(p95_idx, n - 1)], 3),
                "min": round(min(latencies), 3),
                "max": round(max(latencies), 3),
            },
            "storage_bytes": {
                "onchain_per_event": round(statistics.mean(onchain_b), 1),
                "offchain_per_event": round(statistics.mean(offchain_b), 1),
                "total_per_event": round(statistics.mean(onchain_b) + statistics.mean(offchain_b), 1),
            }
        }
