"""
Unified Cryptographic Engine
Coordinates Post-Quantum Signatures (FIPS 204 ML-DSA, FIPS 205 SLH-DSA),
Key Encapsulation (FIPS 203 ML-KEM), and Classical Baselines with telemetry.
"""

import time
import json
from typing import Dict, Any, Tuple, Optional
from config import RiskLevel, CryptoOp, POLICY_MATRIX
from crypto.pqc_ml_dsa import MLDSA
from crypto.pqc_slh_dsa import SLHDSA
from crypto.pqc_ml_kem import HybridPQPayloadEncryptor
from crypto.classical_baseline import ClassicalCryptoBaseline
from data.canonicalizer import canonicalize_json


class CryptoEngine:
    """Manages active cryptographic algorithms and executes adaptive cryptographic policies."""

    def __init__(self):
        # Initialize Classical Baseline
        self.classical = ClassicalCryptoBaseline()

        # Initialize PQC Signature Instances & Keypairs
        self.dsa_44 = MLDSA("ML-DSA-44")
        self.dsa_44_pk, self.dsa_44_sk = self.dsa_44.keygen()

        self.dsa_65 = MLDSA("ML-DSA-65")
        self.dsa_65_pk, self.dsa_65_sk = self.dsa_65.keygen()

        self.dsa_87 = MLDSA("ML-DSA-87")
        self.dsa_87_pk, self.dsa_87_sk = self.dsa_87.keygen()

        self.slh = SLHDSA("SLH-DSA-SHAKE-128s")
        self.slh_pk, self.slh_sk = self.slh.keygen()

        # Initialize Hybrid Payload Encryptors (KEM + AES-256-GCM)
        self.kem_high = HybridPQPayloadEncryptor("ML-KEM-768")
        self.kem_critical = HybridPQPayloadEncryptor("ML-KEM-1024")

        # Telemetry metrics accumulator
        self.metrics_counter = {
            "classical_hashes": 0,
            "hmac_tags": 0,
            "ml_dsa_44_sigs": 0,
            "ml_dsa_65_sigs": 0,
            "slh_dsa_sigs": 0,
            "ml_kem_encryptions": 0,
            "total_crypto_time_ms": 0.0,
        }

    def sign_metadata(self, risk_level: RiskLevel, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Signs the canonical metadata dictionary according to the risk-selected policy.
        Returns signature details: signature_hex, algorithm, public_key_hex, sign_time_ms, sig_size_bytes.
        """
        policy = POLICY_MATRIX[risk_level]
        serialized_meta = canonicalize_json(metadata)

        t_start = time.perf_counter()

        if risk_level == RiskLevel.LOW:
            # Standard lightweight HMAC audit tag
            tag = self.classical.compute_hmac(serialized_meta)
            sign_time = (time.perf_counter() - t_start) * 1000.0
            self.metrics_counter["hmac_tags"] += 1
            self.metrics_counter["total_crypto_time_ms"] += sign_time

            return {
                "algorithm": CryptoOp.CLASSICAL_HASH.value,
                "is_pqc": False,
                "signature_hex": tag,
                "public_key_hex": "HMAC_PRESHARED_AUDIT_TAG",
                "sign_time_ms": round(sign_time, 3),
                "signature_size_bytes": len(tag) // 2,
                "public_key_size_bytes": 32,
            }

        elif risk_level == RiskLevel.MEDIUM:
            # NIST FIPS 204 ML-DSA-44 Digital Signature
            sig = self.dsa_44.sign(self.dsa_44_sk, serialized_meta)
            sign_time = (time.perf_counter() - t_start) * 1000.0
            self.metrics_counter["ml_dsa_44_sigs"] += 1
            self.metrics_counter["total_crypto_time_ms"] += sign_time

            return {
                "algorithm": CryptoOp.ML_DSA_44.value,
                "is_pqc": True,
                "signature_hex": sig.hex(),
                "public_key_hex": self.dsa_44_pk.hex(),
                "sign_time_ms": round(sign_time, 3),
                "signature_size_bytes": len(sig),
                "public_key_size_bytes": len(self.dsa_44_pk),
            }

        elif risk_level == RiskLevel.HIGH:
            # NIST FIPS 204 ML-DSA-65 Higher Parameter Digital Signature
            sig = self.dsa_65.sign(self.dsa_65_sk, serialized_meta)
            sign_time = (time.perf_counter() - t_start) * 1000.0
            self.metrics_counter["ml_dsa_65_sigs"] += 1
            self.metrics_counter["total_crypto_time_ms"] += sign_time

            return {
                "algorithm": CryptoOp.ML_DSA_65.value,
                "is_pqc": True,
                "signature_hex": sig.hex(),
                "public_key_hex": self.dsa_65_pk.hex(),
                "sign_time_ms": round(sign_time, 3),
                "signature_size_bytes": len(sig),
                "public_key_size_bytes": len(self.dsa_65_pk),
            }

        else:  # CRITICAL
            # NIST FIPS 205 SLH-DSA Stateless Hash-Based Digital Signature
            sig = self.slh.sign(self.slh_sk, serialized_meta)
            sign_time = (time.perf_counter() - t_start) * 1000.0
            self.metrics_counter["slh_dsa_sigs"] += 1
            self.metrics_counter["total_crypto_time_ms"] += sign_time

            return {
                "algorithm": CryptoOp.SLH_DSA_SHAKE.value,
                "is_pqc": True,
                "signature_hex": sig.hex(),
                "public_key_hex": self.slh_pk.hex(),
                "sign_time_ms": round(sign_time, 3),
                "signature_size_bytes": len(sig),
                "public_key_size_bytes": len(self.slh_pk),
            }

    def verify_metadata_signature(
        self,
        algorithm_str: str,
        metadata: Dict[str, Any],
        signature_hex: str,
        public_key_hex: str
    ) -> Tuple[bool, float]:
        """
        Verifies metadata signature using the appropriate verification engine.
        Returns (is_valid, verification_time_ms).
        """
        serialized_meta = canonicalize_json(metadata)
        t_start = time.perf_counter()

        try:
            if algorithm_str == CryptoOp.CLASSICAL_HASH.value:
                valid = self.classical.verify_hmac(serialized_meta, signature_hex)
            elif algorithm_str == CryptoOp.ML_DSA_44.value:
                sig_bytes = bytes.fromhex(signature_hex)
                pk_bytes = bytes.fromhex(public_key_hex)
                valid = self.dsa_44.verify(pk_bytes, serialized_meta, sig_bytes)
            elif algorithm_str == CryptoOp.ML_DSA_65.value:
                sig_bytes = bytes.fromhex(signature_hex)
                pk_bytes = bytes.fromhex(public_key_hex)
                valid = self.dsa_65.verify(pk_bytes, serialized_meta, sig_bytes)
            elif algorithm_str == CryptoOp.SLH_DSA_SHAKE.value:
                sig_bytes = bytes.fromhex(signature_hex)
                pk_bytes = bytes.fromhex(public_key_hex)
                valid = self.slh.verify(pk_bytes, serialized_meta, sig_bytes)
            else:
                valid = False
        except Exception:
            valid = False

        verify_time = (time.perf_counter() - t_start) * 1000.0
        return valid, round(verify_time, 3)

    def secure_offchain_payload(self, risk_level: RiskLevel, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, float]:
        """
        Encrypts payload with post-quantum ML-KEM + AES-256-GCM if policy requires confidentiality.
        Returns (payload_to_store, is_encrypted, encryption_time_ms).
        """
        policy = POLICY_MATRIX[risk_level]
        if not policy["require_payload_encryption"]:
            return payload, False, 0.0

        t_start = time.perf_counter()
        if risk_level == RiskLevel.HIGH:
            encrypted = self.kem_high.encrypt_payload(payload)
        else:  # CRITICAL
            encrypted = self.kem_critical.encrypt_payload(payload)

        enc_time = (time.perf_counter() - t_start) * 1000.0
        self.metrics_counter["ml_kem_encryptions"] += 1
        self.metrics_counter["total_crypto_time_ms"] += enc_time

        return encrypted, True, round(enc_time, 3)

    def decrypt_offchain_payload(self, risk_level: RiskLevel, stored_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypts encrypted payload using designated KEM."""
        if "kem_ciphertext_hex" not in stored_payload:
            return stored_payload  # Already plaintext

        if risk_level == RiskLevel.HIGH:
            return self.kem_high.decrypt_payload(stored_payload)
        else:
            return self.kem_critical.decrypt_payload(stored_payload)

    def run_crypto_benchmark(self, iterations: int = 20) -> Dict[str, Any]:
        """
        Executes a comparative benchmark across Classical vs PQC algorithms.
        Generates Table IV cryptographic comparison metrics.
        """
        test_msg = b"ABESIT_AKTU_PQC_AUDIT_BENCHMARK_CANONICAL_TEST_STRING_2026"
        bench_results = {}

        # 1. Classical ECDSA secp256k1
        ecdsa_pk, ecdsa_sk = self.classical.ecdsa_keygen()
        t_sign = 0.0
        t_verify = 0.0
        for _ in range(iterations):
            t0 = time.perf_counter()
            sig = self.classical.ecdsa_sign(ecdsa_sk, test_msg)
            t_sign += (time.perf_counter() - t0)

            t0 = time.perf_counter()
            self.classical.ecdsa_verify(ecdsa_pk, test_msg, sig)
            t_verify += (time.perf_counter() - t0)

        bench_results["Classical ECDSA (secp256k1)"] = {
            "type": "Classical (Quantum-Fragile)",
            "pk_size_bytes": len(ecdsa_pk),
            "sig_size_bytes": len(sig),
            "sign_latency_ms": round((t_sign / iterations) * 1000.0, 3),
            "verify_latency_ms": round((t_verify / iterations) * 1000.0, 3),
            "quantum_resistant": False
        }

        # 2. ML-DSA-44 (FIPS 204)
        t_sign = 0.0
        t_verify = 0.0
        for _ in range(iterations):
            t0 = time.perf_counter()
            sig = self.dsa_44.sign(self.dsa_44_sk, test_msg)
            t_sign += (time.perf_counter() - t0)

            t0 = time.perf_counter()
            self.dsa_44.verify(self.dsa_44_pk, test_msg, sig)
            t_verify += (time.perf_counter() - t0)

        bench_results["ML-DSA-44 (NIST FIPS 204)"] = {
            "type": "Lattice PQC (Category 2)",
            "pk_size_bytes": len(self.dsa_44_pk),
            "sig_size_bytes": len(sig),
            "sign_latency_ms": round((t_sign / iterations) * 1000.0, 3),
            "verify_latency_ms": round((t_verify / iterations) * 1000.0, 3),
            "quantum_resistant": True
        }

        # 3. ML-DSA-65 (FIPS 204)
        t_sign = 0.0
        t_verify = 0.0
        for _ in range(iterations):
            t0 = time.perf_counter()
            sig = self.dsa_65.sign(self.dsa_65_sk, test_msg)
            t_sign += (time.perf_counter() - t0)

            t0 = time.perf_counter()
            self.dsa_65.verify(self.dsa_65_pk, test_msg, sig)
            t_verify += (time.perf_counter() - t0)

        bench_results["ML-DSA-65 (NIST FIPS 204)"] = {
            "type": "Lattice PQC (Category 3)",
            "pk_size_bytes": len(self.dsa_65_pk),
            "sig_size_bytes": len(sig),
            "sign_latency_ms": round((t_sign / iterations) * 1000.0, 3),
            "verify_latency_ms": round((t_verify / iterations) * 1000.0, 3),
            "quantum_resistant": True
        }

        # 4. SLH-DSA (FIPS 205)
        t_sign = 0.0
        t_verify = 0.0
        for _ in range(iterations):
            t0 = time.perf_counter()
            sig = self.slh.sign(self.slh_sk, test_msg)
            t_sign += (time.perf_counter() - t0)

            t0 = time.perf_counter()
            self.slh.verify(self.slh_pk, test_msg, sig)
            t_verify += (time.perf_counter() - t0)

        bench_results["SLH-DSA-SHAKE-128s (NIST FIPS 205)"] = {
            "type": "Stateless Hash-Based PQC (Category 1)",
            "pk_size_bytes": len(self.slh_pk),
            "sig_size_bytes": len(sig),
            "sign_latency_ms": round((t_sign / iterations) * 1000.0, 3),
            "verify_latency_ms": round((t_verify / iterations) * 1000.0, 3),
            "quantum_resistant": True
        }

        # 5. ML-KEM-768 (FIPS 203)
        t_enc = 0.0
        t_dec = 0.0
        for _ in range(iterations):
            t0 = time.perf_counter()
            ss, ct = self.kem_high.kem.encaps(self.kem_high.pk)
            t_enc += (time.perf_counter() - t0)

            t0 = time.perf_counter()
            self.kem_high.kem.decaps(self.kem_high.sk, ct)
            t_dec += (time.perf_counter() - t0)

        bench_results["ML-KEM-768 (NIST FIPS 203 KEM)"] = {
            "type": "Lattice KEM (Category 3)",
            "pk_size_bytes": len(self.kem_high.pk),
            "sig_size_bytes": len(ct),  # Ciphertext size
            "sign_latency_ms": round((t_enc / iterations) * 1000.0, 3),  # Encaps
            "verify_latency_ms": round((t_dec / iterations) * 1000.0, 3),  # Decaps
            "quantum_resistant": True
        }

        return bench_results
