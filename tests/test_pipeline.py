"""
Unit & Integration Test Suite
Verifies all components of the AI-Driven Adaptive Post-Quantum Cybersecurity Logging System.
"""

import unittest
import os
import json
from config import RiskLevel, CryptoOp
from data.canonicalizer import canonicalize_json, compute_canonical_hash
from data.generator import EventStreamGenerator
from ai_engine.model import AIRiskClassifier
from crypto.pqc_ml_dsa import MLDSA
from crypto.pqc_slh_dsa import SLHDSA
from crypto.pqc_ml_kem import HybridPQPayloadEncryptor
from ledger.merkle import MerkleTree
from ledger.dlt_network import PermissionedDLTNetwork
from pipeline.orchestrator import AdaptiveLoggingPipeline
from audit.verifier import AuditVerifier
from audit.attack_simulator import AttackSimulator


class TestPQCCyberLogging(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.generator = EventStreamGenerator(seed=123)
        cls.pipeline = AdaptiveLoggingPipeline()
        cls.verifier = AuditVerifier(cls.pipeline.crypto, cls.pipeline.store, cls.pipeline.ledger)
        cls.simulator = AttackSimulator(cls.pipeline, cls.verifier)

    def test_01_canonicalizer_determinism(self):
        """Tests that key ordering and whitespace don't alter canonical hash."""
        obj1 = {"b": 2, "a": 1, "nested": {"z": 9, "m": 5}}
        obj2 = {"nested": {"m": 5, "z": 9}, "a": 1, "b": 2}
        h1 = compute_canonical_hash(obj1)
        h2 = compute_canonical_hash(obj2)
        self.assertEqual(h1, h2, "Canonical hash must be deterministic regardless of key order")

    def test_02_pqc_ml_dsa(self):
        """Tests NIST FIPS 204 ML-DSA sign and verify."""
        dsa = MLDSA("ML-DSA-44")
        pk, sk = dsa.keygen()
        msg = b"INTEGRITY_CHECK_AKTU_ABESIT_2026"
        sig = dsa.sign(sk, msg)
        self.assertEqual(len(sig), dsa.params["sig_size"])
        self.assertTrue(dsa.verify(pk, msg, sig))

        # Check corrupted message fails
        self.assertFalse(dsa.verify(pk, b"CORRUPTED_MSG", sig))

    def test_03_pqc_slh_dsa(self):
        """Tests NIST FIPS 205 SLH-DSA sign and verify."""
        slh = SLHDSA("SLH-DSA-SHAKE-128s")
        pk, sk = slh.keygen()
        msg = b"CRITICAL_INCIDENT_HASH_2026"
        sig = slh.sign(sk, msg)
        self.assertEqual(len(sig), slh.params["sig_size"])
        self.assertTrue(slh.verify(pk, msg, sig))
        self.assertFalse(slh.verify(pk, b"ALTERED_ALERT", sig))

    def test_04_pqc_ml_kem_encryption(self):
        """Tests NIST FIPS 203 ML-KEM + AES-256-GCM payload encryption & decryption."""
        kem = HybridPQPayloadEncryptor("ML-KEM-768")
        payload = {"secret_exfil_data": "user_passwords_and_tokens", "code": 1337}
        enc = kem.encrypt_payload(payload)
        self.assertIn("kem_ciphertext_hex", enc)
        self.assertIn("aes_ciphertext_hex", enc)

        dec = kem.decrypt_payload(enc)
        self.assertEqual(dec["secret_exfil_data"], payload["secret_exfil_data"])
        self.assertEqual(dec["code"], 1337)

    def test_05_merkle_tree_proofs(self):
        """Tests Merkle tree construction and inclusion verification."""
        leaves = [
            compute_canonical_hash({"e": 1}),
            compute_canonical_hash({"e": 2}),
            compute_canonical_hash({"e": 3}),
            compute_canonical_hash({"e": 4})
        ]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(2)
        valid = MerkleTree.verify_proof(leaves[2], proof, tree.root)
        self.assertTrue(valid)

        # Invalid leaf check
        invalid = MerkleTree.verify_proof("badhash" + "0" * 57, proof, tree.root)
        self.assertFalse(invalid)

    def test_06_ai_inference_and_failsafe(self):
        """Tests AI threat classification and fail-safe policy enforcement."""
        classifier = AIRiskClassifier()
        low_event = self.generator.generate_event(force_tier=RiskLevel.LOW)
        crit_event = self.generator.generate_event(force_tier=RiskLevel.CRITICAL)

        res_low = classifier.infer(low_event)
        res_crit = classifier.infer(crit_event)

        self.assertIn(res_low["risk_level"], [RiskLevel.LOW, RiskLevel.MEDIUM])
        self.assertEqual(res_crit["risk_level"], RiskLevel.CRITICAL)
        self.assertGreater(res_crit["risk_score"], 0.70)

    def test_07_end_to_end_adaptive_pipeline(self):
        """Tests Algorithm 1 end-to-end processing across different risk tiers."""
        event = self.generator.generate_event(force_tier=RiskLevel.CRITICAL)
        res = self.pipeline.process_event(event)

        self.assertIn("record", res)
        self.assertEqual(res["record"]["risk_level"], RiskLevel.CRITICAL.value)
        self.assertTrue(res["cryptography"]["is_pqc"])
        self.assertTrue(res["cryptography"]["is_payload_encrypted"])

        # Flush mempool to commit
        self.pipeline.ledger.flush_pending_pool()

        # Audit event
        audit = self.verifier.audit_event(event["event_id"])
        self.assertEqual(audit["audit_verdict"], "VERIFIED_AUTHENTIC")
        self.assertFalse(audit["tamper_detected"])

    def test_08_adversarial_tamper_detection(self):
        """Tests that off-chain payload tampering is instantly flagged by verifier."""
        tamper_res = self.simulator.test_payload_tampering()
        self.assertTrue(tamper_res["test_passed"])
        self.assertTrue(tamper_res["tamper_detected"])

    def test_09_adversarial_deletion_detection(self):
        """Tests that off-chain payload deletion is detected as a broken link."""
        del_res = self.simulator.test_object_deletion()
        self.assertTrue(del_res["test_passed"])
        self.assertTrue(del_res["tamper_detected"])

    def test_10_blockchain_integrity(self):
        """Tests that the permissioned DLT chain passes cryptographic validation."""
        valid, errors = self.pipeline.ledger.verify_chain_integrity()
        self.assertTrue(valid, f"Chain integrity failed: {errors}")


if __name__ == "__main__":
    unittest.main()
