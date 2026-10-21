"""
Independent Audit Verifier Engine
Performs forensic recomputation, Merkle proof validation, and post-quantum cryptographic checks.
"""

import time
import hashlib
from typing import Dict, Any, Tuple
from config import RiskLevel, CryptoOp
from data.canonicalizer import canonicalize_json, compute_canonical_hash
from crypto.engine import CryptoEngine
from ledger.offchain_store import OffChainStore
from ledger.dlt_network import PermissionedDLTNetwork
from ledger.merkle import MerkleTree


class AuditVerifier:
    """Independent auditor verifying log authenticity, tamper resistance, and PQC validity."""

    def __init__(
        self,
        crypto_engine: CryptoEngine,
        offchain_store: OffChainStore,
        dlt_network: PermissionedDLTNetwork
    ):
        self.crypto = crypto_engine
        self.store = offchain_store
        self.ledger = dlt_network

    def audit_event(self, event_id: str) -> Dict[str, Any]:
        """
        Executes complete verification sequence on an event:
        1. Ledger retrieval & Merkle inclusion proof.
        2. Off-chain payload fetch.
        3. Canonical hash recomputation: H(event_stored) == H(event_onchain).
        4. Cryptographic signature check (ML-DSA / SLH-DSA / HMAC).
        """
        t_start = time.perf_counter()
        audit_log = []

        # Step 1: Fetch on-chain record R
        ledger_entry = self.ledger.get_record(event_id)
        if not ledger_entry:
            return {
                "event_id": event_id,
                "audit_verdict": "FAIL_NOT_FOUND",
                "tamper_detected": True,
                "details": "Event record does not exist on the distributed ledger (possible unauthorized deletion or uncommitted).",
                "checks": {"ledger_inclusion": False},
                "audit_time_ms": round((time.perf_counter() - t_start) * 1000.0, 3)
            }

        record = ledger_entry["record"]
        onchain_hash = record["event_hash"]
        onchain_sig = record["signature"]
        onchain_pk = record["public_key"]
        crypto_op = record["crypto_op"]
        payload_ptr = record["payload_ptr"]
        risk_level = RiskLevel(record["risk_level"])

        audit_log.append(f"Located on-chain record R in Block #{ledger_entry['block_index']}.")

        # Step 2: Validate Merkle root if committed
        merkle_valid = True
        if ledger_entry["status"] == "COMMITTED":
            block_idx = ledger_entry["block_index"]
            block = self.ledger.chain[block_idx]
            leaf_hashes = [r.get("event_hash", "") for r in block.records]
            try:
                rec_idx = leaf_hashes.index(onchain_hash)
                tree = MerkleTree(leaf_hashes)
                proof = tree.get_proof(rec_idx)
                merkle_valid = MerkleTree.verify_proof(onchain_hash, proof, block.merkle_root)
                audit_log.append(f"Merkle inclusion proof verified against block root {block.merkle_root[:16]}...")
            except Exception as e:
                merkle_valid = False
                audit_log.append(f"Merkle proof verification error: {str(e)}")

        # Step 3: Fetch off-chain payload from S
        raw_payload = self.store.get(payload_ptr)
        if raw_payload is None:
            return {
                "event_id": event_id,
                "audit_verdict": "FAIL_OBJECT_DELETED",
                "tamper_detected": True,
                "details": f"Off-chain payload pointed by {payload_ptr} was DELETED or missing from storage!",
                "checks": {
                    "ledger_inclusion": True,
                    "merkle_inclusion": merkle_valid,
                    "offchain_payload_exists": False,
                },
                "audit_time_ms": round((time.perf_counter() - t_start) * 1000.0, 3)
            }

        audit_log.append(f"Retrieved off-chain payload from {payload_ptr}.")

        # Step 4: If payload was encrypted, decrypt it for content inspection
        decrypted_payload = raw_payload
        if record.get("is_encrypted", False):
            try:
                decrypted_payload = self.crypto.decrypt_offchain_payload(risk_level, raw_payload)
                audit_log.append("Successfully decapsulated ML-KEM key and decrypted off-chain payload.")
            except Exception as e:
                audit_log.append(f"CIPHERTEXT TAMPER ALERT: Payload decryption failed ({str(e)}). Authenticated ciphertext corrupted!")
                return {
                    "event_id": event_id,
                    "audit_verdict": "FAIL_CIPHERTEXT_TAMPERED",
                    "tamper_detected": True,
                    "details": f"Post-Quantum encrypted payload ciphertext or GCM tag was corrupted/tampered: {str(e)}",
                    "checks": {
                        "ledger_inclusion": True,
                        "merkle_inclusion": merkle_valid,
                        "offchain_payload_exists": True,
                        "hash_integrity": False,
                        "signature_validity": False,
                    },
                    "audit_time_ms": round((time.perf_counter() - t_start) * 1000.0, 3),
                    "audit_steps": audit_log,
                }

        # Step 5: Recompute canonical event hash H(Canonicalize(e))
        recomputed_hash = compute_canonical_hash(decrypted_payload, algorithm="sha256")
        hash_matches = (recomputed_hash == onchain_hash)

        if not hash_matches:
            audit_log.append(f"TAMPER ALERT: Recomputed hash ({recomputed_hash[:16]}...) != On-chain hash ({onchain_hash[:16]}...)")
        else:
            audit_log.append("Cryptographic hash integrity verified: H(stored_event) matches on-chain commitment.")

        # Step 6: Verify Cryptographic / PQC Signature
        metadata = {
            "event_id": record["event_id"],
            "timestamp": record["timestamp"],
            "risk_level": record["risk_level"],
            "crypto_op": record["crypto_op"],
            "event_hash": onchain_hash,
            "source_ip": decrypted_payload.get("source_ip", "UNKNOWN"),
            "event_type": decrypted_payload.get("event_type", "GENERIC_EVENT"),
        }

        sig_valid, sig_verify_ms = self.crypto.verify_metadata_signature(
            crypto_op,
            metadata,
            onchain_sig,
            onchain_pk
        )

        if not sig_valid:
            audit_log.append(f"SIGNATURE FORGERY DETECTED: Signature verification failed for algorithm {crypto_op}.")
        else:
            audit_log.append(f"Digital signature valid ({crypto_op}) in {sig_verify_ms} ms.")

        overall_valid = (hash_matches and sig_valid and merkle_valid)
        audit_time_ms = (time.perf_counter() - t_start) * 1000.0

        return {
            "event_id": event_id,
            "audit_verdict": "VERIFIED_AUTHENTIC" if overall_valid else "TAMPER_DETECTED",
            "tamper_detected": not overall_valid,
            "checks": {
                "ledger_inclusion": True,
                "merkle_inclusion": merkle_valid,
                "offchain_payload_exists": True,
                "hash_integrity": hash_matches,
                "signature_validity": sig_valid,
            },
            "hashes": {
                "onchain_event_hash": onchain_hash,
                "recomputed_stored_hash": recomputed_hash,
            },
            "cryptography": {
                "algorithm": crypto_op,
                "signature_verification_time_ms": sig_verify_ms,
            },
            "block_info": {
                "block_index": ledger_entry["block_index"],
                "block_hash": ledger_entry["block_hash"],
            },
            "audit_steps": audit_log,
            "audit_time_ms": round(audit_time_ms, 3)
        }
