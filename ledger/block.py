"""
Permissioned DLT Block Representation
Stores compact verification tuples R = (id, t, rho, op, H(event), sigma, ptr)
with Merkle commitment and multi-node consensus signatures.
"""

import time
import hashlib
from typing import List, Dict, Any
from data.canonicalizer import canonicalize_json
from ledger.merkle import MerkleTree


class Block:
    """A cryptographic block in the permissioned distributed audit ledger."""

    def __init__(
        self,
        index: int,
        previous_hash: str,
        records: List[Dict[str, Any]],
        timestamp: str = None,
        validator_signatures: List[Dict[str, str]] = None
    ):
        self.index = index
        self.previous_hash = previous_hash
        self.records = records  # List of verification tuples R
        self.timestamp = timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.validator_signatures = validator_signatures or []

        # Compute Merkle Root of records
        leaf_hashes = [r.get("event_hash", hashlib.sha256(str(r).encode()).hexdigest()) for r in records]
        self.merkle_tree = MerkleTree(leaf_hashes)
        self.merkle_root = self.merkle_tree.root

        # Compute Block Hash over header
        self.block_hash = self.compute_block_hash()

    def compute_block_hash(self) -> str:
        """Computes deterministic hash over block header fields."""
        header = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "num_records": len(self.records),
        }
        canonical_header = canonicalize_json(header)
        return hashlib.sha256(canonical_header).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "block_hash": self.block_hash,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "records_count": len(self.records),
            "records": self.records,
            "validator_signatures": self.validator_signatures,
        }

    def verify_integrity(self) -> bool:
        """Verifies block header hash and internal Merkle root consistency."""
        expected_hash = self.compute_block_hash()
        if expected_hash != self.block_hash:
            return False

        leaf_hashes = [r.get("event_hash", "") for r in self.records]
        recomputed_tree = MerkleTree(leaf_hashes)
        if recomputed_tree.root != self.merkle_root:
            return False

        return True
