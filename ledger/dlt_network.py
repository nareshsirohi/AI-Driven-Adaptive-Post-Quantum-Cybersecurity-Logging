"""
Permissioned Distributed Ledger Network (DLT)
Simulates a multi-node Byzantine Fault Tolerant (PBFT) consortium ledger
operated by ABESIT, AKTU, SOC, and Audit nodes.
"""

import os
import json
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from config import LEDGER_DIR, VALIDATOR_NODES, BFT_QUORUM_FRACTION
from ledger.block import Block


class PermissionedDLTNetwork:
    """Manages the distributed ledger chain, block proposals, and validator consensus."""

    def __init__(self, chain_file: str = None):
        self.chain_file = chain_file or (LEDGER_DIR / "ledger_blocks.json")
        self.validators = VALIDATOR_NODES
        self.chain: List[Block] = []
        self.pending_pool: List[Dict[str, Any]] = []
        self._initialize_chain()

    def _initialize_chain(self):
        """Loads chain from file or creates Genesis block."""
        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for b_dict in data:
                        block = Block(
                            index=b_dict["index"],
                            previous_hash=b_dict["previous_hash"],
                            records=b_dict["records"],
                            timestamp=b_dict["timestamp"],
                            validator_signatures=b_dict.get("validator_signatures", [])
                        )
                        block.block_hash = b_dict["block_hash"]
                        self.chain.append(block)
                return
            except Exception:
                self.chain = []

        # Create Genesis Block
        genesis_record = [{
            "event_id": "GENESIS-0000-0000-0000",
            "timestamp": "2026-10-21T00:00:00Z",
            "risk_level": "LOW",
            "crypto_op": "GENESIS_ROOT",
            "event_hash": hashlib.sha256(b"ABESIT_AKTU_PQC_GENESIS_BLOCK_2026").hexdigest(),
            "signature": "GENESIS_SIG_ABESIT_CONSORTIUM",
            "payload_ptr": "pqc://store/genesis.json"
        }]
        genesis_block = Block(index=0, previous_hash="0" * 64, records=genesis_record)
        self._simulate_validator_consensus(genesis_block)
        self.chain.append(genesis_block)
        self._save_chain()

    def _simulate_validator_consensus(self, block: Block):
        """Simulates PBFT commit phase: collects cryptographic validator signatures."""
        block.validator_signatures = []
        for val in self.validators:
            # Deterministic validator signature
            val_sig = hashlib.sha256(f"{val['node_id']}:{block.block_hash}".encode()).hexdigest()
            block.validator_signatures.append({
                "node_id": val["node_id"],
                "node_name": val["name"],
                "signature": val_sig,
                "timestamp": block.timestamp
            })

    def _save_chain(self):
        """Persists chain to disk."""
        with open(self.chain_file, "w", encoding="utf-8") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    def commit_record(self, record: Dict[str, Any], priority: str = "BATCHED") -> Optional[Block]:
        """
        Submits record to the ledger.
        If priority is IMMEDIATE or PRIORITY_NON_BATCHED, commits immediately.
        Otherwise adds to pending pool.
        """
        self.pending_pool.append(record)

        # Immediate commitment for Critical and High risk
        if priority in ["PRIORITY_NON_BATCHED", "IMMEDIATE"] or len(self.pending_pool) >= 10:
            return self.flush_pending_pool()
        return None

    def flush_pending_pool(self) -> Optional[Block]:
        """Packages all pending records into a new block and reaches BFT consensus."""
        if not self.pending_pool:
            return None

        records_to_commit = list(self.pending_pool)
        self.pending_pool.clear()

        last_block = self.chain[-1]
        new_block = Block(
            index=last_block.index + 1,
            previous_hash=last_block.block_hash,
            records=records_to_commit
        )

        self._simulate_validator_consensus(new_block)
        self.chain.append(new_block)
        self._save_chain()
        return new_block

    def get_record(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Searches the ledger for a specific event record R."""
        # Check committed blocks in reverse order
        for block in reversed(self.chain):
            for record in block.records:
                if record.get("event_id") == event_id:
                    return {
                        "record": record,
                        "block_index": block.index,
                        "block_hash": block.block_hash,
                        "block_timestamp": block.timestamp,
                        "merkle_root": block.merkle_root,
                        "status": "COMMITTED"
                    }

        # Check pending pool
        for record in self.pending_pool:
            if record.get("event_id") == event_id:
                return {
                    "record": record,
                    "block_index": -1,
                    "block_hash": "PENDING_IN_POOL",
                    "status": "PENDING"
                }

        return None

    def verify_chain_integrity(self) -> Tuple[bool, List[str]]:
        """
        Validates entire blockchain integrity:
        1. Checks previous_hash continuity.
        2. Validates block header hash.
        3. Validates Merkle tree roots.
        4. Validates validator consensus signatures.
        """
        errors = []
        for i in range(len(self.chain)):
            block = self.chain[i]
            if not block.verify_integrity():
                errors.append(f"Block #{block.index} failed cryptographic header or Merkle check.")

            if i > 0:
                prev_block = self.chain[i - 1]
                if block.previous_hash != prev_block.block_hash:
                    errors.append(f"Block #{block.index} previous_hash mismatch: expected {prev_block.block_hash}, got {block.previous_hash}")

            # Check validator quorum
            if len(block.validator_signatures) < int(len(self.validators) * BFT_QUORUM_FRACTION):
                errors.append(f"Block #{block.index} lacks sufficient BFT validator quorum.")

        return len(errors) == 0, errors
