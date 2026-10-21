"""
Cryptographic Merkle Tree Implementation
Enables batch verification, efficient audit inclusion proofs, and cryptographic rollups.
"""

import hashlib
from typing import List, Tuple, Dict, Any, Optional


def hash_pair(left: str, right: str) -> str:
    """Computes SHA-256 of concatenated left and right digests safely."""
    hasher = hashlib.sha256()
    try:
        left_b = bytes.fromhex(left)
    except ValueError:
        left_b = left.encode('utf-8')
    try:
        right_b = bytes.fromhex(right)
    except ValueError:
        right_b = right.encode('utf-8')
    hasher.update(left_b + right_b)
    return hasher.hexdigest()


class MerkleTree:
    """Binary Merkle tree over a list of transaction digests."""

    def __init__(self, leaves: List[str]):
        # Ensure at least one leaf
        if not leaves:
            self.leaves = [hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest()]
        else:
            self.leaves = leaves
        self.levels: List[List[str]] = [self.leaves]
        self._build_tree()

    def _build_tree(self):
        current_level = self.leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # Duplicate last element if odd
                next_level.append(hash_pair(left, right))
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        """Generates audit inclusion proof for leaf at index."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds")

        proof = []
        curr_idx = index
        for level in self.levels[:-1]:
            is_right_child = (curr_idx % 2 == 1)
            sibling_idx = curr_idx - 1 if is_right_child else curr_idx + 1

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                sibling_hash = level[curr_idx]  # Duplicated leaf

            proof.append({
                "direction": "left" if is_right_child else "right",
                "sibling_hash": sibling_hash
            })
            curr_idx //= 2

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict[str, str]], root: str) -> bool:
        """Verifies that leaf_hash belongs to the tree represented by root."""
        current = leaf_hash
        for step in proof:
            sibling = step["sibling_hash"]
            if step["direction"] == "left":
                current = hash_pair(sibling, current)
            else:
                current = hash_pair(current, sibling)
        return current.lower() == root.lower()
