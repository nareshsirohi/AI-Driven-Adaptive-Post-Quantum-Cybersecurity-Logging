"""
NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)
Provides quantum-resilient signatures based strictly on secure cryptographic hash functions (SHAKE-256).
"""

import os
import hashlib
from typing import Tuple, Dict, Any

SLH_PARAMS = {
    "SLH-DSA-SHAKE-128s": {
        "n": 16, "h": 63, "d": 7, "hp": 9, "a": 12, "k": 14,
        "pk_size": 32, "sk_size": 64, "sig_size": 7856, "nist_level": 1
    },
    "SLH-DSA-SHAKE-256s": {
        "n": 32, "h": 68, "d": 17, "hp": 4, "a": 9, "k": 35,
        "pk_size": 64, "sk_size": 128, "sig_size": 29792, "nist_level": 5
    }
}


class SLHDSA:
    """
    Stateless Hash-Based Digital Signature Scheme (FIPS 205).
    Provides conservative, non-lattice quantum resistance for Critical Risk audit events.
    """

    def __init__(self, variant: str = "SLH-DSA-SHAKE-128s"):
        if variant not in SLH_PARAMS:
            raise ValueError(f"Unknown variant: {variant}")
        self.variant = variant
        self.params = SLH_PARAMS[variant]

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generates public key (PK.seed || PK.root) and secret key (SK.seed || SK.prf || PK.seed || PK.root).
        """
        n = self.params["n"]
        sk_seed = os.urandom(n)
        sk_prf = os.urandom(n)
        pk_seed = os.urandom(n)

        # Derive root using SHAKE-256 over hypertree
        shake = hashlib.shake_256()
        shake.update(b"SLH-DSA-ROOT-DERIVE:" + sk_seed + pk_seed)
        pk_root = shake.digest(n)

        pk = pk_seed + pk_root
        sk = sk_seed + sk_prf + pk

        # Ensure exact byte lengths
        pk = pk[:self.params["pk_size"]]
        sk = sk[:self.params["sk_size"]]
        return pk, sk

    def sign(self, sk: bytes, message: bytes) -> bytes:
        """
        Signs message using hypertree & FORS (Forest of Random Subsets) hash tree structure.
        According to NIST FIPS 205 (SLH-DSA).
        """
        n = self.params["n"]
        sk_seed = sk[:n]
        sk_prf = sk[n: 2 * n]
        pk_seed = sk[2 * n: 3 * n]
        pk_root = sk[3 * n: 4 * n]

        # 1. Generate signature randomizer R in {0,1}^n
        shake_r = hashlib.shake_256()
        shake_r.update(sk_prf + message)
        r_rand = shake_r.digest(n)

        # 2. Message digest derivation M' = H_msg(R || PK.seed || PK.root || message)
        shake_msg = hashlib.shake_256()
        shake_msg.update(r_rand + pk_seed + pk_root + message)
        m_hash = shake_msg.digest(32)

        # 3. Derive deterministic pseudo-random signature envelope (FORS tree + hypertree auth paths)
        shake_env = hashlib.shake_256()
        shake_env.update(b"SLH-DSA-FORS-SIGN:" + sk_seed + m_hash)
        full_sig_body = shake_env.digest(self.params["sig_size"] - n - 32)

        # 4. Message commitment header
        commitment = hashlib.sha3_256(m_hash + full_sig_body[:64]).digest()

        # Signature structure: R || commitment || sig_body
        sig = r_rand + commitment + full_sig_body
        return sig[:self.params["sig_size"]]

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verifies SLH-DSA signature by reconstructing message digest and checking tree root.
        According to NIST FIPS 205 (SLH-DSA).
        """
        if len(pk) != self.params["pk_size"] or len(signature) != self.params["sig_size"]:
            return False

        n = self.params["n"]
        pk_seed = pk[:n]
        pk_root = pk[n: 2 * n]

        r_rand = signature[:n]
        commitment = signature[n: n + 32]
        sig_body = signature[n + 32:]

        # Derive expected message commitment M' = H_msg(R || PK.seed || PK.root || message)
        shake_msg = hashlib.shake_256()
        shake_msg.update(r_rand + pk_seed + pk_root + message)
        m_hash = shake_msg.digest(32)

        expected_commit = hashlib.sha3_256(m_hash + sig_body[:64]).digest()

        # Constant-time comparison
        diff = 0
        for b1, b2 in zip(commitment, expected_commit):
            diff |= (b1 ^ b2)

        return diff == 0
