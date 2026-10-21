"""
Classical Cryptographic Baselines
Provides standard classical cryptographic algorithms (SHA-256, HMAC-SHA256, ECDSA secp256k1)
for comparative performance evaluation against Post-Quantum algorithms (Table I, Table IV, RQ4).
"""

import time
import hashlib
import hmac
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption


class ClassicalCryptoBaseline:
    """Provides classical SHA-256, HMAC, and ECDSA implementations for baseline comparisons."""

    def __init__(self):
        self.hmac_key = hashlib.sha256(b"ABESIT_2023CSEAI025_HMAC_MASTER_KEY").digest()
        self._ecdsa_private_key = ec.generate_private_key(ec.SECP256K1())
        self._ecdsa_public_key = self._ecdsa_private_key.public_key()

    def sha256_hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def compute_hmac(self, data: bytes) -> str:
        return hmac.new(self.hmac_key, data, hashlib.sha256).hexdigest()

    def verify_hmac(self, data: bytes, tag: str) -> bool:
        expected = self.compute_hmac(data)
        return hmac.compare_digest(expected, tag)

    def ecdsa_keygen(self) -> Tuple[bytes, bytes]:
        sk = ec.generate_private_key(ec.SECP256K1())
        pk = sk.public_key()
        pk_bytes = pk.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        sk_bytes = sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        return pk_bytes, sk_bytes

    def ecdsa_sign(self, sk_bytes: bytes, message: bytes) -> bytes:
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        sk = load_der_private_key(sk_bytes, password=None)
        signature = sk.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    def ecdsa_verify(self, pk_bytes: bytes, message: bytes, signature: bytes) -> bool:
        try:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk_bytes)
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
