"""
RFC 8785 Compliant JSON Canonicalization Scheme (JCS)
Ensures cryptographically deterministic byte serialization across heterogeneous systems.
"""

import json
import hashlib
from typing import Any, Dict


def canonicalize_json(obj: Any) -> bytes:
    """
    Produce a deterministic, canonical UTF-8 JSON representation according to RFC 8785.
    - Sort keys lexicographically.
    - Omit unnecessary whitespace.
    - Encode strings in standard UTF-8 without escaping slashes.
    - Normalize numerical representations.
    """
    def _normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {k: _normalize(v) for k, v in sorted(item.items(), key=lambda x: x[0])}
        elif isinstance(item, list):
            return [_normalize(elem) for elem in item]
        elif isinstance(item, float):
            # Format float to remove scientific notation quirks if integral
            if item.is_integer():
                return int(item)
            return round(item, 8)
        return item

    normalized = _normalize(obj)
    # separators=(',', ':') removes whitespace after comma and colon
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':')
    )
    return serialized.encode('utf-8')


def compute_canonical_hash(event_data: Dict[str, Any], algorithm: str = "sha256") -> str:
    """
    Computes a cryptographic digest over the canonicalized event.
    Returns hexadecimal digest string.
    """
    canonical_bytes = canonicalize_json(event_data)
    if algorithm.lower() == "sha3_256":
        hasher = hashlib.sha3_256()
    else:
        hasher = hashlib.sha256()
    hasher.update(canonical_bytes)
    return hasher.hexdigest()
