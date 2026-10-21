"""
Off-Chain Secure Event Storage S
Maintains full detailed event payloads, encrypted payloads, and provides URI pointers (ptr).
Includes simulation hooks to test tampering and deletion attacks (Section VI-D).
"""

import os
import json
import shutil
from typing import Dict, Any, Optional
from config import OFFCHAIN_DIR
from data.canonicalizer import canonicalize_json, compute_canonical_hash


class OffChainStore:
    """Secure external storage for complete log event payloads."""

    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or OFFCHAIN_DIR
        os.makedirs(self.base_dir, exist_ok=True)
        self.tamper_backups: Dict[str, Dict[str, Any]] = {}

    def put(self, event_id: str, payload_data: Dict[str, Any]) -> str:
        """
        Stores payload and returns content pointer URI.
        Format: pqc://store/events/{event_id}.json
        """
        ptr = f"pqc://store/events/{event_id}.json"
        filepath = os.path.join(self.base_dir, f"{event_id}.json")

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload_data, f, indent=2, sort_keys=True)

        return ptr

    def get(self, ptr: str) -> Optional[Dict[str, Any]]:
        """Retrieves stored payload by URI pointer."""
        event_id = ptr.split("/")[-1].replace(".json", "")
        filepath = os.path.join(self.base_dir, f"{event_id}.json")

        if not os.path.exists(filepath):
            return None

        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def tamper_payload(self, event_id: str, tampered_fields: Dict[str, Any]) -> bool:
        """
        Simulates an attacker modifying an off-chain log payload (Section VI-D Security Test).
        Backs up the original payload first so it can be restored.
        """
        filepath = os.path.join(self.base_dir, f"{event_id}.json")
        if not os.path.exists(filepath):
            return False

        with open(filepath, "r", encoding="utf-8") as f:
            original = json.load(f)

        # Backup for restoration
        self.tamper_backups[event_id] = json.loads(json.dumps(original))

        # If payload was encrypted under ML-KEM + AES-GCM, corrupt ciphertext bytes
        if "aes_ciphertext_hex" in original:
            ct = original["aes_ciphertext_hex"]
            corrupted_ct = ct[:-8] + "deadbeef" if len(ct) > 8 else "deadbeef"
            original["aes_ciphertext_hex"] = corrupted_ct
            original.update(tampered_fields)
        else:
            # Apply tampering directly to fields
            original.update(tampered_fields)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(original, f, indent=2, sort_keys=True)

        return True

    def delete_payload(self, event_id: str) -> bool:
        """
        Simulates an attacker deleting an off-chain event record (Section VI-D Security Test).
        """
        filepath = os.path.join(self.base_dir, f"{event_id}.json")
        if not os.path.exists(filepath):
            return False

        with open(filepath, "r", encoding="utf-8") as f:
            self.tamper_backups[event_id] = json.load(f)

        os.remove(filepath)
        return True

    def restore_payload(self, event_id: str) -> bool:
        """Restores tampered or deleted payload from memory backup."""
        if event_id not in self.tamper_backups:
            return False

        filepath = os.path.join(self.base_dir, f"{event_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.tamper_backups[event_id], f, indent=2, sort_keys=True)

        del self.tamper_backups[event_id]
        return True
