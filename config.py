"""
Configuration & System Parameters for:
AI-Driven Adaptive Post Quantum Cyber Security Logging for Event Stream
Project Id: 2023CSEAI025 | Odd Semester, 2026–27
Department of Computer Science and Engineering (Artificial Intelligence)
ABES Institute of Technology, Ghaziabad (Affiliated to AKTU, Lucknow)
Under the supervision of Ms. Reshu Tyagi, Assistant Professor
Authors: Kanika (2302901520092), Naresh Sirohi (2302901520128),
         Jiya Sharma (2302901520091), Anmol Chaudhary (2302901520035)
"""

import os
from enum import Enum
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data_storage"
DATA_DIR.mkdir(exist_ok=True)
OFFCHAIN_DIR = DATA_DIR / "offchain_payloads"
OFFCHAIN_DIR.mkdir(exist_ok=True)
LEDGER_DIR = DATA_DIR / "ledger_chain"
LEDGER_DIR.mkdir(exist_ok=True)
MODELS_DIR = DATA_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CryptoOp(str, Enum):
    CLASSICAL_HASH = "CLASSICAL_HASH_SHA256"
    ML_DSA_44 = "PQC_SIGN_ML_DSA_44"
    ML_DSA_65 = "PQC_SIGN_ML_DSA_65"
    ML_DSA_87 = "PQC_SIGN_ML_DSA_87"
    SLH_DSA_SHAKE = "PQC_SIGN_SLH_DSA_FIPS205"
    ML_KEM_768_ENC = "PQC_KEM_ML_KEM_768_AES256"
    ML_KEM_1024_ENC = "PQC_KEM_ML_KEM_1024_AES256"
    CLASSICAL_ECDSA = "CLASSICAL_SIGN_ECDSA_SECP256K1"


# Default Risk-to-Protection Mapping (Table III from Research Paper)
POLICY_MATRIX = {
    RiskLevel.LOW: {
        "integrity": "SHA-256",
        "authenticity": "HMAC-SHA256",
        "confidentiality": "NONE",
        "pqc_signature": False,
        "signature_algo": CryptoOp.CLASSICAL_HASH,
        "kem_algo": None,
        "dlt_priority": "BATCHED",
        "batch_window_seconds": 5,
        "require_payload_encryption": False,
    },
    RiskLevel.MEDIUM: {
        "integrity": "SHA-256-CANONICAL",
        "authenticity": "ML-DSA-44",
        "pqc_signature": True,
        "signature_algo": CryptoOp.ML_DSA_44,
        "kem_algo": None,
        "dlt_priority": "NEAR_REAL_TIME",
        "batch_window_seconds": 1,
        "require_payload_encryption": False,
    },
    RiskLevel.HIGH: {
        "integrity": "SHA-256-ENHANCED",
        "authenticity": "ML-DSA-65",
        "pqc_signature": True,
        "signature_algo": CryptoOp.ML_DSA_65,
        "kem_algo": CryptoOp.ML_KEM_768_ENC,
        "dlt_priority": "IMMEDIATE",
        "batch_window_seconds": 0,
        "require_payload_encryption": True,
    },
    RiskLevel.CRITICAL: {
        "integrity": "SHA-256-PROVENANCE",
        "authenticity": "SLH-DSA-SHAKE",
        "pqc_signature": True,
        "signature_algo": CryptoOp.SLH_DSA_SHAKE,
        "kem_algo": CryptoOp.ML_KEM_1024_ENC,
        "dlt_priority": "PRIORITY_NON_BATCHED",
        "batch_window_seconds": 0,
        "require_payload_encryption": True,
    },
}

# Fail-safe settings (Section V-A)
FAILSAFE_RISK_FLOOR = RiskLevel.HIGH
CONFIDENCE_THRESHOLD = 0.65

# Permissioned Ledger Configuration
VALIDATOR_NODES = [
    {"node_id": "validator-node-01-abesit", "name": "ABESIT Trust Anchor", "weight": 1.0},
    {"node_id": "validator-node-02-aktu", "name": "AKTU Central Node", "weight": 1.0},
    {"node_id": "validator-node-03-audit", "name": "Independent Security Auditor", "weight": 1.0},
    {"node_id": "validator-node-04-soc", "name": "Security Operations Center", "weight": 1.0},
]
BFT_QUORUM_FRACTION = 0.67  # Byzantine fault tolerance requires > 2/3 agreement

# Web UI configuration
HOST = "0.0.0.0"
PORT = 8000
