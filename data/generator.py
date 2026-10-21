"""
Security Event Stream Generator
Simulates modern microservices, APIs, IAM systems, and cloud infrastructure events.
Covers routine operations, suspicious activities, privilege escalations, and critical cyber attacks.
"""

import uuid
import random
import datetime
from typing import Dict, Any, List
from config import RiskLevel

# Sample pools
INTERNAL_IPS = ["10.0.1.45", "10.0.2.112", "192.168.1.10", "172.16.4.5"]
EXTERNAL_BENIGN_IPS = ["198.51.100.24", "203.0.113.88", "192.0.2.14"]
SUSPICIOUS_IPS = ["185.220.101.5", "45.154.255.89", "194.26.29.112", "103.251.167.20"]

USERS = ["alice", "bob", "charlie", "david", "svc-billing", "svc-metrics", "kanika_admin", "naresh_sec"]
ADMIN_USERS = ["root", "admin", "kanika_admin", "naresh_sec", "aws_superadmin"]

RESOURCES_BENIGN = [
    "/api/v1/user/profile",
    "/api/v1/dashboard/metrics",
    "/api/v1/orders/list",
    "/healthz",
    "/static/assets/app.js",
]

RESOURCES_SENSITIVE = [
    "/api/v1/admin/users/roles",
    "/api/v1/finance/export",
    "/api/v1/iam/credentials",
    "/api/v1/database/snapshot",
]

RESOURCES_CRITICAL = [
    "/etc/shadow",
    "/proc/kcore",
    "/api/v1/admin/master_pqc_key",
    "/api/v1/cloud/iam/root_access_key",
    "/system/firmware/flash",
]


class EventStreamGenerator:
    """Generates synthetic security event streams across Low, Medium, High, and Critical risk tiers."""

    def __init__(self, seed: int = 42):
        random.seed(seed)

    def generate_event(self, force_tier: RiskLevel = None) -> Dict[str, Any]:
        """Generate a single realistic event, either sampled or forced to a specific risk tier."""
        if force_tier is None:
            # Typical production distribution: 70% Low, 20% Medium, 8% High, 2% Critical
            r = random.random()
            if r < 0.70:
                tier = RiskLevel.LOW
            elif r < 0.90:
                tier = RiskLevel.MEDIUM
            elif r < 0.98:
                tier = RiskLevel.HIGH
            else:
                tier = RiskLevel.CRITICAL
        else:
            tier = force_tier

        now = datetime.datetime.now(datetime.timezone.utc)
        event_id = str(uuid.uuid4())

        if tier == RiskLevel.LOW:
            event = self._generate_low_risk(event_id, now)
        elif tier == RiskLevel.MEDIUM:
            event = self._generate_medium_risk(event_id, now)
        elif tier == RiskLevel.HIGH:
            event = self._generate_high_risk(event_id, now)
        else:
            event = self._generate_critical_risk(event_id, now)

        # Ground truth label for evaluation
        event["ground_truth_risk"] = tier.value
        return event

    def _generate_low_risk(self, event_id: str, ts: datetime.datetime) -> Dict[str, Any]:
        event_types = ["AUTH_LOGIN_SUCCESS", "API_REQUEST_GET", "SESSION_REFRESH", "METRIC_HEARTBEAT"]
        e_type = random.choice(event_types)
        return {
            "event_id": event_id,
            "timestamp": ts.isoformat(),
            "event_type": e_type,
            "source_ip": random.choice(INTERNAL_IPS + EXTERNAL_BENIGN_IPS),
            "user_id": random.choice(USERS),
            "action": f"Executed routine operation {e_type.lower()}",
            "resource": random.choice(RESOURCES_BENIGN),
            "http_status": 200,
            "failure_count": 0,
            "is_admin_action": 0,
            "sensitive_target": 0,
            "hour_of_day": ts.hour,
            "geo_country": "IN",
            "anomaly_indicator": 0.05 + random.uniform(0.0, 0.15),
            "payload": {
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "bytes_transferred": random.randint(120, 2400),
                "client_session_id": f"sess_{random.randint(10000, 99999)}",
                "status": "SUCCESS",
            }
        }

    def _generate_medium_risk(self, event_id: str, ts: datetime.datetime) -> Dict[str, Any]:
        event_types = ["AUTH_LOGIN_FAILED", "PASSWORD_RESET_REQ", "RATE_LIMIT_WARNING", "ANOMALOUS_OFF_HOURS_ACCESS"]
        e_type = random.choice(event_types)
        return {
            "event_id": event_id,
            "timestamp": ts.isoformat(),
            "event_type": e_type,
            "source_ip": random.choice(EXTERNAL_BENIGN_IPS + SUSPICIOUS_IPS[:1]),
            "user_id": random.choice(USERS),
            "action": f"Warning threshold reached: {e_type.lower()}",
            "resource": random.choice(RESOURCES_BENIGN + RESOURCES_SENSITIVE[:1]),
            "http_status": random.choice([401, 403, 429]),
            "failure_count": random.randint(2, 5),
            "is_admin_action": 0,
            "sensitive_target": 0,
            "hour_of_day": ts.hour,
            "geo_country": random.choice(["IN", "US", "DE"]),
            "anomaly_indicator": 0.40 + random.uniform(0.0, 0.20),
            "payload": {
                "reason": "Invalid credentials or high request frequency",
                "attempt_number": random.randint(2, 4),
                "client_session_id": f"sess_warn_{random.randint(10000, 99999)}",
                "status": "CHALLENGED",
            }
        }

    def _generate_high_risk(self, event_id: str, ts: datetime.datetime) -> Dict[str, Any]:
        event_types = ["PRIVILEGE_ESCALATION_ATTEMPT", "SQL_INJECTION_DETECTED", "SENSITIVE_RESOURCE_ACCESS", "BRUTE_FORCE_BURST"]
        e_type = random.choice(event_types)
        return {
            "event_id": event_id,
            "timestamp": ts.isoformat(),
            "event_type": e_type,
            "source_ip": random.choice(SUSPICIOUS_IPS),
            "user_id": random.choice(ADMIN_USERS),
            "action": f"High risk security alert triggered by {e_type.lower()}",
            "resource": random.choice(RESOURCES_SENSITIVE),
            "http_status": random.choice([401, 403, 500]),
            "failure_count": random.randint(6, 18),
            "is_admin_action": 1,
            "sensitive_target": 1,
            "hour_of_day": ts.hour,
            "geo_country": random.choice(["RU", "KP", "CN", "IR"]),
            "anomaly_indicator": 0.75 + random.uniform(0.0, 0.15),
            "payload": {
                "detected_pattern": "' OR '1'='1' -- privilege grant query injection",
                "attack_vector": "Remote IAM Escalation",
                "impacted_roles": ["SecOpsAdmin", "ClusterRoot"],
                "mitigation": "Flagged for immediate PQC cryptographic non-repudiation",
                "status": "SECURITY_ALERT"
            }
        }

    def _generate_critical_risk(self, event_id: str, ts: datetime.datetime) -> Dict[str, Any]:
        event_types = ["ZERO_DAY_EXPLOIT_PAYLOAD", "DATA_EXFILTRATION_BURST", "ROOT_KEY_COMPROMISE_SUSPECT", "RANSOMWARE_ENCRYPTOR_BEACON"]
        e_type = random.choice(event_types)
        return {
            "event_id": event_id,
            "timestamp": ts.isoformat(),
            "event_type": e_type,
            "source_ip": random.choice(SUSPICIOUS_IPS),
            "user_id": "root",
            "action": f"CRITICAL INCIDENT: {e_type.lower()} in progress across core infrastructure",
            "resource": random.choice(RESOURCES_CRITICAL),
            "http_status": 500,
            "failure_count": random.randint(20, 100),
            "is_admin_action": 1,
            "sensitive_target": 1,
            "hour_of_day": ts.hour,
            "geo_country": "TOR_EXIT_NODE",
            "anomaly_indicator": 0.95 + random.uniform(0.0, 0.05),
            "payload": {
                "attack_signature": "CVE-2026-X-ZERO-DAY-RCE",
                "memory_offset": "0x7ffee032488a",
                "exfiltration_size_mb": random.randint(450, 2400),
                "forensic_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "emergency_containment": "Engage NIST FIPS 205 SLH-DSA signing & ML-KEM payload lock",
                "status": "CRITICAL_THREAT_CONFIRMED"
            }
        }

    def generate_batch(self, count: int = 100) -> List[Dict[str, Any]]:
        """Generate a sequence of continuous events."""
        return [self.generate_event() for _ in range(count)]
