"""
FastAPI Application & REST API
Exposes endpoints for real-time cybersecurity logging, AI threat assessment,
adaptive PQC operations, DLT blockchain explorer, attack simulations, and benchmarking.
"""

import os
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import RiskLevel, VALIDATOR_NODES, BASE_DIR
from pipeline.orchestrator import AdaptiveLoggingPipeline
from audit.verifier import AuditVerifier
from audit.attack_simulator import AttackSimulator
from audit.benchmark import BenchmarkSuite
from data.generator import EventStreamGenerator

app = FastAPI(
    title="AI-Driven Adaptive Post-Quantum Cybersecurity Logging System",
    description="AKTU / ABESIT Capstone Project (ID: 2023CSEAI025)",
    version="1.0.0"
)

# Mount static files and templates
STATIC_DIR = BASE_DIR / "web" / "static"
TEMPLATES_DIR = BASE_DIR / "web" / "templates"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Singleton system pipeline
pipeline = AdaptiveLoggingPipeline()
verifier = AuditVerifier(pipeline.crypto, pipeline.store, pipeline.ledger)
simulator = AttackSimulator(pipeline, verifier)
benchmarker = BenchmarkSuite(pipeline)
generator = EventStreamGenerator(seed=2026)

# Pre-populate initial realistic events
print("[*] Pre-populating demo ledger with initial event stream...")
for tier in [RiskLevel.LOW, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
    sample_e = generator.generate_event(force_tier=tier)
    pipeline.process_event(sample_e)
pipeline.ledger.flush_pending_pool()


class CustomEventRequest(BaseModel):
    event_type: str
    source_ip: str
    user_id: str
    action: str
    resource: str
    http_status: int = 200
    failure_count: int = 0
    is_admin_action: int = 0
    sensitive_target: int = 0
    payload: Dict[str, Any] = {}


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """Renders the Cyber SOC Dashboard UI."""
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        return FileResponse(str(html_path), media_type="text/html")
    return HTMLResponse("<h1>AI-Driven Adaptive Post-Quantum Cybersecurity Logging</h1><p>Status: Active</p>")


@app.get("/api/status")
async def get_system_status():
    """System health, academic metadata, and validator consortium status."""
    chain_ok, chain_errs = pipeline.ledger.verify_chain_integrity()
    return {
        "project": {
            "title": "AI-Driven Adaptive Post Quantum Cyber Security Logging for Event Stream",
            "project_id": "2023CSEAI025",
            "semester": "Odd Semester, 2026–27",
            "institution": "ABES Institute of Technology (ABESIT), Ghaziabad",
            "affiliation": "Dr. A.P.J. Abdul Kalam Technical University (AKTU), Lucknow",
            "supervisor": "Ms. Reshu Tyagi (Assistant Professor)",
            "authors": [
                {"name": "Kanika", "roll_no": "2302901520092"},
                {"name": "Naresh Sirohi", "roll_no": "2302901520128"},
                {"name": "Jiya Sharma", "roll_no": "2302901520091"},
                {"name": "Anmol Chaudhary", "roll_no": "2302901520035"},
            ]
        },
        "system": {
            "total_processed_events": pipeline.total_processed,
            "risk_distribution": pipeline.risk_counts,
            "blockchain_height": len(pipeline.ledger.chain),
            "chain_integrity_valid": chain_ok,
            "chain_integrity_errors": chain_errs,
            "validators": VALIDATOR_NODES,
        }
    }


@app.post("/api/event/generate")
async def generate_and_log_event(tier: Optional[str] = None):
    """Generates a realistic stream event and runs it through the full adaptive pipeline."""
    force_t = None
    if tier and tier.upper() in [t.value for t in RiskLevel]:
        force_t = RiskLevel(tier.upper())

    event = generator.generate_event(force_tier=force_t)
    result = pipeline.process_event(event)
    return result


@app.post("/api/event/custom")
async def log_custom_event(payload: CustomEventRequest):
    """Processes a user-submitted custom security event."""
    import uuid, datetime
    # Dynamic origin & anomaly calculation
    geo = "IN"
    if payload.source_ip.startswith("185.220.") or payload.source_ip.startswith("45.154."):
        geo = "TOR_EXIT_NODE"
    elif payload.failure_count > 10:
        geo = "RU"
    elif payload.failure_count > 5:
        geo = "US"

    anomaly = min(0.3 + (payload.failure_count * 0.035) + (0.3 if payload.sensitive_target else 0.0), 1.0)
    if "ZERO_DAY" in payload.event_type.upper() or "RANSOMWARE" in payload.event_type.upper():
        anomaly = 0.98

    custom_e = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": payload.event_type,
        "source_ip": payload.source_ip,
        "user_id": payload.user_id,
        "action": payload.action,
        "resource": payload.resource,
        "http_status": payload.http_status,
        "failure_count": payload.failure_count,
        "is_admin_action": payload.is_admin_action,
        "sensitive_target": payload.sensitive_target,
        "hour_of_day": datetime.datetime.now().hour,
        "geo_country": geo,
        "anomaly_indicator": anomaly,
        "payload": payload.payload or {"custom_note": "User-submitted security event"}
    }
    result = pipeline.process_event(custom_e)
    return result


@app.get("/api/ledger/blocks")
async def get_ledger_blocks():
    """Returns the immutable distributed ledger blockchain."""
    return [b.to_dict() for b in pipeline.ledger.chain]


@app.get("/api/event/{event_id}/audit")
async def audit_event(event_id: str):
    """Executes independent forensic recomputation and PQC audit verification."""
    result = verifier.audit_event(event_id)
    return result


@app.post("/api/attack/simulate")
async def simulate_attack(attack_type: str = "payload_tampering"):
    """
    Executes one of the Section VI-D security tests:
    - payload_tampering
    - object_deletion
    - forged_signature
    - policy_downgrade
    - quantum_readiness
    - all
    """
    if attack_type == "payload_tampering":
        return simulator.test_payload_tampering()
    elif attack_type == "object_deletion":
        return simulator.test_object_deletion()
    elif attack_type == "forged_signature":
        return simulator.test_forged_signature()
    elif attack_type == "policy_downgrade":
        return simulator.test_policy_downgrade()
    elif attack_type == "quantum_readiness":
        return simulator.test_post_quantum_readiness()
    elif attack_type == "all":
        return simulator.run_all_tests()
    else:
        raise HTTPException(status_code=400, detail="Unknown attack type")


@app.get("/api/benchmark/crypto")
async def get_crypto_benchmark():
    """Runs and returns micro-benchmark of Classical vs NIST PQC cryptographic algorithms."""
    return pipeline.crypto.run_crypto_benchmark(iterations=10)


@app.post("/api/benchmark/run")
async def run_system_benchmark(events_count: int = 50):
    """Runs comprehensive benchmark comparing B1, B2, B3, B4."""
    if events_count > 200:
        events_count = 200
    res = benchmarker.run_benchmark(num_events=events_count)
    return res


@app.post("/api/ledger/flush")
async def flush_ledger_pool():
    """Manually forces mining and commitment of all pending mempool transactions."""
    block = pipeline.ledger.flush_pending_pool()
    return {"status": "SUCCESS", "block": block.to_dict() if block else None}
