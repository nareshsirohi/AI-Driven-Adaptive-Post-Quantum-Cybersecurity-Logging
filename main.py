"""
Main Application Entry Point
AI-Driven Adaptive Post-Quantum Cybersecurity Logging for Event Streams
Project Id: 2023CSEAI025 | Odd Semester, 2026–27
Department of Computer Science and Engineering (Artificial Intelligence)
ABES Institute of Technology (ABESIT), Ghaziabad &bull; Affiliated to AKTU Lucknow
Under the supervision of Ms. Reshu Tyagi, Assistant Professor
"""

import sys
import argparse
import uvicorn
from config import HOST, PORT


def run_server(host: str = HOST, port: int = PORT):
    """Starts the FastAPI Web Application and Cyber SOC Dashboard."""
    print("================================================================================")
    print(" 🛡️  AI-Driven Adaptive Post-Quantum Cybersecurity Logging System")
    print(f" 📍  ABESIT / AKTU Capstone Project (ID: 2023CSEAI025)")
    print(f" 🌐  Starting SOC Dashboard on http://{host}:{port}")
    print("================================================================================")
    uvicorn.run("web.app:app", host=host, port=port, reload=False)


def run_tests():
    """Executes the complete test suite."""
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


def run_training():
    """Trains the AI Threat Classification Model."""
    from ai_engine.train import train_and_evaluate
    print("[*] Launching model training pipeline...")
    metrics = train_and_evaluate()
    print("\n[+] Training & Evaluation Completed Successfully!")
    print(f"    Accuracy:     {metrics['accuracy'] * 100:.2f}%")
    print(f"    Weighted F1:  {metrics['f1_score']:.4f}")
    print(f"    False Pos:    {metrics['false_positive_rate']:.4f}")
    print(f"    Avg Latency:  {metrics['avg_detection_latency_ms']} ms")


def run_attacks():
    """Runs all 5 Section VI-D security tests."""
    from pipeline.orchestrator import AdaptiveLoggingPipeline
    from audit.verifier import AuditVerifier
    from audit.attack_simulator import AttackSimulator

    print("[*] Initializing Attack & Tamper Security Lab...")
    pipeline = AdaptiveLoggingPipeline()
    verifier = AuditVerifier(pipeline.crypto, pipeline.store, pipeline.ledger)
    sim = AttackSimulator(pipeline, verifier)

    results = sim.run_all_tests()
    print("\n================== ADVERSARIAL TEST RESULTS (SEC VI-D) ==================")
    for r in results:
        status = "PASSED (TAMPER CAUGHT)" if r.get("test_passed") else "FAILED"
        print(f"\n[+] {r.get('test_name')}: {status}")
        print(f"    Description: {r.get('attack_description', 'N/A')}")
        print(f"    Details:     {r.get('details', 'N/A')}")


def run_benchmark():
    """Executes comparative benchmark across B1, B2, B3, B4."""
    from pipeline.orchestrator import AdaptiveLoggingPipeline
    from audit.benchmark import BenchmarkSuite

    print("[*] Launching Comparative Baseline Benchmark Suite...")
    pipeline = AdaptiveLoggingPipeline()
    bench = BenchmarkSuite(pipeline)
    res = bench.run_benchmark(num_events=50)

    print("\n=================== BENCHMARK SUMMARY (RQ1 - RQ4) ===================")
    print(f"Latency Speedup vs Static PQC: {res['summary']['latency_speedup_vs_static_pqc']}x faster")
    print(f"PQC Storage Saving vs Static PQC (B3): {res['summary']['pqc_onchain_storage_saving_percent']}%")
    print("\nDetailed Baseline Metrics:")
    for key, b in res["baselines"].items():
        print(f"\n- {b['name']}:")
        print(f"    Mean Latency:    {b['latency_ms']['mean']} ms (P95: {b['latency_ms']['p95']} ms)")
        print(f"    Throughput:      {b['throughput_events_per_sec']} events/sec")
        print(f"    On-Chain Bytes:  {b['storage_bytes']['onchain_per_event']} B/event")
        print(f"    PQC Hardness:    {'YES' if b['quantum_resistant'] else 'NO (Classical)'}")


def main():
    parser = argparse.ArgumentParser(
        description="AI-Driven Adaptive Post-Quantum Cybersecurity Logging System"
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="server",
        choices=["server", "test", "train", "attack", "benchmark"],
        help="Action to execute (default: server)"
    )
    parser.add_argument("--port", type=int, default=PORT, help=f"Server port (default: {PORT})")
    parser.add_argument("--host", type=str, default=HOST, help=f"Server host (default: {HOST})")

    args = parser.parse_args()

    if args.action == "server":
        run_server(args.host, args.port)
    elif args.action == "test":
        run_tests()
    elif args.action == "train":
        run_training()
    elif args.action == "attack":
        run_attacks()
    elif args.action == "benchmark":
        run_benchmark()


if __name__ == "__main__":
    main()
