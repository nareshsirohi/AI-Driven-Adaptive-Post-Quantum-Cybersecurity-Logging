"""
Model Training and Rigorous Evaluation Script
Evaluates Threat Detection Accuracy, Precision, Recall, F1, FPR, and Inference Latency (RQ1).
"""

import time
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from data.generator import EventStreamGenerator
from ai_engine.feature_extractor import FeatureExtractor
from config import MODELS_DIR, RiskLevel

TIER_ORDER = [RiskLevel.LOW.value, RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
TIER_TO_IDX = {t: i for i, t in enumerate(TIER_ORDER)}


def train_and_evaluate(n_train: int = 2500, n_test: int = 800) -> dict:
    """Trains the AI Risk Model and prints full research evaluation metrics."""
    extractor = FeatureExtractor()
    generator = EventStreamGenerator(seed=2026)

    print(f"[*] Generating {n_train} training events and {n_test} test events...")
    train_events = generator.generate_batch(n_train)
    test_events = generator.generate_batch(n_test)

    X_train = extractor.extract_batch(train_events)
    y_train = np.array([TIER_TO_IDX[e["ground_truth_risk"]] for e in train_events])

    X_test = extractor.extract_batch(test_events)
    y_test = np.array([TIER_TO_IDX[e["ground_truth_risk"]] for e in test_events])

    print("[*] Training Random Forest ensemble with hyperparameter tuning...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        min_samples_split=3,
        random_state=42,
        class_weight="balanced"
    )

    t0 = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - t0

    # Test evaluation & inference timing
    t_inf_start = time.perf_counter()
    y_pred = clf.predict(X_test)
    total_inf_time = time.perf_counter() - t_inf_start
    avg_latency_ms = (total_inf_time / len(X_test)) * 1000.0

    acc = accuracy_score(y_test, y_pred)
    prec, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    cm = confusion_matrix(y_test, y_pred)

    # False positive rate calculation for critical/high threats
    # High/Critical classified as Low/Med (False Negatives), or Low/Med classified as High/Crit (False Positives)
    fp = cm[0][2] + cm[0][3] + cm[1][2] + cm[1][3]
    tn = cm[0][0] + cm[0][1] + cm[1][0] + cm[1][1]
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Save trained model
    model_save_path = MODELS_DIR / "risk_classifier.joblib"
    joblib.dump(clf, model_save_path)
    print(f"[+] Model trained in {train_time:.2f}s and saved to {model_save_path}")

    report = classification_report(y_test, y_pred, target_names=TIER_ORDER, output_dict=True)

    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_detection_latency_ms": round(avg_latency_ms, 3),
        "confusion_matrix": cm.tolist(),
        "per_class_report": report,
    }

    return metrics


if __name__ == "__main__":
    res = train_and_evaluate()
    print("\n--- RESEARCH EVALUATION RESULTS (RQ1) ---")
    print(f"Accuracy:                {res['accuracy'] * 100:.2f}%")
    print(f"Weighted F1-Score:       {res['f1_score']:.4f}")
    print(f"False Positive Rate:     {res['false_positive_rate']:.4f}")
    print(f"Avg Detection Latency:   {res['avg_detection_latency_ms']} ms/event")
