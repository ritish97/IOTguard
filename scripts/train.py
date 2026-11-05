"""
IoTGuard Training & Evaluation Pipeline
Trains:
1. IoTGuard XGBoost Stage Classifier (300 trees, depth 6, lr 0.1, hist, balanced)
2. Random Forest Baseline (100 trees, depth 16)
3. Decision Tree Baseline (depth 8)
4. XGBoost Ablation (No window features)
Evaluates on Temporal Split and saves models.
"""

import sys
import os
import time
import json
from pathlib import Path
import pandas as pd

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import (
    PROCESSED_DATA_DIR,
    RAW_DATA_DIR,
    MODELS_DIR,
    FEATURE_COLUMNS,
    STATIC_FEATURE_COLUMNS,
    STAGE_CLASSES
)
from iotguard.dataset import prepare_and_save_datasets
from iotguard.models import (
    IoTGuardModel,
    BaselineModels,
    evaluate_stage_classifier
)


def main():
    print("=" * 70)
    print("       IoTGuard Training & Experimental Evaluation Pipeline       ")
    print("=" * 70)

    # 1. Regenerate dataset to ensure multi-session distribution
    train_feat_path = PROCESSED_DATA_DIR / "X_train.csv"
    if True: # Always ensure fresh dataset on train run
        print("[*] Preparing balanced multi-session datasets...")
        prepare_and_save_datasets(total_samples=25000)

    print("[*] Loading temporal train/test splits...")
    X_train = pd.read_csv(PROCESSED_DATA_DIR / "X_train.csv")
    y_train = pd.read_csv(PROCESSED_DATA_DIR / "y_train.csv")["stage"]
    X_test = pd.read_csv(PROCESSED_DATA_DIR / "X_test.csv")
    y_test = pd.read_csv(PROCESSED_DATA_DIR / "y_test.csv")["stage"]

    print(f"    Train connections: {len(X_train):,}")
    print(f"    Test connections:  {len(X_test):,}")
    print(f"    Feature count:     {len(FEATURE_COLUMNS)}")

    results = {}

    # 2. Train Proposed IoTGuard XGBoost Model
    print("\n" + "-" * 70)
    print("[1/4] Training IoTGuard (XGBoost 300 trees, depth 6, hist, balanced)...")
    start_t = time.time()
    iotguard_model = IoTGuardModel(n_estimators=300, max_depth=6, learning_rate=0.1)
    iotguard_model.fit(X_train, y_train)
    train_time = time.time() - start_t
    print(f"      Completed in {train_time:.2f}s")

    # Evaluate IoTGuard
    eval_iotguard = evaluate_stage_classifier(iotguard_model.model, X_test, y_test, FEATURE_COLUMNS)
    results["IoTGuard (XGBoost)"] = eval_iotguard
    model_json_path = MODELS_DIR / "iotguard_xgboost.json"
    iotguard_model.save(model_json_path)
    print(f"      Saved model to: {model_json_path} (Size: {model_json_path.stat().st_size / 1024 / 1024:.2f} MB)")

    # 3. Train Random Forest Baseline
    print("\n" + "-" * 70)
    print("[2/4] Training Random Forest Baseline (100 trees, depth 16)...")
    start_t = time.time()
    rf_model = BaselineModels.train_random_forest(X_train, y_train)
    print(f"      Completed in {time.time() - start_t:.2f}s")
    eval_rf = evaluate_stage_classifier(rf_model, X_test, y_test, FEATURE_COLUMNS)
    results["Random Forest"] = eval_rf
    import joblib
    joblib.dump(rf_model, MODELS_DIR / "baseline_rf.joblib")

    # 4. Train Decision Tree Baseline
    print("\n" + "-" * 70)
    print("[3/4] Training Decision Tree Baseline (depth 8)...")
    start_t = time.time()
    dt_model = BaselineModels.train_decision_tree(X_train, y_train)
    print(f"      Completed in {time.time() - start_t:.2f}s")
    eval_dt = evaluate_stage_classifier(dt_model, X_test, y_test, FEATURE_COLUMNS)
    results["Decision Tree (d=8)"] = eval_dt
    joblib.dump(dt_model, MODELS_DIR / "baseline_dt.joblib")

    # 5. Train Ablation: XGBoost without window features
    print("\n" + "-" * 70)
    print("[4/4] Training XGBoost Ablation (Static features only, NO window features)...")
    start_t = time.time()
    ablation_model = BaselineModels.train_xgboost_no_window(X_train, y_train)
    print(f"      Completed in {time.time() - start_t:.2f}s")
    eval_ablation = evaluate_stage_classifier(ablation_model, X_test, y_test, STATIC_FEATURE_COLUMNS)
    results["XGBoost, no window feat."] = eval_ablation
    ablation_model.save_model(str(MODELS_DIR / "baseline_ablation.json"))

    # 6. Display Comparison Table
    print("\n" + "=" * 70)
    print("                 MODEL COMPARISON ON TEMPORAL SPLIT                 ")
    print("=" * 70)
    header = f"{'Model':<28} | {'Macro F1':<10} | {'Binary F1':<10} | {'Benign FPR':<12} | {'C2 F1':<10}"
    print(header)
    print("-" * len(header))
    for name, r in results.items():
        print(f"{name:<28} | {r['macro_f1']:<10.3f} | {r['binary_f1']:<10.3f} | {r['benign_fpr']*100:<11.2f}% | {r['c2_f1']:<10.3f}")
    print("=" * 70)

    # 7. Display Per-Class Results for IoTGuard
    print("\n" + "=" * 70)
    print("                 PER-CLASS RESULTS OF IOTGUARD                      ")
    print("=" * 70)
    print(f"{'Class':<12} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<10}")
    print("-" * 60)
    for stage in STAGE_CLASSES:
        m = eval_iotguard["per_class"][stage]
        print(f"{stage:<12} | {m['precision']:<10.3f} | {m['recall']:<10.3f} | {m['f1']:<10.3f} | {m['support']:<10}")
    print("-" * 60)
    print(f"{'Macro avg':<12} | {'-':<10} | {'-':<10} | {eval_iotguard['macro_f1']:<10.3f} | {len(y_test):<10}")
    print("=" * 70)

    # 8. Feature Importance
    feat_imp = iotguard_model.get_feature_importances()
    print("\nTop 8 Most Important Features by Gain:")
    for _, row in feat_imp.head(8).iterrows():
        star = " * (Window Feature)" if row["is_window"] else ""
        print(f"  - {row['feature']:<18}: {row['share_pct']:>5.1f}% gain{star}")

    # Save summary report
    summary_path = MODELS_DIR / "evaluation_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Full evaluation summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
