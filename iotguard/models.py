"""
IoTGuard Detection Models Module
Multi-stage machine learning classification pipeline:
- Primary Stage Classifier: XGBoost (300 trees, max_depth 6, lr 0.1, hist, balanced class weighting)
- Baselines:
  1. Random Forest (100 trees, max_depth 16)
  2. Decision Tree (depth 8)
  3. Ablation: XGBoost without 4 window features
  4. Isolation Forest (novelty detector trained on benign only)
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score
)
import xgboost as xgb

from config.settings import (
    STAGE_CLASSES,
    STAGE_TO_INT,
    INT_TO_STAGE,
    FEATURE_COLUMNS,
    STATIC_FEATURE_COLUMNS,
    MODELS_DIR
)


class IoTGuardModel:
    """
    Main 5-stage classifier using XGBoost with histogram-based split finding
    and inverse class frequency weighting.
    """
    def __init__(
        self,
        n_estimators: int = 300,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        tree_method: str = "hist",
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.tree_method = tree_method
        self.random_state = random_state

        self.model = xgb.XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            tree_method=self.tree_method,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=self.random_state
        )
        self.is_trained = False
        self.feature_names = FEATURE_COLUMNS

    def fit(self, X: pd.DataFrame, y: Union[pd.Series, np.ndarray]):
        """
        Fits XGBoost stage classifier with inverse frequency class weighting.
        """
        # Ensure numerical target indices 0..4
        if isinstance(y.iloc[0] if hasattr(y, 'iloc') else y[0], str):
            y_encoded = np.array([STAGE_TO_INT[label] for label in y])
        else:
            y_encoded = np.array(y, dtype=int)

        X_data = X[self.feature_names]

        # Compute sample weights inversely proportional to class frequencies for class balance
        sample_weights = compute_sample_weight(class_weight="balanced", y=y_encoded)

        self.model.fit(X_data, y_encoded, sample_weight=sample_weights)
        self.is_trained = True
        return self

    def predict(self, X: pd.DataFrame) -> List[str]:
        """Predicts kill-chain stage strings ('benign', 'download', 'cnc', 'scan', 'attack')."""
        preds_idx = self.model.predict(X[self.feature_names])
        return [INT_TO_STAGE[idx] for idx in preds_idx]

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Returns array of shape (N, 5) with class probabilities."""
        return self.model.predict_proba(X[self.feature_names])

    def predict_single(self, features_dict: Dict[str, Any]) -> Tuple[str, float, Dict[str, float]]:
        """
        Infers a single connection record with sub-millisecond line-rate latency.
        Returns:
            predicted_stage (str)
            confidence_probability (float)
            all_stage_probabilities (dict)
        """
        row_arr = np.array([[float(features_dict[col]) for col in self.feature_names]], dtype=np.float32)
        probs = self.model.predict_proba(row_arr)[0]
        max_idx = int(np.argmax(probs))
        pred_stage = INT_TO_STAGE[max_idx]
        confidence = float(probs[max_idx])
        prob_dict = {INT_TO_STAGE[i]: float(probs[i]) for i in range(len(STAGE_CLASSES))}
        return pred_stage, confidence, prob_dict

    def predict_batch(self, features_list: List[Dict[str, Any]]) -> List[Tuple[str, float, Dict[str, float]]]:
        """
        Vectorized batch inference for micro-batching.
        Processes up to tens of thousands of connections per second in batches.
        """
        if not features_list:
            return []

        rows = []
        for feat in features_list:
            rows.append([float(feat[col]) for col in self.feature_names])
        batch_arr = np.array(rows, dtype=np.float32)

        probs_matrix = self.model.predict_proba(batch_arr)
        results = []
        for probs in probs_matrix:
            max_idx = int(np.argmax(probs))
            pred_stage = INT_TO_STAGE[max_idx]
            confidence = float(probs[max_idx])
            prob_dict = {INT_TO_STAGE[i]: float(probs[i]) for i in range(len(STAGE_CLASSES))}
            results.append((pred_stage, confidence, prob_dict))

        return results

    def get_feature_importances(self) -> pd.DataFrame:
        """
        Returns feature importance ranked by gain.
        """
        booster = self.model.get_booster()
        score_gain = booster.get_score(importance_type="gain")
        total_gain = sum(score_gain.values()) if score_gain else 1.0

        records = []
        for feat in self.feature_names:
            gain = score_gain.get(feat, 0.0)
            share = (gain / total_gain) * 100.0 if total_gain > 0 else 0.0
            records.append({
                "feature": feat,
                "gain": gain,
                "share_pct": share,
                "is_window": feat in ["nh", "dh", "ph", "fh"]
            })

        df = pd.DataFrame(records).sort_values(by="share_pct", ascending=False).reset_index(drop=True)
        return df

    def save(self, path: Union[str, Path], sign: bool = True, key: Optional[bytes] = None):
        """Save model to JSON or joblib and optionally generate cryptographic signature."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".json":
            self.model.save_model(str(path))
        else:
            joblib.dump(self.model, str(path))

        if sign:
            try:
                from iotguard.security import sign_model_file, DEFAULT_SECRET_KEY
                sign_model_file(path, key=key or DEFAULT_SECRET_KEY)
            except Exception:
                pass

    def load(
        self,
        path: Union[str, Path],
        verify_signature: bool = False,
        sig_path: Optional[Union[str, Path]] = None,
        key: Optional[bytes] = None
    ):
        """
        Load model from file with optional Tier 2 cryptographic verification.
        """
        path = Path(path)
        if verify_signature:
            from iotguard.security import verify_model_signature, DEFAULT_SECRET_KEY
            is_valid, msg = verify_model_signature(path, sig_path=sig_path, key=key or DEFAULT_SECRET_KEY)
            if not is_valid:
                raise ValueError(f"Security Alert: Model verification failed! {msg}")

        if path.suffix == ".json":
            self.model.load_model(str(path))
        else:
            self.model = joblib.load(str(path))
        self.is_trained = True


class BaselineModels:
    """
    Implements comparison baselines:
    1. Random Forest (100 trees, depth 16)
    2. Decision Tree (depth 8)
    3. XGBoost Ablation (No window features)
    4. Isolation Forest (Novelty detector on benign)
    """
    @staticmethod
    def train_random_forest(X: pd.DataFrame, y: Union[pd.Series, np.ndarray], random_state: int = 42) -> RandomForestClassifier:
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1
        )
        if isinstance(y.iloc[0] if hasattr(y, 'iloc') else y[0], str):
            y_enc = np.array([STAGE_TO_INT[label] for label in y])
        else:
            y_enc = np.array(y, dtype=int)
        rf.fit(X[FEATURE_COLUMNS], y_enc)
        return rf

    @staticmethod
    def train_decision_tree(X: pd.DataFrame, y: Union[pd.Series, np.ndarray], random_state: int = 42) -> DecisionTreeClassifier:
        dt = DecisionTreeClassifier(
            max_depth=8,
            class_weight="balanced",
            random_state=random_state
        )
        if isinstance(y.iloc[0] if hasattr(y, 'iloc') else y[0], str):
            y_enc = np.array([STAGE_TO_INT[label] for label in y])
        else:
            y_enc = np.array(y, dtype=int)
        dt.fit(X[FEATURE_COLUMNS], y_enc)
        return dt

    @staticmethod
    def train_xgboost_no_window(X: pd.DataFrame, y: Union[pd.Series, np.ndarray], random_state: int = 42) -> xgb.XGBClassifier:
        model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            tree_method="hist",
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=random_state
        )
        if isinstance(y.iloc[0] if hasattr(y, 'iloc') else y[0], str):
            y_enc = np.array([STAGE_TO_INT[label] for label in y])
        else:
            y_enc = np.array(y, dtype=int)
        sample_weights = compute_sample_weight("balanced", y_enc)
        model.fit(X[STATIC_FEATURE_COLUMNS], y_enc, sample_weight=sample_weights)
        return model

    @staticmethod
    def train_isolation_forest(X_benign: pd.DataFrame, random_state: int = 42) -> IsolationForest:
        iso = IsolationForest(
            n_estimators=100,
            contamination=0.01,
            random_state=random_state,
            n_jobs=-1
        )
        iso.fit(X_benign[FEATURE_COLUMNS])
        return iso


def evaluate_stage_classifier(
    model,
    X_test: pd.DataFrame,
    y_test: Union[pd.Series, np.ndarray],
    features: List[str] = FEATURE_COLUMNS
) -> Dict[str, Any]:
    """
    Evaluates multi-class stage predictions and computes key performance metrics.
    """
    if isinstance(y_test.iloc[0] if hasattr(y_test, 'iloc') else y_test[0], str):
        y_true_enc = np.array([STAGE_TO_INT[l] for l in y_test])
    else:
        y_true_enc = np.array(y_test, dtype=int)

    preds_enc = model.predict(X_test[features])
    if isinstance(preds_enc[0], str):
        preds_enc = np.array([STAGE_TO_INT[l] for l in preds_enc])

    class_labels = list(range(len(STAGE_CLASSES)))
    macro_f1 = f1_score(y_true_enc, preds_enc, average="macro", labels=class_labels, zero_division=0)
    per_class_f1 = f1_score(y_true_enc, preds_enc, average=None, labels=class_labels, zero_division=0)
    per_class_prec = precision_score(y_true_enc, preds_enc, average=None, labels=class_labels, zero_division=0)
    per_class_rec = recall_score(y_true_enc, preds_enc, average=None, labels=class_labels, zero_division=0)

    # Benign False Positive Rate (FPR): Benign test connections misclassified as any attack
    benign_idx = STAGE_TO_INT["benign"]
    benign_mask = (y_true_enc == benign_idx)
    total_benign = int(np.sum(benign_mask))
    benign_fp = int(np.sum(benign_mask & (preds_enc != benign_idx)))
    benign_fpr = (benign_fp / total_benign) if total_benign > 0 else 0.0

    # Binary Malicious-vs-Benign F1
    y_true_bin = (y_true_enc != benign_idx).astype(int)
    y_pred_bin = (preds_enc != benign_idx).astype(int)
    binary_f1 = f1_score(y_true_bin, y_pred_bin, zero_division=0)

    # Confusion matrix
    cm = confusion_matrix(y_true_enc, preds_enc, labels=list(range(len(STAGE_CLASSES))))

    per_class_metrics = {}
    for i, stage in enumerate(STAGE_CLASSES):
        per_class_metrics[stage] = {
            "precision": float(per_class_prec[i]),
            "recall": float(per_class_rec[i]),
            "f1": float(per_class_f1[i]),
            "support": int(np.sum(y_true_enc == i))
        }

    return {
        "macro_f1": float(macro_f1),
        "binary_f1": float(binary_f1),
        "benign_fpr": float(benign_fpr),
        "benign_fp_count": benign_fp,
        "total_benign": total_benign,
        "c2_f1": float(per_class_metrics["cnc"]["f1"]),
        "per_class": per_class_metrics,
        "confusion_matrix": cm.tolist()
    }
