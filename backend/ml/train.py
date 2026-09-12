"""PhishShield AI — ML training pipeline.

Usage:
    cd backend
    python -m ml.train                          # looks for data/raw/*.csv
    python -m ml.train --dataset path/to.csv    # explicit dataset
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# Ensure project root is on sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ml.evaluate import evaluate_model
from ml.features import FEATURE_NAMES
from ml.preprocess import clean_dataset, extract_feature_matrix, load_dataset, print_stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger(__name__)

RANDOM_STATE = 42
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def _find_dataset() -> Path | None:
    """Auto-discover a CSV in data/raw/."""
    raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
    if not raw_dir.exists():
        return None
    csvs = sorted(raw_dir.glob("*.csv"))
    return csvs[0] if csvs else None


def _domain_aware_split(df, test_size=0.15, val_size=0.15, random_state=RANDOM_STATE):
    """Split by registered domain to prevent data leakage where practical.

    Falls back to standard stratified split if domain extraction fails.
    """
    from urllib.parse import urlparse

    def _registered_domain(url: str) -> str:
        try:
            host = urlparse(url).hostname or ""
            parts = host.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else host
        except Exception:
            return url

    df = df.copy()
    df["_domain"] = df["url"].apply(_registered_domain)
    domains = df["_domain"].unique()
    np.random.seed(random_state)
    np.random.shuffle(domains)

    n_test = int(len(domains) * test_size)
    n_val = int(len(domains) * val_size)

    test_domains = set(domains[:n_test])
    val_domains = set(domains[n_test:n_test + n_val])

    test_mask = df["_domain"].isin(test_domains)
    val_mask = df["_domain"].isin(val_domains)
    train_mask = ~(test_mask | val_mask)

    train_df = df[train_mask].drop(columns=["_domain"])
    val_df = df[val_mask].drop(columns=["_domain"])
    test_df = df[test_mask].drop(columns=["_domain"])

    # Verify both classes are present in every split (fall back otherwise)
    for name, split in [("train", train_df), ("val", val_df), ("test", test_df)]:
        if split["label"].nunique() < 2:
            logger.warning("Domain-aware split left %s with < 2 classes — falling back", name)
            return _stratified_split(df.drop(columns=["_domain"], errors="ignore"), test_size, val_size, random_state)

    return train_df, val_df, test_df


def _stratified_split(df, test_size=0.15, val_size=0.15, random_state=RANDOM_STATE):
    """Standard stratified split."""
    train_val, test = train_test_split(df, test_size=test_size, stratify=df["label"], random_state=random_state)
    relative_val = val_size / (1 - test_size)
    train, val = train_test_split(train_val, test_size=relative_val, stratify=train_val["label"], random_state=random_state)
    return train, val, test


def main(dataset_path: str | None = None) -> None:
    # ── 1. Find dataset ─────────────────────────────────────────────────
    if dataset_path:
        ds_path = Path(dataset_path)
    else:
        ds_path = _find_dataset()

    if ds_path is None or not ds_path.exists():
        print("\n" + "=" * 60)
        print("  ERROR: No training dataset found.")
        print("  Place a CSV with 'url' and 'label' columns in:")
        print(f"    backend/data/raw/")
        print("  Or specify --dataset path/to/data.csv")
        print("=" * 60)
        sys.exit(1)

    print(f"\n  Dataset: {ds_path}\n")

    # ── 2. Load & clean ─────────────────────────────────────────────────
    df = load_dataset(ds_path)
    df = clean_dataset(df)
    print_stats(df)

    if len(df) < 50:
        print("ERROR: Dataset too small for meaningful training.")
        sys.exit(1)

    # ── 3. Split ────────────────────────────────────────────────────────
    print("  Splitting data (domain-aware when possible)...")
    train_df, val_df, test_df = _domain_aware_split(df)
    print(f"  Train: {len(train_df):,}  |  Val: {len(val_df):,}  |  Test: {len(test_df):,}\n")

    # ── 4. Feature extraction ───────────────────────────────────────────
    print(f"  Extracting {len(FEATURE_NAMES)} features...")
    t0 = time.time()
    X_train = extract_feature_matrix(train_df["url"])
    y_train = train_df["label"].values
    X_val = extract_feature_matrix(val_df["url"])
    y_val = val_df["label"].values
    X_test = extract_feature_matrix(test_df["url"])
    y_test = test_df["label"].values
    print(f"  Feature extraction: {time.time()-t0:.1f}s\n")

    # ── 5. Baseline — Logistic Regression ───────────────────────────────
    print("  Training baseline (Logistic Regression)...")
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE)
    lr.fit(X_train, y_train)
    lr_metrics = evaluate_model(lr, X_val, y_val, label="Logistic Regression (validation)")

    # ── 6. Primary model — Random Forest ────────────────────────────────
    print("  Training primary model (Random Forest)...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_metrics = evaluate_model(rf, X_val, y_val, label="Random Forest (validation)")

    # ── 7. Select best model ────────────────────────────────────────────
    lr_f1 = lr_metrics["f1"]
    rf_f1 = rf_metrics["f1"]
    if rf_f1 >= lr_f1:
        best_model, best_name, best_val_metrics = rf, "RandomForest", rf_metrics
    else:
        best_model, best_name, best_val_metrics = lr, "LogisticRegression", lr_metrics

    print(f"\n  Selected model: {best_name}  (val F1={best_val_metrics['f1']:.4f})")

    # ── 8. Final evaluation on TEST set ─────────────────────────────────
    test_metrics = evaluate_model(best_model, X_test, y_test, label=f"{best_name} (TEST — final)")

    # ── 9. Save ─────────────────────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "model.pkl"
    meta_path = MODELS_DIR / "metadata.json"

    joblib.dump(best_model, model_path)
    print(f"\n  Model saved → {model_path}")

    metadata = {
        "model_type": best_name,
        "model_version": "rf-v1" if best_name == "RandomForest" else "lr-v1",
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": str(ds_path.name),
        "dataset_samples": len(df),
        "class_distribution": {
            "legitimate": int((df["label"] == 0).sum()),
            "phishing": int((df["label"] == 1).sum()),
        },
        "split": {
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df),
        },
        "test_metrics": test_metrics,
        "val_metrics": best_val_metrics,
        "threshold_safe": 40,
        "threshold_suspicious": 70,
        "random_state": RANDOM_STATE,
    }
    meta_path.write_text(json.dumps(metadata, indent=2))
    print(f"  Metadata saved → {meta_path}\n")

    # ── 10. Summary ─────────────────────────────────────────────────────
    print("=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Model:        {best_name}")
    print(f"  Features:     {len(FEATURE_NAMES)}")
    print(f"  Test Accuracy:  {test_metrics['accuracy']*100:.2f}%")
    print(f"  Test Precision: {test_metrics['precision']*100:.2f}%")
    print(f"  Test Recall:    {test_metrics['recall']*100:.2f}%")
    print(f"  Test F1:        {test_metrics['f1']*100:.2f}%")
    if test_metrics.get("roc_auc") is not None:
        print(f"  Test ROC-AUC:   {test_metrics['roc_auc']*100:.2f}%")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PhishShield AI ML model")
    parser.add_argument("--dataset", type=str, default=None, help="Path to CSV dataset")
    args = parser.parse_args()
    main(args.dataset)
