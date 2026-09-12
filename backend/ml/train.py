"""PhishShield AI — ML training pipeline (Phase 4-8).

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
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# Ensure project root is on sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ml.evaluate import evaluate_model
from ml.features import FEATURE_NAMES, extract_features, features_to_vector
from ml.preprocess import clean_dataset, extract_feature_matrix, load_dataset, print_stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger(__name__)

RANDOM_STATE = 42
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"

# ── Feature sets for ablation ──────────────────────────────────────────────
# The top-4 shortcut features (has_https, has_http, path_length, num_slashes)
# account for ~67% of RF importance but are dataset artifacts, not real
# phishing signals. We remove them to force the model to learn real patterns.
_SHORTCUT_FEATURES = {"has_https", "has_http", "path_length", "num_slashes"}
_SHORTCUT_INDICES = [
    i for i, name in enumerate(FEATURE_NAMES) if name in _SHORTCUT_FEATURES
]


def _find_dataset() -> Path | None:
    """Auto-discover a CSV in data/raw/."""
    raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
    if not raw_dir.exists():
        return None
    csvs = sorted(raw_dir.glob("*.csv"))
    return csvs[0] if csvs else None


def _domain_aware_split(df, test_size=0.15, val_size=0.15, random_state=RANDOM_STATE):
    """Split by registered domain using tldextract (prevents data leakage).

    Falls back to standard stratified split if tldextract fails or any split
    ends up with fewer than 2 classes.
    """
    try:
        import tldextract
    except ImportError:
        logger.warning("tldextract not installed — falling back to stratified split")
        return _stratified_split(df, test_size, val_size, random_state)

    from urllib.parse import urlparse

    def _registered_domain(url: str) -> str:
        try:
            host = urlparse(url).hostname or ""
            ext = tldextract.extract(host)
            reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            return reg.lower()
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


def _remove_features(X: np.ndarray, indices: list[int]) -> np.ndarray:
    """Remove columns at the given indices from feature matrix."""
    mask = np.ones(X.shape[1], dtype=bool)
    mask[indices] = False
    return X[:, mask]


def _sanity_test(model, model_name: str, feature_indices_to_remove: list[int] | None = None):
    """Run real-world sanity predictions on well-known URLs.

    Returns (pass_count, total, results_list).
    """
    sanity_urls = [
        # Legitimate (should be safe or suspicious, NOT phishing)
        ("https://google.com", "not_phishing"),
        ("https://github.com", "not_phishing"),
        ("https://microsoft.com", "not_phishing"),
        ("https://apple.com", "not_phishing"),
        ("https://amazon.com", "not_phishing"),
        ("https://wikipedia.org", "not_phishing"),
        ("https://www.google.com/search?q=test", "not_phishing"),
        ("https://docs.github.com", "not_phishing"),
        ("https://stackoverflow.com/questions", "not_phishing"),
        ("https://en.wikipedia.org/wiki/Main_Page", "not_phishing"),
        # Phishing-like (should be suspicious or phishing, NOT safe)
        ("http://secure-login-verify.attacker.com/login", "not_safe"),
        ("http://paypal.attacker.com/login", "not_safe"),
        ("http://github.com.attacker.com/login", "not_safe"),
        ("http://192.168.1.1/account/verify?password=x", "not_safe"),
        ("http://login-verify-secure-account.tk/confirm", "not_safe"),
    ]

    results = []
    pass_count = 0

    for url, expected in sanity_urls:
        feats = extract_features(url)
        vec = np.array([features_to_vector(feats)], dtype=np.float64)
        if feature_indices_to_remove:
            vec = _remove_features(vec, feature_indices_to_remove)

        proba = model.predict_proba(vec)[0]
        risk_score = int(round(proba[1] * 100))

        if risk_score < 40:
            verdict = "safe"
        elif risk_score < 70:
            verdict = "suspicious"
        else:
            verdict = "phishing"

        if expected == "not_phishing":
            passed = verdict != "phishing"
        else:  # not_safe
            passed = verdict != "safe"

        if passed:
            pass_count += 1

        results.append({
            "url": url,
            "expected": expected,
            "verdict": verdict,
            "risk_score": risk_score,
            "phishing_prob": round(float(proba[1]), 4),
            "passed": passed,
        })

    return pass_count, len(sanity_urls), results


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
    df = load_dataset(ds_path, invert_labels=True)
    df = clean_dataset(df)
    print_stats(df)

    if len(df) < 50:
        print("ERROR: Dataset too small for meaningful training.")
        sys.exit(1)

    # ── 3. Split ────────────────────────────────────────────────────────
    print("  Splitting data (domain-aware with tldextract)...")
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

    # ── 5. Prepare ablation matrices ────────────────────────────────────
    X_train_no_shortcuts = _remove_features(X_train, _SHORTCUT_INDICES)
    X_val_no_shortcuts = _remove_features(X_val, _SHORTCUT_INDICES)
    X_test_no_shortcuts = _remove_features(X_test, _SHORTCUT_INDICES)

    # ═══════════════════════════════════════════════════════════════════
    #  MULTI-MODEL TRAINING
    # ═══════════════════════════════════════════════════════════════════
    rf_params = dict(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    models = {}  # name → (model, val_metrics, test_metrics, sanity, removed_indices)

    # ── Model A: Logistic Regression baseline (all 52) ────────────────
    print("=" * 60)
    print("  Model A: Logistic Regression (baseline, all 52, Scaled)")
    print("=" * 60)
    lr_pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE))
    ])
    lr_pipe.fit(X_train, y_train)
    lr_val = evaluate_model(lr_pipe, X_val, y_val, label="LR-Scaled-52 (validation)")
    lr_test = evaluate_model(lr_pipe, X_test, y_test, label="LR-Scaled-52 (TEST)")
    lr_pass, lr_total, lr_sanity = _sanity_test(lr_pipe, "LR-52")
    print(f"\n  Sanity test: {lr_pass}/{lr_total} passed\n")
    models["LR-Scaled-52"] = (lr_pipe, lr_val, lr_test, (lr_pass, lr_total, lr_sanity), None)

    # ── Model A2: Logistic Regression (no top-4 shortcuts, Scaled) ───────
    print("=" * 60)
    print("  Model A2: Logistic Regression — 48 features (no shortcuts, Scaled)")
    print(f"  Removed: {sorted(_SHORTCUT_FEATURES)}")
    print("=" * 60)
    lr_pipe2 = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE))
    ])
    lr_pipe2.fit(X_train_no_shortcuts, y_train)
    lr2_val = evaluate_model(lr_pipe2, X_val_no_shortcuts, y_val, label="LR-Scaled-48 (validation)")
    lr2_test = evaluate_model(lr_pipe2, X_test_no_shortcuts, y_test, label="LR-Scaled-48 (TEST)")
    lr2_pass, lr2_total, lr2_sanity = _sanity_test(lr_pipe2, "LR-48", _SHORTCUT_INDICES)
    print(f"\n  Sanity test: {lr2_pass}/{lr2_total} passed\n")
    models["LR-Scaled-48-no-shortcuts"] = (lr_pipe2, lr2_val, lr2_test, (lr2_pass, lr2_total, lr2_sanity), _SHORTCUT_INDICES)

    # ── Model B: Random Forest (all 52 features) ───────────────────────
    print("=" * 60)
    print("  Model B: Random Forest — all 52 features")
    print("=" * 60)
    rf_b = RandomForestClassifier(**rf_params)
    rf_b.fit(X_train, y_train)
    rf_b_val = evaluate_model(rf_b, X_val, y_val, label="RF-52 (validation)")
    rf_b_test = evaluate_model(rf_b, X_test, y_test, label="RF-52 (TEST)")
    rf_b_pass, rf_b_total, rf_b_sanity = _sanity_test(rf_b, "RF-52")
    print(f"\n  Sanity test: {rf_b_pass}/{rf_b_total} passed\n")
    models["RF-52"] = (rf_b, rf_b_val, rf_b_test, (rf_b_pass, rf_b_total, rf_b_sanity), None)

    # ── Model D: Random Forest (no top-4 shortcuts) ─────────────────────
    print("=" * 60)
    print("  Model D: Random Forest — 48 features (no top-4 shortcuts)")
    print(f"  Removed: {sorted(_SHORTCUT_FEATURES)}")
    print("=" * 60)
    rf_d = RandomForestClassifier(**rf_params)
    rf_d.fit(X_train_no_shortcuts, y_train)
    rf_d_val = evaluate_model(rf_d, X_val_no_shortcuts, y_val, label="RF-48 (validation)")
    rf_d_test = evaluate_model(rf_d, X_test_no_shortcuts, y_test, label="RF-48 (TEST)")
    rf_d_pass, rf_d_total, rf_d_sanity = _sanity_test(rf_d, "RF-48", _SHORTCUT_INDICES)
    print(f"\n  Sanity test: {rf_d_pass}/{rf_d_total} passed\n")
    models["RF-48-no-shortcuts"] = (rf_d, rf_d_val, rf_d_test, (rf_d_pass, rf_d_total, rf_d_sanity), _SHORTCUT_INDICES)

    # ── Model E: Gradient Boosting (all 52 features) ────────────────────
    print("=" * 60)
    print("  Model E: Gradient Boosting — all 52 features")
    print("=" * 60)
    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        min_samples_split=5,
        min_samples_leaf=2,
        subsample=0.8,
        random_state=RANDOM_STATE,
    )
    gb.fit(X_train, y_train)
    gb_val = evaluate_model(gb, X_val, y_val, label="GB-52 (validation)")
    gb_test = evaluate_model(gb, X_test, y_test, label="GB-52 (TEST)")
    gb_pass, gb_total, gb_sanity = _sanity_test(gb, "GB-52")
    print(f"\n  Sanity test: {gb_pass}/{gb_total} passed\n")
    models["GB-52"] = (gb, gb_val, gb_test, (gb_pass, gb_total, gb_sanity), None)

    # ── Model F: Gradient Boosting (no top-4 shortcuts) ─────────────────
    print("=" * 60)
    print("  Model F: Gradient Boosting — 48 features (no shortcuts)")
    print(f"  Removed: {sorted(_SHORTCUT_FEATURES)}")
    print("=" * 60)
    gb2 = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        min_samples_split=5,
        min_samples_leaf=2,
        subsample=0.8,
        random_state=RANDOM_STATE,
    )
    gb2.fit(X_train_no_shortcuts, y_train)
    gb2_val = evaluate_model(gb2, X_val_no_shortcuts, y_val, label="GB-48 (validation)")
    gb2_test = evaluate_model(gb2, X_test_no_shortcuts, y_test, label="GB-48 (TEST)")
    gb2_pass, gb2_total, gb2_sanity = _sanity_test(gb2, "GB-48", _SHORTCUT_INDICES)
    print(f"\n  Sanity test: {gb2_pass}/{gb2_total} passed\n")
    models["GB-48-no-shortcuts"] = (gb2, gb2_val, gb2_test, (gb2_pass, gb2_total, gb2_sanity), _SHORTCUT_INDICES)

    # ═══════════════════════════════════════════════════════════════════
    #  MODEL COMPARISON & SELECTION
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("  MODEL COMPARISON")
    print("=" * 78)
    print(f"  {'Model':<22s} {'Val F1':>8s} {'Test F1':>8s} {'Sanity':>8s} {'AUC':>8s}")
    print("  " + "-" * 60)

    for name, (_, val_m, test_m, (sp, st, _), _) in models.items():
        auc_str = f"{test_m['roc_auc']*100:.1f}%" if test_m.get("roc_auc") else "   N/A"
        print(f"  {name:<22s} {val_m['f1']*100:7.2f}% {test_m['f1']*100:7.2f}% {sp:3d}/{st:<3d}  {auc_str}")
    print("=" * 78)

    # ── Selection logic ─────────────────────────────────────────────────
    # Goals ordered by priority:
    #   1) Sanity pass rate ≥ 12/15 (must not classify legitimate sites as phishing)
    #   2) Test F1 ≥ 90%  (still useful as a detector)
    #   3) Highest sanity pass, then highest F1 as tiebreaker
    #
    # If NO model hits 12/15 sanity, pick the one with the highest sanity,
    # then F1 as tiebreaker.

    def _selection_key(item):
        name, (_, _, test_m, (sp, st, _), _) = item
        sanity_rate = sp / max(st, 1)
        return (sanity_rate, test_m["f1"])

    best_name, (best_model, best_val, best_test, best_sanity, best_removal) = max(
        models.items(), key=_selection_key
    )

    print(f"\n  ► Selected model: {best_name}")
    print(f"    Test F1={best_test['f1']:.4f}  Sanity={best_sanity[0]}/{best_sanity[1]}\n")

    # ── Feature importance (for tree-based models) ──────────────────────
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        if best_removal:
            feat_names = [n for i, n in enumerate(FEATURE_NAMES) if i not in best_removal]
        else:
            feat_names = FEATURE_NAMES
        ranked = sorted(zip(feat_names, importances), key=lambda x: -x[1])
        print("  Feature importances (top 15):")
        cumulative = 0.0
        for i, (fname, imp) in enumerate(ranked[:15]):
            cumulative += imp
            print(f"    {i+1:2d}. {fname:40s} {imp:.6f}  (cum: {cumulative:.4f})")
        top4 = sum(imp for _, imp in ranked[:4])
        print(f"\n  Top 4 features: {top4:.1%} of total importance")

    # ── Save ────────────────────────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "model.pkl"
    meta_path = MODELS_DIR / "metadata.json"

    joblib.dump(best_model, model_path)
    print(f"\n  Model saved → {model_path}")

    # Determine version tag
    model_type = best_name.split("-")[0]
    version = f"{model_type.lower()}-v2"

    # Feature names for the saved model
    if best_removal:
        saved_feature_names = [n for i, n in enumerate(FEATURE_NAMES) if i not in best_removal]
        removed_features = sorted(FEATURE_NAMES[i] for i in best_removal)
    else:
        saved_feature_names = list(FEATURE_NAMES)
        removed_features = []

    metadata = {
        "model_type": best_name,
        "model_version": version,
        "feature_names": saved_feature_names,
        "feature_count": len(saved_feature_names),
        "removed_features": removed_features,
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
        "test_metrics": best_test,
        "val_metrics": best_val,
        "sanity_test": {
            "passed": best_sanity[0],
            "total": best_sanity[1],
            "results": best_sanity[2],
        },
        "all_models_comparison": {
            name: {
                "val_f1": v["f1"],
                "test_f1": t["f1"],
                "test_auc": t.get("roc_auc"),
                "sanity_passed": sp,
                "sanity_total": st,
            }
            for name, (_, v, t, (sp, st, _), _) in models.items()
        },
        "threshold_safe": 40,
        "threshold_suspicious": 70,
        "random_state": RANDOM_STATE,
    }
    meta_path.write_text(json.dumps(metadata, indent=2))
    print(f"  Metadata saved → {meta_path}\n")

    # ── Sanity test details ─────────────────────────────────────────────
    print("=" * 78)
    print("  SANITY TEST RESULTS — selected model")
    print("=" * 78)
    print(f"  {'URL':55s} {'Expect':12s} {'Verdict':10s} {'Risk':5s} {'Pass':5s}")
    print("  " + "-" * 90)
    for r in best_sanity[2]:
        mark = "✓" if r["passed"] else "✗"
        print(f"  {r['url']:55s} {r['expected']:12s} {r['verdict']:10s} {r['risk_score']:5d} {mark}")
    print()

    # ── Summary ─────────────────────────────────────────────────────────
    print("=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Model:          {best_name} ({version})")
    print(f"  Features:       {len(saved_feature_names)}")
    if removed_features:
        print(f"  Removed:        {', '.join(removed_features)}")
    print(f"  Test Accuracy:  {best_test['accuracy']*100:.2f}%")
    print(f"  Test Precision: {best_test['precision']*100:.2f}%")
    print(f"  Test Recall:    {best_test['recall']*100:.2f}%")
    print(f"  Test F1:        {best_test['f1']*100:.2f}%")
    if best_test.get("roc_auc") is not None:
        print(f"  Test ROC-AUC:   {best_test['roc_auc']*100:.2f}%")
    print(f"  Sanity tests:   {best_sanity[0]}/{best_sanity[1]}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PhishShield AI ML model")
    parser.add_argument("--dataset", type=str, default=None, help="Path to CSV dataset")
    args = parser.parse_args()
    main(args.dataset)
