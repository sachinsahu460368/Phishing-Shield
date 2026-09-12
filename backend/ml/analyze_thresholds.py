import sys
from pathlib import Path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, _PROJECT_ROOT)

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, brier_score_loss
from app.services.url_features import extract_features, features_to_vector
from app.config import MODEL_PATH

# ── 1. Load Model & Datasets ──────────────────────────────────────────
model = joblib.load(MODEL_PATH)

# Historical 15-URL dataset
sanity_15 = [
    ("https://google.com", 0), ("https://github.com", 0),
    ("https://microsoft.com", 0), ("https://apple.com", 0),
    ("https://amazon.com", 0), ("https://wikipedia.org", 0),
    ("https://www.google.com/search?q=test", 0),
    ("https://docs.github.com", 0),
    ("https://stackoverflow.com/questions", 0),
    ("https://en.wikipedia.org/wiki/Main_Page", 0),
    ("http://secure-login-verify.attacker.com/login", 1),
    ("http://paypal.attacker.com/login", 1),
    ("http://github.com.attacker.com/login", 1),
    ("http://192.168.1.1/account/verify?password=x", 1),
    ("http://login-verify-secure-account.tk/confirm", 1),
]

# Formal 50-URL dataset
df_50 = pd.read_csv("data/sanity/real_world_urls.csv")
sanity_50 = [
    (row['url'], 1 if row['expected_label'] == 'phishing' else 0)
    for _, row in df_50.iterrows()
]

# ── 2. Utility Functions ──────────────────────────────────────────────
def get_features_and_probs(dataset):
    results = []
    y_true = []
    y_probs = []
    for url, expected in dataset:
        features = extract_features(url)
        vector = np.array([features_to_vector(features)])
        proba = model.predict_proba(vector)[0][1]
        results.append({"url": url, "expected": expected, "proba": proba})
        y_true.append(expected)
        y_probs.append(proba)
    return pd.DataFrame(results), np.array(y_true), np.array(y_probs)

def evaluate_thresholds(y_true, y_probs, thresholds):
    metrics = []
    for t in thresholds:
        y_pred = (y_probs >= t).astype(int)
        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        legit_fp_rate = fp / (tn + fp) if (tn + fp) > 0 else 0.0
        phish_fn_rate = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        accuracy = (tp + tn) / len(y_true)

        metrics.append({
            "threshold": t,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "legit_fp_rate": legit_fp_rate,
            "phish_fn_rate": phish_fn_rate
        })
    return pd.DataFrame(metrics)

# ── 3. Execution ──────────────────────────────────────────────────────
thresholds = [round(t, 2) for t in np.arange(0.05, 1.0, 0.05)]
res_15, y_t15, y_p15 = get_features_and_probs(sanity_15)
res_50, y_t50, y_p50 = get_features_and_probs(sanity_50)

metrics_15 = evaluate_thresholds(y_t15, y_p15, thresholds)
metrics_50 = evaluate_thresholds(y_t50, y_p50, thresholds)

print("--- Threshold Sweep Results (15 URL) ---")
print(metrics_15.to_string())
print("\n--- Threshold Sweep Results (50 URL) ---")
print(metrics_50.to_string())

# Calibration Check (Task 6)
brier_15 = brier_score_loss(y_t15, y_p15)
brier_50 = brier_score_loss(y_t50, y_p50)
print(f"\nBrier Score (15 URL): {brier_15:.4f}")
print(f"Brier Score (50 URL): {brier_50:.4f}")
