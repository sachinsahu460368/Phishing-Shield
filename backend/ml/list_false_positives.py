import sys
from pathlib import Path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, _PROJECT_ROOT)

import pandas as pd
import numpy as np
import joblib
from app.services.url_features import extract_features, features_to_vector
from app.config import MODEL_PATH

# 1. Load Model & Dataset
model = joblib.load(MODEL_PATH)
df = pd.read_csv("data/sanity/real_world_urls.csv")

# 2. Analyze False Positives
# Expected legitimate: expected_label != 'phishing' (so expected=0)
# Predictive phishing: proba >= 0.40
results = []
for _, row in df.iterrows():
    url = row['url']
    expected = 1 if row['expected_label'] == 'phishing' else 0
    features = extract_features(url)
    vector = np.array([features_to_vector(features)])
    proba = model.predict_proba(vector)[0][1]
    pred = 1 if proba >= 0.40 else 0

    results.append({
        "url": url,
        "expected": expected,
        "proba": proba,
        "risk_score": int(round(proba * 100)),
        "pred": pred
    })

results_df = pd.DataFrame(results)
fps = results_df[(results_df["expected"] == 0) & (results_df["pred"] == 1)]

print(f"Number of FPs at threshold 0.40: {len(fps)}")
print(fps[["url", "expected", "proba", "risk_score", "pred"]].to_string())
