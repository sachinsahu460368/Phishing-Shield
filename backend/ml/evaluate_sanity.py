import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np
import joblib
from pathlib import Path

from app.services.url_features import extract_features, features_to_vector
from app.config import MODEL_PATH
from sklearn.metrics import confusion_matrix

def load_and_evaluate_sanity():
    model_path = MODEL_PATH
    if not Path(model_path).exists():
        print(f"Error: Model not found at {model_path}")
        return

    print("Loading model...")
    model = joblib.load(model_path)

    sanity_df = pd.read_csv("data/sanity/real_world_urls.csv")
    print(f"Loaded {len(sanity_df)} URL samples.\n")

    results = []

    for _, row in sanity_df.iterrows():
        url = row['url']
        expected = 1 if row['expected_label'] == 'phishing' else 0

        features = extract_features(url)
        vector = features_to_vector(features)

        proba = model.predict_proba(np.array([vector]))[0]
        # In PhishShield, proba[1] is phishing
        phishing_prob = proba[1]

        # Risk score logic from predictor.py (THRESHOLD_SAFE=40, THRESHOLD_SUSPICIOUS=70)
        risk_score = int(round(max(0.0, min(1.0, phishing_prob)) * 100))

        if risk_score < 40:
            verdict = "legitimate"
            pred = 0
        elif risk_score < 70:
            verdict = "suspicious"
            # How to map suspicious? Usually treated as phishing/unsafe in binary evaluation
            # Let's treat suspicious as phishing for conservative detection
            pred = 1
        else:
            verdict = "phishing"
            pred = 1

        results.append({
            "url": url,
            "expected": expected,
            "pred": pred,
            "verdict": verdict,
            "category": row['category'],
            "risk_score": risk_score
        })

    results_df = pd.DataFrame(results)

    # Metrics
    total = len(results_df)
    correct = (results_df["expected"] == results_df["pred"]).sum()
    accuracy = correct / total

    # Confusion Matrix
    cm = confusion_matrix(results_df["expected"], results_df["pred"])

    print(f"Sanity Dataset Size: {total}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Confusion Matrix:\n{cm}")

    print("\nMisclassified Examples:")
    misclassified = results_df[results_df["expected"] != results_df["pred"]]
    if not misclassified.empty:
        print(misclassified[["url", "expected", "pred", "verdict", "risk_score"]])
    else:
        print("None.")

    print("\nPer-Category Results:")
    print(results_df.groupby("category").apply(lambda x: (x["expected"] == x["pred"]).mean()))

if __name__ == "__main__":
    load_and_evaluate_sanity()
