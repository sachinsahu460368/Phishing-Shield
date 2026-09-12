import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Ensure project root on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from app.services.url_features import extract_features, features_to_vector, FEATURE_NAMES
from app.config import MODEL_PATH
from ml.train import RANDOM_STATE

def analyze_false_positives():
    model_path = MODEL_PATH
    if not Path(model_path).exists():
        print(f"Error: Model not found at {model_path}")
        return

    # In our implementation, model is a Pipeline
    pipe = joblib.load(model_path)
    scaler = pipe.named_steps['scaler']
    lr = pipe.named_steps['classifier']

    # Coefficients
    coeffs = lr.coef_[0]

    sanity_df = pd.read_csv("data/sanity/real_world_urls.csv")

    analysis_results = []

    for _, row in sanity_df.iterrows():
        url = row['url']
        expected = 1 if row['expected_label'] == 'phishing' else 0

        # 1. Feature Extraction & Vectorization
        features_dict = extract_features(url)
        vector = np.array(features_to_vector(features_dict)).reshape(1, -1)

        # 2. Scaling
        scaled_vector = scaler.transform(vector)

        # 3. LR Prediction
        proba = pipe.predict_proba(vector)[0]
        phishing_prob = proba[1]

        # Verdict logic
        risk_score = int(round(max(0.0, min(1.0, phishing_prob)) * 100))
        pred = 1 if risk_score >= 40 else 0 # Threshold safe=40 in predictor.py logic

        # Contribution = standardized_feature * coefficient
        contributions = scaled_vector[0] * coeffs

        # Top 5 phishing / legitimate pushers
        # Zip with names
        feat_contribs = list(zip(FEATURE_NAMES, scaled_vector[0], contributions))

        # Sort by contribution
        sorted_contribs = sorted(feat_contribs, key=lambda x: x[2], reverse=True)

        top5_phishing = sorted_contribs[:5]

        analysis_results.append({
            "url": url,
            "category": row['category'],
            "expected": expected,
            "pred": pred,
            "risk_score": risk_score,
            "phishing_prob": phishing_prob,
            **{f"feat_{name}": val for name, val, c in feat_contribs},
            **{f"contrib_{name}": c for name, val, c in feat_contribs},
            "top_phishing_1": top5_phishing[0][0], "contrib_1": top5_phishing[0][2],
            "top_phishing_2": top5_phishing[1][0], "contrib_2": top5_phishing[1][2],
            "top_phishing_3": top5_phishing[2][0], "contrib_3": top5_phishing[2][2],
            "top_phishing_4": top5_phishing[3][0], "contrib_4": top5_phishing[3][2],
            "top_phishing_5": top5_phishing[4][0], "contrib_5": top5_phishing[4][2],
        })

    results_df = pd.DataFrame(analysis_results)
    print("Analysis complete. Saving...")
    results_df.to_csv("backend/reports/fp_analysis_full.csv", index=False)

    # Task 2: Filter False Positives (expected=0, pred=1, risk_score >= 40)
    fps = results_df[(results_df["expected"] == 0) & (results_df["pred"] == 1)]
    print(f"False Positives: {len(fps)}")
    fps.to_csv("backend/reports/false_positive_analysis.csv", index=False)

if __name__ == "__main__":
    analyze_false_positives()
