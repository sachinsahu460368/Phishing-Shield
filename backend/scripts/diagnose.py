"""Model diagnostics script — Phase 1-3 inspection."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import numpy as np
import joblib

from app.services.url_features import extract_features, features_to_vector, FEATURE_NAMES

model = joblib.load("models/model.pkl")
meta = json.loads(Path("models/metadata.json").read_text())

print("=== MODEL DIAGNOSTICS ===")
print(f"model.classes_: {model.classes_}")
print(f"n_classes: {len(model.classes_)}")
print(f"model_type: {meta['model_type']}")
print(f"model_version: {meta['model_version']}")
print(f"feature_count: {meta['feature_count']}")
print(f"class_distribution: {meta['class_distribution']}")
print()

# Phase 2 — Verify class mapping
print("=== LABEL MAPPING VERIFICATION ===")
print(f"classes_[0]={model.classes_[0]} -> proba[0] = probability of class {model.classes_[0]}")
print(f"classes_[1]={model.classes_[1]} -> proba[1] = probability of class {model.classes_[1]}")
if list(model.classes_) == [0, 1]:
    print("PASS: model.classes_ = [0, 1] as expected")
    print("  proba[0] = P(legitimate), proba[1] = P(phishing)")
else:
    print(f"FAIL: model.classes_ = {list(model.classes_)} — NOT [0, 1]!")
print()

# Prediction sanity
urls_test = [
    ("https://google.com", "safe"),
    ("https://github.com", "safe"),
    ("https://microsoft.com", "safe"),
    ("https://apple.com", "safe"),
    ("https://amazon.com", "safe"),
    ("https://wikipedia.org", "safe"),
    ("http://secure-login-verify.attacker.com/login", "phishing"),
    ("http://paypal.attacker.com/login", "phishing"),
    ("http://github.com.attacker.com/login", "phishing"),
]
print("=== REAL-WORLD SANITY PREDICTIONS ===")
print(f"{'URL':55s} {'Expected':12s} {'Pred':8s} {'Risk':6s} {'PhishP':8s}")
print("-" * 95)
for url, expected in urls_test:
    feats = extract_features(url)
    vec = np.array([features_to_vector(feats)], dtype=np.float64)
    proba = model.predict_proba(vec)[0]
    risk_score = int(round(proba[1] * 100))
    if risk_score < 40:
        verdict = "safe"
    elif risk_score < 70:
        verdict = "suspicious"
    else:
        verdict = "phishing"
    match = "OK" if verdict == expected else "FAIL"
    print(f"{url:55s} {expected:12s} {verdict:8s} {risk_score:6d} {proba[1]:8.4f}  {match}")
print()

# Feature importance
importances = model.feature_importances_
ranked = sorted(zip(meta["feature_names"], importances), key=lambda x: -x[1])
print("=== FEATURE IMPORTANCES (all) ===")
cumulative = 0.0
for i, (name, imp) in enumerate(ranked):
    cumulative += imp
    print(f"  {i+1:2d}. {name:40s} {imp:.6f}  (cum: {cumulative:.4f})")
print()

# Top 4 cumulative
top4 = sum(imp for _, imp in ranked[:4])
print(f"Top 4 features account for {top4:.1%} of total importance")

# GitHub feature vector
print()
print("=== GITHUB FEATURE VECTOR ===")
gh_feats = extract_features("https://github.com")
for k, v in gh_feats.items():
    print(f"  {k:40s} = {v}")
