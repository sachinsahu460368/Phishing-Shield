# Threshold & Calibration Analysis - PhishShield AI

## 1. Objective
Assess the impact of threshold tuning on `LR-Scaled-52` model performance, identify optimal operating points using two sanity benchmark datasets (15-URL and 50-URL), and analyze false-positive drivers.

## 2. Current Production Thresholds
- `THRESHOLD_SAFE` (0.0): 40
- `THRESHOLD_SUSPICIOUS` (0.7): 70
*Note: Prediction label `pred=1` treats risk_score >= 40 as Phishing/Unsafe.*

## 3. Historical 15-URL Results
(Summary from Threshold Sweep)
- Threshold 0.40 Accuracy: 73.33%
- Precision/Recall: 0.56/1.00

## 4. Formal 50-URL Results
(Summary from Threshold Sweep)
- Threshold 0.40 Accuracy: 62.00%
- Legitimate False-Positive Rate: 0.76 (19/25)
- Phishing False-Negative Rate: 0.00 (0/25)

## 5. Threshold Sweep Table (50-URL dataset subset)
| Threshold | Accuracy | Precision | Recall | F1 | Legit FP Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 0.05 | 0.50 | 0.500 | 1.0 | 0.67 | 1.00 |
| 0.40 | 0.62 | 0.568 | 1.0 | 0.72 | 0.76 |
| 0.95 | 0.64 | 0.581 | 1.0 | 0.74 | 0.72 |

## 6. Confusion Matrices (50-URL at 0.40 Threshold)
```
[[6, 19],
 [0, 25]]
```

## 7. Precision/Recall Trade-Off
The model exhibits a consistent recall of 1.0 across all tested thresholds (0.05 - 0.95), suggesting phishing samples are strongly separated in the probability space. However, precision is severely degraded by 19 false positives concentrated in high-reputation/deep-path legitimate domains.

## 8. False-Positive Analysis
All 19 FPs are legitimate high-reputation sites incorrectly classified at the 0.40 threshold. 
- Example: `https://wikipedia.org` (proba 0.44), `https://docs.github.com` (proba 1.0), `https://react.dev/reference/react` (proba 1.0).
These exhibit deep URL paths that the model currently interprets as phishing.

## 9. False-Negative Analysis
Phishing False-Negative Rate is 0.0 at all tested thresholds (0.05 - 0.95), indicating the model is overly conservative and highly sensitive.

## 10. Calibration Observations
Brier Score (50-URL): 0.3701 (poor calibration, significantly deviating from expected outcome). The model frequently assigns probability 1.0 to URLs, indicating high overconfidence.

## 11. Recommended Operating Point
Based on the current dataset, *no* threshold adjustment significantly improves accuracy/F1 while holding recall.

## 12. Threshold Tuning Sufficiency
**Threshold tuning cannot fix an underlying feature/training-distribution problem.** The model's overconfidence and misinterpretation of deep URLs as phishing require remediation via feature engineering (addressing the `num_slashes` artifact) or training data refinement to include more legitimate high-complexity/deep-path URL examples.
