"""Model evaluation utilities."""

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray, label: str = "Model") -> dict:
    """Evaluate a model and print + return metrics."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_proba) if y_proba is not None else None
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n{'─'*50}")
    print(f"  {label}")
    print(f"{'─'*50}")
    print(f"  Accuracy:   {acc*100:.2f}%")
    print(f"  Precision:  {prec*100:.2f}%")
    print(f"  Recall:     {rec*100:.2f}%")
    print(f"  F1-score:   {f1*100:.2f}%")
    if auc is not None:
        print(f"  ROC-AUC:    {auc*100:.2f}%")
    print(f"\n  Confusion matrix:")
    print(f"    {cm}")
    print(f"{'─'*50}")

    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    print(f"\n{report}")

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4) if auc is not None else None,
        "confusion_matrix": cm.tolist(),
    }
