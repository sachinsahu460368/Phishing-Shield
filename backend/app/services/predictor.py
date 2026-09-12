"""Prediction service — loads the ML model and makes predictions."""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.pipeline import Pipeline

from app.config import MODEL_PATH, METADATA_PATH, THRESHOLD_SAFE, THRESHOLD_SUSPICIOUS
from app.services.url_features import extract_features, features_to_vector, features_for_display, FEATURE_NAMES
from app.services.explainer import generate_reasons

logger = logging.getLogger(__name__)


class Predictor:
    """Loads a trained model once and serves predictions."""

    def __init__(self) -> None:
        self.model = None
        self.metadata: dict = {}
        self.model_version: str = "unknown"
        self._loaded = False
        self._removed_indices: list[int] = []

    # ── lifecycle ────────────────────────────────────────────────────────
    def load(self) -> bool:
        """Attempt to load model and metadata from disk. Returns True on success."""
        if not Path(MODEL_PATH).exists():
            logger.warning("Model file not found at %s", MODEL_PATH)
            return False
        try:
            self.model = joblib.load(MODEL_PATH)

            # If the model is an sklearn Pipeline, ensure it's loaded as such.
            # joblib handles this automatically; we just log it.
            logger.info("Model pipeline loaded from %s", MODEL_PATH)
        except Exception:
            logger.exception("Failed to load model")
            return False

        if Path(METADATA_PATH).exists():
            try:
                self.metadata = json.loads(METADATA_PATH.read_text())
                self.model_version = self.metadata.get("model_version", "unknown")

                # Determine which features were removed at training time
                removed = self.metadata.get("removed_features", [])
                self._removed_indices = [
                    i for i, name in enumerate(FEATURE_NAMES) if name in removed
                ]
                if self._removed_indices:
                    logger.info(
                        "Model was trained without features: %s (indices %s)",
                        removed, self._removed_indices,
                    )
            except Exception:
                logger.warning("Could not read metadata; using defaults")

        self._loaded = True
        return True

    @property
    def is_ready(self) -> bool:
        return self._loaded and self.model is not None

    # ── prediction ──────────────────────────────────────────────────────
    def predict(self, url: str) -> dict:
        """Run full prediction pipeline and return a response dict."""
        start = time.perf_counter()

        # 1. Feature extraction
        features = extract_features(url)
        vector = features_to_vector(features)
        arr = np.array([vector])

        # Remove features that were excluded during training
        if self._removed_indices:
            mask = np.ones(arr.shape[1], dtype=bool)
            mask[self._removed_indices] = False
            arr = arr[:, mask]

        # 2. Model inference
        # The pipeline handles scaling internally
        proba = self.model.predict_proba(arr)[0]
        # proba is [p_legitimate, p_phishing]
        phishing_prob = float(proba[1]) if len(proba) == 2 else float(proba[0])

        # 3. Risk score
        risk_score = int(round(max(0.0, min(1.0, phishing_prob)) * 100))

        # 4. Verdict
        if risk_score < THRESHOLD_SAFE:
            verdict = "safe"
        elif risk_score < THRESHOLD_SUSPICIOUS:
            verdict = "suspicious"
        else:
            verdict = "phishing"

        # 5. Confidence — probability of the chosen class
        confidence = round(max(phishing_prob, 1 - phishing_prob), 4)

        # 6. Explainability
        top_reasons = generate_reasons(features, risk_score)

        # 7. Display features
        display_features = features_for_display(features)

        elapsed_ms = int((time.perf_counter() - start) * 1000)

        return {
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "top_reasons": top_reasons,
            "features": display_features,
            "processing_time_ms": elapsed_ms,
            "model_version": self.model_version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Module-level singleton
predictor = Predictor()
