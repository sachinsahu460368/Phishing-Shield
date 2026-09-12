"""Feature extraction for the ML pipeline.

Re-exports the canonical feature engine so training and inference use
exactly the same code path.
"""

from app.services.url_features import (
    FEATURE_NAMES,
    SUSPICIOUS_KEYWORDS,
    extract_features,
    features_to_vector,
)

__all__ = ["FEATURE_NAMES", "SUSPICIOUS_KEYWORDS", "extract_features", "features_to_vector"]
