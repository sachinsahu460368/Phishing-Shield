"""Data preprocessing — loading, cleaning, feature extraction."""

import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Add project root to sys.path so `app.*` imports work when run as a script
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ml.features import FEATURE_NAMES, extract_features, features_to_vector

logger = logging.getLogger(__name__)


def load_dataset(path: str | Path) -> pd.DataFrame:
    """Load a CSV dataset with at least 'url' and 'label' columns.

    Supports common label schemes:
      - 0/1 integers (0=legitimate, 1=phishing)
      - 'legitimate'/'phishing' strings
      - 'good'/'bad' strings
      - 'benign'/'phishing' strings

    Returns a DataFrame with columns ['url', 'label'] where label is 0 or 1.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    df = pd.read_csv(path, low_memory=False)
    logger.info("Raw dataset: %d rows, columns=%s", len(df), list(df.columns))

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]

    # Identify URL column
    url_col = None
    for candidate in ("url", "urls", "uri", "link"):
        if candidate in df.columns:
            url_col = candidate
            break
    if url_col is None:
        raise ValueError(f"No URL column found.  Columns: {list(df.columns)}")

    # Identify label column
    label_col = None
    for candidate in ("label", "labels", "type", "class", "status", "phishing"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError(f"No label column found.  Columns: {list(df.columns)}")

    df = df[[url_col, label_col]].rename(columns={url_col: "url", label_col: "label"})

    # Map labels to 0/1
    df["label"] = _normalize_labels(df["label"])

    return df


def _normalize_labels(series: pd.Series) -> pd.Series:
    """Map a variety of label formats to 0 (legitimate) / 1 (phishing)."""
    # Already numeric?
    if pd.api.types.is_numeric_dtype(series):
        return series.astype(int)

    mapping = {
        "legitimate": 0, "benign": 0, "good": 0, "safe": 0, "0": 0, "legal": 0,
        "phishing": 1, "bad": 1, "malicious": 1, "1": 1, "phish": 1, "suspicious": 1,
    }
    mapped = series.astype(str).str.strip().str.lower().map(mapping)
    unmapped = mapped.isna().sum()
    if unmapped > 0:
        logger.warning("%d rows have unmapped labels — dropping them", unmapped)
        mapped = mapped.dropna()
    return mapped.astype(int)


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Remove nulls, duplicates, and invalid URLs."""
    before = len(df)
    df = df.dropna(subset=["url", "label"])
    df = df[df["url"].str.strip().str.len() > 0]
    df = df.drop_duplicates(subset=["url"])
    after = len(df)
    logger.info("Cleaned %d → %d rows (dropped %d)", before, after, before - after)
    return df.reset_index(drop=True)


def extract_feature_matrix(urls: pd.Series) -> np.ndarray:
    """Extract features for every URL and return an (N, F) numpy array."""
    vectors = []
    for url in urls:
        try:
            feats = extract_features(url)
            vectors.append(features_to_vector(feats))
        except Exception:
            # Fallback: zeros
            vectors.append([0] * len(FEATURE_NAMES))
    return np.array(vectors, dtype=np.float64)


def print_stats(df: pd.DataFrame) -> None:
    """Print dataset class distribution stats."""
    total = len(df)
    legit = (df["label"] == 0).sum()
    phish = (df["label"] == 1).sum()
    ratio = phish / max(legit, 1)
    print(f"\n{'='*50}")
    print(f"  Dataset statistics")
    print(f"{'='*50}")
    print(f"  Total samples:      {total:,}")
    print(f"  Legitimate (0):     {legit:,}")
    print(f"  Phishing   (1):     {phish:,}")
    print(f"  Phishing ratio:     {ratio:.2f}")
    print(f"{'='*50}\n")
