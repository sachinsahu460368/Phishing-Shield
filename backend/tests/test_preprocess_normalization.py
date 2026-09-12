import pandas as pd
import pytest
from ml.preprocess import _normalize_labels

def test_normalize_labels_numeric_no_invert():
    s = pd.Series([0, 1, 0, 1])
    normalized = _normalize_labels(s, invert=False)
    assert normalized.tolist() == [0, 1, 0, 1]

def test_normalize_labels_numeric_invert():
    s = pd.Series([0, 1, 0, 1])
    normalized = _normalize_labels(s, invert=True)
    assert normalized.tolist() == [1, 0, 1, 0]

def test_normalize_labels_strings():
    s = pd.Series(["legitimate", "phishing", "good", "bad"])
    normalized = _normalize_labels(s)
    assert normalized.tolist() == [0, 1, 0, 1]
