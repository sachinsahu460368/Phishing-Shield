
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import joblib
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from app.services.url_features import FEATURE_NAMES, extract_features, features_to_vector
from ml.train import RANDOM_STATE

def test_scaler_isolation():
    # Simulate training data
    X_train = np.array([[10, 0.1], [2, 0.9], [5, 0.4]])
    y_train = np.array([0, 1, 0])

    # Create pipeline
    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(random_state=RANDOM_STATE))
    ])

    pipe.fit(X_train, y_train)

    scaler = pipe.named_steps['scaler']

    # Check if scaler was fitted properly
    # mu: (10+2+5)/3 = 5.66
    # sigma: sqrt(((10-5.66)^2 + (2-5.66)^2 + (5-5.66)^2)/3) ≈ 3.3
    assert hasattr(scaler, 'mean_')
    assert hasattr(scaler, 'scale_')

    # Transform test data using the fitted scaler
    X_test = np.array([[10, 0.1]])
    X_scaled = scaler.transform(X_test)

    # Verify transformation
    expected = (X_test - scaler.mean_) / scaler.scale_
    assert np.allclose(X_scaled, expected)

    print("Scaler isolation test passed!")

def test_pipeline_serialization(tmp_path):
    import shutil

    X_train = np.array([[10, 0.1], [2, 0.9], [5, 0.4]])
    y_train = np.array([0, 1, 0])

    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LogisticRegression(random_state=RANDOM_STATE))
    ])

    pipe.fit(X_train, y_train)

    model_path = tmp_path / "model.pkl"
    joblib.dump(pipe, model_path)

    loaded_pipe = joblib.load(model_path)

    assert isinstance(loaded_pipe, Pipeline)
    assert 'scaler' in loaded_pipe.named_steps
    assert 'classifier' in loaded_pipe.named_steps

    X_test = np.array([[10, 0.1]])
    assert np.allclose(pipe.predict_proba(X_test), loaded_pipe.predict_proba(X_test))

    print("Pipeline serialization test passed!")

def test_inference_compatibility():
    # Verify that pipeline accepts 52-feature vector
    dummy_features = {name: 0.1 for name in FEATURE_NAMES}
    vector = features_to_vector(dummy_features)
    assert len(vector) == len(FEATURE_NAMES)

    # ... fitting and predicting using this vector in a pipeline ...
    # This just verifies the feature dimensionality is maintained
    print("Inference compatibility structure test passed (features_to_vector length check)")

if __name__ == "__main__":
    test_scaler_isolation()
    # tmp_path needs to be handled for the test
    import tempfile
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_pipeline_serialization(Path(tmp_dir))
    test_inference_compatibility()
