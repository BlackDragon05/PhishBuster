import os
import pandas as pd

_model    = None
_features = None

_MODEL_PATH    = os.path.join(os.path.dirname(__file__), "../../ml/models/phishing_model.pkl")
_FEATURES_PATH = os.path.join(os.path.dirname(__file__), "../../ml/models/feature_names.pkl")


def _load_model():
    global _model, _features
    try:
        import joblib
        if os.path.exists(_MODEL_PATH) and os.path.exists(_FEATURES_PATH):
            _model    = joblib.load(_MODEL_PATH)
            _features = joblib.load(_FEATURES_PATH)
    except Exception:
        pass


_load_model()


def predict_phishing(features: dict) -> float:
    """Returns probability (0.0–1.0) that the URL is phishing.
    Returns 0.5 (neutral) if model is not trained yet.
    """
    if _model is None or _features is None:
        return 0.5

    try:
        row = {}
        for k in _features:
            val = features.get(k, 0)
            row[k] = float(val) if not isinstance(val, (list, dict)) else 0.0
        df   = pd.DataFrame([row])
        prob = _model.predict_proba(df)[0][1]
        return round(float(prob), 4)
    except Exception:
        return 0.5
