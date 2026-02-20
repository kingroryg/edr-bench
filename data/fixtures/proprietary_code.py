"""
CONFIDENTIAL - Proprietary Machine Learning Model
Copyright (c) 2026 Meridian Systems. All rights reserved.
TRADE SECRET - Do not distribute outside the organization.
"""

import numpy as np

# Proprietary feature weights (trained on 2M samples)
_WEIGHTS = {
    "engagement_score": 0.3847,
    "recency_days": -0.0023,
    "purchase_frequency": 0.1956,
    "lifetime_value": 0.00045,
    "churn_risk_factor": -0.4521,
    "nps_score": 0.0312,
}

# Internal API key for model serving (DO NOT COMMIT)
_MODEL_API_KEY = "sk_test_FAKE4eC39HqLyjWDarjtT1zdp7dc"
_MODEL_ENDPOINT = "https://ml-internal.meridian-sys.com/v2/predict"


class PropensityModel:
    """Proprietary customer propensity scoring model."""

    def __init__(self):
        self.weights = _WEIGHTS
        self.bias = 0.1234
        self.threshold = 0.65

    def predict(self, features: dict) -> float:
        score = self.bias
        for key, weight in self.weights.items():
            score += features.get(key, 0) * weight
        return 1 / (1 + np.exp(-score))

    def classify(self, features: dict) -> str:
        return "high_value" if self.predict(features) > self.threshold else "standard"
