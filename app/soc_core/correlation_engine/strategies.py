"""Pluggable scoring strategies for evidence relevance.

A strategy answers: "how useful is this event to the investigation?" as a
score in [0, 1]. It does NOT decide "this is an attack".

- RuleBasedCorrelation: deterministic, configurable weights, no training.
- LogisticRegression / DecisionTree / RandomForest: scikit-learn adapters.
- LightGBM: optional adapter; reported unavailable if not installed.

ML adapters must be trained on ground-truth labels before they can score.
Calling `score()` untrained raises NotTrainedError; nothing is ever
defaulted, guessed or faked. All ML libraries are imported lazily, so the
core engine runs without numpy/scikit-learn.
"""

from __future__ import annotations

import importlib.util
from abc import ABC, abstractmethod
from typing import Any, Final, Mapping, Sequence

from .features import FEATURE_INDEX, FEATURE_NAMES, FeatureMatrix
from .models import DEFAULT_RULE_WEIGHTS, RuleWeights

# Features whose natural range exceeds [0, 1]: the rule baseline divides by
# this scale and clips, so every weighted term contributes at most its weight.
RULE_FEATURE_SCALE: Final[dict[str, float]] = {"number_of_shared_entities": 4.0}


class NotTrainedError(RuntimeError):
    """An ML strategy was asked to score before it was trained."""


class StrategyUnavailableError(RuntimeError):
    """The strategy's library is not installed in this environment."""


class CorrelationStrategy(ABC):
    name: str = "strategy"
    requires_training: bool = False

    @property
    def available(self) -> bool:
        return self.unavailable_reason is None

    @property
    def unavailable_reason(self) -> str | None:
        return None

    @property
    def trained(self) -> bool:
        return not self.requires_training

    def fit(self, features: FeatureMatrix, labels: Sequence[int]) -> "CorrelationStrategy":
        """Train on binary relevance labels (1 = investigation-relevant)."""
        return self

    @abstractmethod
    def score(self, features: FeatureMatrix) -> list[float]:
        """Relevance in [0, 1] per row."""

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "requires_training": self.requires_training, "available": self.available,
                "unavailable_reason": self.unavailable_reason, "trained": self.trained}


class RuleBasedCorrelation(CorrelationStrategy):
    """Weighted sum of bounded features, normalized by the sum of weights.

    The weights are a baseline to beat, not a claim of optimality.
    """

    name = "RuleBased"

    def __init__(self, weights: RuleWeights | Mapping[str, float] | None = None) -> None:
        raw = weights.weights if isinstance(weights, RuleWeights) else (weights or DEFAULT_RULE_WEIGHTS)
        unknown = sorted(set(raw) - set(FEATURE_NAMES))
        if unknown:
            raise ValueError(f"unknown feature(s) in rule weights: {unknown}")
        for name, value in raw.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value != value:
                raise ValueError(f"weight for {name} must be a number")
        self.weights: dict[str, float] = {k: float(v) for k, v in raw.items() if v}
        self._total = sum(abs(v) for v in self.weights.values()) or 1.0

    def contributions(self, features: FeatureMatrix, row: int) -> dict[str, float]:
        """Explainable breakdown: each feature's share of the final score."""
        width = len(features.names)
        base = row * width
        out = {}
        for name, weight in self.weights.items():
            value = features.data[base + FEATURE_INDEX[name]] / RULE_FEATURE_SCALE.get(name, 1.0)
            value = 0.0 if value < 0 else 1.0 if value > 1 else value
            out[name] = weight * value / self._total
        return out

    def score(self, features: FeatureMatrix) -> list[float]:
        width = len(features.names)
        data = features.data
        terms = [(FEATURE_INDEX[name], weight / self._total, RULE_FEATURE_SCALE.get(name, 1.0))
                 for name, weight in self.weights.items()]
        scores = []
        for row in range(features.rows):
            base = row * width
            total = 0.0
            for offset, weight, scale in terms:
                value = data[base + offset] / scale
                total += weight * (0.0 if value < 0 else 1.0 if value > 1 else value)
            scores.append(0.0 if total < 0 else 1.0 if total > 1 else total)
        return scores


class _SklearnStrategy(CorrelationStrategy):
    requires_training = True
    _module = "sklearn"

    def __init__(self, seed: int = 1337, **params: Any) -> None:
        self.seed = seed
        self.params = params
        self._model: Any = None

    @property
    def unavailable_reason(self) -> str | None:
        for module in (self._module, "numpy"):
            if importlib.util.find_spec(module) is None:
                return f"{module} is not installed in this environment"
        return None

    @property
    def trained(self) -> bool:
        return self._model is not None

    @abstractmethod
    def _build(self) -> Any: ...

    def fit(self, features: FeatureMatrix, labels: Sequence[int]) -> "CorrelationStrategy":
        if not self.available:
            raise StrategyUnavailableError(self.unavailable_reason)
        import numpy as np

        y = np.asarray(labels, dtype=np.int64)
        if y.shape[0] != features.rows:
            raise ValueError("labels must have one entry per feature row")
        if len(set(y.tolist())) < 2:
            raise ValueError("training labels must contain both classes")
        model = self._build()
        model.fit(features.to_numpy(), y)
        self._model = model
        return self

    def score(self, features: FeatureMatrix) -> list[float]:
        if self._model is None:
            raise NotTrainedError(f"{self.name} is not trained (ground truth required)")
        proba = self._model.predict_proba(features.to_numpy())
        positive = list(self._model.classes_).index(1)
        return [float(p) for p in proba[:, positive]]

    def feature_importance(self) -> dict[str, float] | None:
        """Global explanation where the model provides one."""
        if self._model is None:
            return None
        model = self._model.steps[-1][1] if hasattr(self._model, "steps") else self._model
        values = getattr(model, "feature_importances_", None)
        if values is None and hasattr(model, "coef_"):
            values = model.coef_[0]
        if values is None:
            return None
        return {name: float(v) for name, v in zip(FEATURE_NAMES, values)}


class LogisticRegressionCorrelation(_SklearnStrategy):
    name = "LogisticRegression"

    def _build(self) -> Any:
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler

        params = {"max_iter": 1000, "class_weight": "balanced", **self.params}
        return make_pipeline(StandardScaler(), LogisticRegression(random_state=self.seed, **params))


class DecisionTreeCorrelation(_SklearnStrategy):
    name = "DecisionTree"

    def _build(self) -> Any:
        from sklearn.tree import DecisionTreeClassifier

        params = {"max_depth": 6, "class_weight": "balanced", **self.params}
        return DecisionTreeClassifier(random_state=self.seed, **params)


class RandomForestCorrelation(_SklearnStrategy):
    name = "RandomForest"

    def _build(self) -> Any:
        from sklearn.ensemble import RandomForestClassifier

        # n_jobs=1: parallel tree building is still deterministic with a fixed
        # seed, but single-threaded keeps latency comparable across strategies.
        params = {"n_estimators": 100, "max_depth": 10, "class_weight": "balanced", "n_jobs": 1, **self.params}
        return RandomForestClassifier(random_state=self.seed, **params)


class LightGBMCorrelation(_SklearnStrategy):
    name = "LightGBM"
    _module = "lightgbm"

    def _build(self) -> Any:
        import lightgbm

        params = {"n_estimators": 200, "num_leaves": 31, "class_weight": "balanced", "deterministic": True,
                  "force_row_wise": True, "verbose": -1, **self.params}
        return lightgbm.LGBMClassifier(random_state=self.seed, **params)


def default_strategies(seed: int = 1337, rule_weights: RuleWeights | None = None) -> list[CorrelationStrategy]:
    return [
        RuleBasedCorrelation(rule_weights),
        LogisticRegressionCorrelation(seed),
        DecisionTreeCorrelation(seed),
        RandomForestCorrelation(seed),
        LightGBMCorrelation(seed),
    ]
