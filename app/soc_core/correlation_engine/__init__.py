"""Generic correlation and evidence-ranking engine (Stage 3.5 foundation).

Sits before the EvidenceContext Engine and decides which events are related,
which clusters they form, which entities connect them, and which are worth
preserving for downstream investigation. Offline, deterministic, and free of
attack-specific logic: canonical scenario rules and labels are added later.

Named `correlation_engine` because `app.soc_core.correlation` is the existing
Stage 1 alert-to-incident correlator, which this package does not replace.
"""

from .engine import CorrelationEngine, CorrelationResult
from .evaluation import NA, Evaluation, GroundTruth, GroundTruthLabel, evaluate
from .features import FEATURE_NAMES, FeatureMatrix, pair_features
from .models import (
    Candidate,
    CorrelationConfig,
    EntityType,
    NormalizedEvent,
    RuleWeights,
)
from .strategies import (
    CorrelationStrategy,
    DecisionTreeCorrelation,
    LightGBMCorrelation,
    LogisticRegressionCorrelation,
    NotTrainedError,
    RandomForestCorrelation,
    RuleBasedCorrelation,
    StrategyUnavailableError,
    default_strategies,
)

__all__ = [
    "NA", "FEATURE_NAMES", "Candidate", "CorrelationConfig", "CorrelationEngine", "CorrelationResult",
    "CorrelationStrategy", "DecisionTreeCorrelation", "EntityType", "Evaluation", "FeatureMatrix",
    "GroundTruth", "GroundTruthLabel", "LightGBMCorrelation", "LogisticRegressionCorrelation",
    "NormalizedEvent", "NotTrainedError", "RandomForestCorrelation", "RuleBasedCorrelation", "RuleWeights",
    "StrategyUnavailableError", "default_strategies", "evaluate", "pair_features",
]
