"""CorrelationEngine: the stable public interface.

    events -> normalize -> extract entities -> correlate (link + cluster)
           -> build features -> rank (rule baseline [+ trained model])
           -> candidates / evidence objects / token estimate -> evaluate

Offline and deterministic: identical input, configuration and seed give
identical output. No network access, no model provider, no attack-specific
logic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Iterable, Mapping, Sequence

from ..detections import DetectionResult
from .entities import EntityIndex
from .evaluation import Evaluation, GroundTruth, evaluate
from .features import FeatureMatrix, Graph, build_features, link
from .models import Candidate, CorrelationConfig, NormalizationReport, NormalizedEvent
from .normalization import normalize_events
from .ranking import Ranking, candidates, estimate_context_tokens, evidence_objects, rank
from .strategies import CorrelationStrategy, RuleBasedCorrelation


@dataclass
class CorrelationResult:
    events: list[NormalizedEvent]
    report: NormalizationReport
    index: EntityIndex
    graph: Graph
    features: FeatureMatrix
    ranking: Ranking
    rule: RuleBasedCorrelation
    strategy: str
    config: CorrelationConfig
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def selected_event_ids(self) -> list[str]:
        """Selected events in rank order: what the EvidenceContext stage would receive."""
        return [self.events[i].event_id for i in self.ranking.order if i in self.ranking.selected]

    @property
    def correlated_event_count(self) -> int:
        """Events linked to at least one other event inside a cluster that
        contains detection evidence."""
        with_detection = {self.graph.cluster_of[e.index] for e in self.events if e.has_detection}
        return sum(1 for e in self.events
                   if self.graph.cluster_of[e.index] in with_detection and self.graph.degree[e.index] > 0)

    @cached_property
    def evidence_objects(self) -> list[dict[str, Any]]:
        return evidence_objects(self.events, self.ranking.selected, self.graph, self.config)

    @cached_property
    def estimated_context_tokens(self) -> int:
        return estimate_context_tokens(self.evidence_objects)

    def candidates(self, limit: int | None = 50, selected_only: bool = False) -> list[Candidate]:
        return candidates(self.events, self.features, self.graph, self.ranking, self.rule, limit, selected_only)

    def evaluate(self, truth: GroundTruth | None) -> Evaluation:
        return evaluate(self.selected_event_ids, (e.event_id for e in self.events), truth)

    def summary(self, truth: GroundTruth | None = None) -> dict[str, Any]:
        """Integration contract for the Efficiency Lab ("OUR ENGINE" path)."""
        raw = len(self.events)
        selected = len(self.ranking.selected)
        evaluation = self.evaluate(truth)
        return {
            "strategy": self.strategy,
            "raw_events": raw,
            "rejected_inputs": len(self.report.rejected),
            "correlated_events": self.correlated_event_count,
            "clusters": len(self.graph.cluster_sizes),
            "clusters_with_detection": len({self.graph.cluster_of[e.index] for e in self.events if e.has_detection}),
            "edges": self.graph.edges,
            "selected_events": selected,
            "evidence_objects": len(self.evidence_objects),
            "estimated_context_tokens": self.estimated_context_tokens,
            "token_estimator": "ceil(chars/3.5) over canonical JSON of selected evidence objects",
            "reduction_ratio": round(1 - selected / raw, 6) if raw else None,
            "critical_evidence_recall": evaluation.to_dict()["critical_evidence_recall"],
            "evaluation": evaluation.to_dict(),
            "timings_ms": {k: round(v, 1) for k, v in self.timings_ms.items()},
        }


class CorrelationEngine:
    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()
        self.rule = RuleBasedCorrelation(self.config.rule_weights)

    # -- stages ---------------------------------------------------------------

    def normalize_events(
        self, events: Iterable[Any], detections: Iterable[DetectionResult | Mapping[str, Any]] = ()
    ) -> tuple[list[NormalizedEvent], NormalizationReport]:
        return normalize_events(events, detections=detections)

    def extract_entities(self, events: Sequence[NormalizedEvent]) -> EntityIndex:
        return EntityIndex.build(events, self.config)

    def correlate(self, events: Sequence[NormalizedEvent], index: EntityIndex) -> Graph:
        return link(events, index, self.config)

    def build_features(self, events: Sequence[NormalizedEvent], index: EntityIndex, graph: Graph) -> FeatureMatrix:
        return build_features(events, index, graph)

    def rank(
        self, events: Sequence[NormalizedEvent], features: FeatureMatrix,
        strategy: CorrelationStrategy | None = None,
    ) -> Ranking:
        deterministic = self.rule.score(features)
        model = None
        if strategy is not None and not isinstance(strategy, RuleBasedCorrelation):
            model = strategy.score(features)        # raises NotTrainedError if untrained
        elif isinstance(strategy, RuleBasedCorrelation) and strategy is not self.rule:
            deterministic = strategy.score(features)
        return rank(events, features, deterministic, model, self.config)

    # -- whole pipeline -----------------------------------------------------------

    def prepare(
        self, events: Iterable[Any], detections: Iterable[DetectionResult | Mapping[str, Any]] = ()
    ) -> tuple[list[NormalizedEvent], NormalizationReport, EntityIndex, Graph, FeatureMatrix, dict[str, float]]:
        """Everything up to (not including) scoring. Reusable across strategies."""
        timings: dict[str, float] = {}
        t = time.perf_counter()
        normalized, report = self.normalize_events(events, detections)
        timings["normalize"] = _since(t)
        t = time.perf_counter()
        index = self.extract_entities(normalized)
        timings["entities"] = _since(t)
        t = time.perf_counter()
        graph = self.correlate(normalized, index)
        timings["correlate"] = _since(t)
        t = time.perf_counter()
        features = self.build_features(normalized, index, graph)
        timings["features"] = _since(t)
        return normalized, report, index, graph, features, timings

    def score_prepared(
        self, prepared: tuple[list[NormalizedEvent], NormalizationReport, EntityIndex, Graph, FeatureMatrix,
                              dict[str, float]],
        strategy: CorrelationStrategy | None = None,
    ) -> CorrelationResult:
        normalized, report, index, graph, features, timings = prepared
        t = time.perf_counter()
        ranking = self.rank(normalized, features, strategy)
        timings = {**timings, "rank": _since(t)}
        return CorrelationResult(
            events=normalized, report=report, index=index, graph=graph, features=features, ranking=ranking,
            rule=self.rule, strategy=strategy.name if strategy is not None else self.rule.name,
            config=self.config, timings_ms=timings,
        )

    def run(
        self, events: Iterable[Any], detections: Iterable[DetectionResult | Mapping[str, Any]] = (),
        strategy: CorrelationStrategy | None = None,
    ) -> CorrelationResult:
        return self.score_prepared(self.prepare(events, detections), strategy)

    def produce_candidates(self, result: CorrelationResult, limit: int | None = 50) -> list[Candidate]:
        return result.candidates(limit)

    def evaluate(self, result: CorrelationResult, truth: GroundTruth | None) -> Evaluation:
        return result.evaluate(truth)

    # -- training ---------------------------------------------------------------

    @staticmethod
    def labels_for(events: Sequence[NormalizedEvent], truth: GroundTruth) -> list[int]:
        """Binary relevance labels (1 = is_attack_related) aligned to rows."""
        return [1 if truth.is_positive(e.event_id) else 0 for e in events]

    def fit(self, strategy: CorrelationStrategy, result: CorrelationResult, truth: GroundTruth) -> CorrelationStrategy:
        return strategy.fit(result.features, self.labels_for(result.events, truth))


def _since(start: float) -> float:
    return (time.perf_counter() - start) * 1000
