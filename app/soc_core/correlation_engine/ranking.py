"""Ranking, selection, evidence grouping and downstream token estimate.

final_score = (1 - model_weight) * deterministic_score + model_weight * model_score
(deterministic_score only, when no trained model is used). Both parts are
kept on every candidate so the score stays explainable.

Selection: final_score >= threshold, optionally capped at max_selected by
rank; events cited by a detection are always kept when
keep_detection_evidence is set (a cap never drops them).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from ..evidence_context import canonical_json, estimate_tokens
from .features import FeatureMatrix, Graph
from .models import Candidate, CorrelationConfig, NormalizedEvent
from .strategies import RuleBasedCorrelation


@dataclass(frozen=True)
class Ranking:
    order: list[int]                     # event indices, best first (deterministic tie-break)
    final: list[float]
    deterministic: list[float]
    model: list[float] | None
    selected: frozenset[int]
    reasons: dict[int, str]


def rank(
    events: Sequence[NormalizedEvent],
    features: FeatureMatrix,
    deterministic: list[float],
    model: list[float] | None,
    config: CorrelationConfig,
) -> Ranking:
    if model is not None and len(model) != len(deterministic):
        raise ValueError("model scores must align with events")
    w = config.model_weight if model is not None else 0.0
    final = [(1 - w) * d + w * m for d, m in zip(deterministic, model)] if model is not None else list(deterministic)
    order = sorted(range(len(events)), key=lambda i: (-final[i], events[i].epoch is None,
                                                      events[i].epoch or 0.0, events[i].event_id, i))
    selected: set[int] = set()
    reasons: dict[int, str] = {}
    for i in order:
        if final[i] < config.selection_threshold:
            break
        if config.max_selected is not None and len(selected) >= config.max_selected:
            break
        selected.add(i)
        reasons[i] = "score>=threshold"
    if config.keep_detection_evidence:
        for e in events:
            if e.has_detection and e.index not in selected:
                selected.add(e.index)
                reasons[e.index] = "detection evidence (always kept)"
    return Ranking(order=order, final=final, deterministic=deterministic, model=model,
                   selected=frozenset(selected), reasons=reasons)


def candidates(
    events: Sequence[NormalizedEvent],
    features: FeatureMatrix,
    graph: Graph,
    ranking: Ranking,
    rule: RuleBasedCorrelation,
    limit: int | None = None,
    selected_only: bool = False,
) -> list[Candidate]:
    """Explainable candidates in rank order (breakdowns computed on demand)."""
    out: list[Candidate] = []
    for position, i in enumerate(ranking.order, start=1):
        if selected_only and i not in ranking.selected:
            continue
        out.append(Candidate(
            rank=position,
            event_id=events[i].event_id,
            cluster_id=graph.cluster_id(i),
            final_score=ranking.final[i],
            deterministic_score=ranking.deterministic[i],
            model_score=None if ranking.model is None else ranking.model[i],
            selected=i in ranking.selected,
            reason=ranking.reasons.get(i, "below threshold"),
            breakdown=rule.contributions(features, i),
        ))
        if limit is not None and len(out) >= limit:
            break
    return out


def evidence_objects(
    events: Sequence[NormalizedEvent], selected: frozenset[int], graph: Graph, config: CorrelationConfig,
) -> list[dict[str, Any]]:
    """Group selected events the way a downstream context would present them:
    same (cluster, type, action, status, host) collapse into one object once
    the group reaches `aggregate_min_group`. Users are listed inside the
    aggregate rather than keyed on, so a burst across many accounts collapses."""
    groups: dict[tuple, list[int]] = {}
    for i in sorted(selected, key=lambda i: (events[i].epoch is None, events[i].epoch or 0.0, events[i].event_id)):
        e = events[i]
        key = (graph.cluster_id(i), e.event_type, e.action, e.status, e.hostname)
        groups.setdefault(key, []).append(i)
    objects: list[dict[str, Any]] = []
    for key, members in groups.items():
        if len(members) >= config.aggregate_min_group:
            objects.append(_aggregate(key, members, events))
        else:
            objects.extend(_single(events[i], key[0]) for i in members)
    return objects


def _single(e: NormalizedEvent, cluster: str) -> dict[str, Any]:
    fields = {k: v for k, v in e.to_dict().items() if v not in (None, [], ()) and k != "issues"}
    return {"kind": "event", "cluster": cluster, **fields}


def _aggregate(key: tuple, members: list[int], events: Sequence[NormalizedEvent]) -> dict[str, Any]:
    cluster, event_type, action, status, host = key
    sample = [events[i] for i in members]
    times = [e.timestamp for e in sample if e.timestamp]
    distinct = lambda attr: sorted({getattr(e, attr) for e in sample if getattr(e, attr)})[:10]  # noqa: E731
    return {
        "kind": "aggregate", "cluster": cluster, "count": len(members), "event_type": event_type,
        "action": action, "status": status, "hostname": host,
        "distinct_usernames": len({e.username for e in sample if e.username}), "usernames": distinct("username"),
        "first_seen": min(times).isoformat() if times else None,
        "last_seen": max(times).isoformat() if times else None,
        "source_ips": distinct("source_ip"), "destination_ips": distinct("destination_ip"),
        "rule_ids": sorted({r for e in sample for r in e.rule_ids}),
        "techniques": sorted({t for e in sample for t in e.techniques}),
        "representative_event_ids": [e.event_id for e in sample[:5]],
    }


def estimate_context_tokens(objects: list[dict[str, Any]]) -> int:
    """Same deterministic estimator as the EvidenceContext (chars / 3.5) over
    the canonical JSON of the selected evidence objects. This estimates the
    candidate payload handed downstream, not the final EvidenceContext pack."""
    return estimate_tokens(canonical_json(objects)) if objects else 0
