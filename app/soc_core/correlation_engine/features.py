"""Linking, clustering and generic numeric features.

LINKING. For every linking entity (user/host/ip/process/account/resource,
excluding hubs), events are sorted by time and each event links to at most
`neighbors_per_entity` earlier events inside `link_window_seconds`. Edges
are therefore bounded by O(n * entities_per_event * k), never O(n^2).
Linked events form investigation clusters (union-find).

FEATURES. One numeric row per event, suitable for tabular models. The
"reference detection" of an event is the time-nearest detection-cited event
that shares at least one actor/asset entity with it (the event itself if it
is detection-cited); pairwise features are computed against it. Found via
per-entity sorted posting lists of detection events + binary search, so this
is O(n * entities_per_event * log d).

Nothing here encodes an attack pattern.
"""

from __future__ import annotations

import math
from array import array
from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Any, Final, Sequence

from .entities import EntityIndex
from .models import LINKING_ENTITY_TYPES, CorrelationConfig, EntityType, NormalizedEvent

FEATURE_NAMES: Final[tuple[str, ...]] = (
    # event features
    "severity", "detection_match", "detection_count", "technique_count",
    "event_frequency", "rarity", "entity_count", "status_failure",
    # graph / cluster features
    "degree", "cluster_size", "cluster_density", "cluster_has_detection",
    "cluster_detection_fraction", "event_type_similarity", "source_similarity",
    # entity features (vs. the reference detection event)
    "same_user", "same_host", "same_source_ip", "same_destination_ip",
    "same_process", "same_account", "shared_detection", "shared_technique",
    # relationship features
    "number_of_shared_entities", "entity_overlap_ratio",
    # temporal features (vs. the reference detection event)
    "timestamp_distance", "within_1_minute", "within_5_minutes",
    "within_15_minutes", "within_1_hour", "temporal_proximity",
)
FEATURE_INDEX: Final[dict[str, int]] = {name: i for i, name in enumerate(FEATURE_NAMES)}

NO_REFERENCE_SECONDS: Final[float] = 7 * 24 * 3600.0     # distance used when there is no reference
_LOG_NO_REFERENCE: Final[float] = math.log1p(NO_REFERENCE_SECONDS)
_FAILURE: Final[frozenset[str]] = frozenset({"failure", "failed", "denied", "blocked", "error", "fail"})
PROXIMITY_TAU_SECONDS: Final[float] = 900.0


@dataclass
class Graph:
    """Result of linking: clusters and per-event degree."""

    cluster_of: list[int]                 # event index -> dense cluster number (ordered by first time)
    cluster_ids: list[str]                # dense cluster number -> "C00001"
    cluster_sizes: list[int]
    cluster_edges: list[int]
    degree: array
    edges: int

    def cluster_id(self, event_index: int) -> str:
        return self.cluster_ids[self.cluster_of[event_index]]


def link(events: Sequence[NormalizedEvent], index: EntityIndex, config: CorrelationConfig) -> Graph:
    n = len(events)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    degree = array("d", bytes(8 * n))
    new_edges = array("l", bytes(array("l").itemsize * n))
    window = config.link_window_seconds
    k = config.neighbors_per_entity
    epochs = [e.epoch for e in events]

    # Per entity: timestamped members in time order (ties by index). An edge
    # is an (entity, neighbor) link, so two events sharing two entities count
    # two links. Links are applied immediately; no per-event neighbor sets
    # are kept (measured: those dominated memory at 1M events).
    edges = 0
    for entity_id, posting in enumerate(index.postings):
        if len(posting) < 2 or not index.is_linking(entity_id):
            continue
        timed = sorted((epochs[i], i) for i in posting if epochs[i] is not None)
        for pos in range(1, len(timed)):
            t, i = timed[pos]
            lo = max(0, pos - k)
            for back in range(pos - 1, lo - 1, -1):
                t_prev, j = timed[back]
                if t - t_prev > window:
                    break
                degree[i] += 1
                degree[j] += 1
                new_edges[i] += 1
                edges += 1
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)

    roots = [find(i) for i in range(n)]
    first: dict[int, tuple[float, str]] = {}
    for i, root in enumerate(roots):
        key = (epochs[i] if epochs[i] is not None else math.inf, events[i].event_id)
        if root not in first or key < first[root]:
            first[root] = key
    order = sorted(first, key=lambda r: first[r])
    dense = {root: number for number, root in enumerate(order)}
    cluster_of = [dense[r] for r in roots]
    sizes = [0] * len(order)
    cluster_edges = [0] * len(order)
    for i, c in enumerate(cluster_of):
        sizes[c] += 1
        cluster_edges[c] += new_edges[i]
    width = max(5, len(str(len(order))))
    return Graph(
        cluster_of=cluster_of,
        cluster_ids=[f"C{number + 1:0{width}d}" for number in range(len(order))],
        cluster_sizes=sizes,
        cluster_edges=cluster_edges,
        degree=degree,
        edges=edges,
    )


@dataclass
class FeatureMatrix:
    """Row-major float matrix without a numpy dependency (array('d'))."""

    names: tuple[str, ...]
    rows: int
    data: array = field(repr=False)

    def row(self, i: int) -> list[float]:
        width = len(self.names)
        return list(self.data[i * width:(i + 1) * width])

    def value(self, i: int, name: str) -> float:
        return self.data[i * len(self.names) + FEATURE_INDEX[name]]

    def column(self, name: str) -> list[float]:
        width, offset = len(self.names), FEATURE_INDEX[name]
        return list(self.data[offset::width])

    def to_numpy(self) -> Any:
        """(rows, features) float64 view. numpy is imported lazily (ML only)."""
        import numpy as np

        return np.frombuffer(self.data, dtype=np.float64).reshape(self.rows, len(self.names))


def build_features(
    events: Sequence[NormalizedEvent], index: EntityIndex, graph: Graph
) -> FeatureMatrix:
    n = len(events)
    width = len(FEATURE_NAMES)
    data = array("d", bytes(8 * n * width))
    epochs = [e.epoch for e in events]

    # Frequency of (event_type, action) across the whole input.
    freq: dict[tuple[str | None, str | None], int] = {}
    for e in events:
        key = (e.event_type, e.action)
        freq[key] = freq.get(key, 0) + 1
    log_n = math.log1p(n) or 1.0

    # Cluster composition.
    n_clusters = len(graph.cluster_sizes)
    cluster_detections = [0] * n_clusters
    type_counts: dict[tuple[int, str | None], int] = {}
    source_counts: dict[tuple[int, str | None], int] = {}
    for e in events:
        c = graph.cluster_of[e.index]
        if e.has_detection:
            cluster_detections[c] += 1
        type_counts[(c, e.event_type)] = type_counts.get((c, e.event_type), 0) + 1
        source_counts[(c, e.source)] = source_counts.get((c, e.source), 0) + 1

    # Detection ("seed") posting lists per linking entity, sorted by time.
    seed_times: dict[int, list[float]] = {}
    seed_members: dict[int, list[int]] = {}
    seed_untimed: dict[int, int] = {}
    for e in sorted((e for e in events if e.has_detection), key=lambda e: (e.epoch is None, e.epoch or 0.0, e.index)):
        for entity_id in _linking(index, e.index):
            if e.epoch is None:
                seed_untimed.setdefault(entity_id, e.index)
            else:
                seed_times.setdefault(entity_id, []).append(e.epoch)
                seed_members.setdefault(entity_id, []).append(e.index)

    for e in events:
        i = e.index
        base = i * width
        row = data
        c = graph.cluster_of[i]
        size = graph.cluster_sizes[c]
        count = freq[(e.event_type, e.action)]
        detection_entities = [x for x in index.event_entities[i] if index.entities[x][0] is EntityType.DETECTION]
        technique_entities = [x for x in index.event_entities[i] if index.entities[x][0] is EntityType.TECHNIQUE]

        row[base + 0] = e.severity / 4.0
        row[base + 1] = 1.0 if e.has_detection else 0.0
        row[base + 2] = math.log1p(len(detection_entities))
        row[base + 3] = math.log1p(len(e.techniques))
        row[base + 4] = count / n
        row[base + 5] = 1.0 - math.log1p(count) / log_n
        row[base + 6] = float(len(index.event_entities[i]))
        row[base + 7] = 1.0 if (e.status or "").lower() in _FAILURE else 0.0
        row[base + 8] = math.log1p(graph.degree[i])
        row[base + 9] = math.log10(size)
        row[base + 10] = graph.cluster_edges[c] / size
        row[base + 11] = 1.0 if cluster_detections[c] else 0.0
        row[base + 12] = cluster_detections[c] / size
        row[base + 13] = type_counts[(c, e.event_type)] / size
        row[base + 14] = source_counts[(c, e.source)] / size

        reference, distance = _reference(i, e.epoch, _linking(index, i), e.has_detection,
                                         seed_times, seed_members, seed_untimed, epochs)
        if reference is not None:
            pair = pair_features(i, reference, index, None, distance)
            for name in _PAIR_TO_EVENT:
                row[base + FEATURE_INDEX[name]] = pair[name]
        else:
            row[base + FEATURE_INDEX["timestamp_distance"]] = _LOG_NO_REFERENCE
        # detection/technique shared with at least one other event
        row[base + FEATURE_INDEX["shared_detection"]] = math.log1p(
            max((len(index.postings[x]) - 1 for x in detection_entities), default=0))
        row[base + FEATURE_INDEX["shared_technique"]] = 1.0 if any(
            len(index.postings[x]) > 1 for x in technique_entities) else 0.0
    return FeatureMatrix(names=FEATURE_NAMES, rows=n, data=data)


def _linking(index: EntityIndex, i: int) -> frozenset[int]:
    """Actor/asset entities of one event (computed on demand: holding one
    frozenset per event cost hundreds of MB at 1M events)."""
    return frozenset(x for x in index.event_entities[i] if index.entities[x][0] in LINKING_ENTITY_TYPES)


_PAIR_TO_EVENT: Final[tuple[str, ...]] = (
    "same_user", "same_host", "same_source_ip", "same_destination_ip", "same_process", "same_account",
    "number_of_shared_entities", "entity_overlap_ratio", "timestamp_distance", "within_1_minute",
    "within_5_minutes", "within_15_minutes", "within_1_hour", "temporal_proximity",
)


def _reference(
    i: int, epoch: float | None, linking: frozenset[int], is_seed: bool,
    seed_times: dict[int, list[float]], seed_members: dict[int, list[int]],
    seed_untimed: dict[int, int], epochs: list[float | None],
) -> tuple[int | None, float | None]:
    """Nearest detection-cited event sharing a linking entity: (index, seconds)."""
    if is_seed:
        return i, 0.0 if epoch is not None else None
    best: tuple[float, int] | None = None
    for entity_id in linking:
        times = seed_times.get(entity_id)
        if times and epoch is not None:
            pos = bisect_left(times, epoch)
            for p in (pos - 1, pos):
                if 0 <= p < len(times):
                    candidate = (abs(times[p] - epoch), seed_members[entity_id][p])
                    if best is None or candidate < best:
                        best = candidate
        elif times and best is None:
            best = (math.inf, seed_members[entity_id][0])
        untimed = seed_untimed.get(entity_id)
        if untimed is not None and best is None:
            best = (math.inf, untimed)
    if best is None:
        return None, None
    return best[1], (None if math.isinf(best[0]) else best[0])


def pair_features(
    a: int, b: int, index: EntityIndex, linking_sets: Sequence[frozenset[int]] | None = None,
    distance: float | None = None, epochs: Sequence[float | None] | None = None,
) -> dict[str, float]:
    """Relationship features between two events (by index). Symmetric."""
    ents_a, ents_b = index.event_entities[a], index.event_entities[b]
    if linking_sets is None:
        la, lb = _linking(index, a), _linking(index, b)
    else:
        la, lb = linking_sets[a], linking_sets[b]
    if distance is None and epochs is not None and epochs[a] is not None and epochs[b] is not None:
        distance = abs(epochs[a] - epochs[b])
    shared = la & lb
    union = la | lb

    def same(kind: EntityType) -> float:
        return 1.0 if any(index.entities[x][0] is kind for x in shared) else 0.0

    all_shared = set(ents_a) & set(ents_b)
    features = {
        "same_user": same(EntityType.USER),
        "same_host": same(EntityType.HOST),
        "same_process": same(EntityType.PROCESS),
        "same_account": same(EntityType.ACCOUNT),
        "same_source_ip": 0.0,
        "same_destination_ip": 0.0,
        "shared_detection": 1.0 if any(index.entities[x][0] is EntityType.DETECTION for x in all_shared) else 0.0,
        "shared_technique": 1.0 if any(index.entities[x][0] is EntityType.TECHNIQUE for x in all_shared) else 0.0,
        "number_of_shared_entities": float(len(shared)),
        "entity_overlap_ratio": len(shared) / len(union) if union else 0.0,
    }
    features["same_source_ip"] = 1.0 if index.source_ip[a] >= 0 and index.source_ip[a] == index.source_ip[b] else 0.0
    features["same_destination_ip"] = (
        1.0 if index.destination_ip[a] >= 0 and index.destination_ip[a] == index.destination_ip[b] else 0.0
    )
    if distance is None:
        features.update({"timestamp_distance": _LOG_NO_REFERENCE, "within_1_minute": 0.0, "within_5_minutes": 0.0,
                         "within_15_minutes": 0.0, "within_1_hour": 0.0, "temporal_proximity": 0.0})
    else:
        features.update({
            "timestamp_distance": math.log1p(distance),
            "within_1_minute": 1.0 if distance <= 60 else 0.0,
            "within_5_minutes": 1.0 if distance <= 300 else 0.0,
            "within_15_minutes": 1.0 if distance <= 900 else 0.0,
            "within_1_hour": 1.0 if distance <= 3600 else 0.0,
            "temporal_proximity": math.exp(-distance / PROXIMITY_TAU_SECONDS),
        })
    return features

