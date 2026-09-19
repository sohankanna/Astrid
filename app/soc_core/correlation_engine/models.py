"""Data models for the generic correlation engine.

Nothing here knows about any particular attack. Entities, features and
scores are generic; attack-specific rules and labels are added later, once
the canonical scenario is finalized.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Final, Mapping


class EntityType(str, Enum):
    USER = "USER"
    HOST = "HOST"
    IP = "IP"
    PROCESS = "PROCESS"
    ACCOUNT = "ACCOUNT"
    RESOURCE = "RESOURCE"
    DETECTION = "DETECTION"
    TECHNIQUE = "TECHNIQUE"


# Entity types used to LINK events into clusters. TECHNIQUE and rule-ID
# DETECTION entities describe events rather than identify actors/assets, so
# they only feed features. Alert-ID DETECTION entities also link (events cited
# by the same alert belong together); see EntityIndex.is_linking.
LINKING_ENTITY_TYPES: Final[frozenset[EntityType]] = frozenset(
    {EntityType.USER, EntityType.HOST, EntityType.IP, EntityType.PROCESS,
     EntityType.ACCOUNT, EntityType.RESOURCE}
)

SEVERITY_SCALE: Final[dict[str, int]] = {
    "informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


@dataclass(slots=True)
class NormalizedEvent:
    """A schema-independent view of one input event.

    `event_id` always traces back to the source event (or a generated
    `anon-nnnnnn` reference when the source had none, recorded in `issues`).
    `original` is a reference to the untouched input object: normalization
    never mutates or copies it.
    """

    index: int
    event_id: str
    timestamp: datetime | None
    event_type: str | None = None
    severity: int = 0
    source: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    username: str | None = None
    account: str | None = None
    process: str | None = None
    parent_process: str | None = None
    command: str | None = None
    action: str | None = None
    status: str | None = None
    detection_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    issues: tuple[str, ...] = ()
    original: Any = field(default=None, repr=False)

    @property
    def epoch(self) -> float | None:
        return self.timestamp.timestamp() if self.timestamp is not None else None

    @property
    def has_detection(self) -> bool:
        return bool(self.detection_ids or self.rule_ids)

    def to_dict(self) -> dict[str, Any]:
        """Normalized fields only (never `original`)."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type, "severity": self.severity, "source": self.source,
            "hostname": self.hostname, "source_ip": self.source_ip, "destination_ip": self.destination_ip,
            "source_port": self.source_port, "destination_port": self.destination_port,
            "username": self.username, "account": self.account, "process": self.process,
            "parent_process": self.parent_process, "command": self.command, "action": self.action,
            "status": self.status, "detection_ids": list(self.detection_ids), "rule_ids": list(self.rule_ids),
            "techniques": list(self.techniques), "resources": list(self.resources), "issues": list(self.issues),
        }


@dataclass(frozen=True)
class RejectedInput:
    position: int
    reason: str


@dataclass
class NormalizationReport:
    accepted: int = 0
    rejected: list[RejectedInput] = field(default_factory=list)
    issues_by_kind: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "rejected": len(self.rejected),
            "rejected_examples": [{"position": r.position, "reason": r.reason} for r in self.rejected[:20]],
            "issues_by_kind": dict(sorted(self.issues_by_kind.items())),
        }


@dataclass(frozen=True)
class RuleWeights:
    """Weights of the deterministic baseline, keyed by feature name.

    These are starting points, NOT tuned or claimed optimal. The benchmark
    exists to find out whether a trained model beats them.
    """

    weights: Mapping[str, float] = field(default_factory=lambda: dict(DEFAULT_RULE_WEIGHTS))


DEFAULT_RULE_WEIGHTS: Final[dict[str, float]] = {
    "detection_match": 3.0,
    "shared_technique": 0.5,
    "same_user": 1.0,
    "same_host": 1.0,
    "same_source_ip": 1.0,
    "same_destination_ip": 0.5,
    "same_process": 0.5,
    "same_account": 0.25,
    "number_of_shared_entities": 0.25,
    "within_5_minutes": 1.0,
    "within_1_hour": 0.5,
    "severity": 1.0,
    "rarity": 1.0,
    "cluster_has_detection": 0.5,
}


@dataclass(frozen=True)
class CorrelationConfig:
    """Every tunable of the engine. Defaults are generic, not scenario-tuned."""

    link_window_seconds: float = 3600.0      # events sharing an entity link only within this window
    neighbors_per_entity: int = 3            # k nearest earlier events per entity (bounds edges to O(n*k))
    # Optional hub filter (off by default): an entity in more than hub_fraction
    # of events AND at least hub_min_events events builds no edges. Measured
    # on the Stage 3 telemetry at 50K: frequency-based hubs removed the
    # incident's own user, workstation and external IPs from linking (busy is
    # not the same as ubiquitous), so it is opt-in. The k-nearest bound
    # already keeps edges O(n*k) without it.
    hub_fraction: float | None = None
    hub_min_events: int = 1000
    ignored_values: frozenset[str] = frozenset(
        {"-", "", "n/a", "none", "null", "unknown", "system", "0.0.0.0", "127.0.0.1", "::1"}
    )
    selection_threshold: float = 0.35        # final score needed to be selected
    max_selected: int | None = None          # optional hard cap (detection evidence may exceed it)
    keep_detection_evidence: bool = True     # never drop an event a detection cited
    model_weight: float = 0.5                # final = (1-w)*deterministic + w*model, when a model is used
    aggregate_min_group: int = 3             # evidence-object grouping for the token estimate
    rule_weights: RuleWeights = field(default_factory=RuleWeights)
    seed: int = 1337

    def __post_init__(self) -> None:
        if self.link_window_seconds <= 0:
            raise ValueError("link_window_seconds must be positive")
        if self.neighbors_per_entity < 1:
            raise ValueError("neighbors_per_entity must be >= 1")
        if self.hub_fraction is not None and not 0 < self.hub_fraction <= 1:
            raise ValueError("hub_fraction must be in (0, 1] or None")
        if not 0 <= self.selection_threshold <= 1:
            raise ValueError("selection_threshold must be in [0, 1]")
        if not 0 <= self.model_weight <= 1:
            raise ValueError("model_weight must be in [0, 1]")
        if self.max_selected is not None and self.max_selected < 0:
            raise ValueError("max_selected must be non-negative")


@dataclass(frozen=True)
class Candidate:
    """One ranked event, with an explainable score.

    `deterministic_score` and its `breakdown` come from the rule baseline;
    `model_score` is shown separately (None when no model was used).
    """

    rank: int
    event_id: str
    cluster_id: str
    final_score: float
    deterministic_score: float
    model_score: float | None
    selected: bool
    reason: str
    breakdown: Mapping[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank, "event_id": self.event_id, "cluster_id": self.cluster_id,
            "final_score": round(self.final_score, 4), "deterministic_score": round(self.deterministic_score, 4),
            "model_score": None if self.model_score is None else round(self.model_score, 4),
            "selected": self.selected, "reason": self.reason,
            "breakdown": {k: round(v, 4) for k, v in self.breakdown.items() if v},
        }
