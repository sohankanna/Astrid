"""Ground truth and evaluation.

No ground truth ships with this module. Labels for the canonical attack
scenario are added after that scenario is finalized. Until then every
quality metric is reported as N/A, never estimated.

Label schema (one record per labelled event):
    {"event_id": "...", "is_attack_related": true, "attack_stage": "...", "critical": true}

Events without a label are treated as not attack-related (the usual
convention for sparse labelling); `unlabelled_policy` makes that explicit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Iterable, Mapping

NA: Final[str] = "N/A — ground truth unavailable"
MAX_LABELS: Final[int] = 5_000_000


@dataclass(frozen=True)
class GroundTruthLabel:
    event_id: str
    is_attack_related: bool
    attack_stage: str | None = None
    critical: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise ValueError("event_id must be a non-empty string")
        if not isinstance(self.is_attack_related, bool) or not isinstance(self.critical, bool):
            raise ValueError("is_attack_related and critical must be booleans")
        if self.critical and not self.is_attack_related:
            raise ValueError(f"{self.event_id}: critical evidence must be attack-related")
        if self.attack_stage is not None and not isinstance(self.attack_stage, str):
            raise ValueError("attack_stage must be a string or null")


@dataclass(frozen=True)
class GroundTruth:
    labels: Mapping[str, GroundTruthLabel]
    source: str = "unspecified"
    unlabelled_policy: str = "negative"

    @classmethod
    def from_records(cls, records: Iterable[Mapping[str, Any]], source: str = "records") -> "GroundTruth":
        labels: dict[str, GroundTruthLabel] = {}
        for position, record in enumerate(records):
            if len(labels) >= MAX_LABELS:
                raise ValueError(f"too many labels (max {MAX_LABELS})")
            if not isinstance(record, Mapping):
                raise ValueError(f"label #{position} is not an object")
            unknown = set(record) - {"event_id", "is_attack_related", "attack_stage", "critical"}
            if unknown:
                raise ValueError(f"label #{position}: unknown field(s) {sorted(unknown)}")
            label = GroundTruthLabel(
                event_id=record.get("event_id"),  # type: ignore[arg-type]
                is_attack_related=record.get("is_attack_related"),  # type: ignore[arg-type]
                attack_stage=record.get("attack_stage"),
                critical=record.get("critical", False),
            )
            if label.event_id in labels:
                raise ValueError(f"duplicate label for {label.event_id}")
            labels[label.event_id] = label
        return cls(labels=labels, source=source)

    @classmethod
    def from_json(cls, path: str | Path) -> "GroundTruth":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        records = data.get("labels") if isinstance(data, dict) else data
        if not isinstance(records, list):
            raise ValueError("ground truth file must be a list of labels or {\"labels\": [...]}")
        return cls.from_records(records, source=str(path))

    def is_positive(self, event_id: str) -> bool:
        label = self.labels.get(event_id)
        return bool(label and label.is_attack_related)

    @property
    def critical_ids(self) -> frozenset[str]:
        return frozenset(k for k, v in self.labels.items() if v.critical)

    @property
    def positive_ids(self) -> frozenset[str]:
        return frozenset(k for k, v in self.labels.items() if v.is_attack_related)


@dataclass
class Evaluation:
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    critical_evidence_recall: float | None = None
    critical_total: int = 0
    critical_retained: int = 0
    missing_critical: list[str] = field(default_factory=list)
    labels_not_in_input: int = 0
    note: str = NA

    def to_dict(self) -> dict[str, Any]:
        fmt = lambda v: NA if v is None else round(v, 4)  # noqa: E731
        return {
            "precision": fmt(self.precision), "recall": fmt(self.recall), "f1": fmt(self.f1),
            "critical_evidence_recall": fmt(self.critical_evidence_recall),
            "critical_total": self.critical_total, "critical_retained": self.critical_retained,
            "missing_critical": self.missing_critical[:50], "labels_not_in_input": self.labels_not_in_input,
            "note": self.note,
        }


def evaluate(selected_ids: Iterable[str], input_ids: Iterable[str], truth: GroundTruth | None) -> Evaluation:
    """Precision/recall/F1 of the selection against `is_attack_related`, and
    critical evidence recall = critical retained / total critical.

    Only labels whose event is present in the input are scored; labels for
    absent events are counted in `labels_not_in_input` (a mismatch between
    dataset and labels should be visible, not silently lower recall).
    """
    if truth is None:
        return Evaluation()
    present = set(input_ids)
    selected = set(selected_ids) & present
    positives = {e for e in truth.positive_ids if e in present}
    critical = sorted(e for e in truth.critical_ids if e in present)
    missing_labels = sum(1 for e in truth.labels if e not in present)

    tp = len(selected & positives)
    precision = tp / len(selected) if selected else None
    recall = tp / len(positives) if positives else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall > 0 else
          (0.0 if precision is not None and recall is not None else None))
    retained = [e for e in critical if e in selected]
    return Evaluation(
        precision=precision, recall=recall, f1=f1,
        critical_evidence_recall=(len(retained) / len(critical)) if critical else None,
        critical_total=len(critical), critical_retained=len(retained),
        missing_critical=[e for e in critical if e not in selected],
        labels_not_in_input=missing_labels,
        note=f"ground truth: {truth.source}",
    )
