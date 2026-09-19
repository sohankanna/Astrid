"""Transparent, explainable risk scoring.

Deliberately **not** an AI-generated number. An analyst must be able to ask
"why is this a 78?" and get an itemized answer they can argue with. Every
point in the score is attributable to a named factor, and every factor names
the evidence that triggered it.

Scoring model
-------------
Score = clamp(sum of factor contributions, 0..100).

Factors are additive with individual caps, so no single dimension can
dominate, and the total is capped rather than normalized -- a 100 means
"maximum observed risk", not "certainty".

Bands:
    0-19    informational
    20-39   low
    40-59   medium
    60-79   high
    80-100  critical

Tuning these weights is a policy decision, not a technical one. They live in
`RiskWeights` so a hackathon scenario can override them without touching
logic, and every change is visible in the factor breakdown.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Sequence

from .correlation import Incident
from .detections import DetectionResult, severity_rank
from .mitre import TECHNIQUES

# Tactics that indicate the intrusion has progressed beyond initial noise.
_CREDENTIAL_TACTICS: Final[frozenset[str]] = frozenset({"Credential Access"})
_EXECUTION_TACTICS: Final[frozenset[str]] = frozenset({"Execution"})
_PERSISTENCE_TACTICS: Final[frozenset[str]] = frozenset(
    {"Persistence", "Privilege Escalation"}
)
_LATERAL_TACTICS: Final[frozenset[str]] = frozenset({"Lateral Movement"})
_C2_TACTICS: Final[frozenset[str]] = frozenset({"Command and Control"})
_SENSITIVE_TACTICS: Final[frozenset[str]] = frozenset(
    {"Collection", "Exfiltration", "Impact"}
)

# Actions/keywords that indicate sensitive-resource access without relying on
# an ATT&CK mapping being present.
_SENSITIVE_ACTION_MARKERS: Final[tuple[str, ...]] = (
    "admin_share_access",
    "anomalous_api_usage",
    "data_from_cloud_storage",
)

BAND_THRESHOLDS: Final[tuple[tuple[int, str], ...]] = (
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
    (0, "informational"),
)


@dataclass(frozen=True)
class RiskWeights:
    """Tunable scoring policy. Override per scenario; never hide the change."""

    severity_points: dict[str, int] = field(
        default_factory=lambda: {
            "informational": 0,
            "low": 5,
            "medium": 12,
            "high": 22,
            "critical": 30,
        }
    )
    per_additional_alert: int = 4
    additional_alert_cap: int = 16
    credential_activity: int = 18
    execution_activity: int = 10
    persistence_activity: int = 10
    lateral_movement: int = 12
    c2_activity: int = 14
    sensitive_access: int = 10
    multi_host: int = 6
    high_confidence_bonus: int = 4
    # Cloud-era factors. Keyed on specific evidence (T1562.* techniques; the
    # Root identity type), so they never trigger on endpoint-only incidents.
    impair_defenses: int = 14
    privileged_identity: int = 14


@dataclass(frozen=True)
class RiskFactor:
    """One itemized contribution to the score."""

    name: str
    points: int
    reason: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "points": self.points,
            "reason": self.reason,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class RiskAssessment:
    """The score, its band, and the full reasoning behind it."""

    score: int
    band: str
    factors: tuple[RiskFactor, ...]

    @property
    def explanation(self) -> str:
        """Human-readable breakdown -- what an analyst sees on hover."""
        lines = [f"Risk score {self.score}/100 ({self.band}). Contributing factors:"]
        for factor in self.factors:
            lines.append(f"  +{factor.points:>3}  {factor.name}: {factor.reason}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "band": self.band,
            "factors": [factor.to_dict() for factor in self.factors],
        }


def band_for_score(score: int) -> str:
    """Map a 0-100 score onto a severity band."""
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return "informational"


def _tactics_present(technique_ids: Sequence[str]) -> set[str]:
    return {
        TECHNIQUES[tid].tactic for tid in technique_ids if tid in TECHNIQUES
    }


def _alerts_for_tactics(
    alerts: Sequence[DetectionResult], tactics: frozenset[str]
) -> list[str]:
    """Alert IDs whose techniques fall in the given tactics."""
    matched = []
    for alert in alerts:
        alert_tactics = _tactics_present(alert.technique_ids)
        if alert_tactics & tactics:
            matched.append(alert.alert_id)
    return matched


def score_incident(
    incident: Incident, weights: RiskWeights | None = None
) -> RiskAssessment:
    """Compute an explainable risk score for a correlated incident."""
    weights = weights or RiskWeights()
    factors: list[RiskFactor] = []

    # 1. Base severity of the most severe alert.
    base = weights.severity_points.get(incident.severity, 0)
    if base:
        lead = max(incident.alerts, key=lambda a: severity_rank(a.severity))
        factors.append(
            RiskFactor(
                name="alert_severity",
                points=base,
                reason=(
                    f"highest alert severity is '{incident.severity}' "
                    f"(rule {lead.rule_id})"
                ),
                evidence=(lead.alert_id,),
            )
        )

    # 2. Corroboration: independent alerts raise confidence that this is real.
    extra = max(0, len(incident.alerts) - 1)
    if extra:
        points = min(extra * weights.per_additional_alert, weights.additional_alert_cap)
        factors.append(
            RiskFactor(
                name="correlated_alerts",
                points=points,
                reason=(
                    f"{len(incident.alerts)} alerts from {len(incident.rule_ids)} "
                    f"distinct rules corroborate each other"
                ),
                evidence=tuple(incident.alert_ids),
            )
        )

    # 3-8. Kill-chain dimensions. Each is capped and evidence-linked.
    for name, tactics, points, reason in (
        (
            "credential_activity",
            _CREDENTIAL_TACTICS,
            weights.credential_activity,
            "credential access observed (theft enables everything downstream)",
        ),
        (
            "execution_activity",
            _EXECUTION_TACTICS,
            weights.execution_activity,
            "code execution observed on an endpoint",
        ),
        (
            "persistence_indicators",
            _PERSISTENCE_TACTICS,
            weights.persistence_activity,
            "persistence or privilege escalation observed",
        ),
        (
            "lateral_movement",
            _LATERAL_TACTICS,
            weights.lateral_movement,
            "lateral movement observed (blast radius is growing)",
        ),
        (
            "c2_indicators",
            _C2_TACTICS,
            weights.c2_activity,
            "command-and-control activity observed",
        ),
        (
            "sensitive_access",
            _SENSITIVE_TACTICS,
            weights.sensitive_access,
            "collection, exfiltration or impact activity observed",
        ),
    ):
        matched = _alerts_for_tactics(incident.alerts, tactics)
        if matched:
            factors.append(
                RiskFactor(
                    name=name,
                    points=points,
                    reason=reason,
                    evidence=tuple(matched),
                )
            )

    # Sensitive-resource access can also be evident from the raw actions even
    # when no technique was mapped -- catch that separately.
    if not any(f.name == "sensitive_access" for f in factors):
        marker_events = [
            event.event_id
            for event in incident.events
            if event.action in _SENSITIVE_ACTION_MARKERS
        ]
        if marker_events:
            factors.append(
                RiskFactor(
                    name="sensitive_access",
                    points=weights.sensitive_access,
                    reason="access to a sensitive or administrative resource observed",
                    evidence=tuple(marker_events),
                )
            )

    # Impair Defenses (T1562.*): logging stopped, firewall opened. The attacker
    # is blinding the SOC or removing a control, which also means our own
    # evidence for what follows may be incomplete.
    impairing = [
        alert.alert_id
        for alert in incident.alerts
        if any(tid.startswith("T1562") for tid in alert.technique_ids)
    ]
    if impairing:
        factors.append(
            RiskFactor(
                name="impair_defenses",
                points=weights.impair_defenses,
                reason="security logging or a network control was disabled or weakened",
                evidence=tuple(impairing),
            )
        )

    # Cloud root credentials bypass IAM boundaries entirely.
    root_events = [e.event_id for e in incident.events if e.identity_type == "Root"]
    if root_events:
        factors.append(
            RiskFactor(
                name="privileged_identity",
                points=weights.privileged_identity,
                reason="cloud root account credentials were used",
                evidence=tuple(root_events),
            )
        )

    # 9. Spread across hosts.
    if len(incident.hosts) > 1:
        factors.append(
            RiskFactor(
                name="multi_host",
                points=weights.multi_host,
                reason=f"activity spans {len(incident.hosts)} hosts",
                evidence=tuple(incident.hosts),
            )
        )

    # 10. Detection confidence. Low-confidence-only incidents should not reach
    # the top band on heuristics alone.
    high_confidence = [a.alert_id for a in incident.alerts if a.confidence == "high"]
    if high_confidence:
        factors.append(
            RiskFactor(
                name="detection_confidence",
                points=weights.high_confidence_bonus,
                reason=f"{len(high_confidence)} high-confidence detection(s)",
                evidence=tuple(high_confidence),
            )
        )

    total = min(100, max(0, sum(factor.points for factor in factors)))
    return RiskAssessment(
        score=total, band=band_for_score(total), factors=tuple(factors)
    )
