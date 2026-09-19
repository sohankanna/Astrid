"""Alert correlation: grouping related alerts into a single incident.

Analysts do not want ten alerts about one intrusion; they want one incident
with ten pieces of evidence. This module performs that grouping
deterministically, using entity overlap and temporal proximity -- no model is
involved, so the result is reproducible and explainable.

Algorithm: union-find over alerts. Two alerts are linked when they share an
entity (host, user, or source IP) **and** their evidence falls within
`time_window` of each other. Linked sets become incidents.

Why entity + time rather than entity alone: `j.rivera` logging in today and
`j.rivera` triggering an alert next month are not one incident. Time is what
stops an incident from growing without bound.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final, Iterable, Sequence

from .detections import DetectionResult, max_severity, severity_rank
from .events import SecurityEvent
from .mitre import attack_stage, describe, tactics_for

DEFAULT_TIME_WINDOW: Final[timedelta] = timedelta(hours=4)

# Entities too common to imply a relationship. Correlating on these would
# merge unrelated incidents into one useless mega-incident.
GENERIC_ENTITIES: Final[frozenset[str]] = frozenset(
    {
        "host:idp.corp.test",
        "host:cloud-control-plane",
        "user:system",
        "user:-",
        "ip:0.0.0.0",
        "ip:127.0.0.1",
        "ip:::1",
    }
)


@dataclass(frozen=True)
class TimelineEntry:
    """One evidence event, positioned in the incident's narrative."""

    timestamp: datetime
    event_id: str
    summary: str
    severity: str
    alert_ids: tuple[str, ...]


@dataclass
class Incident:
    """A correlated group of alerts plus the evidence behind them."""

    incident_id: str
    title: str
    severity: str
    alerts: list[DetectionResult]
    events: list[SecurityEvent]
    hosts: list[str]
    users: list[str]
    source_ips: list[str]
    technique_ids: list[str]
    timeline: list[TimelineEntry]
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def event_ids(self) -> list[str]:
        return [event.event_id for event in self.events]

    @property
    def entity_values(self) -> list[str]:
        """Every correlated entity, without its namespace prefix.

        This is the set of things a response action may target: the response
        provider's `allowed_targets` is built from it, so an action can only
        touch an identity, key or resource that appears in the evidence.
        """
        return sorted({e.split(":", 1)[1] for e in entities_for(self.events)})

    @property
    def cloud_accounts(self) -> list[str]:
        """Distinct cloud account IDs seen in the incident's evidence."""
        return _distinct(event.account_id for event in self.events)

    @property
    def alert_ids(self) -> list[str]:
        return [alert.alert_id for alert in self.alerts]

    @property
    def rule_ids(self) -> list[str]:
        """Distinct rules that fired, in stable order."""
        seen: list[str] = []
        for alert in self.alerts:
            if alert.rule_id not in seen:
                seen.append(alert.rule_id)
        return seen

    @property
    def duration(self) -> timedelta | None:
        if self.first_seen is None or self.last_seen is None:
            return None
        return self.last_seen - self.first_seen

    @property
    def attack_stage(self) -> str | None:
        """Furthest kill-chain tactic reached, derived from mapped techniques."""
        return attack_stage(self.technique_ids)

    @property
    def tactics(self) -> list[str]:
        return tactics_for(self.technique_ids)

    def describe_techniques(self) -> list[str]:
        return [describe(tid) for tid in self.technique_ids]

    def to_dict(self) -> dict:
        """Plain-data view, for serialization and for the AI analyst input.

        Deliberately excludes raw log text: the analyst pipeline decides what
        untrusted content to include and how to delimit it (see
        prompts/SOC_ANALYST_PROMPT.md), rather than getting it by default.
        """
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "hosts": self.hosts,
            "users": self.users,
            "source_ips": self.source_ips,
            "technique_ids": self.technique_ids,
            "attack_stage": self.attack_stage,
            "alert_ids": self.alert_ids,
            "rule_ids": self.rule_ids,
            "event_ids": self.event_ids,
            "timeline": [
                {
                    "timestamp": entry.timestamp.isoformat(),
                    "event_id": entry.event_id,
                    "summary": entry.summary,
                    "severity": entry.severity,
                }
                for entry in self.timeline
            ],
        }


def entities_for(events: Iterable[SecurityEvent]) -> set[str]:
    """Namespaced entity keys for a set of events.

    Namespacing ('host:', 'user:', 'ip:') prevents a hostname from colliding
    with a username that happens to have the same string value.
    """
    entities: set[str] = set()
    for event in events:
        if event.hostname:
            entities.add(f"host:{event.hostname}")
        # An AWS service acting on our behalf ('ec2.amazonaws.com') is shared
        # infrastructure, not an actor; linking on it would merge everything.
        is_service = event.identity_type == "AWSService"
        if event.username and not is_service:
            entities.add(f"user:{event.username}")
        if event.source_ip and _is_ip(event.source_ip):
            entities.add(f"ip:{event.source_ip}")
        if event.destination_ip:
            entities.add(f"ip:{event.destination_ip}")
        if event.is_cloud and not is_service:
            entities |= _cloud_entities(event)
    return entities - GENERIC_ENTITIES


def _is_ip(value: str) -> bool:
    """CloudTrail puts service hostnames in sourceIPAddress; only real IPs link."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _cloud_entities(event: SecurityEvent) -> set[str]:
    """Identity and resource entities from a cloud event.

    The important link is `role:`. An AssumeRole call names the role it
    targets, and every later call made with that session names the same role
    as its session issuer. So the escalation step and everything done
    afterwards share one entity even if the attacker changes source address.
    Keys work the same way: the key minted in a response is the key seen on
    later calls.

    Account IDs are deliberately NOT entities. Every event in an account
    shares one, so linking on it would collapse all activity into a single
    incident.
    """
    entities: set[str] = set()
    if event.principal_arn:
        entities.add(f"principal:{event.principal_arn}")
    if event.session_issuer_arn:
        entities.add(f"role:{event.session_issuer_arn}")
    if event.access_key_id:
        entities.add(f"key:{event.access_key_id}")

    params = event.request_parameters
    role_arn = params.get("roleArn")
    if isinstance(role_arn, str):
        entities.add(f"role:{role_arn}")
    target_user = params.get("userName")
    if isinstance(target_user, str):
        entities.add(f"user:{target_user}")
    for resource_key in ("groupId", "bucketName"):
        value = params.get(resource_key)
        if isinstance(value, str):
            entities.add(f"res:{value}")

    response = event.response_elements
    credentials = response.get("credentials")
    minted_key = response.get("accessKeyId") or (
        credentials.get("accessKeyId") if isinstance(credentials, dict) else None
    )
    if isinstance(minted_key, str):
        entities.add(f"key:{minted_key}")

    for resource in event.cloud_resources:
        entities.add(f"res:{resource}")
    return entities


class _UnionFind:
    """Minimal disjoint-set structure over alert indices."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, index: int) -> int:
        while self._parent[index] != index:
            self._parent[index] = self._parent[self._parent[index]]
            index = self._parent[index]
        return index

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root


class CorrelationEngine:
    """Groups alerts into incidents by shared entity and temporal proximity."""

    def __init__(
        self,
        time_window: timedelta = DEFAULT_TIME_WINDOW,
        *,
        correlate_by_technique: bool = False,
    ) -> None:
        self.time_window = time_window
        # Technique overlap alone is a weak signal -- two unrelated hosts both
        # running PowerShell is not one incident -- so it is off by default and
        # only ever applied in addition to temporal proximity.
        self.correlate_by_technique = correlate_by_technique

    def correlate(
        self, alerts: Sequence[DetectionResult], events: Sequence[SecurityEvent]
    ) -> list[Incident]:
        """Return incidents, most severe first.

        Alerts whose evidence is missing from `events` are skipped and noted:
        an alert we cannot substantiate must not silently become an incident.
        """
        by_id = {event.event_id: event for event in events}
        usable: list[DetectionResult] = []
        orphaned: list[str] = []
        for alert in alerts:
            if all(eid in by_id for eid in alert.evidence_event_ids):
                usable.append(alert)
            else:
                orphaned.append(alert.alert_id)

        if not usable:
            return []

        alert_events = [
            [by_id[eid] for eid in alert.evidence_event_ids] for alert in usable
        ]
        alert_entities = [entities_for(group) for group in alert_events]
        spans = [
            (
                min(e.timestamp for e in group),
                max(e.timestamp for e in group),
            )
            for group in alert_events
        ]

        union = _UnionFind(len(usable))
        for i in range(len(usable)):
            for j in range(i + 1, len(usable)):
                if self._should_link(
                    usable[i],
                    usable[j],
                    alert_entities[i],
                    alert_entities[j],
                    spans[i],
                    spans[j],
                ):
                    union.union(i, j)

        clusters: dict[int, list[int]] = {}
        for index in range(len(usable)):
            clusters.setdefault(union.find(index), []).append(index)

        incidents = [
            self._build_incident(
                [usable[i] for i in sorted(indices)],
                {e.event_id: e for i in indices for e in alert_events[i]},
                sequence,
                orphaned if sequence == 1 else [],
            )
            for sequence, indices in enumerate(
                sorted(
                    clusters.values(),
                    key=lambda idx: min(spans[i][0] for i in idx),
                ),
                start=1,
            )
        ]
        incidents.sort(
            key=lambda inc: (
                -severity_rank(inc.severity),
                inc.first_seen or datetime.max,
            )
        )
        return incidents

    def _should_link(
        self,
        left: DetectionResult,
        right: DetectionResult,
        left_entities: set[str],
        right_entities: set[str],
        left_span: tuple[datetime, datetime],
        right_span: tuple[datetime, datetime],
    ) -> bool:
        """Two alerts belong together when they overlap in entity and time."""
        if self._gap(left_span, right_span) > self.time_window:
            return False
        if left_entities & right_entities:
            return True
        if set(left.evidence_event_ids) & set(right.evidence_event_ids):
            return True
        if self.correlate_by_technique:
            return bool(set(left.technique_ids) & set(right.technique_ids))
        return False

    @staticmethod
    def _gap(
        left: tuple[datetime, datetime], right: tuple[datetime, datetime]
    ) -> timedelta:
        """Time between two spans; zero when they overlap."""
        if left[1] < right[0]:
            return right[0] - left[1]
        if right[1] < left[0]:
            return left[0] - right[1]
        return timedelta(0)

    def _build_incident(
        self,
        alerts: list[DetectionResult],
        events_by_id: dict[str, SecurityEvent],
        sequence: int,
        orphaned_alert_ids: list[str],
    ) -> Incident:
        events = sorted(events_by_id.values(), key=lambda e: e.timestamp)
        severity = max_severity(alert.severity for alert in alerts)

        alerts_by_event: dict[str, list[str]] = {}
        for alert in alerts:
            for event_id in alert.evidence_event_ids:
                alerts_by_event.setdefault(event_id, []).append(alert.alert_id)

        timeline = [
            TimelineEntry(
                timestamp=event.timestamp,
                event_id=event.event_id,
                summary=summarize_event(event),
                severity=event.severity,
                alert_ids=tuple(alerts_by_event.get(event.event_id, ())),
            )
            for event in events
        ]

        technique_ids: list[str] = []
        for alert in alerts:
            for technique_id in alert.technique_ids:
                if technique_id not in technique_ids:
                    technique_ids.append(technique_id)

        notes: list[str] = []
        if orphaned_alert_ids:
            notes.append(
                "Alerts skipped because their evidence events were not supplied: "
                + ", ".join(orphaned_alert_ids)
            )

        incident = Incident(
            incident_id=f"inc-{sequence:04d}",
            title=_incident_title(alerts, events),
            severity=severity,
            alerts=alerts,
            events=events,
            hosts=_distinct(event.hostname for event in events),
            users=_distinct(event.username for event in events),
            source_ips=_distinct(event.source_ip for event in events),
            technique_ids=technique_ids,
            timeline=timeline,
            first_seen=events[0].timestamp if events else None,
            last_seen=events[-1].timestamp if events else None,
            notes=notes,
        )
        return incident


def summarize_event(event: SecurityEvent) -> str:
    """One-line, non-quoting description of an event for the timeline.

    Attacker-controlled free text (command lines, domains, filenames) is NOT
    interpolated here. The timeline is rendered in analyst UIs and passed
    around; keeping it to structured fields avoids carrying an injection
    payload into places that never screened for it. The full untrusted content
    stays available on the event itself.
    """
    who = event.username or "unknown user"
    # Cloud control-plane events have no host; the account is where they happened.
    where = event.hostname or (
        f"AWS account {event.account_id}" if event.account_id else "unknown host"
    )
    base = f"{event.action} on {where} as {who}"
    if event.category == "process" and event.process:
        parent = f" (parent {event.parent_process})" if event.parent_process else ""
        return f"{base}: {event.process}{parent}"
    if event.category == "network" and event.destination_ip:
        return f"{base}: -> {event.destination_ip}:{event.destination_port}"
    if event.category == "dns":
        return f"{base}: DNS query [domain withheld from summary]"
    if event.category == "alert":
        return f"{base}: rule {event.details.get('rule_id', 'unknown')}"
    return base


def _incident_title(
    alerts: list[DetectionResult], events: list[SecurityEvent]
) -> str:
    """Title from the highest-severity rule plus the primary host."""
    lead = max(alerts, key=lambda a: severity_rank(a.severity))
    hosts = _distinct(event.hostname for event in events)
    accounts = _distinct(event.account_id for event in events)
    if accounts:
        # Cloud incidents are scoped by account; many have no host at all.
        scope = f"AWS account {accounts[0]}" if len(accounts) == 1 else f"{len(accounts)} AWS accounts"
    else:
        scope = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"
    if len(alerts) > 1:
        return f"{lead.title} and {len(alerts) - 1} related alert(s) on {scope}"
    return f"{lead.title} on {scope}"


def _distinct(values: Iterable[str | None]) -> list[str]:
    """Order-preserving de-duplication, dropping None."""
    seen: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.append(value)
    return seen
