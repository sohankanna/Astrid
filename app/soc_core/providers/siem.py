"""SIEM provider abstraction.

The core simulation reads events through this interface, so the same pipeline
runs against a local JSON file today and a real SIEM later without any change
to detection, correlation, or triage code.

Implemented:   MockSIEMProvider (local synthetic data, no network)
Placeholders:  SplunkProvider, WazuhProvider -- interface + TODOs only

Security posture: **everything a provider returns is untrusted input**, even
from a "trusted" SIEM, because the SIEM is only relaying what an attacker may
have written. Results are parsed and validated through `soc_core.events`
exactly like any other input.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Sequence

from ..events import SecurityEvent, load_events

# A query that returns everything would be a resource-exhaustion vector
# against us as much as a performance problem. Every query is bounded.
DEFAULT_QUERY_LIMIT: Final[int] = 1000
MAX_QUERY_LIMIT: Final[int] = 10_000


@dataclass(frozen=True)
class EventQuery:
    """A bounded, structured query.

    Structured fields rather than a raw query string: a free-form query
    language passed through from user or model input is an injection surface
    (the SIEM equivalent of SQL injection). Providers translate these fields
    into their own dialect with proper escaping.
    """

    start: datetime | None = None
    end: datetime | None = None
    hosts: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    event_ids: tuple[str, ...] = ()
    limit: int = DEFAULT_QUERY_LIMIT

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("limit must be >= 1")
        if self.limit > MAX_QUERY_LIMIT:
            raise ValueError(f"limit exceeds MAX_QUERY_LIMIT ({MAX_QUERY_LIMIT})")
        if self.start and self.end and self.start > self.end:
            raise ValueError("start must be <= end")

    def matches(self, event: SecurityEvent) -> bool:
        """Evaluate the filter against one event."""
        if self.start and event.timestamp < self.start:
            return False
        if self.end and event.timestamp > self.end:
            return False
        if self.hosts and event.hostname not in self.hosts:
            return False
        if self.users and event.username not in self.users:
            return False
        if self.categories and event.category not in self.categories:
            return False
        if self.severities and event.severity not in self.severities:
            return False
        if self.event_ids and event.event_id not in self.event_ids:
            return False
        return True


@dataclass
class SIEMCase:
    """A case/ticket created in the SIEM."""

    case_id: str
    title: str
    severity: str
    description: str
    event_ids: tuple[str, ...]
    created_at: datetime
    status: str = "open"


class SIEMProvider(ABC):
    """Interface every SIEM integration implements."""

    name: str

    @abstractmethod
    def query_events(self, query: EventQuery) -> list[SecurityEvent]:
        """Return validated events matching `query`, respecting `query.limit`."""

    @abstractmethod
    def get_event(self, event_id: str) -> SecurityEvent | None:
        """Return one event by ID, or None if it does not exist."""

    @abstractmethod
    def get_alerts(self) -> list[dict[str, Any]]:
        """Return alerts the SIEM itself generated (distinct from our rules)."""

    @abstractmethod
    def acknowledge_alert(self, alert_id: str, *, analyst: str) -> bool:
        """Mark a SIEM-side alert acknowledged. Returns False if unknown."""

    @abstractmethod
    def create_case(
        self,
        title: str,
        severity: str,
        description: str,
        event_ids: Sequence[str],
    ) -> SIEMCase:
        """Create a case/ticket. Must be idempotent-safe to retry."""


class MockSIEMProvider(SIEMProvider):
    """Offline provider backed by the synthetic dataset.

    Makes no network calls and needs no credentials. State (acknowledgements,
    cases) is in-memory only and disappears with the process, which is exactly
    what we want for a repeatable demo.
    """

    name = "mock"

    def __init__(
        self,
        events: Sequence[SecurityEvent] | None = None,
        *,
        dataset_path: str | Path | None = None,
    ) -> None:
        if events is not None and dataset_path is not None:
            raise ValueError("pass either events or dataset_path, not both")
        if events is None:
            if dataset_path is None:
                raise ValueError("one of events or dataset_path is required")
            events = load_events(dataset_path)
        self._events: list[SecurityEvent] = sorted(events, key=lambda e: e.timestamp)
        self._by_id = {event.event_id: event for event in self._events}
        self._acknowledged: set[str] = set()
        self._cases: list[SIEMCase] = []

    def query_events(self, query: EventQuery) -> list[SecurityEvent]:
        matched = [event for event in self._events if query.matches(event)]
        return matched[: query.limit]

    def get_event(self, event_id: str) -> SecurityEvent | None:
        return self._by_id.get(event_id)

    def get_alerts(self) -> list[dict[str, Any]]:
        """Vendor alerts already present in the data (category == 'alert').

        These are the SIEM's/EDR's own detections, kept separate from the
        alerts our DetectionEngine produces so their provenance stays clear.
        """
        return [
            {
                "alert_id": event.event_id,
                "rule_id": event.details.get("rule_id"),
                "rule_name": event.details.get("rule_name"),
                "severity": event.severity,
                "host": event.hostname,
                "acknowledged": event.event_id in self._acknowledged,
                "vendor": event.details.get("vendor", event.source),
            }
            for event in self._events
            if event.category == "alert"
        ]

    def acknowledge_alert(self, alert_id: str, *, analyst: str) -> bool:
        if alert_id not in self._by_id:
            return False
        self._acknowledged.add(alert_id)
        return True

    def create_case(
        self,
        title: str,
        severity: str,
        description: str,
        event_ids: Sequence[str],
    ) -> SIEMCase:
        unknown = [eid for eid in event_ids if eid not in self._by_id]
        if unknown:
            raise ValueError(f"cannot create a case citing unknown events: {unknown}")
        case = SIEMCase(
            case_id=f"case-{len(self._cases) + 1:04d}",
            title=title,
            severity=severity,
            description=description,
            event_ids=tuple(event_ids),
            created_at=datetime.now().astimezone(),
        )
        self._cases.append(case)
        return case

    @property
    def cases(self) -> list[SIEMCase]:
        return list(self._cases)


class SplunkProvider(SIEMProvider):
    """PLACEHOLDER -- not implemented. No live connection is made.

    Intended shape when implemented:

    * Auth: bearer token from `SPLUNK_TOKEN` in the environment. Never a
      hardcoded credential, never a token in a query string.
    * Transport: HTTPS with certificate verification on, explicit timeout.
    * `query_events`: translate `EventQuery` into SPL. Field values must be
      quoted/escaped -- never f-string a user- or model-supplied value into
      SPL (the SIEM equivalent of SQL injection).
    * Always bound the search with `earliest`/`latest` and `head <limit>`;
      an unbounded search is a self-inflicted DoS.
    * Map results to the normalized schema, then run them through
      `soc_core.events.parse_event` so SIEM data gets the same validation as
      everything else.
    * `create_case`: Splunk ES notable event or an ITSI episode.
    * AWS: the Splunk Add-on for AWS ingests CloudTrail (`aws:cloudtrail`) and
      VPC Flow Logs from the S3 log-archive bucket via SQS notifications, and
      GuardDuty via EventBridge -> Firehose -> HEC. Map results with a
      `normalize_cloudtrail()` into the `cloud` category (see
      docs/SOC_SIMULATION.md section 12), then parse_event() as usual.

    TODO(problem-statement): implement only if the scenario requires Splunk.
    """

    name = "splunk"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "SplunkProvider is an interface placeholder. The core simulation "
            "runs on MockSIEMProvider and requires no live SIEM."
        )

    def query_events(self, query: EventQuery) -> list[SecurityEvent]:
        raise NotImplementedError

    def get_event(self, event_id: str) -> SecurityEvent | None:
        raise NotImplementedError

    def get_alerts(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def acknowledge_alert(self, alert_id: str, *, analyst: str) -> bool:
        raise NotImplementedError

    def create_case(
        self,
        title: str,
        severity: str,
        description: str,
        event_ids: Sequence[str],
    ) -> SIEMCase:
        raise NotImplementedError


class WazuhProvider(SIEMProvider):
    """PLACEHOLDER -- not implemented. No live connection is made.

    Intended shape when implemented:

    * Auth: Wazuh API user/password from the environment, exchanged for a
      short-lived JWT. Refresh on 401; never log the token.
    * `query_events`: Wazuh Indexer (OpenSearch) query DSL against
      `wazuh-alerts-*`, with an explicit time range and `size` limit.
    * Map Wazuh's `rule.level` (0-15) onto our severity vocabulary once,
      in one documented place, rather than scattering conversions.
    * `get_alerts`: Wazuh rules that already fired -- these are vendor
      detections and must stay distinguishable from our own.
    * `acknowledge_alert`/`create_case`: Wazuh has no native case object;
      route to the configured ticketing system instead and say so plainly
      rather than pretending the capability exists.

    * AWS: Wazuh's `aws-s3` wodle reads CloudTrail, VPC Flow Logs and
      GuardDuty from the log bucket. Its decoded fields (`data.aws.*`) still
      need our normalizer. Keep GuardDuty findings as vendor `alert` events
      so they stay distinguishable from our own detections.

    Wazuh is the strongest candidate for an offline demo: it is open source
    and self-hostable, so a hackathon judge can run it.

    TODO(problem-statement): implement only if the scenario requires Wazuh.
    """

    name = "wazuh"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "WazuhProvider is an interface placeholder. The core simulation "
            "runs on MockSIEMProvider and requires no live SIEM."
        )

    def query_events(self, query: EventQuery) -> list[SecurityEvent]:
        raise NotImplementedError

    def get_event(self, event_id: str) -> SecurityEvent | None:
        raise NotImplementedError

    def get_alerts(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def acknowledge_alert(self, alert_id: str, *, analyst: str) -> bool:
        raise NotImplementedError

    def create_case(
        self,
        title: str,
        severity: str,
        description: str,
        event_ids: Sequence[str],
    ) -> SIEMCase:
        raise NotImplementedError
