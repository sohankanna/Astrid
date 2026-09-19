"""Deterministic detection engine.

Design rule, from the reference architecture: **no AI decides whether a rule
fired.** Everything here is explainable, testable, and reproducible -- an
analyst can read the rule that produced an alert and re-derive it by hand.
The LLM interprets these alerts later; it never creates them.

Two rule shapes:

* `EventRule`     -- evaluates one event at a time (signature layer).
* `ThresholdRule` -- counts events grouped by an entity inside a time window
                     (aggregation layer).

Both produce `DetectionResult` objects carrying the event IDs that justify
them, so every downstream claim can be traced back to evidence.

Adding a rule means subclassing one of the two bases and appending it to
`default_rules()`. No other file needs to change.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Final, Iterable, Sequence

from .events import SecurityEvent
from .mitre import validate_technique_ids

SEVERITY_ORDER: Final[tuple[str, ...]] = (
    "informational",
    "low",
    "medium",
    "high",
    "critical",
)

CONFIDENCE_LEVELS: Final[frozenset[str]] = frozenset({"low", "medium", "high"})


def severity_rank(severity: str) -> int:
    """Numeric rank for comparing severities. Unknown severities rank lowest."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def max_severity(severities: Iterable[str]) -> str:
    """Highest severity in the iterable, or 'informational' when empty."""
    ranked = sorted(severities, key=severity_rank)
    return ranked[-1] if ranked else "informational"


@dataclass(frozen=True)
class DetectionResult:
    """One alert produced by one rule.

    `evidence_event_ids` is the contract with everything downstream: an alert
    that cannot point at the events that caused it is not usable in a SOC.
    """

    alert_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    evidence_event_ids: tuple[str, ...]
    technique_ids: tuple[str, ...] = ()
    matched_fields: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"invalid severity: {self.severity!r}")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {self.confidence!r}")
        if not self.evidence_event_ids:
            raise ValueError(f"rule {self.rule_id} produced an alert with no evidence")
        unknown = validate_technique_ids(list(self.technique_ids))[1]
        if unknown:
            raise ValueError(
                f"rule {self.rule_id} references unknown ATT&CK technique(s): {unknown}"
            )


class DetectionRule(ABC):
    """Base class for all detection rules."""

    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    technique_ids: tuple[str, ...] = ()
    sigma_rule: str | None = None  # filename in security/detection_rules/

    @abstractmethod
    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        """Return zero or more alerts for this batch of events."""

    def _result(
        self,
        suffix: str,
        event_ids: Sequence[str],
        *,
        description: str | None = None,
        matched_fields: dict[str, str] | None = None,
        severity: str | None = None,
    ) -> DetectionResult:
        return DetectionResult(
            alert_id=f"alert-{self.rule_id}-{suffix}",
            rule_id=self.rule_id,
            title=self.title,
            description=description or self.description,
            severity=severity or self.severity,
            confidence=self.confidence,
            evidence_event_ids=tuple(event_ids),
            technique_ids=self.technique_ids,
            matched_fields=matched_fields or {},
        )


class EventRule(DetectionRule):
    """A rule that inspects one event at a time."""

    @abstractmethod
    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        """Return the matched field values, or None if the event does not match."""

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        results = []
        for event in events:
            matched = self.matches(event)
            if matched is not None:
                results.append(
                    self._result(
                        event.event_id, [event.event_id], matched_fields=matched
                    )
                )
        return results


class ThresholdRule(DetectionRule):
    """A rule that fires when N qualifying events share an entity in a window."""

    threshold: int
    window: timedelta

    @abstractmethod
    def qualifies(self, event: SecurityEvent) -> bool:
        """True if this event counts toward the threshold."""

    @abstractmethod
    def group_key(self, event: SecurityEvent) -> str | None:
        """The entity to group by, or None to ignore the event."""

    def distinct_key(self, event: SecurityEvent) -> str | None:
        """Optional second dimension that must vary.

        Password spraying is defined by *many accounts*, not many attempts, so
        the spray rule requires distinct usernames rather than a raw count.
        """
        return None

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in events:
            if not self.qualifies(event):
                continue
            key = self.group_key(event)
            if key is not None:
                grouped[key].append(event)

        results: list[DetectionResult] = []
        for key, group in grouped.items():
            group.sort(key=lambda e: e.timestamp)
            window_events = self._first_window_exceeding(group)
            if window_events is None:
                continue
            results.append(
                self._result(
                    _slug(key),
                    [e.event_id for e in window_events],
                    description=self._describe(key, window_events),
                    matched_fields={
                        "group_key": key,
                        "count": str(len(window_events)),
                        "window_seconds": str(int(self.window.total_seconds())),
                    },
                )
            )
        return results

    def _first_window_exceeding(
        self, group: list[SecurityEvent]
    ) -> list[SecurityEvent] | None:
        """Sliding window over time-sorted events; returns the first hit.

        Once the threshold is met, the window is extended to include every
        other qualifying event still inside it. Reporting only the minimum
        number of events needed to trip the rule would hand the analyst
        partial evidence -- a spray alert should name every account attempted,
        not just the first three.
        """
        start = 0
        for end in range(len(group)):
            while group[end].timestamp - group[start].timestamp > self.window:
                start += 1
            if not self._window_meets_threshold(group[start : end + 1]):
                continue
            last = end
            while (
                last + 1 < len(group)
                and group[last + 1].timestamp - group[start].timestamp <= self.window
            ):
                last += 1
            return group[start : last + 1]
        return None

    def _window_meets_threshold(self, window: list[SecurityEvent]) -> bool:
        distinct = {
            key
            for key in (self.distinct_key(event) for event in window)
            if key is not None
        }
        if distinct:
            return len(distinct) >= self.threshold
        return len(window) >= self.threshold

    def _describe(self, key: str, window: list[SecurityEvent]) -> str:
        return (
            f"{self.description} Observed {len(window)} qualifying events for "
            f"{key} within {int(self.window.total_seconds())}s."
        )


def _slug(value: str) -> str:
    """Filesystem/ID-safe form of an entity key, for stable alert IDs."""
    return re.sub(r"[^A-Za-z0-9._-]", "-", value)


# ---------------------------------------------------------------------------
# Rule 1 -- password spraying
# ---------------------------------------------------------------------------


class PasswordSprayRule(ThresholdRule):
    """Many distinct accounts failing from one source in a short window.

    Distinct *usernames* is the discriminator. Counting attempts alone would
    also match one user fat-fingering a password, which is not spraying.
    """

    rule_id = "SOC-AUTH-001"
    title = "Password spraying from a single source"
    description = (
        "Multiple distinct accounts failed authentication from one source "
        "address in a short window, consistent with password spraying."
    )
    severity = "high"
    confidence = "high"
    technique_ids = ("T1110.003",)
    sigma_rule = "auth_password_spray.yml"
    threshold = 3
    window = timedelta(minutes=5)

    def qualifies(self, event: SecurityEvent) -> bool:
        if event.category != "authentication" or event.outcome != "failure":
            return False
        # A denied MFA prompt is not a password guess. Counting it here would
        # both inflate this alert and duplicate SOC-AUTH-002's evidence, so
        # the two rules stay disjoint and each alert means one thing.
        reason = str(event.details.get("failure_reason", "")).lower()
        return "mfa" not in reason and "mfa" not in event.action.lower()

    def group_key(self, event: SecurityEvent) -> str | None:
        return event.source_ip

    def distinct_key(self, event: SecurityEvent) -> str | None:
        return event.username


# ---------------------------------------------------------------------------
# Rule 2 -- suspicious PowerShell
# ---------------------------------------------------------------------------

_SUSPICIOUS_PS_FLAGS: Final[tuple[str, ...]] = (
    "-nop",
    "-noprofile",
    "-w hidden",
    "-windowstyle hidden",
    "-ep bypass",
    "-executionpolicy bypass",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "frombase64string",
)


class SuspiciousPowerShellRule(EventRule):
    """PowerShell launched with flags typical of tradecraft rather than admin use."""

    rule_id = "SOC-EXEC-001"
    title = "Suspicious PowerShell execution"
    description = (
        "PowerShell was launched with flags commonly used to hide execution "
        "or pull remote code."
    )
    severity = "high"
    confidence = "medium"
    technique_ids = ("T1059.001",)
    sigma_rule = "proc_suspicious_powershell.yml"

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "process":
            return None
        process = (event.process or "").lower()
        if "powershell" not in process:
            return None
        command_line = (event.command_line or "").lower()
        hits = [flag for flag in _SUSPICIOUS_PS_FLAGS if flag in command_line]
        if not hits:
            return None
        return {"process": process, "suspicious_flags": ", ".join(hits)}


# ---------------------------------------------------------------------------
# Rule 3 -- encoded PowerShell
# ---------------------------------------------------------------------------

# -e / -en / -enc / -encodedcommand are all accepted by PowerShell.
_ENCODED_FLAG_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\s)-(?:e|en|enc|encodedcommand)\s+(?P<payload>[A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)


class EncodedPowerShellRule(EventRule):
    """Base64-encoded PowerShell command lines.

    Kept separate from the general suspicious-PowerShell rule because encoding
    is a distinct technique (T1027.010) and a stronger signal on its own.

    The payload is never decoded and never executed -- only its presence and
    length are recorded.
    """

    rule_id = "SOC-EXEC-002"
    title = "Encoded PowerShell command"
    description = (
        "PowerShell was invoked with a base64-encoded command, obscuring what "
        "was executed."
    )
    severity = "high"
    confidence = "high"
    technique_ids = ("T1059.001", "T1027.010")
    sigma_rule = "proc_encoded_powershell.yml"

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "process":
            return None
        if "powershell" not in (event.process or "").lower():
            return None
        command_line = event.command_line or ""
        match = _ENCODED_FLAG_RE.search(command_line)
        if match is None:
            return None
        payload = match.group("payload")
        return {
            "process": event.process or "",
            "encoded_payload_length": str(len(payload)),
            "encoded_payload_prefix": payload[:16],
        }


# ---------------------------------------------------------------------------
# Rule 4 -- suspicious parent/child process relationship
# ---------------------------------------------------------------------------

# Parent -> children that should essentially never occur in normal use.
_SUSPICIOUS_LINEAGE: Final[dict[str, frozenset[str]]] = {
    "winword.exe": frozenset({"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"}),
    "excel.exe": frozenset({"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"}),
    "outlook.exe": frozenset({"powershell.exe", "cmd.exe", "wscript.exe"}),
    "powershell.exe": frozenset({"rundll32.exe", "regsvr32.exe", "mshta.exe"}),
    "w3wp.exe": frozenset({"cmd.exe", "powershell.exe"}),
}


class SuspiciousProcessLineageRule(EventRule):
    """Office or server processes spawning interpreters and proxy binaries."""

    rule_id = "SOC-EXEC-003"
    title = "Suspicious parent-child process relationship"
    description = (
        "A process spawned a child that is rare or illegitimate for that "
        "parent, a common sign of macro or exploit execution."
    )
    severity = "high"
    confidence = "medium"
    technique_ids = ("T1204.002", "T1218.011")
    sigma_rule = "proc_suspicious_lineage.yml"

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "process":
            return None
        parent = (event.parent_process or "").lower()
        child = (event.process or "").lower()
        if not parent or not child:
            return None
        if child not in _SUSPICIOUS_LINEAGE.get(parent, frozenset()):
            return None
        return {"parent_process": parent, "process": child}


# ---------------------------------------------------------------------------
# Rule 5 -- suspicious DNS
# ---------------------------------------------------------------------------


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character.

    Used as a cheap, explainable proxy for algorithmically generated domain
    labels. It is a heuristic: legitimate CDN hostnames also score highly,
    which is why this rule is medium-confidence and never auto-actions.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for char in value:
        counts[char] += 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * _log2(probability)
    return entropy


def _log2(value: float) -> float:
    from math import log2

    return log2(value)


class SuspiciousDNSRule(EventRule):
    """DNS queries whose leftmost label looks machine-generated."""

    rule_id = "SOC-DNS-001"
    title = "Suspicious DNS query (high-entropy label)"
    description = (
        "A DNS query used a long, high-entropy hostname label, consistent "
        "with algorithmically generated domains used for C2."
    )
    severity = "medium"
    confidence = "low"
    technique_ids = ("T1568.002",)
    sigma_rule = "dns_high_entropy_query.yml"

    min_label_length: Final[int] = 12
    min_entropy: Final[float] = 3.2

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "dns":
            return None
        domain = event.domain
        if not domain:
            return None
        label = domain.split(".", 1)[0]
        if len(label) < self.min_label_length:
            return None
        entropy = shannon_entropy(label)
        if entropy < self.min_entropy:
            return None
        return {
            "domain": domain,
            "label": label,
            "entropy": f"{entropy:.2f}",
        }


# ---------------------------------------------------------------------------
# Rule 6 -- credential dumping / LSASS access
# ---------------------------------------------------------------------------

_CREDENTIAL_ACCESS_MARKERS: Final[tuple[str, ...]] = (
    "lsass",
    "credential_access",
    "credential dumping",
    "sekurlsa",
)


class CredentialDumpingRule(EventRule):
    """LSASS access or an EDR credential-access alert.

    Fires even when the EDR reports `outcome == "blocked"`. A blocked attempt
    still proves intent and an active foothold; suppressing it would hide the
    most important event in the chain.
    """

    rule_id = "SOC-CRED-001"
    title = "Potential credential dumping (LSASS access)"
    description = (
        "Access to LSASS memory or an equivalent credential-access detection "
        "was observed, indicating an attempt to harvest credentials."
    )
    severity = "critical"
    confidence = "high"
    technique_ids = ("T1003.001",)
    sigma_rule = "cred_lsass_access.yml"

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        haystack = " ".join(
            part.lower()
            for part in (
                event.action,
                event.raw,
                str(event.details.get("rule_name", "")),
            )
            if part
        )
        hits = [marker for marker in _CREDENTIAL_ACCESS_MARKERS if marker in haystack]
        if not hits:
            return None
        return {
            "markers": ", ".join(hits),
            "process": event.process or "unknown",
            "outcome": event.outcome,
        }


# ---------------------------------------------------------------------------
# Rule 7 -- suspicious outbound connection
# ---------------------------------------------------------------------------

_INTERNAL_PREFIXES: Final[tuple[str, ...]] = ("10.", "192.168.", "172.16.", "192.0.2.")


class SuspiciousOutboundConnectionRule(ThresholdRule):
    """Repeated outbound connections to one external address (beacon-shaped).

    Two samples cannot prove a beacon interval, so this is medium confidence
    and deliberately describes the shape rather than asserting C2.
    """

    rule_id = "SOC-NET-001"
    title = "Repeated outbound connections to a single external host"
    description = (
        "A host made repeated outbound connections to the same external "
        "address, a pattern consistent with command-and-control beaconing."
    )
    severity = "high"
    confidence = "medium"
    technique_ids = ("T1071.001",)
    sigma_rule = "net_repeated_outbound.yml"
    threshold = 2
    window = timedelta(hours=1)

    def qualifies(self, event: SecurityEvent) -> bool:
        if event.category != "network":
            return False
        if event.details.get("direction") != "outbound":
            return False
        destination = event.destination_ip or ""
        return bool(destination) and not destination.startswith(_INTERNAL_PREFIXES)

    def group_key(self, event: SecurityEvent) -> str | None:
        if not event.hostname or not event.destination_ip:
            return None
        return f"{event.hostname}->{event.destination_ip}"


# ---------------------------------------------------------------------------
# Rule 8 -- MFA fatigue
# ---------------------------------------------------------------------------


class MFAFatigueRule(ThresholdRule):
    """Repeated MFA prompts denied by one user in a short window.

    The attacker has valid credentials and is spamming push prompts hoping the
    user approves one. Grouping is by user, not source IP, because the prompts
    land on the user's device regardless of where the attacker is.
    """

    rule_id = "SOC-AUTH-002"
    title = "MFA fatigue / push bombing"
    description = (
        "A single account denied repeated multi-factor prompts in a short "
        "window, consistent with an attacker who already holds the password."
    )
    severity = "high"
    confidence = "medium"
    technique_ids = ("T1621",)
    sigma_rule = "auth_mfa_fatigue.yml"
    threshold = 3
    window = timedelta(minutes=10)

    _MFA_ACTIONS: Final[frozenset[str]] = frozenset(
        {"mfa_denied", "mfa_bypass_attempt", "mfa_push_denied"}
    )

    def qualifies(self, event: SecurityEvent) -> bool:
        if event.category != "authentication":
            return False
        if event.action in self._MFA_ACTIONS:
            return True
        reason = str(event.details.get("failure_reason", ""))
        return "mfa" in reason.lower()

    def group_key(self, event: SecurityEvent) -> str | None:
        return event.username


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def default_rules() -> list[DetectionRule]:
    """The demonstration rule set, in stable order."""
    return [
        PasswordSprayRule(),
        MFAFatigueRule(),
        SuspiciousPowerShellRule(),
        EncodedPowerShellRule(),
        SuspiciousProcessLineageRule(),
        SuspiciousDNSRule(),
        CredentialDumpingRule(),
        SuspiciousOutboundConnectionRule(),
    ]


class DetectionEngine:
    """Runs a rule set over a batch of events.

    Rule failures are isolated: one broken rule must not silence the others,
    so exceptions are collected and surfaced rather than swallowed or allowed
    to abort the run.
    """

    def __init__(self, rules: Sequence[DetectionRule] | None = None) -> None:
        self.rules: list[DetectionRule] = list(
            rules if rules is not None else default_rules()
        )
        self._check_unique_rule_ids()

    def _check_unique_rule_ids(self) -> None:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.rule_id in seen:
                raise ValueError(f"duplicate rule_id: {rule.rule_id}")
            seen.add(rule.rule_id)

    def run(
        self, events: Sequence[SecurityEvent]
    ) -> tuple[list[DetectionResult], list[str]]:
        """Evaluate every rule.

        Returns (alerts, rule_errors). Alerts are sorted by severity then
        rule_id so output is deterministic and demo-stable.
        """
        alerts: list[DetectionResult] = []
        errors: list[str] = []
        for rule in self.rules:
            try:
                alerts.extend(rule.evaluate(events))
            except Exception as exc:  # noqa: BLE001 -- isolate a faulty rule
                errors.append(f"{rule.rule_id}: {type(exc).__name__}: {exc}")
        alerts.sort(key=lambda a: (-severity_rank(a.severity), a.rule_id, a.alert_id))
        return alerts, errors
