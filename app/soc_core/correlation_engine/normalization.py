"""Generic event normalization.

Accepts the project's `SecurityEvent` objects and loosely-shaped dicts from
other sources. Every field is optional: a sparse event normalizes to what it
has. Invalid values are dropped and recorded in `issues`, never guessed.
Inputs that are not events at all are rejected with a reason (reported,
not silently skipped). The input object is never modified.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Final, Iterable, Mapping

from ..detections import DetectionResult
from ..events import SecurityEvent
from .models import SEVERITY_SCALE, NormalizationReport, NormalizedEvent, RejectedInput

MAX_FIELD_LENGTH: Final[int] = 512
_TECHNIQUE: Final[re.Pattern[str]] = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MISSING: Final[object] = object()

# Candidate paths per normalized field, tried in order. Dotted paths walk
# nested dicts. Covers the project schema plus common SIEM/EDR/cloud names.
ALIASES: Final[dict[str, tuple[str, ...]]] = {
    "event_id": ("event_id", "id", "eventID", "event.id", "_id", "uid"),
    "timestamp": ("timestamp", "@timestamp", "time", "ts", "eventTime", "event_time", "event.created"),
    "event_type": ("event_type", "category", "eventType", "type", "event.category"),
    "severity": ("severity", "level", "priority", "event.severity"),
    "source": ("source", "log_source", "sourcetype", "provider", "event.provider"),
    "hostname": ("hostname", "host.hostname", "host.name", "computer", "device", "host"),
    "source_ip": ("source_ip", "src_ip", "src", "sourceIPAddress", "client_ip", "source.ip",
                  "auth.source_ip", "network.source_ip", "cloud.source_ip"),
    "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "dst", "destination.ip",
                       "network.destination_ip"),
    "source_port": ("source_port", "src_port", "sport", "source.port", "network.source_port"),
    "destination_port": ("destination_port", "dest_port", "dst_port", "dport", "destination.port",
                         "network.destination_port"),
    "username": ("username", "user_name", "user.name", "userIdentity.userName", "account_name", "user"),
    "account": ("account", "account_id", "recipientAccountId", "cloud.account_id", "cloud.account.id"),
    "process": ("process_name", "process.name", "image", "process"),
    "parent_process": ("parent_process", "parent_process_name", "parent_image", "process.parent_name"),
    "command": ("command", "command_line", "cmdline", "process.command_line"),
    "action": ("action", "eventName", "event_name", "operation", "event.action"),
    "status": ("status", "outcome", "result", "event.outcome"),
    "detection_id": ("detection_id", "alert_id", "detection_ids", "alert_ids"),
    "rule_id": ("rule_id", "rule", "signature_id", "rule_ids", "rule.id"),
    "technique": ("technique", "technique_id", "mitre_technique", "technique_ids", "mitre", "alert.technique_ids"),
    "resource": ("resource", "resources", "cloud.resources", "resource_id", "bucketName",
                 "cloud.request_parameters.bucketName"),
}


def normalize_events(
    events: Iterable[Any],
    *,
    detections: Iterable[DetectionResult | Mapping[str, Any]] = (),
) -> tuple[list[NormalizedEvent], NormalizationReport]:
    """Normalize a stream of events.

    `detections` (optional) attaches detection/rule/technique IDs to the
    events they cite, whatever produced them (the project's DetectionEngine,
    or an external alert feed as dicts with `evidence_event_ids`).
    """
    by_event = _detections_by_event(detections)
    report = NormalizationReport()
    out: list[NormalizedEvent] = []
    for position, raw in enumerate(events):
        try:
            if isinstance(raw, SecurityEvent):
                event = _from_security_event(len(out), raw)
            elif isinstance(raw, Mapping):
                event = _from_mapping(len(out), raw)
            else:
                report.rejected.append(RejectedInput(position, f"unsupported input type {type(raw).__name__}"))
                continue
        except (TypeError, ValueError) as exc:
            report.rejected.append(RejectedInput(position, f"malformed event: {exc}"))
            continue
        extra = by_event.get(event.event_id)
        if extra:
            event.detection_ids = _merge(event.detection_ids, extra[0])
            event.rule_ids = _merge(event.rule_ids, extra[1])
            event.techniques = _merge(event.techniques, extra[2])
        for issue in event.issues:
            kind = issue.split(":", 1)[0]
            report.issues_by_kind[kind] = report.issues_by_kind.get(kind, 0) + 1
        out.append(event)
    report.accepted = len(out)
    return out, report


# ---------------------------------------------------------------------------


def _from_security_event(index: int, event: SecurityEvent) -> NormalizedEvent:
    """The project's validated event type: read through its flat accessors."""
    issues: list[str] = []
    resources = list(event.cloud_resources)
    for key in ("bucketName", "groupId", "roleArn"):
        value = event.request_parameters.get(key)
        if isinstance(value, str):
            resources.append(value)
    alert_techniques = event.detail("technique_ids", scope="alert")
    return NormalizedEvent(
        index=index,
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_type=_text(event.category, "event_type", issues),
        severity=SEVERITY_SCALE.get(event.severity, 0),
        source=_text(event.source, "source", issues),
        hostname=_text(event.hostname, "hostname", issues),
        source_ip=_ip(event.source_ip, "source_ip", issues),
        destination_ip=_ip(event.destination_ip, "destination_ip", issues),
        source_port=_port(event.detail("source_port"), "source_port", issues),
        destination_port=_port(event.destination_port, "destination_port", issues),
        username=_text(event.username, "username", issues),
        account=_text(event.account_id, "account", issues),
        process=_text(event.process, "process", issues),
        parent_process=_text(event.parent_process, "parent_process", issues),
        command=_text(event.command_line, "command", issues),
        action=_text(event.cloud_event_name or event.action, "action", issues),
        status=_text(event.outcome, "status", issues),
        techniques=_techniques(alert_techniques, issues),
        resources=_strings(resources, "resource", issues),
        issues=tuple(issues),
        original=event,
    )


def _from_mapping(index: int, raw: Mapping[str, Any]) -> NormalizedEvent:
    issues: list[str] = []
    event_id = _lookup(raw, "event_id")
    if isinstance(event_id, (int, str)) and str(event_id).strip():
        event_id = _clip(str(event_id).strip())
    else:
        event_id = f"anon-{index:06d}"
        issues.append("missing:event_id")
    timestamp = _timestamp(_lookup(raw, "timestamp"), issues)
    host = _lookup(raw, "hostname")
    if isinstance(host, Mapping):
        host = host.get("hostname") or host.get("name")
    user = _lookup(raw, "username")
    if isinstance(user, Mapping):
        user = user.get("name")
    process = _lookup(raw, "process")
    if isinstance(process, Mapping):
        process = process.get("name")
    return NormalizedEvent(
        index=index,
        event_id=event_id,
        timestamp=timestamp,
        event_type=_text(_lookup(raw, "event_type"), "event_type", issues),
        severity=_severity(_lookup(raw, "severity"), issues),
        source=_text(_lookup(raw, "source"), "source", issues),
        hostname=_text(host, "hostname", issues),
        source_ip=_ip(_lookup(raw, "source_ip"), "source_ip", issues),
        destination_ip=_ip(_lookup(raw, "destination_ip"), "destination_ip", issues),
        source_port=_port(_lookup(raw, "source_port"), "source_port", issues),
        destination_port=_port(_lookup(raw, "destination_port"), "destination_port", issues),
        username=_text(user, "username", issues),
        account=_text(_lookup(raw, "account"), "account", issues),
        process=_text(process, "process", issues),
        parent_process=_text(_lookup(raw, "parent_process"), "parent_process", issues),
        command=_text(_lookup(raw, "command"), "command", issues),
        action=_text(_lookup(raw, "action"), "action", issues),
        status=_text(_lookup(raw, "status"), "status", issues),
        detection_ids=_strings(_lookup(raw, "detection_id"), "detection_id", issues),
        rule_ids=_strings(_lookup(raw, "rule_id"), "rule_id", issues),
        techniques=_techniques(_lookup(raw, "technique"), issues),
        resources=_strings(_lookup(raw, "resource"), "resource", issues),
        issues=tuple(issues),
        original=raw,
    )


def _lookup(raw: Mapping[str, Any], name: str) -> Any:
    for path in ALIASES[name]:
        value = _path(raw, path)
        if value is not _MISSING and value is not None:
            return value
    return None


def _path(raw: Mapping[str, Any], path: str) -> Any:
    if path in raw:
        return raw[path]
    if "." not in path:
        return _MISSING
    node: Any = raw
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _clip(value: str) -> str:
    return value if len(value) <= MAX_FIELD_LENGTH else value[:MAX_FIELD_LENGTH]


def _text(value: Any, name: str, issues: list[str]) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        issues.append(f"invalid_type:{name}")
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > MAX_FIELD_LENGTH:
        issues.append(f"truncated:{name}")
    return _clip(text)


def _ip(value: Any, name: str, issues: list[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        issues.append(f"invalid_ip:{name}")
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        # CloudTrail puts service hostnames here (e.g. "ec2.amazonaws.com").
        issues.append(f"invalid_ip:{name}")
        return None


def _port(value: Any, name: str, issues: list[str]) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        issues.append(f"invalid_port:{name}")
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        issues.append(f"invalid_port:{name}")
        return None
    if not 0 <= port <= 65535:
        issues.append(f"invalid_port:{name}")
        return None
    return port


def _severity(value: Any, issues: list[str]) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        mapped = SEVERITY_SCALE.get(value.strip().lower())
        if mapped is not None:
            return mapped
        if value.strip().isdigit():
            value = int(value.strip())
        else:
            issues.append("invalid_severity")
            return 0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, min(4, int(value)))
    issues.append("invalid_severity")
    return 0


def _timestamp(value: Any, issues: list[str]) -> datetime | None:
    if value is None:
        issues.append("missing:timestamp")
        return None
    try:
        if isinstance(value, datetime):
            ts = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            seconds = value / 1000 if value > 1e11 else value   # epoch ms or s
            ts = datetime.fromtimestamp(seconds, tz=timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            ts = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        else:
            raise ValueError
    except (ValueError, OverflowError, OSError):
        issues.append("invalid:timestamp")
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _strings(value: Any, name: str, issues: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    items = value if isinstance(value, (list, tuple)) else [value]
    out: list[str] = []
    for item in items:
        text = _text(item, name, issues)
        if text and text not in out:
            out.append(text)
    return tuple(out)


def _techniques(value: Any, issues: list[str]) -> tuple[str, ...]:
    valid: list[str] = []
    for item in _strings(value, "technique", issues):
        if _TECHNIQUE.match(item.upper()):
            if item.upper() not in valid:
                valid.append(item.upper())
        else:
            issues.append("invalid:technique")
    return tuple(valid)


def _merge(existing: tuple[str, ...], extra: Iterable[str]) -> tuple[str, ...]:
    out = list(existing)
    for item in extra:
        if item not in out:
            out.append(item)
    return tuple(out)


def _detections_by_event(
    detections: Iterable[DetectionResult | Mapping[str, Any]],
) -> dict[str, tuple[list[str], list[str], list[str]]]:
    """event_id -> (detection IDs, rule IDs, techniques) citing it."""
    out: dict[str, tuple[list[str], list[str], list[str]]] = {}
    for det in detections:
        if isinstance(det, DetectionResult):
            alert_id, rule_id, techniques, evidence = det.alert_id, det.rule_id, det.technique_ids, det.evidence_event_ids
        elif isinstance(det, Mapping):
            alert_id, rule_id = det.get("alert_id"), det.get("rule_id")
            techniques, evidence = det.get("technique_ids", ()), det.get("evidence_event_ids", ())
        else:
            raise TypeError(f"unsupported detection type {type(det).__name__}")
        if not isinstance(evidence, (list, tuple)):
            raise ValueError("detection evidence_event_ids must be a list")
        for event_id in evidence:
            if not isinstance(event_id, str):
                continue
            ids, rules, techs = out.setdefault(event_id, ([], [], []))
            if isinstance(alert_id, str) and alert_id not in ids:
                ids.append(alert_id)
            if isinstance(rule_id, str) and rule_id not in rules:
                rules.append(rule_id)
            for tech in techniques or ():
                if isinstance(tech, str) and _TECHNIQUE.match(tech) and tech not in techs:
                    techs.append(tech)
    return out
