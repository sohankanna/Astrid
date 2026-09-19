"""Parsing and validation for normalized SOC security events.

This module is deliberately dependency-free (standard library only) so the
foundation can be exercised before the project settles on pydantic, a database
layer, or a web framework.

Security posture: every string inside an event is attacker-influenced data.
Parsing here answers only "is this structurally a valid event?" -- it never
decides that content is safe. Callers that pass event text to an LLM must
treat it as untrusted (see prompts/SOC_ANALYST_PROMPT.md).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Iterator

SCHEMA_VERSION: Final[str] = "1.0.0"

# The original endpoint/network vocabulary. Kept as its own constant (rather
# than extended in place) because the endpoint dataset is required to cover
# exactly this set -- see tests/test_security_events.py.
VALID_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"authentication", "process", "network", "dns", "alert"}
)

# Cloud control-plane telemetry (e.g. AWS CloudTrail). Added additively:
# every pre-existing dataset remains valid unchanged. VPC Flow Logs reuse the
# `network` category and GuardDuty-style findings reuse `alert`; only API
# audit events needed a new category.
CLOUD_CATEGORIES: Final[frozenset[str]] = frozenset({"cloud"})

# What parse_event() actually accepts.
ALL_CATEGORIES: Final[frozenset[str]] = VALID_CATEGORIES | CLOUD_CATEGORIES

VALID_SEVERITIES: Final[frozenset[str]] = frozenset(
    {"informational", "low", "medium", "high", "critical"}
)
VALID_OUTCOMES: Final[frozenset[str]] = frozenset(
    {"success", "failure", "blocked", "unknown"}
)

# Category -> the detail object that category must carry.
REQUIRED_DETAIL_BY_CATEGORY: Final[dict[str, str]] = {
    "authentication": "auth",
    "process": "process",
    "network": "network",
    "dns": "dns",
    "alert": "alert",
    "cloud": "cloud",
}

_REQUIRED_TOP_LEVEL_FIELDS: Final[tuple[str, ...]] = (
    "event_id",
    "timestamp",
    "source",
    "category",
    "action",
    "outcome",
    "severity",
    "host",
)

# Cloud control-plane events have no machine behind them: an IAM API call is
# made *to* AWS, not *on* a host. Forcing a placeholder hostname (e.g. the
# account ID) would make every event in an account share one "host" entity
# and the correlation engine would merge unrelated incidents. So `host` is
# optional when an event is cloud-native -- category `cloud`, or any event
# carrying a `cloud` context object (e.g. an IAM-scoped GuardDuty finding).
_HOST_OPTIONAL_FIELDS: Final[tuple[str, ...]] = tuple(
    f for f in _REQUIRED_TOP_LEVEL_FIELDS if f != "host"
)

# Upper bound on any single string field. Prevents a single oversized log line
# from blowing out an LLM context window or a downstream UI.
MAX_FIELD_LENGTH: Final[int] = 4096


class EventValidationError(ValueError):
    """Raised when an event cannot be parsed into a valid SecurityEvent."""

    def __init__(self, message: str, *, event_id: str | None = None) -> None:
        self.event_id = event_id
        location = f" (event_id={event_id})" if event_id else ""
        super().__init__(f"{message}{location}")


@dataclass(frozen=True)
class SecurityEvent:
    """A normalized security event.

    `details` holds the category-specific object (auth/process/network/dns/alert)
    and `raw` holds the original vendor log line. Both are untrusted.
    """

    event_id: str
    timestamp: datetime
    source: str
    category: str
    action: str
    outcome: str
    severity: str
    host: dict[str, Any]
    user: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    aux: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Detail objects present on the event beyond its own category's.

    An EDR `alert` event commonly also carries the `process` object it fired
    on. Keeping those here means a detection rule can ask about the process
    without caring which category delivered it.
    """

    def detail(self, key: str, *, scope: str | None = None) -> Any:
        """Look a detail field up in this event's own details, then in `aux`.

        `scope` optionally restricts the aux lookup to one detail object
        (e.g. scope="process"), which avoids a field name colliding across
        two different objects.
        """
        if scope is None and key in self.details:
            return self.details[key]
        if scope is not None:
            scoped = self.details if self.category == scope else self.aux.get(scope, {})
            return scoped.get(key)
        for obj in self.aux.values():
            if key in obj:
                return obj[key]
        return None

    @property
    def is_noteworthy(self) -> bool:
        """True for severities an analyst queue should surface by default."""
        return self.severity in {"high", "critical"}

    # ------------------------------------------------------------------
    # Flat accessors.
    #
    # The stored shape is nested (host/user/details) because that is how log
    # sources present data and how it round-trips to JSON. Detection rules,
    # however, read far better against flat field names. These read-only
    # properties provide that view without duplicating state, so there is
    # exactly one source of truth per value.
    #
    # Every accessor returns None when the field is absent rather than
    # raising: a detection rule asking a DNS question of a process event is
    # normal control flow, not an error.
    # ------------------------------------------------------------------

    @property
    def event_type(self) -> str:
        """Alias for `category`, matching the flat schema vocabulary."""
        return self.category

    @property
    def raw_message(self) -> str:
        """Alias for `raw`. Untrusted, attacker-influenced text."""
        return self.raw

    @property
    def hostname(self) -> str | None:
        return self.host.get("hostname")

    @property
    def username(self) -> str | None:
        return self.user.get("name")

    @property
    def source_ip(self) -> str | None:
        """Originating address, wherever this category records it.

        Falls back to the host's own IP so that host-local activity still has
        an entity to correlate on.
        """
        value = self.detail("source_ip")
        if isinstance(value, str):
            return value
        host_ip = self.host.get("ip")
        return host_ip if isinstance(host_ip, str) else None

    @property
    def destination_ip(self) -> str | None:
        value = self.detail("destination_ip")
        return value if isinstance(value, str) else None

    @property
    def destination_port(self) -> int | None:
        value = self.detail("destination_port")
        return value if isinstance(value, int) else None

    @property
    def process(self) -> str | None:
        """Process image name, from a process event or an alert's process."""
        value = self.detail("name", scope="process")
        return value if isinstance(value, str) else None

    @property
    def parent_process(self) -> str | None:
        value = self.detail("parent_name", scope="process")
        return value if isinstance(value, str) else None

    @property
    def command_line(self) -> str | None:
        """Attacker-controlled in the general case. Never execute or eval."""
        value = self.detail("command_line", scope="process")
        return value if isinstance(value, str) else None

    @property
    def domain(self) -> str | None:
        """DNS query name for dns events. Attacker-controlled."""
        value = self.detail("query_name", scope="dns")
        return value if isinstance(value, str) else None

    @property
    def file_hash(self) -> str | None:
        value = self.detail("hash_sha256", scope="process")
        return value if isinstance(value, str) else None

    @property
    def scenario(self) -> str | None:
        """Synthetic-dataset scenario tag (test data only, never from a real feed)."""
        value = self.metadata.get("scenario")
        return value if isinstance(value, str) else None

    # ------------------------------------------------------------------
    # Cloud accessors.
    #
    # A `cloud` object is either this event's own details (category `cloud`,
    # e.g. a CloudTrail API call) or an auxiliary context object on another
    # category (a VPC flow `network` event or a GuardDuty `alert`). These
    # accessors hide that difference from detection rules.
    #
    # Trust note: CloudTrail envelope fields (eventName, eventSource,
    # identity type, account) are written by AWS. Request parameters, the
    # user agent, and every name an attacker chose (user names, role
    # descriptions, tags) are attacker-controlled and must be treated as such.
    # ------------------------------------------------------------------

    @property
    def cloud(self) -> dict[str, Any]:
        """The cloud context object, or an empty dict for non-cloud events."""
        if self.category in CLOUD_CATEGORIES:
            return self.details
        value = self.aux.get("cloud", {})
        return value if isinstance(value, dict) else {}

    @property
    def is_cloud(self) -> bool:
        return bool(self.cloud)

    def _cloud_str(self, key: str) -> str | None:
        value = self.cloud.get(key)
        return value if isinstance(value, str) else None

    @property
    def cloud_provider(self) -> str | None:
        return self._cloud_str("provider")

    @property
    def cloud_event_name(self) -> str | None:
        """API operation, e.g. 'AssumeRole'. Set by the cloud provider."""
        return self._cloud_str("event_name")

    @property
    def cloud_event_source(self) -> str | None:
        """Service endpoint, e.g. 'iam.amazonaws.com'."""
        return self._cloud_str("event_source")

    @property
    def account_id(self) -> str | None:
        return self._cloud_str("account_id")

    @property
    def region(self) -> str | None:
        return self._cloud_str("region")

    @property
    def identity_type(self) -> str | None:
        """'IAMUser', 'AssumedRole', 'Root', 'AWSService', ..."""
        return self._cloud_str("identity_type")

    @property
    def principal_arn(self) -> str | None:
        return self._cloud_str("principal_arn")

    @property
    def session_issuer_arn(self) -> str | None:
        """For assumed-role sessions: the role the session was issued from."""
        return self._cloud_str("session_issuer_arn")

    @property
    def access_key_id(self) -> str | None:
        return self._cloud_str("access_key_id")

    @property
    def user_agent(self) -> str | None:
        """Client-supplied and therefore attacker-controlled."""
        return self._cloud_str("user_agent")

    @property
    def mfa_authenticated(self) -> bool | None:
        value = self.cloud.get("mfa_authenticated")
        return value if isinstance(value, bool) else None

    @property
    def error_code(self) -> str | None:
        return self._cloud_str("error_code")

    @property
    def request_parameters(self) -> dict[str, Any]:
        """Attacker-controlled API arguments. Never execute or interpolate."""
        value = self.cloud.get("request_parameters")
        return value if isinstance(value, dict) else {}

    @property
    def response_elements(self) -> dict[str, Any]:
        value = self.cloud.get("response_elements")
        return value if isinstance(value, dict) else {}

    @property
    def cloud_resources(self) -> list[str]:
        """Resource identifiers (ARNs / IDs) the event acted on."""
        value = self.cloud.get("resources")
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]


def parse_timestamp(value: str) -> datetime:
    """Parse an RFC 3339 / ISO 8601 timestamp into a UTC-aware datetime.

    Raises EventValidationError rather than letting ValueError escape, so
    callers have a single exception type to handle.
    """
    if not isinstance(value, str):
        raise EventValidationError(
            f"timestamp must be a string, got {type(value).__name__}"
        )
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EventValidationError(
            f"timestamp is not valid ISO 8601: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise EventValidationError(
            f"timestamp must include a timezone offset: {value!r}"
        )
    return parsed.astimezone(timezone.utc)


def _require_str(obj: dict[str, Any], key: str, event_id: str | None) -> str:
    """Return obj[key] if it is a non-empty, length-bounded string."""
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise EventValidationError(
            f"field {key!r} must be a non-empty string", event_id=event_id
        )
    if len(value) > MAX_FIELD_LENGTH:
        raise EventValidationError(
            f"field {key!r} exceeds MAX_FIELD_LENGTH "
            f"({len(value)} > {MAX_FIELD_LENGTH})",
            event_id=event_id,
        )
    return value


def _is_cloud_native(obj: dict[str, Any]) -> bool:
    """True for cloud control-plane events, which may legitimately lack a host."""
    return obj.get("category") in CLOUD_CATEGORIES or isinstance(
        obj.get("cloud"), dict
    )


def parse_event(obj: Any) -> SecurityEvent:
    """Validate one raw mapping and return a SecurityEvent.

    Raises EventValidationError on any structural problem.
    """
    if not isinstance(obj, dict):
        raise EventValidationError(
            f"event must be an object, got {type(obj).__name__}"
        )

    event_id = obj.get("event_id") if isinstance(obj.get("event_id"), str) else None

    cloud_native = _is_cloud_native(obj)
    required = _HOST_OPTIONAL_FIELDS if cloud_native else _REQUIRED_TOP_LEVEL_FIELDS
    missing = [f for f in required if f not in obj]
    if missing:
        raise EventValidationError(
            f"missing required field(s): {', '.join(missing)}", event_id=event_id
        )

    for key in ("event_id", "source", "category", "action", "outcome", "severity"):
        _require_str(obj, key, event_id)

    category = obj["category"]
    if category not in ALL_CATEGORIES:
        raise EventValidationError(
            f"unknown category {category!r}; expected one of "
            f"{sorted(ALL_CATEGORIES)}",
            event_id=event_id,
        )

    severity = obj["severity"]
    if severity not in VALID_SEVERITIES:
        raise EventValidationError(
            f"unknown severity {severity!r}; expected one of "
            f"{sorted(VALID_SEVERITIES)}",
            event_id=event_id,
        )

    outcome = obj["outcome"]
    if outcome not in VALID_OUTCOMES:
        raise EventValidationError(
            f"unknown outcome {outcome!r}; expected one of "
            f"{sorted(VALID_OUTCOMES)}",
            event_id=event_id,
        )

    host = obj.get("host", {})
    if not isinstance(host, dict):
        raise EventValidationError("host must be an object", event_id=event_id)
    if not cloud_native and not host.get("hostname"):
        raise EventValidationError(
            "host must be an object with a 'hostname'", event_id=event_id
        )

    user = obj.get("user", {})
    if not isinstance(user, dict):
        raise EventValidationError(
            "user must be an object when present", event_id=event_id
        )

    detail_key = REQUIRED_DETAIL_BY_CATEGORY[category]
    details = obj.get(detail_key)
    if not isinstance(details, dict) or not details:
        raise EventValidationError(
            f"category {category!r} requires a non-empty {detail_key!r} object",
            event_id=event_id,
        )

    raw = obj.get("raw", "")
    if not isinstance(raw, str):
        raise EventValidationError(
            "raw must be a string when present", event_id=event_id
        )
    if len(raw) > MAX_FIELD_LENGTH:
        raise EventValidationError(
            f"raw exceeds MAX_FIELD_LENGTH ({len(raw)} > {MAX_FIELD_LENGTH})",
            event_id=event_id,
        )

    # Detail objects belonging to other categories (e.g. the `process` an EDR
    # alert fired on) are kept rather than discarded, so detection rules can
    # reach them. Only known detail keys are collected: arbitrary top-level
    # keys are not promoted into the event.
    aux = {
        other_key: obj[other_key]
        for other_key in REQUIRED_DETAIL_BY_CATEGORY.values()
        if other_key != detail_key
        and isinstance(obj.get(other_key), dict)
        and obj[other_key]
    }

    metadata = obj.get("metadata", {})
    if not isinstance(metadata, dict):
        raise EventValidationError(
            "metadata must be an object when present", event_id=event_id
        )
    # `scenario` and `notes` are synthetic-dataset annotations, not log fields.
    metadata = dict(metadata)
    for annotation in ("scenario", "notes"):
        if isinstance(obj.get(annotation), str):
            metadata.setdefault(annotation, obj[annotation])

    return SecurityEvent(
        event_id=obj["event_id"],
        timestamp=parse_timestamp(obj["timestamp"]),
        source=obj["source"],
        category=category,
        action=obj["action"],
        outcome=outcome,
        severity=severity,
        host=host,
        user=user,
        details=details,
        raw=raw,
        metadata=metadata,
        aux=aux,
    )


def parse_events(raw_events: Any) -> list[SecurityEvent]:
    """Parse a list of raw events, rejecting duplicate event_ids.

    Fails fast: one bad event invalidates the batch, so a malformed or poisoned
    record cannot be silently dropped without anyone noticing.
    """
    if not isinstance(raw_events, list):
        raise EventValidationError(
            f"'events' must be a list, got {type(raw_events).__name__}"
        )

    parsed: list[SecurityEvent] = []
    seen: set[str] = set()
    for item in raw_events:
        event = parse_event(item)
        if event.event_id in seen:
            raise EventValidationError(
                "duplicate event_id in batch", event_id=event.event_id
            )
        seen.add(event.event_id)
        parsed.append(event)
    return parsed


def load_events(path: str | Path) -> list[SecurityEvent]:
    """Load and validate an event dataset file.

    The file must be a JSON object carrying 'schema_version' and 'events'.
    """
    dataset_path = Path(path)
    try:
        text = dataset_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EventValidationError(
            f"cannot read dataset {dataset_path}: {exc}"
        ) from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EventValidationError(
            f"dataset {dataset_path} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise EventValidationError("dataset root must be a JSON object")

    version = payload.get("schema_version")
    if version != SCHEMA_VERSION:
        raise EventValidationError(
            f"unsupported schema_version {version!r}; "
            f"this module expects {SCHEMA_VERSION!r}"
        )

    return parse_events(payload.get("events", []))


def iter_untrusted_text(event: SecurityEvent) -> Iterator[tuple[str, str]]:
    """Yield (field_path, text) for every attacker-influenced string in an event.

    Used by injection-screening and redaction steps before event text reaches an
    LLM. Nested containers are walked so a payload cannot hide one level down.
    """

    def walk(prefix: str, value: Any) -> Iterator[tuple[str, str]]:
        if isinstance(value, str):
            yield prefix, value
        elif isinstance(value, dict):
            for key, nested in value.items():
                yield from walk(f"{prefix}.{key}", nested)
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                yield from walk(f"{prefix}[{index}]", nested)

    yield from walk("host", event.host)
    yield from walk("user", event.user)
    yield from walk("details", event.details)
    for aux_key, aux_obj in event.aux.items():
        yield from walk(f"aux.{aux_key}", aux_obj)
    if event.raw:
        yield "raw", event.raw
