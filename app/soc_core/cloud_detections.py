"""Deterministic cloud-security detections (AWS control plane).

These are ordinary `DetectionRule`s. They run on the same `DetectionEngine`,
produce the same `DetectionResult`, and feed the same correlation, risk and
AI pipeline as the endpoint rules. There is no second engine.

Same rule as the rest of the codebase: **no AI decides whether a rule fired.**

Kept in a separate module (rather than appended to `default_rules()`) so the
endpoint profile, its demo output and its tests are byte-for-byte unchanged.
Use `all_rules()` to run both.

Trust note for rule authors
---------------------------
CloudTrail's envelope (eventName, eventSource, userIdentity.type, account)
is written by AWS and can be relied on for *matching*. Request parameters,
the user agent, and any name or description an attacker chose are
attacker-controlled. Rules may match on them, but must never execute,
decode-and-run, or interpolate them into anything that is.

Environment-specific constants
------------------------------
`SENSITIVE_BUCKETS`, `SENSITIVE_PORTS` and the internal address prefixes are
tuned to the synthetic dataset. **They must be revised for any real
environment.** A stale sensitive-bucket list silently disables CLOUD-S3-001.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Final, Sequence

from .detections import (
    _INTERNAL_PREFIXES,
    DetectionResult,
    DetectionRule,
    EventRule,
    ThresholdRule,
    default_rules,
)
from .events import SecurityEvent

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

AWS_SERVICE_IDENTITY: Final[str] = "AWSService"

SENSITIVE_BUCKETS: Final[frozenset[str]] = frozenset(
    {"corp-finance-archive", "hr-records"}
)

# Ports that should never be reachable from the whole internet.
SENSITIVE_PORTS: Final[frozenset[int]] = frozenset(
    {22, 23, 1433, 2375, 3306, 3389, 5432, 6379, 9200, 27017}
)
OPEN_CIDRS: Final[frozenset[str]] = frozenset({"0.0.0.0/0", "::/0"})

ADMIN_POLICY_SUFFIXES: Final[tuple[str, ...]] = (
    ":policy/AdministratorAccess",
    ":policy/IAMFullAccess",
)
POLICY_ATTACH_EVENTS: Final[frozenset[str]] = frozenset(
    {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
)
INLINE_POLICY_EVENTS: Final[frozenset[str]] = frozenset(
    {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicyVersion"}
)

# Logging tampering. Destructive events stop or remove telemetry outright;
# modifying events can narrow it silently but also occur in normal admin work.
LOG_TAMPER_DESTRUCTIVE: Final[frozenset[str]] = frozenset(
    {"StopLogging", "DeleteTrail", "DeleteFlowLogs"}
)
LOG_TAMPER_MODIFYING: Final[frozenset[str]] = frozenset(
    {"UpdateTrail", "PutEventSelectors"}
)

S3_READ_EVENTS: Final[frozenset[str]] = frozenset({"GetObject", "CopyObject"})
DISCOVERY_PREFIXES: Final[tuple[str, ...]] = ("List", "Describe", "Get")

GUARDDUTY_VENDOR: Final[str] = "aws-guardduty"
GUARDDUTY_HIGH: Final[float] = 7.0
GUARDDUTY_CRITICAL: Final[float] = 9.0

# Finding type -> ATT&CK, ONLY where the finding type's documented meaning maps
# cleanly onto one technique. Unknown types map to nothing rather than to a
# guess: an absent mapping is honest; an invented one is a hallucination we
# wrote ourselves.
GUARDDUTY_TECHNIQUES: Final[dict[str, tuple[str, ...]]] = {
    "Exfiltration:S3/AnomalousBehavior": ("T1530",),
    "Stealth:IAMUser/CloudTrailLoggingDisabled": ("T1562.008",),
    "Discovery:IAMUser/AnomalousBehavior": ("T1580",),
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": ("T1078.004",),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_external_source(value: str | None) -> bool:
    """True when `value` is an IP address outside our internal ranges.

    CloudTrail records AWS-internal callers with a service hostname
    ('ec2.amazonaws.com') instead of an IP; those are not external. Uses the
    same internal prefixes as the endpoint rules so the two never disagree.
    """
    if not value or "amazonaws.com" in value or value == "AWS Internal":
        return False
    if not any(char.isdigit() for char in value):
        return False
    return not value.startswith(_INTERNAL_PREFIXES)


def arn_account(arn: str | None) -> str | None:
    """Account ID from an ARN ('arn:aws:iam::111122223333:role/x')."""
    if not arn or not arn.startswith("arn:"):
        return None
    parts = arn.split(":")
    if len(parts) < 5 or not parts[4]:
        return None
    return parts[4]


def principal_key(event: SecurityEvent) -> str | None:
    """Stable identity for grouping: the role behind a session, else the ARN.

    Grouping assumed-role sessions by their *issuer* means a new session name
    cannot reset a threshold counter.
    """
    return event.session_issuer_arn or event.principal_arn or event.username


def _is_api(event: SecurityEvent, names: frozenset[str] | set[str]) -> bool:
    return event.category == "cloud" and event.cloud_event_name in names


def _policy_grants_admin(document: Any) -> tuple[bool, str]:
    """Return (is_admin, reason) for an IAM policy document.

    An unparsable document is reported as a match: a policy we cannot read is
    a policy we cannot clear, and failing toward visibility is the safe
    direction for a detection.
    """
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return True, "policy document could not be parsed"
    if not isinstance(document, dict):
        return True, "policy document has an unexpected shape"

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return True, "policy Statement has an unexpected shape"

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        if ("*" in actions or "iam:*" in actions) and "*" in resources:
            return True, f"Allow {'/'.join(actions)} on Resource *"
    return False, ""


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# ---------------------------------------------------------------------------
# 1. Root account activity
# ---------------------------------------------------------------------------


class RootAccountActivityRule(EventRule):
    """Any API or console activity by the account root user.

    Root should be used almost never, behind hardware MFA, for a handful of
    tasks that require it. Every use is worth a human look.
    """

    rule_id = "CLOUD-ROOT-001"
    title = "AWS root account activity"
    description = (
        "The account root user performed an action. Root bypasses IAM "
        "permission boundaries and should almost never be used."
    )
    severity = "high"
    confidence = "high"
    technique_ids = ("T1078.004",)

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "cloud" or event.identity_type != "Root":
            return None
        return {
            "event_name": event.cloud_event_name or event.action,
            "account_id": event.account_id or "unknown",
            "source_ip": event.source_ip or "unknown",
        }


# ---------------------------------------------------------------------------
# 2. Console login without MFA
# ---------------------------------------------------------------------------


class ConsoleLoginWithoutMFARule(EventRule):
    """Successful console sign-in where MFA was explicitly not used.

    Fires only on an explicit `mfa_authenticated: false`. A missing value is
    unknown, not negative, and is left to a data-quality check rather than
    guessed here.
    """

    rule_id = "CLOUD-AUTH-001"
    title = "AWS console login without MFA"
    description = (
        "A successful AWS console login did not use multi-factor "
        "authentication; a stolen password alone was sufficient."
    )
    severity = "high"
    confidence = "high"
    technique_ids = ("T1078.004",)

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if not _is_api(event, {"ConsoleLogin"}) or event.outcome != "success":
            return None
        if event.mfa_authenticated is not False:
            return None
        return {
            "principal": event.principal_arn or event.username or "unknown",
            "identity_type": event.identity_type or "unknown",
            "source_ip": event.source_ip or "unknown",
        }


# ---------------------------------------------------------------------------
# 3. Unusual AssumeRole
# ---------------------------------------------------------------------------


class UnusualAssumeRoleRule(EventRule):
    """AssumeRole that is cross-account, chained, or from an external address.

    Each is legitimate in some environments (vendor integrations are
    cross-account; automation chains roles). That is why this rule is medium
    confidence and records *which* condition fired, so an analyst can dismiss
    a known pattern quickly.
    """

    rule_id = "CLOUD-IAM-001"
    title = "Unusual AWS role assumption"
    description = (
        "A role was assumed across accounts, by an already-assumed role "
        "(role chaining), or from outside internal address ranges."
    )
    severity = "medium"
    confidence = "medium"
    technique_ids = ("T1078.004",)

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if not _is_api(event, {"AssumeRole"}) or event.outcome != "success":
            return None
        if event.identity_type == AWS_SERVICE_IDENTITY:
            return None

        role_arn = str(event.request_parameters.get("roleArn", ""))
        reasons: list[str] = []

        caller_account = arn_account(event.principal_arn)
        role_account = arn_account(role_arn)
        if caller_account and role_account and caller_account != role_account:
            reasons.append("cross-account")
        if event.identity_type == "AssumedRole":
            reasons.append("role-chaining")
        if is_external_source(event.source_ip):
            reasons.append("external-source")

        if not reasons:
            return None
        return {
            "reasons": ", ".join(reasons),
            "role_arn": role_arn or "unknown",
            "caller": event.principal_arn or event.username or "unknown",
        }


# ---------------------------------------------------------------------------
# 4. IAM privilege escalation
# ---------------------------------------------------------------------------


class IAMPrivilegeEscalationRule(EventRule):
    """Administrative permissions granted via managed or inline policy."""

    rule_id = "CLOUD-IAM-002"
    title = "IAM privilege escalation (administrative policy granted)"
    description = (
        "An identity was granted administrative IAM permissions via an "
        "attached managed policy or a wildcard inline policy."
    )
    severity = "high"
    confidence = "high"
    technique_ids = ("T1098.003",)

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "cloud" or event.outcome != "success":
            return None
        params = event.request_parameters
        name = event.cloud_event_name
        target = str(
            params.get("userName") or params.get("roleName")
            or params.get("groupName") or params.get("policyArn") or "unknown"
        )

        if name in POLICY_ATTACH_EVENTS:
            policy_arn = str(params.get("policyArn", ""))
            if policy_arn.endswith(ADMIN_POLICY_SUFFIXES):
                return {"event_name": name, "target": target, "policy": policy_arn}
            return None

        if name in INLINE_POLICY_EVENTS:
            if name == "CreatePolicyVersion" and params.get("setAsDefault") is not True:
                return None
            is_admin, reason = _policy_grants_admin(params.get("policyDocument"))
            if is_admin:
                return {"event_name": name, "target": target, "policy": reason}
        return None


# ---------------------------------------------------------------------------
# 5. Access-key creation
# ---------------------------------------------------------------------------


class AccessKeyCreationRule(EventRule):
    """Access key created for *another* principal, or by root.

    A user rotating their own key is routine and deliberately does not fire:
    an alert on every rotation trains analysts to ignore this rule. Creating a
    key for someone else is how an attacker mints persistence.
    """

    rule_id = "CLOUD-IAM-003"
    title = "Access key created for another identity or by root"
    description = (
        "A long-lived access key was created for a different IAM user, or by "
        "the root account, a common persistence technique."
    )
    severity = "high"
    confidence = "high"
    technique_ids = ("T1098.001",)

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if not _is_api(event, {"CreateAccessKey"}) or event.outcome != "success":
            return None
        caller = event.username or "unknown"
        target = str(event.request_parameters.get("userName") or caller)
        by_root = event.identity_type == "Root"
        if target == caller and not by_root:
            return None
        return {
            "caller": caller,
            "target_user": target,
            "new_access_key_id": str(
                event.response_elements.get("accessKeyId", "unknown")
            ),
            "by_root": str(by_root).lower(),
        }


# ---------------------------------------------------------------------------
# 6. Security group opened to the internet
# ---------------------------------------------------------------------------


class SecurityGroupExposureRule(EventRule):
    """Ingress from 0.0.0.0/0 or ::/0 to a sensitive port, or to all ports.

    0.0.0.0/0 on 443 for a public web tier is normal and does not fire; the
    rule is scoped to administrative and database ports.
    """

    rule_id = "CLOUD-NET-001"
    title = "Security group opened to the internet on a sensitive port"
    description = (
        "A security group rule now allows the entire internet to reach an "
        "administrative or database port."
    )
    severity = "high"
    confidence = "high"
    technique_ids = ("T1562.007",)

    _EVENTS: Final[frozenset[str]] = frozenset(
        {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"}
    )

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if not _is_api(event, self._EVENTS) or event.outcome != "success":
            return None
        params = event.request_parameters
        permissions = params.get("ipPermissions", [])
        if not isinstance(permissions, list):
            return None

        exposed: list[str] = []
        matched_cidrs: set[str] = set()
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            open_here = {permission.get("cidrIp"), permission.get("cidrIpv6")} & OPEN_CIDRS
            if not open_here:
                continue
            if permission.get("ipProtocol") == "-1":
                exposed.append("ALL")
                matched_cidrs |= open_here
                continue
            low, high = _as_int(permission.get("fromPort")), _as_int(permission.get("toPort"))
            if low is None or high is None:
                continue
            hits = [str(port) for port in sorted(SENSITIVE_PORTS) if low <= port <= high]
            if hits:
                exposed.extend(hits)
                matched_cidrs |= open_here

        if not exposed:
            return None
        return {
            "group_id": str(params.get("groupId", "unknown")),
            "exposed_ports": ", ".join(exposed),
            "cidr": ", ".join(sorted(matched_cidrs)),
        }


# ---------------------------------------------------------------------------
# 7. VPC flow: accepted inbound admin connection from the internet
# ---------------------------------------------------------------------------


class InboundAdminPortFlowRule(EventRule):
    """VPC Flow Logs show an ACCEPTED inbound connection to an admin port.

    Complements CLOUD-NET-001: that rule sees the door being opened, this one
    sees someone walk through it.

    No ATT&CK mapping: a flow record proves a connection was accepted, not
    that a session was authenticated. Mapping it to Remote Services would
    claim more than the evidence shows.
    """

    rule_id = "CLOUD-NET-002"
    title = "Inbound internet connection accepted on an admin port"
    description = (
        "VPC flow telemetry shows an external address connecting to an "
        "administrative port, and the connection was accepted."
    )
    severity = "high"
    confidence = "medium"
    technique_ids = ()

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "network":
            return None
        details = event.details
        if details.get("direction") != "inbound" or details.get("flow_action") != "ACCEPT":
            return None
        port = event.destination_port
        if port not in SENSITIVE_PORTS or not is_external_source(event.source_ip):
            return None
        return {
            "source_ip": event.source_ip or "unknown",
            "destination": f"{event.destination_ip}:{port}",
            "instance": event.hostname or "unknown",
        }


# ---------------------------------------------------------------------------
# 8. Suspicious S3 access
# ---------------------------------------------------------------------------


class SuspiciousS3AccessRule(ThresholdRule):
    """Repeated reads of a sensitive bucket by one identity from outside."""

    rule_id = "CLOUD-S3-001"
    title = "Bulk read of a sensitive S3 bucket from an external address"
    description = (
        "One identity read multiple objects from a sensitive bucket from "
        "outside internal address ranges in a short window."
    )
    severity = "high"
    confidence = "medium"
    technique_ids = ("T1530",)
    threshold = 3
    window = timedelta(minutes=10)

    def qualifies(self, event: SecurityEvent) -> bool:
        if not _is_api(event, S3_READ_EVENTS):
            return False
        if event.cloud_event_source != "s3.amazonaws.com":
            return False
        bucket = event.request_parameters.get("bucketName")
        return bucket in SENSITIVE_BUCKETS and is_external_source(event.source_ip)

    def group_key(self, event: SecurityEvent) -> str | None:
        principal = principal_key(event)
        bucket = event.request_parameters.get("bucketName")
        if not principal or not isinstance(bucket, str):
            return None
        return f"{principal}@{bucket}"


# ---------------------------------------------------------------------------
# 9. Logging tampering
# ---------------------------------------------------------------------------


class CloudLoggingTamperingRule(EventRule):
    """CloudTrail or VPC flow logging stopped, deleted, or narrowed.

    Severity depends on the operation: stopping or deleting logging is
    critical; narrowing it (UpdateTrail, PutEventSelectors) is medium because
    it is also routine administration. Fires whatever the outcome -- a
    *failed* attempt to stop logging is still evidence of intent.
    """

    rule_id = "CLOUD-LOG-001"
    title = "Cloud logging tampering"
    description = (
        "Audit or flow logging was stopped, deleted or modified. Attackers do "
        "this to blind the SOC before acting."
    )
    severity = "critical"
    confidence = "high"
    technique_ids = ("T1562.008",)

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if not _is_api(event, LOG_TAMPER_DESTRUCTIVE | LOG_TAMPER_MODIFYING):
            return None
        params = event.request_parameters
        target = params.get("name") or params.get("trailName") or params.get("flowLogIds")
        return {
            "event_name": event.cloud_event_name or event.action,
            "target": str(target or "unknown"),
            "outcome": event.outcome,
        }

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        results = []
        for event in events:
            matched = self.matches(event)
            if matched is None:
                continue
            destructive = event.cloud_event_name in LOG_TAMPER_DESTRUCTIVE
            results.append(
                self._result(
                    event.event_id,
                    [event.event_id],
                    matched_fields=matched,
                    severity="critical" if destructive else "medium",
                )
            )
        return results


# ---------------------------------------------------------------------------
# 10. Unusual API activity (enumeration burst)
# ---------------------------------------------------------------------------


class UnusualAPIActivityRule(ThresholdRule):
    """Many *distinct* discovery calls by one identity from outside, quickly.

    The signature of someone with fresh credentials working out what they can
    reach. Distinct API names, not raw count: a dashboard polling one API is
    not enumeration.
    """

    rule_id = "CLOUD-API-001"
    title = "Cloud API enumeration burst from an external address"
    description = (
        "One identity called many distinct List/Describe/Get APIs from "
        "outside internal ranges in a short window, consistent with "
        "post-compromise discovery."
    )
    severity = "medium"
    confidence = "medium"
    technique_ids = ("T1580",)
    threshold = 5
    window = timedelta(minutes=5)

    def qualifies(self, event: SecurityEvent) -> bool:
        if event.category != "cloud" or event.identity_type == AWS_SERVICE_IDENTITY:
            return False
        name = event.cloud_event_name or ""
        if not name.startswith(DISCOVERY_PREFIXES) or name in S3_READ_EVENTS:
            return False
        return is_external_source(event.source_ip)

    def group_key(self, event: SecurityEvent) -> str | None:
        return principal_key(event)

    def distinct_key(self, event: SecurityEvent) -> str | None:
        return event.cloud_event_name


# ---------------------------------------------------------------------------
# 11. GuardDuty-style high-severity finding
# ---------------------------------------------------------------------------


class GuardDutyHighSeverityRule(EventRule):
    """Surface vendor findings at GuardDuty severity >= 7.0.

    This rule does not re-derive the vendor's logic; it promotes the vendor's
    own verdict into our pipeline so it can correlate with our detections.
    Provenance stays visible through `matched_fields['finding_type']`.
    """

    rule_id = "CLOUD-GD-001"
    title = "High-severity GuardDuty finding"
    description = (
        "AWS GuardDuty reported a high- or critical-severity finding. "
        "Promoted so it correlates with deterministic detections."
    )
    severity = "high"
    confidence = "medium"
    technique_ids = ()  # per-finding; see GUARDDUTY_TECHNIQUES

    def matches(self, event: SecurityEvent) -> dict[str, str] | None:
        if event.category != "alert" or event.details.get("vendor") != GUARDDUTY_VENDOR:
            return None
        score = event.details.get("gd_severity")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            return None
        if score < GUARDDUTY_HIGH:
            return None
        return {
            "finding_type": str(event.details.get("rule_id", "unknown")),
            "gd_severity": f"{float(score):.1f}",
        }

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        results = []
        for event in events:
            matched = self.matches(event)
            if matched is None:
                continue
            score = float(matched["gd_severity"])
            results.append(
                DetectionResult(
                    alert_id=f"alert-{self.rule_id}-{event.event_id}",
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity="critical" if score >= GUARDDUTY_CRITICAL else "high",
                    confidence=self.confidence,
                    evidence_event_ids=(event.event_id,),
                    technique_ids=GUARDDUTY_TECHNIQUES.get(matched["finding_type"], ()),
                    matched_fields=matched,
                )
            )
        return results


# ---------------------------------------------------------------------------
# Rule sets
# ---------------------------------------------------------------------------


def cloud_rules() -> list[DetectionRule]:
    """The cloud demonstration rule set, in stable order."""
    return [
        RootAccountActivityRule(),
        ConsoleLoginWithoutMFARule(),
        UnusualAssumeRoleRule(),
        IAMPrivilegeEscalationRule(),
        AccessKeyCreationRule(),
        SecurityGroupExposureRule(),
        InboundAdminPortFlowRule(),
        SuspiciousS3AccessRule(),
        CloudLoggingTamperingRule(),
        UnusualAPIActivityRule(),
        GuardDutyHighSeverityRule(),
    ]


def all_rules() -> list[DetectionRule]:
    """Endpoint + cloud rules on one engine.

    Endpoint rules stay in because cloud workloads produce endpoint-shaped
    telemetry too: VPC flow logs from an EC2 instance are `network` events,
    and SOC-NET-001 (beaconing) applies to them unchanged.
    """
    return default_rules() + cloud_rules()
