"""Response automation abstraction.

This is the module where a mistake has real-world consequences, so it is the
most conservative one in the codebase:

1. **Dry run is the default.** Executing requires explicitly constructing the
   provider with `dry_run=False` AND passing an approval for anything
   disruptive. There is no way to execute by accident.
2. **Actions are a closed enum.** A string that is not a known action is
   rejected. A model cannot invent `delete_all_logs` into existence.
3. **Targets are validated against the incident.** The system cannot isolate a
   host that does not appear in the evidence.
4. **Tiering gates authority.** T2 and above require a human approver.
5. **Protected assets are never auto-actioned**, whatever the tier.
6. **Everything is audited**, including refusals.

Implemented:   MockResponseProvider (records intent, changes nothing)
Placeholders:  real integrations -- see the TODO at the bottom.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final, Sequence


class ResponseAction(str, Enum):
    """The closed set of actions the system can even name.

    Anything outside this enum is rejected before any provider sees it.
    """

    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    COLLECT_ARTIFACT = "collect_artifact"
    CREATE_TICKET = "create_ticket"
    NOTIFY_ANALYST = "notify_analyst"

    # Cloud control-plane actions. See CLOUD_ACTIONS: these are dry-run only
    # in this build, enforced in the base class.
    REVOKE_ACCESS_KEY = "revoke_access_key"
    DISABLE_IAM_USER = "disable_iam_user"
    DETACH_POLICY = "detach_policy"
    ISOLATE_EC2_INSTANCE = "isolate_ec2_instance"
    MODIFY_SECURITY_GROUP = "modify_security_group"
    BLOCK_NETWORK_INDICATOR = "block_network_indicator"


# Action tiers, matching the reference architecture:
#   T0 read-only · T1 reversible/low blast radius
#   T2 disruptive but reversible · T3 destructive or wide-reaching
ACTION_TIERS: Final[dict[ResponseAction, str]] = {
    ResponseAction.NOTIFY_ANALYST: "T1",
    ResponseAction.CREATE_TICKET: "T1",
    ResponseAction.COLLECT_ARTIFACT: "T1",
    ResponseAction.BLOCK_DOMAIN: "T2",
    ResponseAction.BLOCK_IP: "T2",
    ResponseAction.ISOLATE_HOST: "T2",
    ResponseAction.DISABLE_ACCOUNT: "T3",
    # Every cloud action is T2 or higher, so every one requires a human.
    # Revoking a key or detaching a policy can take down production
    # workloads that depend on that identity, which is disruptive even
    # when it is technically reversible.
    ResponseAction.REVOKE_ACCESS_KEY: "T2",
    ResponseAction.DETACH_POLICY: "T2",
    ResponseAction.ISOLATE_EC2_INSTANCE: "T2",
    ResponseAction.MODIFY_SECURITY_GROUP: "T2",
    ResponseAction.BLOCK_NETWORK_INDICATOR: "T2",
    ResponseAction.DISABLE_IAM_USER: "T3",
}

REVERSIBLE: Final[dict[ResponseAction, bool]] = {
    ResponseAction.NOTIFY_ANALYST: True,
    ResponseAction.CREATE_TICKET: True,
    ResponseAction.COLLECT_ARTIFACT: True,
    ResponseAction.BLOCK_DOMAIN: True,
    ResponseAction.BLOCK_IP: True,
    ResponseAction.ISOLATE_HOST: True,
    ResponseAction.DISABLE_ACCOUNT: False,
    # Revoke = set key Inactive (reversible). Deleting a key is not modelled.
    ResponseAction.REVOKE_ACCESS_KEY: True,
    ResponseAction.DETACH_POLICY: True,
    ResponseAction.ISOLATE_EC2_INSTANCE: True,
    ResponseAction.MODIFY_SECURITY_GROUP: True,
    ResponseAction.BLOCK_NETWORK_INDICATOR: True,
    # Conservatively irreversible: disabling a user removes the console
    # password (login profile), which cannot be restored as it was.
    ResponseAction.DISABLE_IAM_USER: False,
}

# Actions against a cloud control plane. In this build they can only ever be
# dry-run: the base class refuses them outright when dry_run is False, even
# with approval, so no code path here can call a cloud API.
CLOUD_ACTIONS: Final[frozenset[ResponseAction]] = frozenset(
    {
        ResponseAction.REVOKE_ACCESS_KEY,
        ResponseAction.DISABLE_IAM_USER,
        ResponseAction.DETACH_POLICY,
        ResponseAction.ISOLATE_EC2_INSTANCE,
        ResponseAction.MODIFY_SECURITY_GROUP,
        ResponseAction.BLOCK_NETWORK_INDICATOR,
    }
)

TIERS_REQUIRING_APPROVAL: Final[frozenset[str]] = frozenset({"T2", "T3"})

# Assets that must never be auto-actioned regardless of tier or approval
# automation. An attacker who can forge a log line implicating a domain
# controller must not be able to turn our SOC into the outage (threat T18).
DEFAULT_PROTECTED_ASSETS: Final[frozenset[str]] = frozenset(
    {
        "DC-CORP-01",
        "idp.corp.test",
        "cloud-control-plane",
        "SRV-FILE-03",
        "svc_backup",
        # Cloud: the identities incident response itself depends on. Disabling
        # them mid-incident can lock the responders out of the account.
        "root",
        "break-glass-admin",
        "OrganizationAccountAccessRole",
    }
)

# Blast-radius ceiling per provider instance.
DEFAULT_MAX_ACTIONS: Final[int] = 10


class ResponseRefused(Exception):
    """Raised when a request is refused by policy. Never swallowed silently."""


@dataclass(frozen=True)
class ResponseRequest:
    """A proposed action. Construction does not execute anything."""

    action: ResponseAction
    target: str
    reason: str
    incident_id: str
    approved_by: str | None = None

    @property
    def tier(self) -> str:
        return ACTION_TIERS[self.action]

    @property
    def requires_approval(self) -> bool:
        return self.tier in TIERS_REQUIRING_APPROVAL

    @property
    def reversible(self) -> bool:
        return REVERSIBLE[self.action]


@dataclass(frozen=True)
class ResponseResult:
    """The outcome of a request: executed, dry-run, or refused."""

    request: ResponseRequest
    status: str  # "dry_run" | "executed" | "refused" | "rejected"
    detail: str
    timestamp: datetime
    would_have: str | None = None

    @property
    def executed(self) -> bool:
        """True only when something actually changed in the real world."""
        return self.status == "executed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.request.action.value,
            "target": self.request.target,
            "incident_id": self.request.incident_id,
            "tier": self.request.tier,
            "status": self.status,
            "detail": self.detail,
            "would_have": self.would_have,
            "approved_by": self.request.approved_by,
            "timestamp": self.timestamp.isoformat(),
        }


class ResponseProvider(ABC):
    """Interface for response tooling, with policy enforced in the base class.

    `execute()` is intentionally not abstract: policy checks run here so no
    implementation can bypass them. Implementations override `_perform()`,
    which is only ever reached once a request has passed every gate.
    """

    name: str

    def __init__(
        self,
        *,
        dry_run: bool = True,
        protected_assets: frozenset[str] = DEFAULT_PROTECTED_ASSETS,
        max_actions: int = DEFAULT_MAX_ACTIONS,
        allowed_targets: Sequence[str] | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.protected_assets = protected_assets
        self.max_actions = max_actions
        # When set, the targets that appear in the incident's evidence. A
        # target outside this set cannot be acted on.
        self.allowed_targets = set(allowed_targets) if allowed_targets else None
        self._audit: list[ResponseResult] = []

    @property
    def audit_log(self) -> list[ResponseResult]:
        """Append-only record of every request, including refusals."""
        return list(self._audit)

    @property
    def executed_count(self) -> int:
        return sum(1 for result in self._audit if result.executed)

    def execute(self, request: ResponseRequest) -> ResponseResult:
        """Run a request through policy, then dry-run or perform it."""
        refusal = self._refusal_reason(request)
        if refusal is not None:
            return self._record(request, "refused", refusal)

        if self.dry_run:
            return self._record(
                request,
                "dry_run",
                "DRY RUN -- no change was made to any system.",
                would_have=self._describe(request),
            )

        detail = self._perform(request)
        return self._record(request, "executed", detail)

    def record_rejection(
        self, request: ResponseRequest, *, reviewer: str, reason: str
    ) -> ResponseResult:
        """Audit a human analyst's decision NOT to take a proposed action.

        Rejections are decisions too. Without this, a declined action leaves
        no trace and an auditor cannot tell "rejected" from "never proposed".
        Nothing is executed or dry-run.
        """
        if not reviewer.strip():
            raise ValueError("a rejection must name the reviewer")
        return self._record(
            request, "rejected", f"rejected by {reviewer}: {reason}"
        )

    def _refusal_reason(self, request: ResponseRequest) -> str | None:
        """Return why the request must be refused, or None to allow it."""
        if not isinstance(request.action, ResponseAction):
            return f"unknown action {request.action!r}; not in the allow-list"

        # Hard stop, checked before approval: approval cannot unlock it. Cloud
        # actions have account-wide blast radius and act on identities the
        # responders may themselves depend on.
        if request.action in CLOUD_ACTIONS and not self.dry_run:
            return (
                f"refused: {request.action.value} is a cloud control-plane action "
                f"and this build is dry-run only for cloud actions; no cloud API "
                f"is ever called"
            )

        if not request.target.strip():
            return "refused: empty target"

        if request.target in self.protected_assets:
            return (
                f"refused: {request.target!r} is a protected asset and is never "
                f"auto-actioned (blast-radius control)"
            )

        if self.allowed_targets is not None and request.target not in self.allowed_targets:
            return (
                f"refused: {request.target!r} does not appear in the incident "
                f"evidence; actions are limited to observed entities"
            )

        if request.requires_approval and not request.approved_by:
            return (
                f"refused: {request.action.value} is tier {request.tier} and "
                f"requires explicit human approval"
            )

        # Blast-radius ceiling counts everything that got past the gates,
        # including dry runs, so a runaway loop is caught in testing too.
        if len(self._audit) >= self.max_actions:
            return (
                f"refused: blast-radius limit reached "
                f"({self.max_actions} actions); escalate to a human"
            )

        return None

    def _describe(self, request: ResponseRequest) -> str:
        return (
            f"WOULD {request.action.value} target={request.target!r} "
            f"(tier {request.tier}, "
            f"{'reversible' if request.reversible else 'NOT reversible'}) "
            f"for incident {request.incident_id}: {request.reason}"
        )

    def _record(
        self,
        request: ResponseRequest,
        status: str,
        detail: str,
        would_have: str | None = None,
    ) -> ResponseResult:
        result = ResponseResult(
            request=request,
            status=status,
            detail=detail,
            timestamp=datetime.now(timezone.utc),
            would_have=would_have,
        )
        self._audit.append(result)
        return result

    @abstractmethod
    def _perform(self, request: ResponseRequest) -> str:
        """Actually carry out the action. Only called when dry_run is False."""


class MockResponseProvider(ResponseProvider):
    """Records what would have happened. Changes nothing, ever.

    Even with `dry_run=False` this provider only appends to an in-memory list
    -- there is no code path here that touches a real system. That is the
    point: the pipeline can be exercised end to end, including the
    "execution" branch, with zero risk.
    """

    name = "mock"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.performed: list[ResponseRequest] = []

    def _perform(self, request: ResponseRequest) -> str:
        self.performed.append(request)
        return (
            f"SIMULATED {request.action.value} on {request.target!r} "
            f"(mock provider -- no real system was contacted)"
        )


def requests_from_analysis(
    recommended_actions: Sequence[dict[str, Any]],
    incident_id: str,
    *,
    hosts: Sequence[str] = (),
    users: Sequence[str] = (),
) -> list[ResponseRequest]:
    """Translate AI-proposed actions into structured requests.

    This is the boundary where free-form model output stops being text and
    must become a known action. Anything that does not map to a
    `ResponseAction` is dropped here rather than being improvised -- which is
    what makes a successful prompt injection produce, at worst, a rejected
    suggestion.

    The mapping is intentionally crude keyword matching: the real contract in
    a production build would be the model returning an action *enum value*,
    not prose. Keeping it explicit here documents where that contract belongs.
    """
    keyword_map: list[tuple[str, ResponseAction]] = [
        ("isolat", ResponseAction.ISOLATE_HOST),
        ("password reset", ResponseAction.DISABLE_ACCOUNT),
        ("session revocation", ResponseAction.DISABLE_ACCOUNT),
        ("disable", ResponseAction.DISABLE_ACCOUNT),
        ("block ip", ResponseAction.BLOCK_IP),
        ("block domain", ResponseAction.BLOCK_DOMAIN),
        ("collect", ResponseAction.COLLECT_ARTIFACT),
        ("ticket", ResponseAction.CREATE_TICKET),
        ("hunt", ResponseAction.NOTIFY_ANALYST),
        ("review", ResponseAction.NOTIFY_ANALYST),
        ("confirm", ResponseAction.NOTIFY_ANALYST),
    ]

    requests: list[ResponseRequest] = []
    for item in recommended_actions:
        # Structured path: the analyst named an enum value and a target. This
        # is the contract the docstring above says belongs here, and it avoids
        # prose pitfalls like "do not isolate" mapping to ISOLATE_HOST.
        if "response_action" in item:
            structured = _structured_request(item, incident_id)
            if structured is not None:
                requests.append(structured)
            continue

        text = str(item.get("action", "")).lower()
        action = next(
            (action for keyword, action in keyword_map if keyword in text), None
        )
        if action is None:
            continue

        if action == ResponseAction.ISOLATE_HOST:
            targets: Sequence[str] = hosts or ("unknown-host",)
        elif action == ResponseAction.DISABLE_ACCOUNT:
            targets = users or ("unknown-user",)
        else:
            targets = (incident_id,)

        for target in targets:
            requests.append(
                ResponseRequest(
                    action=action,
                    target=target,
                    reason=str(item.get("rationale", "proposed by AI triage")),
                    incident_id=incident_id,
                    # Approval is deliberately NOT populated from the model's
                    # own `requires_human_approval` field. A human supplies it
                    # or the action is refused.
                    approved_by=None,
                )
            )
    return requests


def _structured_request(
    item: dict[str, Any], incident_id: str
) -> ResponseRequest | None:
    """Build a request from an explicit `response_action` + `target`.

    Returns None, dropping the item, when:
      * `response_action` is None: the item is a manual human task (e.g.
        "restore logging"), deliberately not automatable;
      * the value is not a ResponseAction: never improvise an action;
      * the target is missing or empty.

    The target is NOT trusted here. The provider's `allowed_targets` gate
    still checks that it appears in the incident evidence.
    """
    value = item.get("response_action")
    if value is None:
        return None
    try:
        action = ResponseAction(value)
    except ValueError:
        return None
    target = item.get("target")
    if not isinstance(target, str) or not target.strip():
        return None
    return ResponseRequest(
        action=action,
        target=target,
        reason=str(item.get("rationale", "proposed by AI triage")),
        incident_id=incident_id,
        approved_by=None,  # never taken from model output
    )


# TODO(problem-statement): real integrations.
#
# Each would subclass ResponseProvider and implement _perform() only -- the
# policy gates above are inherited and must not be overridden:
#
#   CrowdStrikeResponseProvider  -> isolate_host via Hosts API device actions
#   EntraIDResponseProvider      -> disable_account / revoke sessions
#   FirewallResponseProvider     -> block_ip / block_domain
#   JiraResponseProvider         -> create_ticket
#   AwsResponseProvider          -> revoke_access_key (iam:UpdateAccessKey
#                                   Status=Inactive), detach_policy,
#                                   disable_iam_user, modify_security_group
#                                   (revoke the offending ingress rule),
#                                   isolate_ec2_instance (swap to a
#                                   deny-all quarantine security group)
#
# Cloud-specific requirements, on top of the list below. CLOUD_ACTIONS stays
# dry-run-only until all of these hold:
#   * A dedicated responder role, assumable only via a break-glass path with
#     MFA, holding exactly the IAM/EC2 permissions the allow-list needs.
#   * Every call tagged with incident_id and approver, so CloudTrail itself
#     independently records who authorized it.
#   * A pre-change snapshot (key status, policy attachments, SG rules) stored
#     before acting, since that snapshot IS the rollback.
#   * Protected identities (root, break-glass, org access role) excluded at
#     both the gate here AND in the responder role's IAM policy.
#
# Requirements before any of these may execute for real:
#   * A tested rollback path for every action (nothing automatable without it).
#   * Scoped, least-privilege credentials from the environment, held only by
#     the orchestrator -- never by the AI pipeline's identity.
#   * A visible kill switch that disables all automated response at once.
#   * Rate limits and blast-radius caps enforced above, not per-integration.
