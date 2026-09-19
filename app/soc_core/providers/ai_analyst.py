"""AI SOC analyst abstraction.

Position in the system, and the whole point of this module's design:

    deterministic detection + correlation  ->  EVIDENCE (authoritative)
    AI analyst                             ->  INTERPRETATION (advisory)

The AI never decides what was detected. It reads evidence the deterministic
pipeline already produced and explains it. If the AI is unavailable, wrong, or
actively manipulated, the incident, its alerts, and its risk score are all
still intact.

Implemented:   MockAIAnalyst (offline, deterministic, no model)
Placeholders:  OllamaAnalyst, HostedLLMAnalyst -- interface + TODOs only

Every implementation inherits `analyze()`, which runs validation on whatever
the implementation produced. That is deliberate: validation must not be
something a future integration can forget to call.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Iterable, Sequence

from ..cloud_detections import is_external_source
from ..correlation import Incident
from ..events import SecurityEvent, iter_untrusted_text
from ..mitre import TECHNIQUES, attack_stage, validate_technique_ids
from .response import ACTION_TIERS, REVERSIBLE, ResponseAction

if TYPE_CHECKING:  # imported for type hints only; avoids an import cycle
    from ..evidence_context import EvidenceContext

CONFIDENCE_LEVELS: Final[frozenset[str]] = frozenset({"low", "medium", "high"})

# Strings that suggest log content is trying to instruct the model rather than
# describe an event. Screening is advisory: matches are surfaced to the
# analyst as findings, never silently stripped, because an injection attempt
# is itself valuable evidence.
INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions",
        r"disregard\s+(?:all\s+)?(?:previous|prior|above)",
        r"you\s+are\s+now\s+(?:in\s+)?(?:a\s+)?\w+\s*(?:mode|assistant|agent)",
        r"system\s*(?:notice|message|prompt)\s*:",
        r"\bmark\s+(?:this|the)\s+(?:incident|alert)\s+(?:as\s+)?benign",
        r"\bclose_incident\b",
        r"\bapproved\s*=\s*true\b",
        r"(?:reveal|print|repeat|output)\s+(?:your\s+)?(?:system\s+)?prompt",
        r"<<<\s*END_UNTRUSTED_EVENT_DATA\s*>>>",
        r"\bmaintenance\s+mode\b",
        r"severity\s+(?:is\s+)?informational",
    )
)

# Past-tense claims that a response action was carried out. The AI proposes;
# it never performs. Violating this is a critical failure (threat T17), so it
# is checked mechanically rather than trusted to the prompt.
ACTION_CLAIM_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bi\s+(?:have\s+)?(?:isolated|blocked|disabled|quarantined|closed|remediated)\b",
        r"\bhas\s+been\s+(?:isolated|blocked|disabled|quarantined|closed|remediated)\b",
        r"\bhave\s+been\s+(?:isolated|blocked|disabled|quarantined|closed|remediated)\b",
        r"\bi\s+(?:am\s+)?(?:isolating|blocking|disabling|quarantining|closing)\b",
        r"\bi\s+will\s+(?:isolate|block|disable|quarantine|close)\b",
        r"\baction\s+(?:has\s+been\s+)?(?:taken|completed|executed)\b",
    )
)

# Negations that flip an apparent action claim into its opposite. "No response
# action has been taken" is the statement we WANT, so matching it as a
# violation would train implementations to stop saying the true thing.
_NEGATION_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:no|not|never|none|without|cannot|can't|won't|nothing|neither)\b",
    re.IGNORECASE,
)

_SENTENCE_BREAK: Final[str] = ".;\n"


def claims_action_performed(text: str) -> list[str]:
    """Return the action-claim patterns `text` violates.

    A match is ignored when a negation appears earlier in the same sentence,
    so "no action has been taken" passes while "the account has been disabled"
    does not.

    This is a heuristic on prose. It is a backstop for the prompt rule, not
    the primary control -- the primary control is that the AI has no tools, so
    it cannot perform an action regardless of what it writes.
    """
    violations: list[str] = []
    for pattern in ACTION_CLAIM_PATTERNS:
        for match in pattern.finditer(text):
            prefix = text[: match.start()]
            sentence_start = max(
                (prefix.rfind(char) for char in _SENTENCE_BREAK), default=-1
            )
            if _NEGATION_RE.search(prefix[sentence_start + 1 :]):
                continue
            violations.append(pattern.pattern)
            break
    return violations


@dataclass(frozen=True)
class InjectionFinding:
    """A suspicious instruction-like string found in event data."""

    event_id: str
    field_path: str
    pattern: str
    excerpt: str

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "field_path": self.field_path,
            "pattern": self.pattern,
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True)
class AIAnalysis:
    """Structured output of an AI analyst pass.

    `proposed_only` is not configurable. Nothing in this object has been
    executed; it is a set of proposals for a human.
    """

    incident_id: str
    summary: str
    severity_assessment: str
    evidence: tuple[dict[str, Any], ...]
    likely_attack_stage: str | None
    technique_ids: tuple[str, ...]
    recommended_actions: tuple[dict[str, Any], ...]
    confidence: str
    uncertainty: tuple[str, ...]
    analyst_questions: tuple[str, ...]
    injection_attempt_detected: bool = False
    injection_findings: tuple[InjectionFinding, ...] = ()
    model: str = "mock"
    validation_warnings: tuple[str, ...] = field(default_factory=tuple)
    proposed_only: bool = True
    # Evidence-cited claims. Each: {claim, classification, evidence_ids,
    # event_ids, supported}. `supported` is set by validation, never by the
    # model: a claim whose evidence IDs don't resolve is kept but flagged.
    citations: tuple[dict[str, Any], ...] = ()
    # Extended structured sections from context-aware providers (e.g. Claude):
    # attack_assessment, timeline_interpretation, affected_assets, ...
    investigation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "citations": [dict(c) for c in self.citations],
            "investigation": dict(self.investigation),
            "incident_id": self.incident_id,
            "summary": self.summary,
            "severity_assessment": self.severity_assessment,
            "evidence": [dict(item) for item in self.evidence],
            "likely_attack_stage": self.likely_attack_stage,
            "technique_ids": list(self.technique_ids),
            "recommended_actions": [dict(a) for a in self.recommended_actions],
            "confidence": self.confidence,
            "uncertainty": list(self.uncertainty),
            "analyst_questions": list(self.analyst_questions),
            "injection_attempt_detected": self.injection_attempt_detected,
            "injection_findings": [f.to_dict() for f in self.injection_findings],
            "model": self.model,
            "validation_warnings": list(self.validation_warnings),
            "proposed_only": self.proposed_only,
        }


def screen_for_injection(
    events: Iterable[SecurityEvent], *, excerpt_length: int = 120
) -> list[InjectionFinding]:
    """Flag instruction-shaped strings in untrusted event fields.

    Findings are reported, not removed: a log line trying to manipulate
    automated analysis is a high-value detection in its own right.

    This is a heuristic and will miss novel phrasings. It is one layer of
    defense, not the defense -- the structural controls (AI has no tools,
    output is validated, humans approve actions) are what actually hold.
    """
    findings: list[InjectionFinding] = []
    for event in events:
        for field_path, text in iter_untrusted_text(event):
            normalized = _normalize(text)
            for pattern in INJECTION_PATTERNS:
                match = pattern.search(normalized)
                if match is None:
                    continue
                findings.append(
                    InjectionFinding(
                        event_id=event.event_id,
                        field_path=field_path,
                        pattern=pattern.pattern,
                        excerpt=normalized[:excerpt_length],
                    )
                )
                break  # one finding per field is enough to flag it
    return findings


def _normalize(text: str) -> str:
    """NFKC-normalize and strip zero-width/bidi characters.

    Without this, `i​gnore previous instructions` slips past every
    pattern above while still reading normally to a model (threat T6).
    """
    import unicodedata

    stripped = "".join(
        char
        for char in text
        if char not in "​‌‍⁠﻿‪‫‬‭‮"
    )
    return unicodedata.normalize("NFKC", stripped)


def validate_analysis(analysis: AIAnalysis, incident: Incident) -> list[str]:
    """Check an analysis against the rules in prompts/SOC_ANALYST_PROMPT.md.

    Returns a list of violations. Applied to every implementation's output,
    including a future real LLM, because a prompt is a request and a validator
    is a control.
    """
    warnings: list[str] = []

    if analysis.incident_id != incident.incident_id:
        warnings.append(
            f"analysis incident_id {analysis.incident_id!r} does not match "
            f"incident {incident.incident_id!r}"
        )

    # RULE 4 -- cite or do not claim.
    known_event_ids = set(incident.event_ids)
    for item in analysis.evidence:
        for event_id in item.get("event_ids", []):
            if event_id not in known_event_ids:
                warnings.append(
                    f"evidence cites unknown event_id {event_id!r} "
                    f"(not part of {incident.incident_id})"
                )

    # RULE 7 -- ATT&CK mappings must exist in the pinned catalog.
    unknown = validate_technique_ids(list(analysis.technique_ids))[1]
    for technique_id in unknown:
        warnings.append(f"unknown ATT&CK technique {technique_id!r} (hallucination)")

    # ...and must have been produced by the deterministic engine. The AI may
    # interpret mapped techniques; it may not introduce new ones.
    engine_techniques = set(incident.technique_ids)
    for technique_id in analysis.technique_ids:
        if technique_id not in unknown and technique_id not in engine_techniques:
            warnings.append(
                f"ATT&CK technique {technique_id!r} was not mapped by the "
                f"deterministic engine for {incident.incident_id}"
            )

    # Every citation must resolve to real evidence (set by check_citations).
    for citation in analysis.citations:
        if citation.get("supported") is False:
            warnings.append(
                f"unsupported claim (no valid evidence): {str(citation.get('claim', ''))[:80]!r}"
            )

    # RULE 2 -- never claim an action was performed.
    claim_surfaces = [
        analysis.summary,
        *(str(a.get("action", "")) for a in analysis.recommended_actions),
        *(str(c.get("claim", "")) for c in analysis.citations),
    ]
    for surface in claim_surfaces:
        for pattern_text in claims_action_performed(surface):
            warnings.append(
                f"output claims an action was performed (pattern {pattern_text!r}): "
                f"{surface[:80]!r}"
            )

    if analysis.confidence not in CONFIDENCE_LEVELS:
        warnings.append(f"invalid confidence {analysis.confidence!r}")

    if not analysis.proposed_only:
        warnings.append("proposed_only must be True; the AI never executes actions")

    # Tier discipline: anything disruptive needs a human.
    for action in analysis.recommended_actions:
        tier = action.get("tier")
        if tier in {"T2", "T3"} and not action.get("requires_human_approval"):
            warnings.append(
                f"action {action.get('action')!r} is tier {tier} but does not "
                f"require human approval"
            )

    # Structured actions: the named enum must exist, and the tier the analyst
    # claims must match the tier policy assigns. A model that labels
    # disable_iam_user as "T1" is trying (or failing) to skip a human gate.
    for action in analysis.recommended_actions:
        if "response_action" not in action or action["response_action"] is None:
            continue
        try:
            enum_value = ResponseAction(action["response_action"])
        except ValueError:
            warnings.append(
                f"unknown response_action {action['response_action']!r}; "
                f"it will be dropped, not improvised"
            )
            continue
        expected = ACTION_TIERS[enum_value]
        if action.get("tier") != expected:
            warnings.append(
                f"response_action {enum_value.value!r} labelled tier "
                f"{action.get('tier')!r} but policy tier is {expected!r}"
            )

    return warnings


class AIAnalyst(ABC):
    """Interface every AI analyst implementation satisfies."""

    name: str

    @abstractmethod
    def _analyze(self, incident: Incident) -> AIAnalysis:
        """Produce an analysis. Implementations override this, not `analyze`."""

    def _analyze_with_context(
        self, incident: Incident, context: "EvidenceContext | None"
    ) -> AIAnalysis:
        """Context-aware providers override this. The default ignores the
        context, so context-free providers (the mock) keep working unchanged."""
        return self._analyze(incident)

    def analyze(self, incident: Incident, context: "EvidenceContext | None" = None) -> AIAnalysis:
        """Analyze an incident and validate the result.

        Validation is applied here, in the base class, so no implementation
        can return unvalidated output. Violations are attached as
        `validation_warnings` rather than raising: the analyst still needs to
        see the (flagged) output, and a suppressed analysis teaches us nothing.

        `context` is the redacted EvidenceContext. Providers that call a
        hosted model must receive ONLY this, never raw events.
        """
        from dataclasses import replace

        analysis = self._analyze_with_context(incident, context)
        if context is not None and analysis.citations:
            analysis = replace(analysis, citations=check_citations(analysis.citations, context))
        warnings = validate_analysis(analysis, incident)
        if warnings:
            analysis = _replace_warnings(analysis, tuple(warnings))
        return analysis


CLAIM_CLASSIFICATIONS: Final[frozenset[str]] = frozenset(
    {"OBSERVED", "CORRELATED", "INFERRED", "AI_RECOMMENDATION"}
)


def check_citations(
    citations: Iterable[dict[str, Any]], context: "EvidenceContext"
) -> tuple[dict[str, Any], ...]:
    """Resolve and verify every citation against the context.

    A claim is `supported` only when it cites at least one evidence ID that
    exists in the context (AI_RECOMMENDATION claims may cite none). Unknown IDs
    are dropped from the citation and reported; the claim is never presented
    as fact without valid evidence. Event IDs are resolved server-side from
    the evidence IDs, so the UI can show the actual supporting events.
    """
    valid_ids = context.evidence_ids
    out = []
    for raw in citations:
        classification = str(raw.get("classification", "")).upper()
        if classification not in CLAIM_CLASSIFICATIONS:
            classification = "INFERRED"
        cited = [str(e) for e in raw.get("evidence_ids", []) if isinstance(e, (str, int))]
        good = [e for e in cited if e in valid_ids]
        bad = [e for e in cited if e not in valid_ids]
        supported = bool(good) or (classification == "AI_RECOMMENDATION" and not bad)
        out.append({
            "claim": str(raw.get("claim", ""))[:600],
            "classification": classification,
            "evidence_ids": good,
            "invalid_evidence_ids": bad,
            "event_ids": context.events_for(good),
            "supported": supported,
        })
    return tuple(out)


def _replace_warnings(analysis: AIAnalysis, warnings: tuple[str, ...]) -> AIAnalysis:
    from dataclasses import replace

    return replace(analysis, validation_warnings=warnings)


class MockAIAnalyst(AIAnalyst):
    """Deterministic, offline analyst. No model, no network, no key.

    It composes its narrative from the deterministic evidence using templates,
    which has a useful property for the hackathon: it is *structurally*
    incapable of following an injected instruction, because it never
    interprets log text as language. That makes it a clean baseline to
    demonstrate the difference between "the prompt told it not to" and "it
    cannot".

    It is not a substitute for a real model -- it cannot generalize. It exists
    so the pipeline is end-to-end runnable and testable offline.
    """

    name = "mock"

    def _analyze(self, incident: Incident) -> AIAnalysis:
        findings = screen_for_injection(incident.events)
        evidence = self._build_evidence(incident)
        actions = self._recommend_actions(incident)
        confidence = self._confidence(incident)

        return AIAnalysis(
            incident_id=incident.incident_id,
            summary=self._summarize(incident, findings),
            severity_assessment=incident.severity,
            evidence=tuple(evidence),
            likely_attack_stage=attack_stage(incident.technique_ids),
            technique_ids=tuple(incident.technique_ids),
            recommended_actions=tuple(actions),
            confidence=confidence,
            uncertainty=tuple(self._uncertainty(incident, findings)),
            analyst_questions=tuple(self._questions(incident)),
            injection_attempt_detected=bool(findings),
            injection_findings=tuple(findings),
            model="mock-deterministic",
        )

    def _summarize(
        self, incident: Incident, findings: Sequence[InjectionFinding]
    ) -> str:
        hosts = ", ".join(incident.hosts) or "unknown hosts"
        users = ", ".join(incident.users) or "unknown users"
        rules = len(incident.rule_ids)
        span = incident.duration
        span_text = f" over {int(span.total_seconds() // 60)} minutes" if span else ""
        accounts = incident.cloud_accounts
        if accounts:
            instances = f" (instances: {', '.join(incident.hosts)})" if incident.hosts else ""
            scope = f"AWS account(s) {', '.join(accounts)}{instances} and identities {users}"
        else:
            scope = f"{hosts} and account(s) {users}"
        parts = [
            f"{len(incident.alerts)} alert(s) from {rules} distinct detection "
            f"rule(s) correlated into one incident affecting {scope}{span_text}.",
        ]
        stage = attack_stage(incident.technique_ids)
        if stage:
            parts.append(f"The furthest observed kill-chain stage is {stage}.")
        if findings:
            parts.append(
                f"NOTE: {len(findings)} field(s) in the evidence contain text that "
                f"attempts to manipulate automated analysis. That text was treated "
                f"as data and reported, not followed."
            )
        parts.append(
            "This is an automated interpretation of deterministic detections. "
            "No response action has been taken."
        )
        return " ".join(parts)

    def _build_evidence(self, incident: Incident) -> list[dict[str, Any]]:
        return [
            {
                "observation": f"{alert.title} ({alert.rule_id})",
                "detail": alert.description,
                "event_ids": list(alert.evidence_event_ids),
                "matched_fields": dict(alert.matched_fields),
                "rule_confidence": alert.confidence,
            }
            for alert in incident.alerts
        ]

    def _confidence(self, incident: Incident) -> str:
        """Corroboration drives confidence -- not the model's self-belief."""
        high_confidence_rules = sum(
            1 for alert in incident.alerts if alert.confidence == "high"
        )
        if len(incident.rule_ids) >= 3 and high_confidence_rules >= 2:
            return "high"
        if len(incident.rule_ids) >= 2:
            return "medium"
        return "low"

    def _recommend_actions(self, incident: Incident) -> list[dict[str, Any]]:
        """Map observed tactics onto proposed, tiered actions."""
        if incident.cloud_accounts:
            return self._recommend_cloud_actions(incident)

        actions: list[dict[str, Any]] = []
        tactics = set(incident.tactics)

        actions.append(
            {
                "action": "Review the correlated timeline and confirm the incident with the account owner",
                "rationale": "Fastest way to confirm or refute the activity with a human in the loop.",
                "tier": "T0",
                "requires_human_approval": False,
                "reversible": True,
                "proposed_only": True,
            }
        )

        if "Execution" in tactics or "Command and Control" in tactics:
            actions.append(
                {
                    "action": "Collect volatile evidence from the affected host before containment",
                    "rationale": "Isolation may destroy memory-resident artifacts needed for analysis.",
                    "tier": "T1",
                    "requires_human_approval": False,
                    "reversible": True,
                    "proposed_only": True,
                }
            )
            actions.append(
                {
                    "action": f"Propose isolating host(s): {', '.join(incident.hosts) or 'n/a'}",
                    "rationale": "Execution plus outbound C2-shaped traffic suggests an active foothold.",
                    "tier": "T2",
                    "requires_human_approval": True,
                    "reversible": True,
                    "proposed_only": True,
                }
            )

        if "Credential Access" in tactics:
            actions.append(
                {
                    "action": f"Propose password reset and session revocation for: {', '.join(incident.users) or 'n/a'}",
                    "rationale": "Credential access was observed; existing sessions may be attacker-controlled.",
                    "tier": "T3",
                    "requires_human_approval": True,
                    "reversible": False,
                    "proposed_only": True,
                }
            )

        if "Command and Control" in tactics:
            actions.append(
                {
                    "action": "Hunt for other hosts contacting the same external infrastructure",
                    "rationale": "Establishes whether the compromise extends beyond the known hosts.",
                    "tier": "T0",
                    "requires_human_approval": False,
                    "reversible": True,
                    "proposed_only": True,
                }
            )

        return actions

    def _recommend_cloud_actions(self, incident: Incident) -> list[dict[str, Any]]:
        """Cloud playbook: restore visibility, contain identities, then network.

        Every automatable proposal names a `ResponseAction` and a target taken
        from deterministic evidence (alert matched_fields and evidence events),
        never from free text. Restoring logging is proposed as a *manual* task
        (`response_action: None`): it is the first thing to do, because until
        logging is back the SOC is blind, but it is done by a person in the
        console, not by this pipeline.
        """
        actions: list[dict[str, Any]] = []
        seen: set[tuple[str | None, str]] = set()

        def propose(
            text: str, rationale: str, action: ResponseAction | None, target: str
        ) -> None:
            key = (action.value if action else None, target)
            if key in seen:
                return
            seen.add(key)
            tier = ACTION_TIERS[action] if action else "T1"
            actions.append(
                {
                    "action": text,
                    "rationale": rationale,
                    "response_action": action.value if action else None,
                    "target": target,
                    "tier": tier,
                    "requires_human_approval": tier in {"T2", "T3"},
                    "reversible": REVERSIBLE[action] if action else True,
                    "proposed_only": True,
                }
            )

        alerts_by_rule: dict[str, list] = {}
        for alert in incident.alerts:
            alerts_by_rule.setdefault(alert.rule_id, []).append(alert)

        propose(
            "Review the correlated timeline and confirm the activity with the identity owners",
            "Fastest way to confirm or refute the activity with a human in the loop.",
            ResponseAction.NOTIFY_ANALYST,
            incident.incident_id,
        )

        for alert in alerts_by_rule.get("CLOUD-LOG-001", []):
            trail = alert.matched_fields.get("target", "unknown")
            propose(
                f"MANUAL: restore logging on {trail} and verify no other trail or selector was changed",
                "Until logging is restored, further attacker activity may be invisible.",
                None,
                trail,
            )

        # Long-lived IAM user keys used from outside corporate ranges.
        for event in incident.events:
            if (
                event.identity_type == "IAMUser"
                and event.access_key_id
                and is_external_source(event.source_ip)
            ):
                propose(
                    f"Propose deactivating access key {event.access_key_id} "
                    f"(used from {event.source_ip})",
                    "A long-lived key used from an external address is the likely initial access.",
                    ResponseAction.REVOKE_ACCESS_KEY,
                    event.access_key_id,
                )

        for alert in alerts_by_rule.get("CLOUD-IAM-003", []):
            key = alert.matched_fields.get("new_access_key_id", "")
            user = alert.matched_fields.get("target_user", "")
            if key and key != "unknown":
                propose(
                    f"Propose deactivating newly minted access key {key}",
                    "Keys created during the incident are likely attacker persistence.",
                    ResponseAction.REVOKE_ACCESS_KEY,
                    key,
                )
            if user and alert.matched_fields.get("by_root") != "true":
                propose(
                    f"Propose disabling IAM user {user}",
                    "Identity received new credentials during the incident.",
                    ResponseAction.DISABLE_IAM_USER,
                    user,
                )

        for alert in alerts_by_rule.get("CLOUD-IAM-002", []):
            target = alert.matched_fields.get("target", "")
            if target and target != "unknown":
                propose(
                    f"Propose detaching the administrative policy from {target}",
                    f"Administrative permissions granted during the incident "
                    f"({alert.matched_fields.get('policy', 'policy')}).",
                    ResponseAction.DETACH_POLICY,
                    target,
                )

        for alert in alerts_by_rule.get("CLOUD-NET-001", []):
            group = alert.matched_fields.get("group_id", "")
            if group and group != "unknown":
                propose(
                    f"Propose revoking the internet-wide ingress rule on {group} "
                    f"(ports {alert.matched_fields.get('exposed_ports', '?')})",
                    "Administrative port exposed to 0.0.0.0/0 during the incident.",
                    ResponseAction.MODIFY_SECURITY_GROUP,
                    group,
                )

        for host in incident.hosts:
            propose(
                f"Snapshot volumes of {host} before any containment",
                "Evidence before containment: isolation can destroy volatile state.",
                ResponseAction.COLLECT_ARTIFACT,
                host,
            )
            propose(
                f"Propose isolating EC2 instance {host} with a deny-all quarantine security group",
                "Accepted inbound admin connection plus beacon-shaped outbound traffic.",
                ResponseAction.ISOLATE_EC2_INSTANCE,
                host,
            )

        external_ips: list[str] = []
        for event in incident.events:
            for address in (event.source_ip, event.destination_ip):
                if address and is_external_source(address) and address not in external_ips:
                    external_ips.append(address)
        for address in external_ips:
            propose(
                f"Propose blocking network indicator {address}",
                "External address observed in the incident evidence.",
                ResponseAction.BLOCK_NETWORK_INDICATOR,
                address,
            )

        if any(event.identity_type == "Root" for event in incident.events):
            propose(
                "MANUAL: confirm root use with the account owner; rotate the root "
                "password and verify hardware MFA out-of-band",
                "Root is a protected identity: response is a manual, break-glass process.",
                None,
                "root",
            )

        propose(
            "Open an incident ticket",
            "Tracks ownership and the approval trail for every action above.",
            ResponseAction.CREATE_TICKET,
            incident.incident_id,
        )
        return actions

    def _uncertainty(
        self, incident: Incident, findings: Sequence[InjectionFinding]
    ) -> list[str]:
        items = [
            "Detection rules are heuristics; benign automation can produce similar patterns.",
            "Correlation is based on shared entities and timing, not on observed causation "
            "between the events.",
        ]
        low_confidence = [a.rule_id for a in incident.alerts if a.confidence == "low"]
        if low_confidence:
            items.append(
                "Low-confidence rule(s) contributed to this incident: "
                + ", ".join(sorted(set(low_confidence)))
            )
        if findings:
            items.append(
                "Evidence contains attacker-controlled text designed to influence "
                "analysis; treat narrative conclusions with extra scrutiny."
            )
        if len(incident.hosts) > 1:
            items.append(
                "Activity spans multiple hosts; whether it is one actor or coincident "
                "activity cannot be confirmed from this data alone."
            )
        rule_ids = set(incident.rule_ids)
        if "CLOUD-LOG-001" in rule_ids:
            items.append(
                "Audit logging was tampered with during this incident. Absence of "
                "later events in that trail is NOT evidence that activity stopped."
            )
        if "CLOUD-GD-001" in rule_ids:
            items.append(
                "GuardDuty findings are vendor verdicts; their underlying logic is "
                "not visible to this pipeline."
            )
        if incident.cloud_accounts:
            items.append(
                "CloudTrail source addresses can reflect proxies, VPNs or cloud "
                "egress; an external address is not by itself proof of an external actor."
            )
        return items

    def _questions(self, incident: Incident) -> list[str]:
        questions = [
            f"Are any of the source addresses ({', '.join(incident.source_ips) or 'n/a'}) "
            f"known corporate egress points?",
        ]
        if incident.users:
            questions.append(
                f"Can {incident.users[0]} confirm whether they performed this activity?"
            )
        if any(a.rule_id.startswith("SOC-EXEC") for a in incident.alerts):
            questions.append(
                "What is the decoded content of the observed encoded command line?"
            )
        if any(a.rule_id.startswith("SOC-NET") for a in incident.alerts):
            questions.append(
                "Is the external destination known infrastructure for any approved vendor?"
            )
        if incident.cloud_accounts:
            rule_ids = set(incident.rule_ids)
            keys = sorted(
                {
                    e.access_key_id
                    for e in incident.events
                    if e.identity_type == "IAMUser" and e.access_key_id
                    and is_external_source(e.source_ip)
                }
            )
            for key in keys:
                questions.append(
                    f"Is access key {key} expected to be used from outside corporate "
                    f"address ranges (e.g. by an external CI system)?"
                )
            if rule_ids & {"CLOUD-IAM-002", "CLOUD-IAM-003"}:
                questions.append(
                    "Was any of the IAM change activity approved through change management?"
                )
            if "CLOUD-LOG-001" in rule_ids:
                questions.append(
                    "Did another trail (organization or data-events) keep recording "
                    "during the logging gap?"
                )
            if any(
                "cross-account" in a.matched_fields.get("reasons", "")
                for a in incident.alerts
            ):
                questions.append(
                    "Is the calling AWS account a known, contracted partner account?"
                )
        return questions


class OllamaAnalyst(AIAnalyst):
    """PLACEHOLDER -- not implemented. Makes no network calls.

    Intended shape when implemented:

    * Endpoint from `OLLAMA_HOST` (default http://localhost:11434). Bind
      Ollama to localhost: an exposed endpoint is an open inference server.
    * Build the prompt from prompts/SOC_ANALYST_PROMPT.md. Event data goes
      inside the untrusted delimiters and NOWHERE else; escape any occurrence
      of the delimiter in the data first (see evt-0024 for why).
    * Run `screen_for_injection()` before the call and pass the findings in as
      metadata, so the model is told what was flagged rather than having to
      notice it unaided.
    * temperature=0 for reproducibility; cap `num_predict` and the request
      timeout.
    * Parse the response as strict JSON into `AIAnalysis`. On a parse failure,
      retry once, then fall back to MockAIAnalyst and mark the degradation --
      never ship unparsed model text onward.
    * A local model is NOT inherently injection-resistant. Every control in
      `validate_analysis()` still applies, which is why `analyze()` in the
      base class runs it regardless of implementation.

    Value for this track: zero data egress (trust boundary TB-3 disappears),
    no API key, and the demo survives conference wifi.

    TODO(problem-statement): implement if local inference is required.
    """

    name = "ollama"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "OllamaAnalyst is an interface placeholder. The core simulation "
            "runs on MockAIAnalyst and requires no model server."
        )

    def _analyze(self, incident: Incident) -> AIAnalysis:
        raise NotImplementedError


class HostedLLMAnalyst(AIAnalyst):
    """PLACEHOLDER -- not implemented. Makes no network calls.

    Intended shape when implemented:

    * Provider-agnostic behind this interface. Default would be Claude via the
      `anthropic` SDK with the key read from `ANTHROPIC_API_KEY` -- from the
      environment only, never hardcoded, never logged, never in a prompt.
    * Same prompt assembly and delimiter-escaping rules as OllamaAnalyst.
    * REDACT BEFORE SENDING (trust boundary TB-3): minimize fields to what the
      analysis needs and strip secret-shaped strings. Incident data leaving
      our boundary is a disclosure event, so it should be a deliberate,
      documented one.
    * No tools/function-calling on the triage call. The model returns proposed
      action names; `ResponseProvider` resolves them against its allow-list.
      This is what makes a successful prompt injection a bad *suggestion*
      rather than a real *action*.
    * Hard caps: max input tokens per incident, max output tokens, per-day
      cost ceiling, request timeout, and a circuit breaker that degrades to
      rules-only when the budget is exhausted.
    * Log model, prompt hash, token counts and latency -- not the payload.

    TODO(problem-statement): implement if a hosted model is permitted.
    """

    name = "hosted"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "HostedLLMAnalyst is an interface placeholder. The core simulation "
            "runs on MockAIAnalyst and requires no API key."
        )

    def _analyze(self, incident: Incident) -> AIAnalysis:
        raise NotImplementedError
