"""Stateful adapter between the HTTP API and the SOC core.

Deliberately has NO FastAPI import: everything here is plain Python over the
existing `soc_core` pipeline, so it is testable with any interpreter and the
web layer stays a thin shell.

What this module does NOT do: invent detections, incidents, risk scores or
analysis text. Every value it returns is produced by the SOC core. It only
(1) runs the core for a chosen scenario, (2) holds the result in memory, and
(3) reshapes it for the console.

Security posture
----------------
* The client can never name a response action, a target, or an approver. It
  may only reference a server-generated `action_id` and say approve/reject.
* Approval identity is fixed server-side (there is no user auth in this local
  lab build) and every decision still passes the ResponseProvider policy
  gates: protected assets, target-in-evidence, tiers, dry-run-only for cloud.
* All state is in memory. Nothing is persisted, nothing leaves the process.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Final

from ..soc_core.cloud_detections import all_rules
from ..soc_core.cloud_scenarios import CLOUD_SCENARIOS
from ..soc_core.correlation import CorrelationEngine, Incident
from ..soc_core.demo import CLOUD_MAX_ACTIONS
from ..soc_core.detections import (
    DetectionEngine,
    DetectionResult,
    DetectionRule,
    default_rules,
    max_severity,
    severity_rank,
)
from ..soc_core.events import SecurityEvent, load_events
from ..soc_core.mitre import TECHNIQUES
from ..soc_core.correlation_engine import CorrelationEngine as EvidenceCorrelationEngine
from ..soc_core.correlation_engine import canonical
from ..soc_core.efficiency import (
    BASELINE_LABEL,
    BenchmarkRunner,
    Pricing,
    budget_experiment,
    canonical_fidelity,
    compare_costs,
)
from ..soc_core.evidence_context import ESTIMATED_OUTPUT_TOKENS, EvidenceContext, build_evidence_context
from ..soc_core.providers.ai_analyst import (
    AIAnalysis,
    AIAnalyst,
    InjectionFinding,
    MockAIAnalyst,
    check_citations,
    screen_for_injection,
)
from ..soc_core.providers.claude_ai import AIProviderError
from ..soc_core.providers.selection import build_analyst, configured_provider
from ..soc_core.providers.response import (
    MockResponseProvider,
    ResponseRequest,
    ResponseResult,
    requests_from_analysis,
)
from ..soc_core.providers.siem import EventQuery, MockSIEMProvider
from ..soc_core.risk import RiskAssessment, score_incident
from ..soc_core.scenarios import SCENARIOS, Scenario, events_for_scenario

logger = logging.getLogger("soc.api")
CANONICAL_SCENARIO_ID: Final[str] = "canonical-50k"

DATA_DIR: Final[Path] = Path(__file__).resolve().parents[2] / "data"
ENDPOINT_DATASET: Final[Path] = DATA_DIR / "sample_security_events.json"
CLOUD_DATASET: Final[Path] = DATA_DIR / "aws_cloudtrail_samples.json"

DEFAULT_SCENARIO: Final[str] = "hybrid-full"

# No authentication exists in this local lab build, so the approver identity
# is fixed server-side and labelled as such. It is never read from the client.
OPERATOR_ID: Final[str] = "local-analyst (unauthenticated lab session)"

MAX_REASON_LENGTH: Final[int] = 500
MAX_FIELD_PREVIEW: Final[int] = 240
MAX_EVENTS_RETURNED: Final[int] = 1000

TIER_RISK: Final[dict[str, str]] = {"T0": "LOW", "T1": "LOW", "T2": "HIGH", "T3": "CRITICAL"}


# ---------------------------------------------------------------------------
# Errors the web layer maps onto HTTP status codes
# ---------------------------------------------------------------------------


class NotFoundError(LookupError):
    """Unknown incident, scenario or action (HTTP 404)."""


class ConflictError(RuntimeError):
    """Valid request in the wrong state, e.g. deciding twice (HTTP 409)."""


class ProviderUnavailableError(RuntimeError):
    """A provider (AI analyst, response engine) failed (HTTP 503)."""


# ---------------------------------------------------------------------------
# Scenario catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioSpec:
    """One runnable scenario: which datasets, which rules, which subset."""

    scenario_id: str
    name: str
    description: str
    group: str
    profile: str
    datasets: tuple[Path, ...]
    rules: Callable[[], list[DetectionRule]]
    scenario_key: str | None = None
    registry: dict[str, Scenario] | None = None
    expect_alerts: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "group": self.group,
            "profile": self.profile,
            "expect_alerts": self.expect_alerts,
        }


def _group_for(scenario: Scenario, profile: str) -> str:
    if "injection" in scenario.name.lower():
        return "Prompt Injection Attempt"
    if not scenario.expect_alerts:
        return "Benign Activity"
    return "Cloud Attack" if profile == "cloud" else "Endpoint Attack"


def build_catalog() -> dict[str, ScenarioSpec]:
    """All runnable scenarios, derived from the existing scenario registries.

    The three `-full` entries run whole datasets. `hybrid-full` loads the
    endpoint and cloud datasets together through ONE engine run; it adds no
    linkage of its own, so incidents only merge if the evidence links them.
    """
    specs = [
        ScenarioSpec(
            "hybrid-full",
            "Hybrid estate: endpoint + network + cloud",
            "Both datasets through one pipeline run: endpoint intrusion, AWS "
            "control-plane attack chain, root misuse and a vendor false positive.",
            "Hybrid Attack",
            "hybrid",
            (ENDPOINT_DATASET, CLOUD_DATASET),
            all_rules,
        ),
        ScenarioSpec(
            "endpoint-full",
            "Endpoint estate: full dataset",
            "All 26 endpoint/network events: spray, MFA fatigue, macro "
            "execution, C2, LSASS access, injection attempts and benign noise.",
            "Endpoint Attack",
            "endpoint",
            (ENDPOINT_DATASET,),
            default_rules,
        ),
        ScenarioSpec(
            "cloud-full",
            "AWS estate: full dataset",
            "All 37 AWS events: CloudTrail, VPC Flow Logs and GuardDuty.",
            "Cloud Attack",
            "cloud",
            (CLOUD_DATASET,),
            all_rules,
        ),
    ]
    for key, scenario in sorted(SCENARIOS.items()):
        specs.append(
            ScenarioSpec(
                f"endpoint-{key.lower()}",
                scenario.name,
                scenario.description,
                _group_for(scenario, "endpoint"),
                "endpoint",
                (ENDPOINT_DATASET,),
                default_rules,
                key,
                SCENARIOS,
                scenario.expect_alerts,
            )
        )
    for key, scenario in sorted(CLOUD_SCENARIOS.items()):
        specs.append(
            ScenarioSpec(
                f"cloud-{key.lower()}",
                scenario.name,
                scenario.description,
                _group_for(scenario, "cloud"),
                "cloud",
                (CLOUD_DATASET,),
                all_rules,
                key,
                CLOUD_SCENARIOS,
                scenario.expect_alerts,
            )
        )
    specs.append(ScenarioSpec(
        scenario_id=CANONICAL_SCENARIO_ID,
        name="Canonical 50K SOC benchmark",
        description=("50,000 raw events reduced by the correlation engine; the console shows only the selected "
                     "evidence. Alerts are generic baseline signals, not ground truth."),
        group="Canonical Benchmark",
        profile="hybrid",
        datasets=(),
        rules=lambda: [],
    ))
    return {spec.scenario_id: spec for spec in specs}


# ---------------------------------------------------------------------------
# Response plan state
# ---------------------------------------------------------------------------


@dataclass
class PlannedAction:
    """A proposed action awaiting (or past) an analyst decision."""

    action_id: str
    request: ResponseRequest
    status: str
    result: ResponseResult | None = None
    decision_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        request = self.request
        return {
            "action_id": self.action_id,
            "action": request.action.value,
            "target": request.target,
            "reason": request.reason,
            "tier": request.tier,
            "risk": TIER_RISK.get(request.tier, "HIGH"),
            "reversible": request.reversible,
            "requires_approval": request.requires_approval,
            "status": self.status,
            "decided_by": (
                request.approved_by
                or (OPERATOR_ID if self.result and self.result.status == "rejected" else None)
            ),
            "decision_reason": self.decision_reason,
            "outcome_detail": self.result.detail if self.result else None,
            "would_have": self.result.would_have if self.result else None,
            "executed": bool(self.result and self.result.executed),
        }


_STATUS_FROM_RESULT: Final[dict[str, str]] = {
    "dry_run": "DRY_RUN_COMPLETE",
    "refused": "BLOCKED_BY_POLICY",
    "rejected": "REJECTED",
    "executed": "EXECUTED",
}


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


@dataclass
class _RunState:
    spec: ScenarioSpec
    started_at: datetime
    events: list[SecurityEvent] = field(default_factory=list)
    alerts: list[DetectionResult] = field(default_factory=list)
    rule_errors: list[str] = field(default_factory=list)
    findings: list[InjectionFinding] = field(default_factory=list)
    incidents: dict[str, Incident] = field(default_factory=dict)
    risk: dict[str, RiskAssessment] = field(default_factory=dict)
    analyses: dict[str, AIAnalysis] = field(default_factory=dict)
    plans: dict[str, list[PlannedAction]] = field(default_factory=dict)
    manual_tasks: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    providers: dict[str, MockResponseProvider] = field(default_factory=dict)
    contexts: dict[str, EvidenceContext] = field(default_factory=dict)
    ai_runs: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def events_by_id(self) -> dict[str, SecurityEvent]:
        """Computed on demand so it can never drift from `events`."""
        return {event.event_id: event for event in self.events}


class SocService:
    """Holds the current scenario run and answers console queries about it."""

    def __init__(
        self,
        default_scenario: str | None = DEFAULT_SCENARIO,
        analyst: AIAnalyst | None = None,
        fallback_analyst: AIAnalyst | None = None,
        efficiency: BenchmarkRunner | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self.efficiency = efficiency or BenchmarkRunner()
        self._fidelity: dict[str, Any] | None = None
        self._canonical: dict[str, Any] | None = None
        self.catalog = build_catalog()
        self.provider_config = configured_provider()
        if analyst is not None:
            # Explicit injection (tests, embedding): use exactly this analyst,
            # with only the fallback the caller asked for.
            self.analyst: AIAnalyst = analyst
            self.fallback_analyst: AIAnalyst | None = fallback_analyst
        else:
            # Environment selection: a live provider always gets the offline
            # mock as a visible fallback, so the console never depends on it.
            self.analyst = build_analyst(self.provider_config)
            self.fallback_analyst = (
                None if isinstance(self.analyst, MockAIAnalyst) else (fallback_analyst or MockAIAnalyst())
            )
        self._state: _RunState | None = None
        if default_scenario:
            self.run_scenario(default_scenario)

    # -- scenario execution -------------------------------------------------

    def list_scenarios(self) -> list[dict[str, Any]]:
        current = self._state.spec.scenario_id if self._state else None
        return [
            {**spec.to_dict(), "active": spec.scenario_id == current}
            for spec in self.catalog.values()
        ]

    def run_scenario(self, scenario_id: str) -> dict[str, Any]:
        """Run the SOC core end to end (up to risk) for one scenario.

        AI analysis and response planning are deliberately NOT run here: they
        are analyst-triggered steps, exactly as in a real console.
        """
        spec = self.catalog.get(scenario_id)
        if spec is None:
            raise NotFoundError(f"unknown scenario {scenario_id!r}")

        if spec.scenario_id == CANONICAL_SCENARIO_ID:
            return self._run_canonical(spec)
        events: list[SecurityEvent] = []
        for dataset in spec.datasets:
            events.extend(load_events(dataset))
        siem = MockSIEMProvider(events=events)
        events = siem.query_events(EventQuery(limit=MAX_EVENTS_RETURNED))
        if spec.scenario_key:
            events = events_for_scenario(events, spec.scenario_key, spec.registry)

        state = _RunState(spec=spec, started_at=datetime.now(timezone.utc), events=events)
        state.findings = screen_for_injection(events)
        state.alerts, state.rule_errors = DetectionEngine(spec.rules()).run(events)
        for error in state.rule_errors:
            logger.warning("detection rule error: %s", error)
        for incident in CorrelationEngine().correlate(state.alerts, events):
            state.incidents[incident.incident_id] = incident
            state.risk[incident.incident_id] = score_incident(incident)

        with self._lock:
            self._state = state
        logger.info(
            "scenario run: %s events=%d alerts=%d incidents=%d injection_findings=%d",
            scenario_id, len(events), len(state.alerts), len(state.incidents), len(state.findings),
        )
        return self.metrics()

    def _run_canonical(self, spec: ScenarioSpec) -> dict[str, Any]:
        """Canonical 50K: the correlation engine reduces the raw telemetry; the
        console (incidents, EvidenceContext, AI, response) then runs on the
        selected evidence only. Raw telemetry never reaches the AI path."""
        run = canonical.run_representation("raw")
        events, alerts = canonical.console_inputs(run.events, run.signals, run.result.selected_event_ids)
        state = _RunState(spec=spec, started_at=datetime.now(timezone.utc), events=events)
        state.findings = screen_for_injection(events)
        state.alerts = alerts
        for incident in CorrelationEngine().correlate(state.alerts, events):
            state.incidents[incident.incident_id] = incident
            state.risk[incident.incident_id] = score_incident(incident)
        with self._lock:
            self._state = state
        logger.info("scenario run: %s raw=%d selected=%d alerts=%d incidents=%d", spec.scenario_id,
                    len(run.events), len(events), len(alerts), len(state.incidents))
        return self.metrics()

    @property
    def state(self) -> _RunState:
        if self._state is None:
            raise ConflictError("no scenario has been run yet")
        return self._state

    # -- read models ----------------------------------------------------------

    def health(self) -> dict[str, Any]:
        state = self._state
        return {
            "status": "ok",
            "soc_online": True,
            "environment": "LOCAL / OFFLINE LAB",
            "siem": {"provider": "MockSIEMProvider", "connected": True, "mode": "synthetic datasets"},
            "ai_analyst": {
                "provider": type(self.analyst).__name__,
                "name": _analyst_name(self.analyst),
                "fallback": type(self.fallback_analyst).__name__ if self.fallback_analyst else None,
                "ready": True,
                "config": self.provider_config.to_dict(),
            },
            "response_engine": {"provider": "MockResponseProvider", "mode": "DRY RUN", "armed": True},
            "active_scenario": state.spec.scenario_id if state else None,
            "rule_errors": list(state.rule_errors) if state else [],
        }

    def metrics(self) -> dict[str, Any]:
        state = self.state
        alert_severity = {level: 0 for level in ("critical", "high", "medium", "low", "informational")}
        for alert in state.alerts:
            alert_severity[alert.severity] = alert_severity.get(alert.severity, 0) + 1
        incident_severity = {level: 0 for level in alert_severity}
        for incident in state.incidents.values():
            incident_severity[incident.severity] += 1

        responses = {"pending": 0, "dry_run": 0, "blocked": 0, "rejected": 0, "executed": 0}
        for plan in state.plans.values():
            for action in plan:
                key = {
                    "PENDING_APPROVAL": "pending",
                    "READY": "pending",
                    "DRY_RUN_COMPLETE": "dry_run",
                    "BLOCKED_BY_POLICY": "blocked",
                    "REJECTED": "rejected",
                    "EXECUTED": "executed",
                }[action.status]
                responses[key] += 1

        return {
            "scenario": {
                **state.spec.to_dict(),
                "started_at": state.started_at.isoformat(),
            },
            "alert_severity": alert_severity,
            "incident_severity": incident_severity,
            "active_incidents": len(state.incidents),
            "alerts": len(state.alerts),
            "events_ingested": len(state.events),
            "ai_investigations": len(state.analyses),
            "injection_findings": len(state.findings),
            "responses": responses,
        }

    def list_incidents(self) -> list[dict[str, Any]]:
        state = self.state
        return [self._incident_summary(incident) for incident in state.incidents.values()]

    def incident_detail(self, incident_id: str) -> dict[str, Any]:
        state = self.state
        incident = self._incident(incident_id)
        analysis = state.analyses.get(incident_id)
        plan = state.plans.get(incident_id)
        incident_event_ids = set(incident.event_ids)
        return {
            "incident": self._incident_summary(incident),
            "risk": state.risk[incident_id].to_dict(),
            "attack_chain": self._attack_chain(incident),
            "mitre": self._mitre(incident),
            "timeline": self._timeline(incident),
            "correlated": {
                "alerts": [self._alert_view(alert, incident_id) for alert in incident.alerts],
                "rule_ids": incident.rule_ids,
                "hosts": incident.hosts,
                "users": incident.users,
                "source_ips": incident.source_ips,
                "cloud_accounts": incident.cloud_accounts,
                "attack_stage": incident.attack_stage,
                "notes": incident.notes,
            },
            "injection_findings": [
                f.to_dict() for f in state.findings if f.event_id in incident_event_ids
            ],
            "analysis": analysis.to_dict() if analysis else None,
            "response_plan": [a.to_dict() for a in plan] if plan is not None else None,
            "manual_tasks": state.manual_tasks.get(incident_id, []),
            "ai_context": {
                "metrics": self._context(incident_id).metrics,
                "last_run": state.ai_runs.get(incident_id),
                "configured_provider": _analyst_name(self.analyst),
            },
        }

    def context_pack(self, incident_id: str) -> dict[str, Any]:
        """The exact redacted payload an LLM would receive for this incident."""
        context = self._context(incident_id)
        return {"incident_id": incident_id, "metrics": context.metrics, "pack": context.pack}

    def _context(self, incident_id: str) -> EvidenceContext:
        """Build (once per run) the redacted evidence context for an incident."""
        state = self.state
        incident = self._incident(incident_id)
        with self._lock:
            if incident_id not in state.contexts:
                state.contexts[incident_id] = build_evidence_context(
                    incident,
                    all_events=state.events,
                    risk=state.risk[incident_id],
                    findings=state.findings,
                )
            return state.contexts[incident_id]

    def list_alerts(self) -> list[dict[str, Any]]:
        state = self.state
        owner = {
            alert.alert_id: incident.incident_id
            for incident in state.incidents.values()
            for alert in incident.alerts
        }
        return [self._alert_view(alert, owner.get(alert.alert_id)) for alert in state.alerts]

    def list_events(self, limit: int = 500) -> list[dict[str, Any]]:
        if limit < 1 or limit > MAX_EVENTS_RETURNED:
            raise ValueError(f"limit must be between 1 and {MAX_EVENTS_RETURNED}")
        state = self.state
        rules_by_event = self._rules_by_event(state.alerts)
        flagged = self._flags_by_event(state.findings)
        return [
            self._event_view(event, rules_by_event, flagged)
            for event in state.events[:limit]
        ]

    def screening(self) -> list[dict[str, Any]]:
        state = self.state
        owner = {
            event_id: incident.incident_id
            for incident in state.incidents.values()
            for event_id in incident.event_ids
        }
        return [{**f.to_dict(), "incident_id": owner.get(f.event_id)} for f in state.findings]

    # -- analyst actions ------------------------------------------------------

    def analyze(self, incident_id: str) -> dict[str, Any]:
        """Incident -> EvidenceContext (reduced + redacted + token-estimated)
        -> AI provider -> validated structured investigation.

        The provider receives only the context. If the configured provider
        fails and a fallback exists, the fallback runs and the response says
        so explicitly (`provider.used`, `provider.fallback_reason`).
        """
        incident = self._incident(incident_id)
        context = self._context(incident_id)
        name = _analyst_name(self.analyst)
        run: dict[str, Any] = {
            "requested": name,
            "used": name,
            "fallback_reason": None,
            "live_model": False,
        }
        started = time.perf_counter()
        try:
            analysis = _run_analyst(self.analyst, incident, context)
            run["live_model"] = name != "mock"
            run["latency_ms"] = round((time.perf_counter() - started) * 1000)
        except Exception as exc:  # provider failure must not crash the console
            reason = str(exc) if isinstance(exc, AIProviderError) else "AI analyst failed"
            logger.warning("AI analyst %s failed for %s: %s", name, incident_id, reason)
            if self.fallback_analyst is None:
                raise ProviderUnavailableError(
                    "AI analyst unavailable. Deterministic evidence is unaffected."
                ) from exc
            try:
                analysis = _run_analyst(self.fallback_analyst, incident, context)
            except Exception as fallback_exc:
                logger.exception("fallback analyst failed for %s", incident_id)
                raise ProviderUnavailableError(
                    "AI analyst unavailable. Deterministic evidence is unaffected."
                ) from fallback_exc
            run.update(used=_analyst_name(self.fallback_analyst), fallback_reason=reason)

        if not analysis.citations:
            # Context-free providers (the mock) cite events, not evidence IDs.
            # Derive evidence-ID citations from their deterministic evidence.
            derived = [
                {"claim": item.get("observation", ""), "classification": "CORRELATED",
                 "evidence_ids": context.evidence_for_events(item.get("event_ids", []))}
                for item in analysis.evidence
            ]
            analysis = replace(analysis, citations=check_citations(derived, context))

        run["model"] = analysis.model
        run["usage"] = getattr(self.analyst, "last_usage", None) if run["live_model"] else None
        with self._lock:
            self.state.analyses[incident_id] = analysis
            self.state.ai_runs[incident_id] = run
        logger.info(
            "ai investigation: incident=%s provider=%s model=%s tokens~%s warnings=%d injection=%s",
            incident_id, run["used"], analysis.model, context.metrics["estimated_tokens"],
            len(analysis.validation_warnings), analysis.injection_attempt_detected,
        )
        return {
            "provider": run,
            "investigation": analysis.to_dict(),
            "context_metrics": context.metrics,
        }

    # -- AI efficiency lab ----------------------------------------------------

    def efficiency_status(self) -> dict[str, Any]:
        return self.efficiency.status()

    def efficiency_run(self, scales: list[int], force: bool = False) -> dict[str, Any]:
        """Queue benchmark scales; they run in a background thread."""
        logger.info("efficiency benchmark requested: scales=%s force=%s", scales, force)
        return self.efficiency.request(scales, force=force)

    def efficiency_fidelity(self) -> dict[str, Any]:
        """Evidence retention + budget experiment on the canonical incidents
        (deterministic, computed once)."""
        with self._lock:
            if self._fidelity is None:
                self._fidelity = {"retention": canonical_fidelity(), "budget": budget_experiment()}
            return self._fidelity

    def efficiency_cost(
        self,
        scale: int,
        pricing: Pricing,
        investigations: int,
        output_tokens: int = ESTIMATED_OUTPUT_TOKENS,
        context_window: int | None = None,
    ) -> dict[str, Any]:
        """Path A (raw baseline, theoretical) vs Path B (evidence context)
        for a MEASURED scale. Refuses scales that have not been measured."""
        result = self.efficiency.results.get(scale)
        if result is None:
            raise ConflictError(f"Scale {scale:,} has not been measured yet. Run the benchmark first.")
        comparison = compare_costs(
            result["estimated_raw_context_tokens"], result["estimated_context_tokens"], pricing,
            output_tokens=output_tokens, investigations=investigations, context_window=context_window,
        )
        return {"scale": scale, "baseline_label": BASELINE_LABEL, **comparison}

    def efficiency_live(self) -> dict[str, Any]:
        """Measured usage from real model calls made by the normal analyze
        path (EvidenceContext only). There is no separate live benchmark
        pipeline, and nothing here triggers a model call."""
        with self._lock:
            runs = [
                {"incident_id": incident_id, "model": run.get("model"), "latency_ms": run.get("latency_ms"),
                 "input_tokens": (run.get("usage") or {}).get("input_tokens"),
                 "output_tokens": (run.get("usage") or {}).get("output_tokens"),
                 "served_by": (run.get("usage") or {}).get("served_by"),
                 "estimated_input_tokens": self._context(incident_id).metrics["estimated_tokens"]}
                for incident_id, run in self.state.ai_runs.items()
                if run.get("live_model") and run.get("usage")
            ]
        configured = self.provider_config.to_dict()
        return {
            "available": bool(runs),
            "message": None if runs else "Live model usage unavailable — benchmark running offline.",
            "provider": configured,
            "runs": runs,
        }

    # -- canonical 50K benchmark ------------------------------------------------

    def canonical_benchmark(self, refresh: bool = False) -> dict[str, Any]:
        """Measured canonical 50K result (cached on disk by the CLI or the
        first request). Offline; nothing here calls a model."""
        with self._lock:
            if not refresh and self._canonical is None and canonical.CACHE_FILE.is_file():
                try:
                    self._canonical = json.loads(canonical.CACHE_FILE.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    self._canonical = None      # corrupt cache: recompute, never trust
            if refresh or self._canonical is None:
                try:
                    result = canonical.canonical_result()
                except canonical.DatasetError as exc:
                    raise NotFoundError(f"canonical dataset unavailable: {exc}") from exc
                canonical.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                canonical.CACHE_FILE.write_text(json.dumps(result, indent=1), encoding="utf-8")
                self._canonical = result
            return self._canonical

    # -- correlation engine (Stage 3.5, debug only) ---------------------------

    def correlation_debug(self, limit: int = 25) -> dict[str, Any]:
        """Run the generic correlation engine over the current scenario's
        events + alerts. Read-only inspection: nothing downstream consumes it
        yet, no model is called, and only IDs/scores are returned (no raw
        event text)."""
        with self._lock:
            events, alerts = list(self.state.events), list(self.state.alerts)
            scenario = self.state.spec.scenario_id
        result = EvidenceCorrelationEngine().run(events, alerts)
        return {
            "scenario": scenario,
            "summary": result.summary(),
            "normalization": result.report.to_dict(),
            "entities": result.index.stats(),
            "candidates": [c.to_dict() for c in result.candidates(limit)],
        }

    def response_plan(self, incident_id: str) -> dict[str, Any]:
        """Turn the analysis into server-owned, policy-gated proposed actions.

        Idempotent: a second call returns the existing plan rather than
        creating a new one (a new plan would reset the audit trail).
        """
        state = self.state
        incident = self._incident(incident_id)
        with self._lock:
            if incident_id in state.plans:
                return self._plan_view(incident_id)
            analysis = state.analyses.get(incident_id)
            if analysis is None:
                raise ConflictError("run the AI investigation before requesting a response plan")

            if incident.cloud_accounts:
                provider = MockResponseProvider(
                    dry_run=True,
                    allowed_targets=[*incident.entity_values, incident_id],
                    max_actions=CLOUD_MAX_ACTIONS,
                )
            else:
                provider = MockResponseProvider(
                    dry_run=True,
                    allowed_targets=[*incident.hosts, *incident.users, incident_id],
                )
            requests = requests_from_analysis(
                analysis.recommended_actions,
                incident_id,
                hosts=incident.hosts,
                users=incident.users,
            )
            state.providers[incident_id] = provider
            state.plans[incident_id] = [
                PlannedAction(
                    action_id=f"act-{index:02d}",
                    request=request,
                    status="PENDING_APPROVAL" if request.requires_approval else "READY",
                )
                for index, request in enumerate(requests, start=1)
            ]
            state.manual_tasks[incident_id] = [
                {"action": a["action"], "rationale": a.get("rationale", ""), "target": a.get("target")}
                for a in analysis.recommended_actions
                if "response_action" in a and a["response_action"] is None
            ]
        logger.info("response plan: incident=%s actions=%d", incident_id, len(requests))
        return self._plan_view(incident_id)

    def decide(
        self, incident_id: str, action_id: str, decision: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Record an analyst decision on one server-generated action.

        Approve -> the provider runs its policy gates and performs a DRY RUN
        (or refuses). Reject -> audited rejection. Nothing is ever executed.
        """
        if decision not in {"approve", "reject"}:
            raise ValueError("decision must be 'approve' or 'reject'")
        clean_reason = _clean_text(reason)

        state = self.state
        self._incident(incident_id)
        with self._lock:
            plan = state.plans.get(incident_id)
            if plan is None:
                raise ConflictError("no response plan exists for this incident yet")
            action = next((a for a in plan if a.action_id == action_id), None)
            if action is None:
                raise NotFoundError(f"unknown action {action_id!r} for {incident_id}")
            if action.status not in {"PENDING_APPROVAL", "READY"}:
                raise ConflictError(f"{action_id} was already decided ({action.status})")

            provider = state.providers[incident_id]
            try:
                if decision == "reject":
                    result = provider.record_rejection(
                        action.request,
                        reviewer=OPERATOR_ID,
                        reason=clean_reason or "rejected by analyst",
                    )
                else:
                    request = action.request
                    if request.requires_approval:
                        request = replace(request, approved_by=OPERATOR_ID)
                    action.request = request
                    result = provider.execute(request)
            except Exception as exc:
                logger.exception("response provider failed for %s/%s", incident_id, action_id)
                raise ProviderUnavailableError(
                    "Response engine unavailable. No action was taken."
                ) from exc

            action.result = result
            action.status = _STATUS_FROM_RESULT[result.status]
            action.decision_reason = clean_reason

        logger.info(
            "response decision: incident=%s action=%s type=%s target=%s decision=%s outcome=%s",
            incident_id, action_id, action.request.action.value, action.request.target,
            decision, action.status,
        )
        return {"action": action.to_dict(), "plan": self._plan_view(incident_id)}

    # -- helpers --------------------------------------------------------------

    def _incident(self, incident_id: str) -> Incident:
        incident = self.state.incidents.get(incident_id)
        if incident is None:
            raise NotFoundError(f"unknown incident {incident_id!r}")
        return incident

    def _plan_view(self, incident_id: str) -> dict[str, Any]:
        state = self.state
        plan = state.plans.get(incident_id, [])
        return {
            "incident_id": incident_id,
            "mode": "DRY RUN (simulated; no infrastructure is ever changed)",
            "operator": OPERATOR_ID,
            "actions": [a.to_dict() for a in plan],
            "manual_tasks": state.manual_tasks.get(incident_id, []),
            "executed_count": sum(1 for a in plan if a.result and a.result.executed),
        }

    def _status(self, incident_id: str) -> str:
        state = self.state
        plan = state.plans.get(incident_id)
        if plan is not None:
            if any(a.status in {"PENDING_APPROVAL", "READY"} for a in plan):
                return "AWAITING_APPROVAL"
            return "RESPONSE_REVIEWED"
        if incident_id in state.analyses:
            return "INVESTIGATING"
        return "NEW"

    def _incident_summary(self, incident: Incident) -> dict[str, Any]:
        state = self.state
        risk = state.risk[incident.incident_id]
        event_ids = set(incident.event_ids)
        sources = sorted({event.source for event in incident.events})
        is_cloud = any(event.is_cloud for event in incident.events)
        is_endpoint = any(not event.is_cloud for event in incident.events)
        domain = "hybrid" if is_cloud and is_endpoint and not incident.cloud_accounts else (
            "cloud" if is_cloud else "endpoint"
        )
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": risk.score,
            "risk_band": risk.band,
            "confidence": (
                state.analyses[incident.incident_id].confidence
                if incident.incident_id in state.analyses else None
            ),
            "alert_count": len(incident.alerts),
            "event_count": len(incident.events),
            "technique_ids": incident.technique_ids,
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            "status": self._status(incident.incident_id),
            "sources": sources,
            "domain": domain,
            "hosts": incident.hosts,
            "users": incident.users,
            "cloud_accounts": incident.cloud_accounts,
            "attack_stage": incident.attack_stage,
            "injection_detected": any(f.event_id in event_ids for f in state.findings),
        }

    def _alert_view(self, alert: DetectionResult, incident_id: str | None) -> dict[str, Any]:
        events = self.state.events_by_id
        stamps = [events[eid].timestamp for eid in alert.evidence_event_ids if eid in events]
        return {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "evidence_event_ids": list(alert.evidence_event_ids),
            "technique_ids": list(alert.technique_ids),
            "matched_fields": dict(alert.matched_fields),
            "first_seen": min(stamps).isoformat() if stamps else None,
            "incident_id": incident_id,
        }

    def _attack_chain(self, incident: Incident) -> list[dict[str, Any]]:
        """Alerts in the order their evidence first appeared.

        Consecutive alerts from the same rule collapse into one node. The
        chain is built only from correlated alerts: no step is inferred.
        """
        events = self.state.events_by_id

        def first_seen(alert: DetectionResult) -> datetime:
            return min(events[eid].timestamp for eid in alert.evidence_event_ids)

        nodes: list[dict[str, Any]] = []
        for alert in sorted(incident.alerts, key=lambda a: (first_seen(a), a.rule_id)):
            if nodes and nodes[-1]["rule_id"] == alert.rule_id:
                node = nodes[-1]
                node["alert_ids"].append(alert.alert_id)
                node["event_ids"].extend(
                    eid for eid in alert.evidence_event_ids if eid not in node["event_ids"]
                )
                node["severity"] = max_severity([node["severity"], alert.severity])
                continue
            techniques = [
                {"technique_id": tid, "name": TECHNIQUES[tid].name, "tactic": TECHNIQUES[tid].tactic}
                for tid in alert.technique_ids if tid in TECHNIQUES
            ]
            nodes.append(
                {
                    "rule_id": alert.rule_id,
                    "label": techniques[0]["name"] if techniques else alert.title,
                    "title": alert.title,
                    "tactic": techniques[0]["tactic"] if techniques else "Unmapped",
                    "techniques": techniques,
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "first_seen": first_seen(alert).isoformat(),
                    "alert_ids": [alert.alert_id],
                    "event_ids": list(alert.evidence_event_ids),
                    "matched_fields": dict(alert.matched_fields),
                }
            )
        for index, node in enumerate(nodes, start=1):
            node["step"] = index
        return nodes

    def _mitre(self, incident: Incident) -> list[dict[str, Any]]:
        entries = []
        for technique_id in incident.technique_ids:
            technique = TECHNIQUES.get(technique_id)
            if technique is None:
                continue
            mapping_alerts = [a for a in incident.alerts if technique_id in a.technique_ids]
            event_ids: list[str] = []
            for alert in mapping_alerts:
                event_ids.extend(e for e in alert.evidence_event_ids if e not in event_ids)
            entries.append(
                {
                    "technique_id": technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                    "detected_by": [
                        {
                            "rule_id": a.rule_id,
                            "alert_id": a.alert_id,
                            "title": a.title,
                            "description": a.description,
                            "confidence": a.confidence,
                            "matched_fields": dict(a.matched_fields),
                        }
                        for a in mapping_alerts
                    ],
                    "event_ids": event_ids,
                }
            )
        return entries

    def _timeline(self, incident: Incident) -> list[dict[str, Any]]:
        rules_by_event = self._rules_by_event(incident.alerts)
        flagged = self._flags_by_event(self.state.findings)
        events = {event.event_id: event for event in incident.events}
        views = []
        for entry in incident.timeline:
            view = self._event_view(events[entry.event_id], rules_by_event, flagged)
            view["summary"] = entry.summary
            views.append(view)
        return views

    @staticmethod
    def _rules_by_event(alerts: list[DetectionResult]) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for alert in alerts:
            for event_id in alert.evidence_event_ids:
                rules = mapping.setdefault(event_id, [])
                if alert.rule_id not in rules:
                    rules.append(alert.rule_id)
        return mapping

    @staticmethod
    def _flags_by_event(findings: list[InjectionFinding]) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for finding in findings:
            mapping.setdefault(finding.event_id, []).append(finding.field_path)
        return mapping

    @staticmethod
    def _event_view(
        event: SecurityEvent,
        rules_by_event: dict[str, list[str]],
        flagged: dict[str, list[str]],
    ) -> dict[str, Any]:
        """Structured view of one event. Free-text fields are attacker-
        controlled: they are truncated and returned under `untrusted_fields`
        so the UI can render them as inert, clearly-labelled data."""
        destination = (
            f"{event.destination_ip}:{event.destination_port}"
            if event.destination_ip else None
        )
        untrusted = {
            "process": event.process,
            "parent_process": event.parent_process,
            "command_line": event.command_line,
            "domain": event.domain,
            "api_call": event.cloud_event_name,
            "user_agent": event.user_agent,
        }
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "category": event.category,
            "action": event.action,
            "outcome": event.outcome,
            "severity": event.severity,
            "source": event.source,
            "user": event.username,
            "host": event.hostname,
            "account_id": event.account_id,
            "source_ip": event.source_ip,
            "destination": destination,
            "rules": rules_by_event.get(event.event_id, []),
            "injection_flags": flagged.get(event.event_id, []),
            "untrusted_fields": {
                key: _preview(value) for key, value in untrusted.items() if value
            },
        }


def _analyst_name(analyst: Any) -> str:
    return str(getattr(analyst, "name", type(analyst).__name__))


def _run_analyst(analyst: Any, incident: Incident, context: EvidenceContext) -> AIAnalysis:
    """AIAnalyst subclasses get the redacted context; any other analyst-shaped
    object is called with the incident alone (it never sees the context)."""
    if isinstance(analyst, AIAnalyst):
        return analyst.analyze(incident, context)
    return analyst.analyze(incident)


def _preview(value: str) -> str:
    text = _clean_text(value) or ""
    return text if len(text) <= MAX_FIELD_PREVIEW else text[: MAX_FIELD_PREVIEW - 1] + "…"


def _clean_text(value: str | None) -> str | None:
    """Strip control characters and bound length. Used for analyst-supplied
    reasons and for previews of untrusted log fields."""
    if value is None:
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable() or ch == " ").strip()
    return cleaned[:MAX_REASON_LENGTH] or None
