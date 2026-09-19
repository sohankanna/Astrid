"""End-to-end SOC pipeline demonstration.

Run with:

    python -m app.soc_core.demo
    python -m app.soc_core.demo --scenario B
    python -m app.soc_core.demo --json

Runs entirely offline: no network, no API key, no database, no SIEM. Every
external system is behind a Mock provider.

Pipeline:

    events -> detections -> alerts -> correlation -> incident
           -> risk score -> AI triage -> proposed response (DRY RUN)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Sequence

from .cloud_detections import all_rules
from .cloud_scenarios import (
    CLOUD_SCENARIOS,
    SIMULATED_ANALYST_DECISIONS,
    SIMULATED_REVIEWER,
)
from .correlation import CorrelationEngine, Incident
from .detections import DetectionEngine, DetectionResult, DetectionRule, default_rules
from .events import SecurityEvent
from .mitre import describe
from .providers.ai_analyst import (
    AIAnalysis,
    InjectionFinding,
    MockAIAnalyst,
    screen_for_injection,
)
from .providers.response import (
    MockResponseProvider,
    ResponseRequest,
    ResponseResult,
    requests_from_analysis,
)
from .providers.siem import EventQuery, MockSIEMProvider
from .risk import RiskAssessment, score_incident
from .scenarios import SCENARIOS, Scenario, events_for_scenario

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DEFAULT_DATASET = DATA_DIR / "sample_security_events.json"
CLOUD_DATASET = DATA_DIR / "aws_cloudtrail_samples.json"

# The cloud playbook proposes more actions per incident than the endpoint one
# (keys, users, policies, SGs, instances, indicators). The cap is raised
# explicitly and visibly rather than silently.
CLOUD_MAX_ACTIONS = 25


@dataclass(frozen=True)
class Profile:
    """A dataset + rule set + scenario registry that run together.

    `simulate_analyst` is True only for the cloud demo, where a fixed and
    clearly labelled decision table stands in for a human approver so every
    branch of the approval path can be shown offline.
    """

    name: str
    dataset: Path
    rules: Callable[[], list[DetectionRule]]
    scenarios: dict[str, Scenario]
    simulate_analyst: bool


PROFILES: dict[str, Profile] = {
    "endpoint": Profile("endpoint", DEFAULT_DATASET, default_rules, SCENARIOS, False),
    "cloud": Profile("cloud", CLOUD_DATASET, all_rules, CLOUD_SCENARIOS, True),
}

RULE = "=" * 78
THIN = "-" * 78


def _header(title: str) -> str:
    return f"\n{RULE}\n{title}\n{RULE}"


@dataclass
class PipelineOutput:
    """Everything one pipeline run produced.

    Returned rather than printed so tests assert against exactly what the demo
    displays, instead of re-deriving it.
    """

    events: list[SecurityEvent]
    injection_findings: list[InjectionFinding]
    alerts: list[DetectionResult]
    results: list[tuple[Incident, RiskAssessment, AIAnalysis, list[ResponseResult]]]
    profile: str = "endpoint"


def run_pipeline(
    dataset_path: Path | None = None,
    scenario: str | None = None,
    *,
    profile: str = "endpoint",
) -> PipelineOutput:
    """Execute the full pipeline and return everything produced.

    `profile="endpoint"` (the default) is exactly the original pipeline.
    `profile="cloud"` loads the AWS dataset, runs endpoint + cloud rules on
    the same engine, and applies the SIMULATED analyst decision table.
    """
    prof = PROFILES[profile]
    siem = MockSIEMProvider(dataset_path=dataset_path or prof.dataset)
    events = siem.query_events(EventQuery(limit=1000))

    if scenario:
        events = events_for_scenario(events, scenario, prof.scenarios)

    # Injection screening runs across ALL ingested events, not just those that
    # end up in an incident. A log line trying to manipulate automated
    # analysis is a finding in its own right, and it must be visible even when
    # no detection rule fires on that event.
    injection_findings = screen_for_injection(events)

    alerts, rule_errors = DetectionEngine(prof.rules()).run(events)
    if rule_errors:
        print("WARNING: rule errors occurred:", file=sys.stderr)
        for error in rule_errors:
            print(f"  {error}", file=sys.stderr)

    incidents = CorrelationEngine().correlate(alerts, events)

    analyst = MockAIAnalyst()
    results = []
    for incident in incidents:
        risk = score_incident(incident)
        analysis = analyst.analyze(incident)

        requests = requests_from_analysis(
            analysis.recommended_actions,
            incident.incident_id,
            hosts=incident.hosts,
            users=incident.users,
        )

        if prof.simulate_analyst:
            # Cloud targets are keys, policies, SGs and IPs, not just hosts and
            # users, so the allow-list is every entity in the evidence.
            responder = MockResponseProvider(
                dry_run=True,
                allowed_targets=[*incident.entity_values, incident.incident_id],
                max_actions=CLOUD_MAX_ACTIONS,
            )
            response_results = [
                _apply_simulated_decision(responder, request) for request in requests
            ]
        else:
            # Response provider is constrained to entities actually observed in
            # this incident, and runs dry by default.
            responder = MockResponseProvider(
                dry_run=True,
                allowed_targets=[*incident.hosts, *incident.users, incident.incident_id],
            )
            response_results = [responder.execute(request) for request in requests]
        results.append((incident, risk, analysis, response_results))

    return PipelineOutput(
        events=events,
        injection_findings=injection_findings,
        alerts=alerts,
        results=results,
        profile=profile,
    )


def _apply_simulated_decision(
    responder: MockResponseProvider, request: ResponseRequest
) -> ResponseResult:
    """Stand-in for a human approver in the offline cloud demo.

    Only requests that need approval consult the table. Listed approvals get
    `approved_by` set to the clearly-SIMULATED reviewer; listed rejections are
    audited as rejections; anything unlisted stays pending and the provider
    refuses it for lack of approval. Approval still leads only to a DRY RUN:
    cloud actions cannot execute in this build.
    """
    if not request.requires_approval:
        return responder.execute(request)
    decision = SIMULATED_ANALYST_DECISIONS.get((request.action.value, request.target))
    if decision is None:
        return responder.execute(request)
    verdict, reason = decision
    if verdict == "reject":
        return responder.record_rejection(
            request, reviewer=SIMULATED_REVIEWER, reason=reason
        )
    return responder.execute(replace(request, approved_by=SIMULATED_REVIEWER))


def render(output: PipelineOutput, scenario: str | None) -> None:
    """Print a human-readable walkthrough of the pipeline."""
    events, alerts, results = output.events, output.alerts, output.results
    registry = PROFILES[output.profile].scenarios
    label = f" [scenario {scenario}: {registry[scenario].name}]" if scenario else ""
    if output.profile != "endpoint":
        label = f" [{output.profile} profile]{label}"
    print(_header(f"1. INGEST & NORMALIZE{label}"))
    print(f"Loaded and validated {len(events)} events via MockSIEMProvider (offline).")
    by_category: dict[str, int] = {}
    for event in events:
        by_category[event.category] = by_category.get(event.category, 0) + 1
    for category, count in sorted(by_category.items()):
        print(f"  {category:16} {count}")

    print(_header("1b. UNTRUSTED CONTENT SCREENING (all ingested events)"))
    if not output.injection_findings:
        print("No instruction-shaped content found in event fields.")
    else:
        print(
            f"{len(output.injection_findings)} field(s) contain text that attempts to "
            f"manipulate automated analysis.\nReported as evidence, NOT obeyed, and "
            f"never stripped from the record:"
        )
        for finding in output.injection_findings:
            print(f"  ! {finding.event_id}  {finding.field_path}")
            print(f"      pattern : {finding.pattern}")
            print(f"      excerpt : {finding.excerpt[:100]}")

    print(_header("2. DETECTION (deterministic -- no AI involved)"))
    if not alerts:
        print("No alerts. Activity matched no detection rule.")
    for alert in alerts:
        print(f"  [{alert.severity:8}] {alert.rule_id}  {alert.title}")
        print(f"             confidence={alert.confidence}  evidence={list(alert.evidence_event_ids)}")
        if alert.matched_fields:
            fields = ", ".join(f"{k}={v}" for k, v in alert.matched_fields.items())
            print(f"             matched: {fields}")

    print(_header("3. CORRELATION -> INCIDENTS"))
    if not results:
        print("No incidents produced.")
    for incident, risk, analysis, responses in results:
        print(f"\n{incident.incident_id}  [{incident.severity}]  {incident.title}")
        print(THIN)
        print(f"  window      : {incident.first_seen} -> {incident.last_seen} ({incident.duration})")
        print(f"  hosts       : {', '.join(incident.hosts) or '-'}")
        print(f"  users       : {', '.join(incident.users) or '-'}")
        print(f"  source IPs  : {', '.join(incident.source_ips) or '-'}")
        print(f"  alerts      : {len(incident.alerts)} from rules {', '.join(incident.rule_ids)}")
        for note in incident.notes:
            print(f"  note        : {note}")

        print("\n  TIMELINE")
        for entry in incident.timeline:
            marker = "*" if entry.alert_ids else " "
            print(f"   {marker} {entry.timestamp:%H:%M:%S}  {entry.event_id}  {entry.summary}")

        print("\n  MITRE ATT&CK")
        for technique_id in incident.technique_ids:
            print(f"    - {describe(technique_id)}")
        print(f"    furthest stage: {incident.attack_stage}")

        print(f"\n  RISK SCORE (transparent, not AI-generated)")
        for line in risk.explanation.splitlines():
            print(f"    {line}")

        print(f"\n  AI TRIAGE (advisory -- model: {analysis.model})")
        print(f"    summary     : {analysis.summary}")
        print(f"    severity    : {analysis.severity_assessment}   confidence: {analysis.confidence}")
        print(f"    stage       : {analysis.likely_attack_stage}")
        print(f"    injection   : {'DETECTED' if analysis.injection_attempt_detected else 'none detected'}")
        for finding in analysis.injection_findings:
            print(f"        ! {finding.event_id} {finding.field_path}: {finding.excerpt[:70]}...")
        print("    uncertainty :")
        for item in analysis.uncertainty:
            print(f"        - {item}")
        print("    questions for the analyst:")
        for question in analysis.analyst_questions:
            print(f"        ? {question}")
        if analysis.validation_warnings:
            print("    VALIDATION WARNINGS:")
            for warning in analysis.validation_warnings:
                print(f"        ! {warning}")
        else:
            print("    validation  : passed (citations, techniques, no action claims)")

        manual = [
            a for a in analysis.recommended_actions
            if "response_action" in a and a["response_action"] is None
        ]
        if manual:
            print("\n  MANUAL TASKS (for a human; never automated)")
            for task in manual:
                print(f"    - {task['action']}")

        print("\n  PROPOSED RESPONSE (DRY RUN -- nothing was executed)")
        if output.profile != "endpoint":
            print(f"    Analyst decisions below are SIMULATED by a fixed table ({SIMULATED_REVIEWER}).")
            print("    Approval only unlocks a DRY RUN: cloud actions cannot execute in this build.")
        if not responses:
            print("    no actions proposed")
        for result in responses:
            print(f"    [{result.status:8}] {result.request.action.value} -> {result.request.target}")
            print(f"               tier={result.request.tier} {result.detail}")
            if result.request.approved_by:
                print(f"               approved_by={result.request.approved_by}")
                print(f"               {result.would_have}")
        executed = sum(1 for r in responses if r.executed)
        print(f"\n    actions actually executed: {executed}")

    print(_header("PIPELINE COMPLETE"))
    print("Nothing was executed. No external service was contacted.")
    print("Detection and correlation are deterministic; AI output is advisory only.")


def to_json(output: PipelineOutput) -> str:
    """Machine-readable pipeline output, for piping into other tools."""
    events, alerts, results = output.events, output.alerts, output.results
    return json.dumps(
        {
            "profile": output.profile,
            "event_count": len(events),
            "injection_findings": [f.to_dict() for f in output.injection_findings],
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "rule_id": a.rule_id,
                    "title": a.title,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "evidence_event_ids": list(a.evidence_event_ids),
                    "technique_ids": list(a.technique_ids),
                }
                for a in alerts
            ],
            "incidents": [
                {
                    "incident": incident.to_dict(),
                    "risk": risk.to_dict(),
                    "ai_analysis": analysis.to_dict(),
                    "proposed_response": [r.to_dict() for r in responses],
                }
                for incident, risk, analysis, responses in results
            ],
        },
        indent=2,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.soc_core.demo",
        description="Offline AI-assisted SOC pipeline demonstration.",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="endpoint",
        help="endpoint (default: original demo) or cloud (synthetic AWS telemetry)",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="path to a synthetic event dataset (default: the profile's dataset)",
    )
    parser.add_argument(
        "--scenario",
        choices=sorted(set(SCENARIOS) | set(CLOUD_SCENARIOS)),
        help="restrict the run to one labelled scenario of the chosen profile",
    )
    parser.add_argument(
        "--list-scenarios", action="store_true", help="list scenarios and exit"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)
    registry = PROFILES[args.profile].scenarios

    if args.list_scenarios:
        for key in sorted(registry):
            scenario = registry[key]
            print(f"{key}  {scenario.name}")
            print(f"   {scenario.description}")
            print(f"   events: {len(scenario.event_ids)}")
        return 0

    if args.scenario and args.scenario not in registry:
        parser.error(
            f"scenario {args.scenario!r} does not exist in the {args.profile} "
            f"profile; choose from {sorted(registry)}"
        )

    output = run_pipeline(args.dataset, args.scenario, profile=args.profile)

    if args.json:
        print(to_json(output))
    else:
        render(output, args.scenario)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
