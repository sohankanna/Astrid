"""Tests for correlation, incident construction, risk scoring and ATT&CK mapping."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = REPO_ROOT / "data" / "sample_security_events.json"
sys.path.insert(0, str(REPO_ROOT / "app"))

from soc_core.correlation import (  # noqa: E402
    CorrelationEngine,
    entities_for,
    summarize_event,
)
from soc_core.detections import DetectionEngine, DetectionResult  # noqa: E402
from soc_core.events import load_events, parse_event  # noqa: E402
from soc_core.mitre import (  # noqa: E402
    TECHNIQUES,
    UnknownTechniqueError,
    attack_stage,
    describe,
    get_technique,
    is_known_technique,
    tactics_for,
    validate_technique_ids,
)
from soc_core.risk import (  # noqa: E402
    RiskWeights,
    band_for_score,
    score_incident,
)
from soc_core.scenarios import events_for_scenario  # noqa: E402


def load() -> list:
    return load_events(DATASET_PATH)


def pipeline(scenario: str | None = None):
    events = load()
    if scenario:
        events = events_for_scenario(events, scenario)
    alerts, _ = DetectionEngine().run(events)
    incidents = CorrelationEngine().correlate(alerts, events)
    return events, alerts, incidents


class TestMitreCatalog(unittest.TestCase):
    def test_known_technique(self) -> None:
        self.assertTrue(is_known_technique("T1059.001"))

    def test_unknown_technique(self) -> None:
        self.assertFalse(is_known_technique("T9999"))

    def test_get_unknown_raises(self) -> None:
        with self.assertRaises(UnknownTechniqueError):
            get_technique("T9999")

    def test_validate_splits_known_and_unknown(self) -> None:
        known, unknown = validate_technique_ids(["T1059.001", "T9999", "T1003.001"])
        self.assertEqual(known, ["T1059.001", "T1003.001"])
        self.assertEqual(unknown, ["T9999"])

    def test_validate_deduplicates(self) -> None:
        known, _ = validate_technique_ids(["T1059.001", "T1059.001"])
        self.assertEqual(known, ["T1059.001"])

    def test_subtechnique_parent(self) -> None:
        self.assertEqual(get_technique("T1059.001").parent_id, "T1059")
        self.assertTrue(get_technique("T1059.001").is_subtechnique)
        self.assertFalse(get_technique("T1078").is_subtechnique)

    def test_tactics_in_killchain_order(self) -> None:
        tactics = tactics_for(["T1071.001", "T1110.003", "T1059.001"])
        self.assertEqual(tactics, ["Execution", "Credential Access", "Command and Control"])

    def test_attack_stage_is_furthest_tactic(self) -> None:
        self.assertEqual(attack_stage(["T1110.003", "T1071.001"]), "Command and Control")

    def test_attack_stage_of_nothing(self) -> None:
        self.assertIsNone(attack_stage([]))

    def test_describe_format(self) -> None:
        self.assertEqual(describe("T1059.001"), "T1059.001 (PowerShell, Execution)")

    def test_every_catalog_entry_has_a_valid_tactic(self) -> None:
        from soc_core.mitre import TACTIC_ORDER

        for technique in TECHNIQUES.values():
            self.assertIn(technique.tactic, TACTIC_ORDER)


class TestEntityExtraction(unittest.TestCase):
    def test_entities_are_namespaced(self) -> None:
        events = [e for e in load() if e.event_id == "evt-0006"]
        entities = entities_for(events)
        self.assertIn("user:j.rivera", entities)
        self.assertIn("ip:203.0.113.45", entities)

    def test_generic_entities_excluded(self) -> None:
        """Correlating on a shared IdP host would merge unrelated incidents."""
        events = [e for e in load() if e.event_id == "evt-0007"]
        self.assertNotIn("host:idp.corp.test", entities_for(events))


class TestCorrelation(unittest.TestCase):
    def test_full_chain_becomes_one_incident(self) -> None:
        _, _, incidents = pipeline()
        self.assertEqual(len(incidents), 1)

    def test_incident_has_identity_fields(self) -> None:
        _, _, incidents = pipeline()
        incident = incidents[0]
        self.assertTrue(incident.incident_id.startswith("inc-"))
        self.assertTrue(incident.title)
        self.assertEqual(incident.severity, "critical")
        self.assertIn("WKS-FIN-014", incident.hosts)
        self.assertIn("j.rivera", incident.users)
        self.assertIn("203.0.113.45", incident.source_ips)

    def test_timeline_is_chronological(self) -> None:
        _, _, incidents = pipeline()
        timestamps = [entry.timestamp for entry in incidents[0].timeline]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_timeline_covers_every_evidence_event(self) -> None:
        _, _, incidents = pipeline()
        incident = incidents[0]
        cited = {eid for a in incident.alerts for eid in a.evidence_event_ids}
        self.assertEqual(cited, {entry.event_id for entry in incident.timeline})

    def test_timeline_summary_withholds_untrusted_free_text(self) -> None:
        """Timelines travel widely; they must not carry injection payloads."""
        events = [e for e in load() if e.event_id == "evt-0016"]
        summary = summarize_event(events[0])
        self.assertNotIn("IGNORE ALL PREVIOUS", summary.upper())

    def test_dns_summary_withholds_domain(self) -> None:
        event = [e for e in load() if e.event_id == "evt-0010"][0]
        self.assertNotIn("cdn-metrics", summarize_event(event))

    def test_techniques_aggregated_from_alerts(self) -> None:
        _, _, incidents = pipeline()
        techniques = set(incidents[0].technique_ids)
        self.assertIn("T1110.003", techniques)
        self.assertIn("T1003.001", techniques)

    def test_attack_stage_reaches_c2(self) -> None:
        _, _, incidents = pipeline()
        self.assertEqual(incidents[0].attack_stage, "Command and Control")

    def test_unrelated_activity_is_not_merged(self) -> None:
        """Different host, different user, far apart in time -> two incidents."""
        far_future = datetime(2027, 1, 1, tzinfo=timezone.utc)
        events = load()
        extra = parse_event(
            {
                "event_id": "evt-far",
                "timestamp": far_future.isoformat().replace("+00:00", "Z"),
                "source": "unit_test",
                "category": "process",
                "action": "process_created",
                "outcome": "success",
                "severity": "high",
                "host": {"hostname": "OTHER-HOST"},
                "user": {"name": "other.user"},
                "process": {
                    "name": "powershell.exe",
                    "parent_name": "winword.exe",
                    "command_line": "powershell.exe -nop -w hidden",
                },
            }
        )
        all_events = events + [extra]
        alerts, _ = DetectionEngine().run(all_events)
        incidents = CorrelationEngine().correlate(alerts, all_events)
        self.assertGreaterEqual(len(incidents), 2)

    def test_no_alerts_produces_no_incidents(self) -> None:
        events = events_for_scenario(load(), "A")
        self.assertEqual(CorrelationEngine().correlate([], events), [])

    def test_alert_with_missing_evidence_is_skipped(self) -> None:
        """An alert we cannot substantiate must not become an incident."""
        orphan = DetectionResult(
            alert_id="a-orphan",
            rule_id="SOC-TEST",
            title="orphan",
            description="d",
            severity="high",
            confidence="high",
            evidence_event_ids=("evt-does-not-exist",),
        )
        incidents = CorrelationEngine().correlate([orphan], load())
        self.assertEqual(incidents, [])

    def test_incidents_sorted_by_severity(self) -> None:
        from soc_core.detections import severity_rank

        _, _, incidents = pipeline()
        ranks = [severity_rank(i.severity) for i in incidents]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_narrow_window_splits_the_chain(self) -> None:
        """Correlation window is a real control, not decoration."""
        events = load()
        alerts, _ = DetectionEngine().run(events)
        wide = CorrelationEngine(time_window=timedelta(hours=4)).correlate(alerts, events)
        narrow = CorrelationEngine(time_window=timedelta(seconds=1)).correlate(alerts, events)
        self.assertGreater(len(narrow), len(wide))

    def test_to_dict_is_serializable(self) -> None:
        import json

        _, _, incidents = pipeline()
        payload = json.dumps(incidents[0].to_dict())
        self.assertIn("incident_id", payload)

    def test_to_dict_excludes_raw_log_text(self) -> None:
        """Raw untrusted text must be an explicit choice, not a default."""
        _, _, incidents = pipeline()
        self.assertNotIn("raw", incidents[0].to_dict())


class TestRiskScoring(unittest.TestCase):
    def test_bands(self) -> None:
        for score, expected in (
            (0, "informational"),
            (19, "informational"),
            (20, "low"),
            (45, "medium"),
            (65, "high"),
            (95, "critical"),
        ):
            with self.subTest(score=score):
                self.assertEqual(band_for_score(score), expected)

    def test_full_chain_scores_critical(self) -> None:
        _, _, incidents = pipeline()
        assessment = score_incident(incidents[0])
        self.assertEqual(assessment.band, "critical")
        self.assertGreaterEqual(assessment.score, 80)

    def test_score_is_bounded(self) -> None:
        _, _, incidents = pipeline()
        assessment = score_incident(incidents[0])
        self.assertLessEqual(assessment.score, 100)
        self.assertGreaterEqual(assessment.score, 0)

    def test_score_equals_sum_of_factors(self) -> None:
        """Transparency requirement: the number must be reconstructable."""
        _, _, incidents = pipeline()
        assessment = score_incident(incidents[0])
        self.assertEqual(
            assessment.score,
            min(100, sum(factor.points for factor in assessment.factors)),
        )

    def test_every_factor_is_explained_and_evidenced(self) -> None:
        _, _, incidents = pipeline()
        for factor in score_incident(incidents[0]).factors:
            self.assertTrue(factor.reason, f"{factor.name} has no reason")
            self.assertTrue(factor.evidence, f"{factor.name} has no evidence")

    def test_credential_activity_recognized(self) -> None:
        _, _, incidents = pipeline()
        names = {f.name for f in score_incident(incidents[0]).factors}
        self.assertIn("credential_activity", names)
        self.assertIn("c2_indicators", names)

    def test_smaller_incident_scores_lower(self) -> None:
        _, _, full = pipeline()
        _, _, dns_only = pipeline("C")
        self.assertGreater(
            score_incident(full[0]).score, score_incident(dns_only[0]).score
        )

    def test_weights_are_tunable(self) -> None:
        _, _, incidents = pipeline()
        default_score = score_incident(incidents[0]).score
        lowered = score_incident(
            incidents[0], RiskWeights(credential_activity=0, c2_activity=0)
        ).score
        self.assertLess(lowered, default_score)

    def test_explanation_is_human_readable(self) -> None:
        _, _, incidents = pipeline()
        explanation = score_incident(incidents[0]).explanation
        self.assertIn("Risk score", explanation)
        self.assertIn("alert_severity", explanation)

    def test_scoring_is_deterministic(self) -> None:
        _, _, incidents = pipeline()
        self.assertEqual(
            score_incident(incidents[0]).score, score_incident(incidents[0]).score
        )

    def test_to_dict_serializable(self) -> None:
        import json

        _, _, incidents = pipeline()
        self.assertIn("score", json.dumps(score_incident(incidents[0]).to_dict()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
