"""Tests for the deterministic detection engine.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = REPO_ROOT / "data" / "sample_security_events.json"
sys.path.insert(0, str(REPO_ROOT / "app"))

from soc_core.detections import (  # noqa: E402
    CredentialDumpingRule,
    DetectionEngine,
    DetectionResult,
    EncodedPowerShellRule,
    MFAFatigueRule,
    PasswordSprayRule,
    SuspiciousDNSRule,
    SuspiciousOutboundConnectionRule,
    SuspiciousPowerShellRule,
    SuspiciousProcessLineageRule,
    default_rules,
    max_severity,
    severity_rank,
    shannon_entropy,
)
from soc_core.events import load_events, parse_event  # noqa: E402
from soc_core.scenarios import events_for_scenario  # noqa: E402


def load() -> list:
    return load_events(DATASET_PATH)


def by_id(events) -> dict:
    return {event.event_id: event for event in events}


def make_event(**overrides) -> object:
    """Build a valid event with overrides, for rule unit tests."""
    base = {
        "event_id": "evt-x",
        "timestamp": "2026-09-17T08:00:00Z",
        "source": "unit_test",
        "category": "process",
        "action": "process_created",
        "outcome": "success",
        "severity": "low",
        "host": {"hostname": "HOST-1", "ip": "192.0.2.1"},
        "user": {"name": "u1", "domain": "CORP"},
        "process": {"name": "powershell.exe", "parent_name": "explorer.exe"},
    }
    base.update(overrides)
    return parse_event(base)


def auth_event(event_id: str, user: str, ip: str, offset_seconds: int, **extra):
    auth = {"logon_type": "network", "source_ip": ip, "failure_reason": "bad_password"}
    auth.update(extra.pop("auth", {}))
    timestamp = datetime(2026, 9, 17, 8, 0, tzinfo=timezone.utc) + timedelta(
        seconds=offset_seconds
    )
    payload = {
        "event_id": event_id,
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "source": "unit_test",
        "category": "authentication",
        "action": "logon_failed",
        "outcome": "failure",
        "severity": "low",
        "host": {"hostname": "DC-1"},
        "user": {"name": user, "domain": "CORP"},
        "auth": auth,
    }
    payload.update(extra)
    return parse_event(payload)


class TestDetectionResultContract(unittest.TestCase):
    """An alert without evidence is unusable; the type must forbid it."""

    def _result(self, **overrides) -> DetectionResult:
        payload = {
            "alert_id": "a1",
            "rule_id": "R1",
            "title": "t",
            "description": "d",
            "severity": "high",
            "confidence": "high",
            "evidence_event_ids": ("evt-1",),
        }
        payload.update(overrides)
        return DetectionResult(**payload)

    def test_valid_result(self) -> None:
        self.assertEqual(self._result().severity, "high")

    def test_rejects_empty_evidence(self) -> None:
        with self.assertRaises(ValueError):
            self._result(evidence_event_ids=())

    def test_rejects_bad_severity(self) -> None:
        with self.assertRaises(ValueError):
            self._result(severity="apocalyptic")

    def test_rejects_bad_confidence(self) -> None:
        with self.assertRaises(ValueError):
            self._result(confidence="certain")

    def test_rejects_unknown_attack_technique(self) -> None:
        """A rule citing a non-existent technique must fail loudly."""
        with self.assertRaises(ValueError):
            self._result(technique_ids=("T9999.999",))


class TestSeverityHelpers(unittest.TestCase):
    def test_rank_order(self) -> None:
        self.assertLess(severity_rank("low"), severity_rank("critical"))

    def test_unknown_severity_ranks_lowest(self) -> None:
        self.assertEqual(severity_rank("nonsense"), 0)

    def test_max_severity(self) -> None:
        self.assertEqual(max_severity(["low", "critical", "medium"]), "critical")

    def test_max_severity_of_empty(self) -> None:
        self.assertEqual(max_severity([]), "informational")


class TestPasswordSprayRule(unittest.TestCase):
    def setUp(self) -> None:
        self.rule = PasswordSprayRule()

    def test_fires_on_distinct_accounts_from_one_source(self) -> None:
        events = [
            auth_event("e1", "alice", "203.0.113.45", 0),
            auth_event("e2", "bob", "203.0.113.45", 2),
            auth_event("e3", "carol", "203.0.113.45", 4),
        ]
        results = self.rule.evaluate(events)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].technique_ids, ("T1110.003",))

    def test_does_not_fire_for_one_account_retrying(self) -> None:
        """Many attempts by one user is brute force, not spraying."""
        events = [auth_event(f"e{i}", "alice", "203.0.113.45", i) for i in range(6)]
        self.assertEqual(self.rule.evaluate(events), [])

    def test_does_not_fire_across_different_sources(self) -> None:
        events = [
            auth_event("e1", "alice", "203.0.113.1", 0),
            auth_event("e2", "bob", "203.0.113.2", 1),
            auth_event("e3", "carol", "203.0.113.3", 2),
        ]
        self.assertEqual(self.rule.evaluate(events), [])

    def test_does_not_fire_outside_time_window(self) -> None:
        events = [
            auth_event("e1", "alice", "203.0.113.45", 0),
            auth_event("e2", "bob", "203.0.113.45", 3600),
            auth_event("e3", "carol", "203.0.113.45", 7200),
        ]
        self.assertEqual(self.rule.evaluate(events), [])

    def test_ignores_successful_logons(self) -> None:
        events = [
            auth_event("e1", "alice", "203.0.113.45", 0, action="logon_success", outcome="success"),
            auth_event("e2", "bob", "203.0.113.45", 1, action="logon_success", outcome="success"),
            auth_event("e3", "carol", "203.0.113.45", 2, action="logon_success", outcome="success"),
        ]
        self.assertEqual(self.rule.evaluate(events), [])

    def test_excludes_mfa_denials(self) -> None:
        """MFA denial is a different technique and belongs to SOC-AUTH-002."""
        events = [
            auth_event("e1", "alice", "203.0.113.45", 0),
            auth_event("e2", "bob", "203.0.113.45", 1),
            auth_event(
                "e3", "carol", "203.0.113.45", 2,
                auth={"failure_reason": "mfa_push_denied"},
            ),
        ]
        self.assertEqual(self.rule.evaluate(events), [])

    def test_evidence_includes_all_sprayed_accounts(self) -> None:
        """Partial evidence would mislead the analyst about the spray's scope."""
        events = load()
        results = self.rule.evaluate(events)
        self.assertEqual(len(results), 1)
        self.assertEqual(
            set(results[0].evidence_event_ids),
            {"evt-0002", "evt-0003", "evt-0004", "evt-0005"},
        )


class TestMFAFatigueRule(unittest.TestCase):
    def test_fires_on_repeated_denials_for_one_user(self) -> None:
        events = events_for_scenario(load(), "G")
        results = MFAFatigueRule().evaluate(events)
        self.assertEqual(len(results), 1)
        self.assertEqual(
            set(results[0].evidence_event_ids), {"evt-0019", "evt-0020", "evt-0007"}
        )

    def test_does_not_fire_below_threshold(self) -> None:
        events = [
            auth_event("e1", "alice", "203.0.113.45", 0, action="mfa_denied"),
            auth_event("e2", "alice", "203.0.113.45", 5, action="mfa_denied"),
        ]
        self.assertEqual(MFAFatigueRule().evaluate(events), [])

    def test_groups_by_user_not_source_ip(self) -> None:
        """Prompts land on the user's device wherever the attacker is."""
        events = [
            auth_event("e1", "alice", "203.0.113.1", 0, action="mfa_denied"),
            auth_event("e2", "alice", "203.0.113.2", 5, action="mfa_denied"),
            auth_event("e3", "alice", "203.0.113.3", 9, action="mfa_denied"),
        ]
        results = MFAFatigueRule().evaluate(events)
        self.assertEqual(len(results), 1)


class TestPowerShellRules(unittest.TestCase):
    def test_suspicious_flags_detected(self) -> None:
        event = make_event(
            process={"name": "powershell.exe", "command_line": "powershell.exe -nop -w hidden -c x"}
        )
        self.assertIsNotNone(SuspiciousPowerShellRule().matches(event))

    def test_benign_powershell_not_flagged(self) -> None:
        event = make_event(
            process={"name": "powershell.exe", "command_line": "powershell.exe Get-Process"}
        )
        self.assertIsNone(SuspiciousPowerShellRule().matches(event))

    def test_encoded_command_detected(self) -> None:
        event = make_event(
            process={
                "name": "powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
            }
        )
        matched = EncodedPowerShellRule().matches(event)
        self.assertIsNotNone(matched)
        self.assertIn("encoded_payload_length", matched)

    def test_short_encoding_prefixes_detected(self) -> None:
        """PowerShell accepts -e/-en, so the rule must not only match -enc."""
        for flag in ("-e", "-en", "-enc", "-EncodedCommand"):
            with self.subTest(flag=flag):
                event = make_event(
                    process={
                        "name": "powershell.exe",
                        "command_line": f"powershell.exe {flag} SQBFAFgAIAAoAE4AZQB3AC0A",
                    }
                )
                self.assertIsNotNone(EncodedPowerShellRule().matches(event))

    def test_encoded_payload_is_never_decoded(self) -> None:
        """The rule records metadata about the payload, never its content."""
        event = make_event(
            process={
                "name": "powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
            }
        )
        matched = EncodedPowerShellRule().matches(event)
        self.assertNotIn("decoded", " ".join(matched.keys()).lower())

    def test_non_powershell_ignored(self) -> None:
        event = make_event(
            process={"name": "cmd.exe", "command_line": "cmd.exe -enc AAAAAAAAAAAAAAAAAA"}
        )
        self.assertIsNone(EncodedPowerShellRule().matches(event))


class TestProcessLineageRule(unittest.TestCase):
    def test_office_spawning_powershell(self) -> None:
        event = make_event(
            process={"name": "powershell.exe", "parent_name": "winword.exe"}
        )
        self.assertIsNotNone(SuspiciousProcessLineageRule().matches(event))

    def test_powershell_spawning_rundll32(self) -> None:
        event = make_event(
            process={"name": "rundll32.exe", "parent_name": "powershell.exe"}
        )
        self.assertIsNotNone(SuspiciousProcessLineageRule().matches(event))

    def test_normal_lineage_ignored(self) -> None:
        event = make_event(
            process={"name": "git.exe", "parent_name": "Code.exe"}
        )
        self.assertIsNone(SuspiciousProcessLineageRule().matches(event))

    def test_services_spawning_msiexec_ignored(self) -> None:
        event = make_event(
            process={"name": "msiexec.exe", "parent_name": "services.exe"}
        )
        self.assertIsNone(SuspiciousProcessLineageRule().matches(event))


class TestEntropyAndDNSRule(unittest.TestCase):
    def test_entropy_of_uniform_string_is_zero(self) -> None:
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_entropy_of_empty_string(self) -> None:
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_entropy_rises_with_variety(self) -> None:
        self.assertGreater(shannon_entropy("k3j4h5g6q7w8e9r0"), shannon_entropy("aaaabbbb"))

    def test_high_entropy_domain_flagged(self) -> None:
        events = load()
        results = SuspiciousDNSRule().evaluate(events)
        flagged = {eid for r in results for eid in r.evidence_event_ids}
        self.assertIn("evt-0010", flagged)

    def test_normal_domain_not_flagged(self) -> None:
        events = [e for e in load() if e.event_id == "evt-0014"]
        self.assertEqual(SuspiciousDNSRule().evaluate(events), [])

    def test_rule_confidence_is_low(self) -> None:
        """Entropy is a heuristic; the rule must not overstate itself."""
        self.assertEqual(SuspiciousDNSRule().confidence, "low")


class TestCredentialDumpingRule(unittest.TestCase):
    def test_fires_on_lsass_alert(self) -> None:
        events = [e for e in load() if e.event_id == "evt-0013"]
        results = CredentialDumpingRule().evaluate(events)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "critical")

    def test_fires_even_when_blocked(self) -> None:
        """A blocked attempt still proves intent and an active foothold."""
        event = [e for e in load() if e.event_id == "evt-0013"][0]
        self.assertEqual(event.outcome, "blocked")
        self.assertIsNotNone(CredentialDumpingRule().matches(event))

    def test_ignores_unrelated_events(self) -> None:
        self.assertIsNone(CredentialDumpingRule().matches(make_event()))


class TestOutboundConnectionRule(unittest.TestCase):
    def test_fires_on_repeated_external_connections(self) -> None:
        events = load()
        results = SuspiciousOutboundConnectionRule().evaluate(events)
        self.assertEqual(len(results), 1)
        self.assertEqual(
            set(results[0].evidence_event_ids), {"evt-0011", "evt-0012"}
        )

    def test_ignores_internal_destinations(self) -> None:
        rule = SuspiciousOutboundConnectionRule()
        event = parse_event(
            {
                "event_id": "evt-i",
                "timestamp": "2026-09-17T08:00:00Z",
                "source": "unit_test",
                "category": "network",
                "action": "network_connection",
                "outcome": "success",
                "severity": "low",
                "host": {"hostname": "H"},
                "network": {
                    "direction": "outbound",
                    "destination_ip": "192.0.2.50",
                    "destination_port": 443,
                },
            }
        )
        self.assertFalse(rule.qualifies(event))


class TestDetectionEngine(unittest.TestCase):
    def test_default_rule_set_has_eight_rules(self) -> None:
        self.assertEqual(len(default_rules()), 8)

    def test_rule_ids_are_unique(self) -> None:
        ids = [rule.rule_id for rule in default_rules()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_rejects_duplicate_rule_ids(self) -> None:
        with self.assertRaises(ValueError):
            DetectionEngine([PasswordSprayRule(), PasswordSprayRule()])

    def test_run_produces_alerts_without_errors(self) -> None:
        alerts, errors = DetectionEngine().run(load())
        self.assertEqual(errors, [])
        self.assertGreater(len(alerts), 0)

    def test_alerts_sorted_by_severity(self) -> None:
        alerts, _ = DetectionEngine().run(load())
        ranks = [severity_rank(a.severity) for a in alerts]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_every_alert_cites_real_events(self) -> None:
        events = load()
        known = {event.event_id for event in events}
        alerts, _ = DetectionEngine().run(events)
        for alert in alerts:
            for event_id in alert.evidence_event_ids:
                self.assertIn(event_id, known)

    def test_a_broken_rule_does_not_silence_the_others(self) -> None:
        class BrokenRule(PasswordSprayRule):
            rule_id = "SOC-BROKEN"

            def evaluate(self, events):
                raise RuntimeError("boom")

        engine = DetectionEngine([BrokenRule(), CredentialDumpingRule()])
        alerts, errors = engine.run(load())
        self.assertEqual(len(errors), 1)
        self.assertIn("SOC-BROKEN", errors[0])
        self.assertGreater(len(alerts), 0)

    def test_benign_scenario_produces_no_alerts(self) -> None:
        """The false-positive control: normal activity must stay quiet."""
        benign = events_for_scenario(load(), "A")
        alerts, errors = DetectionEngine().run(benign)
        self.assertEqual(errors, [])
        self.assertEqual(
            alerts, [], f"benign activity produced false positives: {[a.rule_id for a in alerts]}"
        )

    def test_empty_input_produces_no_alerts(self) -> None:
        alerts, errors = DetectionEngine().run([])
        self.assertEqual((alerts, errors), ([], []))

    def test_detection_is_deterministic(self) -> None:
        """Same input, same output -- no model, no randomness."""
        events = load()
        first, _ = DetectionEngine().run(events)
        second, _ = DetectionEngine().run(events)
        self.assertEqual(
            [a.alert_id for a in first], [a.alert_id for a in second]
        )


class TestScenarioCoverage(unittest.TestCase):
    """Each attack scenario must actually trigger detection."""

    def test_attack_scenarios_produce_alerts(self) -> None:
        events = load()
        for key in ("B", "C", "D", "E", "F", "G"):
            with self.subTest(scenario=key):
                subset = events_for_scenario(events, key)
                alerts, _ = DetectionEngine().run(subset)
                self.assertGreater(
                    len(alerts), 0, f"scenario {key} produced no alerts"
                )

    def test_full_chain_covers_multiple_tactics(self) -> None:
        subset = events_for_scenario(load(), "G")
        alerts, _ = DetectionEngine().run(subset)
        rule_ids = {alert.rule_id for alert in alerts}
        self.assertGreaterEqual(len(rule_ids), 6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
