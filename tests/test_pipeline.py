"""End-to-end pipeline and dataset-integrity tests.

Asserts the demo path works start to finish offline, and that the synthetic
dataset stays safe (documentation addresses only, nothing resolvable).
"""

from __future__ import annotations

import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = REPO_ROOT / "data" / "sample_security_events.json"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "app"))

from soc_core.demo import main, run_pipeline, to_json  # noqa: E402
from soc_core.events import load_events  # noqa: E402
from soc_core.scenarios import (  # noqa: E402
    SCENARIOS,
    UnknownScenarioError,
    events_for_scenario,
    get_scenario,
)


class TestScenarioDefinitions(unittest.TestCase):
    def test_all_required_scenarios_defined(self) -> None:
        self.assertEqual(set(SCENARIOS), set("ABCDEFGH"))

    def test_every_scenario_references_real_events(self) -> None:
        known = {event.event_id for event in load_events(DATASET_PATH)}
        for key, scenario in SCENARIOS.items():
            with self.subTest(scenario=key):
                missing = set(scenario.event_ids) - known
                self.assertFalse(missing, f"scenario {key} references {missing}")

    def test_every_scenario_is_non_empty(self) -> None:
        for key, scenario in SCENARIOS.items():
            with self.subTest(scenario=key):
                self.assertTrue(scenario.event_ids)

    def test_scenario_lookup_is_case_insensitive(self) -> None:
        self.assertEqual(get_scenario("b").key, "B")

    def test_unknown_scenario_raises(self) -> None:
        with self.assertRaises(UnknownScenarioError):
            get_scenario("Z")

    def test_events_returned_in_chronological_order(self) -> None:
        events = events_for_scenario(load_events(DATASET_PATH), "G")
        timestamps = [event.timestamp for event in events]
        self.assertEqual(timestamps, sorted(timestamps))


class TestPipelineEndToEnd(unittest.TestCase):
    def setUp(self) -> None:
        self.output = run_pipeline(DATASET_PATH)

    def test_produces_events_alerts_and_an_incident(self) -> None:
        self.assertEqual(len(self.output.events), 26)
        self.assertGreater(len(self.output.alerts), 0)
        self.assertEqual(len(self.output.results), 1)

    def test_incident_is_critical(self) -> None:
        incident, risk, _, _ = self.output.results[0]
        self.assertEqual(incident.severity, "critical")
        self.assertEqual(risk.band, "critical")

    def test_ai_analysis_passes_validation(self) -> None:
        _, _, analysis, _ = self.output.results[0]
        self.assertEqual(analysis.validation_warnings, ())

    def test_nothing_is_executed(self) -> None:
        """The core guarantee: a full run changes nothing."""
        _, _, _, responses = self.output.results[0]
        self.assertTrue(responses)
        self.assertEqual([r for r in responses if r.executed], [])

    def test_disruptive_actions_are_refused_without_approval(self) -> None:
        _, _, _, responses = self.output.results[0]
        disruptive = [r for r in responses if r.request.tier in {"T2", "T3"}]
        self.assertTrue(disruptive)
        self.assertTrue(all(r.status == "refused" for r in disruptive))

    def test_injection_screening_runs_on_all_events(self) -> None:
        flagged = {f.event_id for f in self.output.injection_findings}
        self.assertIn("evt-0016", flagged)
        self.assertIn("evt-0024", flagged)

    def test_json_output_is_valid(self) -> None:
        payload = json.loads(to_json(self.output))
        self.assertEqual(payload["event_count"], 26)
        self.assertIn("incidents", payload)
        self.assertIn("injection_findings", payload)

    def test_pipeline_is_deterministic(self) -> None:
        second = run_pipeline(DATASET_PATH)
        self.assertEqual(
            [a.alert_id for a in self.output.alerts],
            [a.alert_id for a in second.alerts],
        )

    def test_benign_scenario_yields_no_incident(self) -> None:
        output = run_pipeline(DATASET_PATH, scenario="A")
        self.assertEqual(output.alerts, [])
        self.assertEqual(output.results, [])

    def test_injection_scenario_flags_without_alerting(self) -> None:
        """Injection is surfaced even when no detection rule fires."""
        output = run_pipeline(DATASET_PATH, scenario="H")
        self.assertEqual(output.alerts, [])
        self.assertTrue(output.injection_findings)

    def test_every_attack_scenario_runs(self) -> None:
        for key in "BCDEFG":
            with self.subTest(scenario=key):
                output = run_pipeline(DATASET_PATH, scenario=key)
                self.assertTrue(output.alerts, f"scenario {key} produced no alerts")


class TestDemoCommand(unittest.TestCase):
    def test_demo_main_returns_zero(self) -> None:
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)

    def test_demo_json_mode(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main(["--json"])
        self.assertIn("incidents", json.loads(buffer.getvalue()))

    def test_demo_scenario_mode(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main(["--scenario", "B"])
        self.assertIn("Password spraying", buffer.getvalue())

    def test_demo_lists_scenarios(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main(["--list-scenarios"])
        self.assertIn("Complete multi-stage attack chain", buffer.getvalue())

    def test_demo_states_nothing_executed(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main([])
        self.assertIn("Nothing was executed", buffer.getvalue())


class TestSyntheticDataSafety(unittest.TestCase):
    """Nothing in the dataset may point at real infrastructure."""

    ALLOWED_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.", "0.0.0.")
    ALLOWED_TLDS = (".test", ".invalid", ".example", ".localhost")

    def setUp(self) -> None:
        self.text = DATASET_PATH.read_text(encoding="utf-8")
        self.events = load_events(DATASET_PATH)

    def test_only_documentation_ip_ranges(self) -> None:
        for address in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", self.text):
            with self.subTest(address=address):
                self.assertTrue(
                    address.startswith(self.ALLOWED_IP_PREFIXES),
                    f"non-documentation IP in dataset: {address}",
                )

    def test_domains_use_reserved_tlds(self) -> None:
        for event in self.events:
            if event.category != "dns" or not event.domain:
                continue
            with self.subTest(domain=event.domain):
                self.assertTrue(
                    event.domain.endswith(self.ALLOWED_TLDS),
                    f"domain {event.domain} does not use a reserved TLD",
                )

    def test_no_real_looking_credentials(self) -> None:
        """Guards against someone pasting a real token into the fixtures."""
        for pattern in (r"sk-[A-Za-z0-9]{20,}", r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, self.text))

    def test_dataset_grew_only_by_appending(self) -> None:
        """The original 18 events must still be present and parseable."""
        ids = {event.event_id for event in self.events}
        for index in range(1, 19):
            with self.subTest(event=index):
                self.assertIn(f"evt-{index:04d}", ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
