"""Canonical 50K dataset integration tests.

Skipped when the dataset is not present. No ground truth is used or created:
these tests check structure, determinism, measurement plumbing and the model
boundary, never detection quality.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.soc_core.correlation_engine import NA  # noqa: E402
from app.soc_core.correlation_engine import canonical  # noqa: E402

HAVE_DATASET = all(any((canonical.DATASET_DIR / n).is_file() for n in names)
                   for names in (canonical.RAW_CANDIDATES, canonical.SIEM_CANDIDATES))
HAVE_HTTP = bool(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"))


class TestAdapterUnits(unittest.TestCase):
    def test_parse_message(self) -> None:
        fields = canonical.parse_message('2026 host=WS07 user=a request="GET /x HTTP/1.1" status=200 [client 10.0.0.5]')
        self.assertEqual(fields["host"], "WS07")
        self.assertEqual(fields["request"], "GET /x HTTP/1.1")
        self.assertEqual(fields["client"], "10.0.0.5")

    def test_is_external(self) -> None:
        self.assertTrue(canonical.is_external("198.51.100.1"))   # documentation range is NOT internal
        for ip in ("10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", None, "not-an-ip"):
            self.assertFalse(canonical.is_external(ip))

    def test_both_representations_map_to_the_same_generic_event(self) -> None:
        msg = "2026-09-19T09:00:06Z host=WS07 EventID=4625 AccountName=bob IpAddress=203.0.113.9 Status=0xC000006D"
        raw = canonical.to_event("raw", {"event_id": "E1", "timestamp": "2026-09-19T09:00:06Z", "host": "WS07",
                                         "source_type": "windows_security", "source_file": "f", "raw_message": msg})
        siem = canonical.to_event("siem", {"connector_event_id": "E1", "_time": "2026-09-19T09:00:06Z", "host": "WS07",
                                           "sourcetype": "windows_security", "_raw": msg, "provider": "Splunk"})
        for key in ("event_id", "timestamp", "host", "source_ip", "username", "status", "event_code"):
            self.assertEqual(raw[key], siem[key], key)
        self.assertEqual(raw["status"], "failure")

    def test_signals_are_generic_and_deterministic(self) -> None:
        events = [canonical.to_event("raw", {
            "event_id": f"E{i}", "timestamp": f"2026-09-19T10:00:{i:02d}Z", "host": "H", "source_type": "windows_security",
            "raw_message": f"EventID={'4625' if i < 6 else '4624'} AccountName=u{i} IpAddress=203.0.113.7"})
            for i in range(7)]
        a, b = canonical.baseline_signals(events), canonical.baseline_signals(events)
        self.assertEqual([s.alert_id for s in a], [s.alert_id for s in b])
        rules = {s.rule_id for s in a}
        self.assertTrue({"SIG-EXT-SRC", "SIG-AUTH-BURST", "SIG-AUTH-SUCCESS-AFTER-BURST"} <= rules)
        source = Path(canonical.__file__).read_text(encoding="utf-8")
        for scenario_value in ("198.51.100.90", "10.10.20.17", "USB-0042", "CRED-WS07", "export.zip", "neha"):
            self.assertNotIn(scenario_value, source, "no scenario-specific values in the adapter")


@unittest.skipUnless(HAVE_DATASET, "canonical 50K dataset not present")
class TestCanonicalDataset(unittest.TestCase):
    result: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = canonical.canonical_result()

    def test_validation_exact_counts_no_malformed(self) -> None:
        for kind in ("raw", "siem"):
            v = self.result["validation"][kind]
            self.assertEqual(v["records"], 50_000, kind)
            self.assertEqual(v["unique_event_ids"], 50_000, kind)
            self.assertEqual(v["problems"], {}, kind)
            self.assertTrue(v["valid"], kind)

    def test_engine_output_measured(self) -> None:
        for kind in ("raw", "siem"):
            rep = self.result["representations"][kind]
            engine = rep["engine"]
            self.assertEqual(engine["events"], 50_000)
            self.assertGreater(engine["evidence_objects"], 0)
            self.assertGreater(engine["relevant_events"], 0)
            self.assertLess(engine["context_tokens"], rep["as_delivered_tokens"])
            self.assertTrue(rep["relationships"]["edges"])
            self.assertTrue(rep["attack_stage_candidates"])

    def test_evidence_context_generated(self) -> None:
        ctx = self.result["evidence_context"]
        self.assertTrue(ctx["generated"])
        self.assertGreater(ctx["evidence_objects"], 0)

    def test_no_ground_truth_no_quality_metrics(self) -> None:
        self.assertFalse(self.result["ground_truth_available"])
        self.assertEqual(self.result["ground_truth"], "NOT YET PROVIDED")
        self.assertEqual(set(self.result["quality_metrics"].values()), {NA})
        text = json.dumps(self.result)
        for key in ('"precision": 0', '"recall": 0', '"f1": 0', '"precision": 1'):
            self.assertNotIn(key, text)

    def test_deterministic_counts(self) -> None:
        again = canonical.run_representation("raw").result.summary()
        engine = self.result["representations"]["raw"]["engine"]
        self.assertEqual((again["selected_events"], again["evidence_objects"], again["estimated_context_tokens"]),
                         (engine["relevant_events"], engine["evidence_objects"], engine["context_tokens"]))

    def test_raw_telemetry_never_reaches_claude(self) -> None:
        from app.api.service import SocService
        from app.soc_core.efficiency import BenchmarkRunner
        from app.soc_core.providers.ai_analyst import MockAIAnalyst
        from app.soc_core.providers.claude_ai import ClaudeAnalyst, build_user_message

        sent: list[dict] = []

        def create(**kwargs):
            sent.append(kwargs)
            raise RuntimeError("offline test client")

        client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
        soc = SocService(default_scenario=None, analyst=ClaudeAnalyst(client=client), fallback_analyst=MockAIAnalyst(),
                         efficiency=BenchmarkRunner(cache_file=None))
        soc.run_scenario("canonical-50k")
        incident_id = soc.list_incidents()[0]["incident_id"]
        response = soc.analyze(incident_id)
        self.assertEqual(response["provider"]["used"], "mock")   # fake client failed -> visible fallback
        self.assertEqual(len(sent), 1)
        message = sent[0]["messages"][0]["content"]
        self.assertEqual(message, build_user_message(soc._context(incident_id)))
        raw_bytes = canonical.dataset_path("raw").stat().st_size
        self.assertLess(len(message), raw_bytes / 100)
        selected = {e.event_id for e in soc.state.events}
        raw_ids = [e["event_id"] for e in canonical.load("raw")]
        unselected = [i for i in raw_ids if i not in selected][:5_000]
        self.assertFalse(any(f'"{i}"' in message for i in unselected), "unselected raw events must not be sent")
        self.assertNotIn("neha", message, "usernames are pseudonymized in the context")


@unittest.skipUnless(HAVE_DATASET and HAVE_HTTP, "dataset or fastapi/httpx missing")
class TestCanonicalEndpoint(unittest.TestCase):
    def test_endpoint(self) -> None:
        from fastapi.testclient import TestClient

        from app.api.main import create_app
        from app.api.service import SocService
        from app.soc_core.efficiency import BenchmarkRunner

        client = TestClient(create_app(SocService(efficiency=BenchmarkRunner(cache_file=None))))
        data = client.get("/api/efficiency/canonical").json()
        self.assertEqual(data["dataset"], "canonical_50k")
        self.assertEqual(data["representations"]["raw"]["events"], 50_000)
        self.assertFalse(data["ground_truth_available"])


if __name__ == "__main__":
    unittest.main()
