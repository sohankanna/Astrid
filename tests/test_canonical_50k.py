"""Canonical 50K dataset integration tests.

Skipped when the dataset is not present. Ground-truth checks run only when the
reconstructed artifact exists (scripts/build_canonical_ground_truth.py); these
tests check structure, determinism, metric arithmetic and the model boundary.
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

    def test_quality_metrics_only_with_ground_truth(self) -> None:
        if not canonical.ground_truth_available():
            self.assertEqual(self.result["ground_truth"], "NOT YET PROVIDED")
            self.assertEqual(set(self.result["quality_metrics"].values()), {NA})
            self.assertIsNone(self.result["evaluation"])
            return
        self.assertIn("RECONSTRUCTED", self.result["ground_truth"])
        for kind in ("raw", "siem"):
            ev = self.result["evaluation"][kind]
            self.assertEqual(ev["TP"] + ev["FP"], ev["selected"])
            self.assertEqual(ev["TP"] + ev["FN"], 137)
            self.assertEqual(ev["TP"] + ev["FP"] + ev["FN"] + ev["TN"], 50_000)
            self.assertAlmostEqual(ev["precision"], round(ev["TP"] / (ev["TP"] + ev["FP"]), 4))
            self.assertAlmostEqual(ev["recall"], round(ev["TP"] / (ev["TP"] + ev["FN"]), 4))
            self.assertEqual(ev["engine_config"], "defaults (no tuning against ground truth)")

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


@unittest.skipUnless(HAVE_DATASET and canonical.GROUND_TRUTH_FILE.is_file(), "reconstructed ground truth not present")
class TestReconstructedGroundTruth(unittest.TestCase):
    def test_artifact_integrity(self) -> None:
        labels = [json.loads(line) for line in canonical.GROUND_TRUTH_FILE.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(labels), 50_000)
        self.assertEqual(len({l["event_id"] for l in labels}), 50_000)
        raw_ids = {r["event_id"] for _, r in canonical.iter_records(canonical.dataset_path("raw"))}
        self.assertEqual({l["event_id"] for l in labels}, raw_ids)
        for l in labels:
            self.assertEqual(set(l), {"event_id", "attack_related", "attack_stage", "critical"})
            if not l["attack_related"]:
                self.assertIsNone(l["attack_stage"])
                self.assertFalse(l["critical"])
        validation = json.loads((canonical.GROUND_TRUTH_DIR / "ground_truth_validation.json").read_text(encoding="utf-8"))
        self.assertFalse(validation["authoritative"])
        self.assertEqual(validation["attack_related_count"], 137)
        self.assertEqual(validation["counts_by_attack_stage"], {
            "S10_ARCHIVE_DELETION": 8, "S1_RECON": 14, "S2_BRUTE_FORCE": 27, "S3_PASSWORD_SPRAY": 1,
            "S5_PHISHING": 2, "S6_ENDPOINT_COMPROMISE": 10, "S7_CREDENTIAL_HARVESTING": 14, "S7_VALID_ACCOUNT": 8,
            "S8_FINANCE_DATA_STAGING": 15, "S8_WEB_SHELL": 20, "S9_USB_TRANSFER": 10, "WEB01_FOOTHOLD": 8})

    def test_labels_independent_of_engine(self) -> None:
        source = (REPO_ROOT / "scripts" / "build_canonical_ground_truth.py").read_text(encoding="utf-8")
        for engine_symbol in ("CorrelationEngine", "run_representation", "baseline_signals", "selected_event_ids"):
            self.assertNotIn(engine_symbol, source)

    def test_jsonl_loader(self) -> None:
        from app.soc_core.correlation_engine.evaluation import GroundTruth

        truth = GroundTruth.from_jsonl(canonical.GROUND_TRUTH_FILE)
        self.assertEqual(len(truth.positive_ids), 137)
        self.assertEqual(len(truth.critical_ids), 98)


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
        self.assertEqual(data["ground_truth_available"], canonical.ground_truth_available())

    @unittest.skipUnless((canonical.DATASET_DIR / "attack_chain_audit.json").is_file(), "audit not present")
    def test_attack_path_endpoint(self) -> None:
        from fastapi.testclient import TestClient

        from app.api.main import create_app
        from app.api.service import SocService
        from app.soc_core.efficiency import BenchmarkRunner

        client = TestClient(create_app(SocService(efficiency=BenchmarkRunner(cache_file=None))))
        data = client.get("/api/canonical/attack-path").json()
        stages = data["stages"]
        self.assertEqual(len({s["ground_truth_stage"] for s in stages}), 12)
        self.assertEqual(sum(s["missed"] for s in stages), data["metrics"]["FN"])
        self.assertEqual(sum(s["selected"] for s in stages), data["metrics"]["TP"])
        for stage in stages:
            self.assertEqual(stage["selected"] + stage["missed"], stage["attack_events"])
            self.assertEqual(sum(e["selected"] for e in stage["events"]), stage["selected"])
            self.assertTrue(all(e["ground_truth"]["attack_related"] for e in stage["events"]))
        foothold = next(s for s in stages if s["ground_truth_stage"] == "WEB01_FOOTHOLD")
        self.assertEqual(foothold["selected"], 0, "a missed stage must never be reported as retained")


if __name__ == "__main__":
    unittest.main()
