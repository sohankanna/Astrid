"""Tests for the AI Efficiency & Economics Lab (app/soc_core/efficiency.py).

Offline and deterministic. Scales above 10K are not run here (the CLI and
the console measure those); the properties tested hold at every scale.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.api.service import ConflictError, SocService  # noqa: E402
from app.soc_core import efficiency as ef  # noqa: E402
from app.soc_core.cloud_detections import all_rules  # noqa: E402
from app.soc_core.correlation import CorrelationEngine  # noqa: E402
from app.soc_core.detections import DetectionEngine  # noqa: E402
from app.soc_core.events import REQUIRED_DETAIL_BY_CATEGORY, parse_event  # noqa: E402
from app.soc_core.evidence_context import CHARS_PER_TOKEN, build_evidence_context, estimate_tokens  # noqa: E402
from app.soc_core.providers.ai_analyst import MockAIAnalyst  # noqa: E402
from app.soc_core.providers.claude_ai import ClaudeAnalyst, build_user_message  # noqa: E402
from app.soc_core.redaction import contains_secret  # noqa: E402
from app.soc_core.risk import score_incident  # noqa: E402

HAVE_HTTP = bool(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"))
FAKE_KEY = "sk-" + "ant-api03-EFFICIENCY-FAKE-TEST-KEY-000"  # assembled: keeps scanners quiet


def _runner(**kwargs) -> ef.BenchmarkRunner:
    return ef.BenchmarkRunner(cache_file=None, **kwargs)


class TestSyntheticTelemetry(unittest.TestCase):
    def test_exact_size_and_canonical_events_embedded(self) -> None:
        events = ef.generate_events(1_000)
        self.assertEqual(len(events), 1_000)
        ids = {e.event_id for e in events}
        self.assertEqual(len(ids), 1_000, "event IDs must be unique")
        self.assertTrue({e.event_id for e in ef.canonical_events()} <= ids)

    def test_generation_is_deterministic_per_seed(self) -> None:
        a = [(e.event_id, e.timestamp, e.raw) for e in ef.generate_events(2_000, seed=7)]
        b = [(e.event_id, e.timestamp, e.raw) for e in ef.generate_events(2_000, seed=7)]
        c = [(e.event_id, e.timestamp, e.raw) for e in ef.generate_events(2_000, seed=8)]
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_noise_mix_covers_every_required_kind(self) -> None:
        prefixes = {e.event_id.split("-")[0] for e in ef.generate_events(1_000)}
        # benign, repeated, entity-linked, detection-matching, near-timeline
        self.assertTrue({"bn", "rp", "el", "dm", "nt"} <= prefixes)

    def test_direct_construction_matches_validated_parsing(self) -> None:
        """Noise events skip parse_event for speed; every one must still be a
        valid event under the normal validator."""
        canonical = {e.event_id for e in ef.canonical_events()}
        for event in (e for e in ef.generate_events(600) if e.event_id not in canonical):
            record = {
                "event_id": event.event_id, "timestamp": event.timestamp.isoformat(), "source": event.source,
                "category": event.category, "action": event.action, "outcome": event.outcome,
                "severity": event.severity, "user": dict(event.user), "raw": event.raw,
                REQUIRED_DETAIL_BY_CATEGORY[event.category]: json.loads(json.dumps(event.details)),
                "host": dict(event.host),
            }
            parsed = parse_event(record)
            self.assertEqual((parsed.category, parsed.action, parsed.timestamp, parsed.details),
                             (event.category, event.action, event.timestamp, record[REQUIRED_DETAIL_BY_CATEGORY[event.category]]))

    def test_scale_below_canonical_size_is_rejected(self) -> None:
        with self.assertRaises(ef.UnsupportedScaleError):
            ef.generate_events(10)


class TestRawBaseline(unittest.TestCase):
    def test_raw_tokens_use_the_same_estimator(self) -> None:
        events = ef.generate_events(500)
        tokens, chars = ef.estimate_raw_context_tokens(events)
        expected_chars = sum(
            len(json.dumps(ef.raw_event_record(e), separators=(",", ":"), default=str)) + 1 for e in events
        )
        self.assertEqual(chars, expected_chars)
        self.assertEqual(tokens, math.ceil(chars / CHARS_PER_TOKEN))

    def test_raw_tokens_grow_linearly_with_events(self) -> None:
        small, _ = ef.estimate_raw_context_tokens(ef.generate_events(1_000))
        large, _ = ef.estimate_raw_context_tokens(ef.generate_events(10_000))
        self.assertGreater(large / small, 8)

    def test_zero_events_is_zero_tokens(self) -> None:
        self.assertEqual(ef.estimate_raw_context_tokens([]), (0, 0))


class TestBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.r1k = ef.run_benchmark(1_000)
        cls.r10k = ef.run_benchmark(10_000)

    def test_evidence_tokens_are_the_real_context_tokens(self) -> None:
        events = ef.generate_events(1_000)
        alerts, _ = DetectionEngine(all_rules()).run(events)
        incidents = CorrelationEngine().correlate(alerts, events)
        total = 0
        for incident in incidents:
            context = build_evidence_context(incident, all_events=events, risk=score_incident(incident),
                                             findings=())
            total += context.metrics["estimated_tokens"]
            metrics = context.metrics
            self.assertEqual(metrics["estimated_tokens"], math.ceil(metrics["context_chars"] / CHARS_PER_TOKEN))
            # the metric is taken before the metrics block itself is embedded
            self.assertAlmostEqual(metrics["estimated_tokens"], estimate_tokens(context.to_json()), delta=100)
        # findings only add injection flags to canonical items; totals stay close
        self.assertAlmostEqual(self.r1k["estimated_context_tokens"], total, delta=total * 0.05)

    def test_reduction_percent_formula(self) -> None:
        r = self.r10k
        expected = round((1 - r["estimated_context_tokens"] / r["estimated_raw_context_tokens"]) * 100, 2)
        self.assertEqual(r["context_reduction_percent"], expected)

    def test_context_stays_bounded_while_raw_grows(self) -> None:
        self.assertGreater(self.r10k["estimated_raw_context_tokens"], 8 * self.r1k["estimated_raw_context_tokens"])
        self.assertLess(self.r10k["estimated_context_tokens"], 1.2 * self.r1k["estimated_context_tokens"])

    def test_small_scale_reports_negative_reduction_honestly(self) -> None:
        """At 100 events the evidence pack is larger than the raw log. The
        benchmark must say so, not clamp or hide it."""
        r = ef.run_benchmark(100)
        self.assertLess(r["context_reduction_percent"], 0)

    def test_counts_are_consistent(self) -> None:
        r = self.r10k
        self.assertEqual(r["raw_event_count"], 10_000)
        self.assertLessEqual(r["relevant_event_count"], r["raw_event_count"])
        self.assertLess(r["evidence_object_count"], r["relevant_event_count"])
        self.assertGreater(r["excluded_event_count"], 0)
        self.assertLess(r["excluded_event_count"], r["raw_event_count"])

    def test_benchmark_is_reproducible(self) -> None:
        again = ef.run_benchmark(1_000)
        stable = ("relevant_event_count", "evidence_object_count", "estimated_context_tokens",
                  "estimated_raw_context_tokens", "context_reduction_percent", "payload_sha256",
                  "evidence_retention_percent", "citation_coverage_percent")
        self.assertEqual({k: again[k] for k in stable}, {k: self.r1k[k] for k in stable})

    def test_retention_holds_under_noise(self) -> None:
        for r in (self.r1k, self.r10k):
            self.assertEqual(r["evidence_retention_percent"], 100.0)
            self.assertEqual(r["missing_facts"], [])

    def test_unsupported_scale(self) -> None:
        with self.assertRaises(ef.UnsupportedScaleError):
            ef.run_benchmark(12_345)
        with self.assertRaises(ef.UnsupportedScaleError):
            _runner().request([7])

    def test_scale_refused_when_memory_is_insufficient(self) -> None:
        with mock.patch.object(ef, "_free_memory_bytes", return_value=100 * 1024 * 1024):
            with self.assertRaises(ef.UnsupportedScaleError) as caught:
                ef.check_scale(1_000_000)
        self.assertIn("not run", str(caught.exception))

    def test_result_is_labelled_synthetic_and_theoretical(self) -> None:
        self.assertEqual(self.r1k["telemetry"], "Synthetic benchmark telemetry")
        self.assertIn("not sent to the model", self.r1k["baseline_label"])


class TestRetention(unittest.TestCase):
    def test_canonical_incidents_preserve_every_critical_fact(self) -> None:
        result = ef.canonical_fidelity()
        self.assertEqual(result["critical_facts"], len(ef.CRITICAL_FACTS))
        self.assertEqual(result["preserved_facts"], result["critical_facts"])
        self.assertEqual(result["citation_coverage_percent"], 100.0)
        for fact in result["facts"]:
            self.assertTrue(fact["evidence_ids"], fact["fact_id"])

    def test_missing_evidence_lowers_retention_and_coverage(self) -> None:
        events = ef.canonical_events()
        alerts, _ = DetectionEngine(all_rules()).run(events)
        incidents = CorrelationEngine().correlate(alerts, events)
        endpoint_only = [build_evidence_context(i, all_events=events, risk=score_incident(i))
                         for i in incidents if not any(r.startswith("CLOUD") for r in i.rule_ids)]
        result = ef.evaluate_retention(endpoint_only)
        self.assertLess(result["preserved_facts"], result["critical_facts"])
        self.assertIn("F12", result["missing_facts"])
        self.assertLess(result["citation_coverage_percent"], 100.0)

    def test_empty_context_list(self) -> None:
        result = ef.evaluate_retention([])
        self.assertEqual(result["preserved_facts"], 0)
        self.assertEqual(result["evidence_retention_percent"], 0.0)

    def test_budget_experiment_reports_loss_honestly(self) -> None:
        result = ef.budget_experiment()
        rows = {r["budget_percent"]: r for r in result["rows"]}
        self.assertEqual(rows[100]["evidence_retention_percent"], 100.0)
        for pct in (75, 50, 25):
            row = rows[pct]
            # whatever is lost is reported, and the numbers are internally consistent
            self.assertEqual(row["critical_facts"] - row["preserved_facts"], len(row["missing_facts"]))
            self.assertLessEqual(row["actual_tokens"], result["full_context_tokens"])
            if row["actual_tokens"] > row["target_tokens"]:
                self.assertTrue(row["hit_floor"])
        # facts no detection rule fires on are the ones budget trimming can lose
        via_context = {f.fact_id for f in ef.CRITICAL_FACTS if f.via_context}
        for row in result["rows"]:
            self.assertTrue(set(row["missing_facts"]) <= via_context)


class TestEconomics(unittest.TestCase):
    def test_cost_formula(self) -> None:
        pricing = ef.Pricing(input_per_mtok=3.0, output_per_mtok=15.0)
        cost = ef.token_cost(2_000_000, 100_000, pricing)
        self.assertAlmostEqual(cost["input_cost"], 6.0)
        self.assertAlmostEqual(cost["output_cost"], 1.5)
        self.assertAlmostEqual(cost["total_cost"], 7.5)

    def test_zero_tokens_cost_nothing(self) -> None:
        self.assertEqual(ef.token_cost(0, 0, ef.Pricing())["total_cost"], 0)
        comparison = ef.compare_costs(0, 0, ef.Pricing(), output_tokens=0)
        self.assertIsNone(comparison["token_reduction_percent"])
        self.assertIsNone(comparison["cost_reduction_percent"])

    def test_pricing_is_configurable_and_labelled_as_example(self) -> None:
        default = ef.Pricing()
        self.assertIn("not a vendor quote", default.label)
        custom = ef.Pricing(model="my-model", input_per_mtok=1.0, output_per_mtok=2.0)
        a = ef.compare_costs(1_000_000, 10_000, custom, output_tokens=0)
        self.assertAlmostEqual(a["baseline"]["total_cost"], 1.0)
        self.assertAlmostEqual(a["evidence"]["total_cost"], 0.01)
        self.assertEqual(a["pricing"]["model"], "my-model")

    def test_invalid_prices_rejected(self) -> None:
        for bad in (-1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                ef.Pricing(input_per_mtok=bad)
        with self.assertRaises(ValueError):
            ef.token_cost(-1, 0, ef.Pricing())

    def test_comparison_scales_and_reduction(self) -> None:
        c = ef.compare_costs(1_000_000, 20_000, ef.Pricing(input_per_mtok=5, output_per_mtok=25),
                             output_tokens=2_500, investigations=100, context_window=200_000)
        self.assertAlmostEqual(c["per_1000_investigations"]["baseline"], c["baseline"]["total_cost"] * 1000)
        self.assertAlmostEqual(c["per_10000_investigations"]["evidence"], c["evidence"]["total_cost"] * 10_000)
        self.assertAlmostEqual(c["baseline"]["total_for_investigations"], c["baseline"]["total_cost"] * 100)
        self.assertEqual(c["token_reduction_percent"], 98.0)
        self.assertTrue(c["baseline"]["exceeds_context_window"])
        self.assertEqual(c["baseline"]["context_windows_needed"], 5)
        self.assertFalse(c["evidence"]["exceeds_context_window"])
        self.assertIn("not sent to model", c["baseline"]["label"])


class TestModelBoundary(unittest.TestCase):
    """The raw baseline is a local estimate. Nothing in the lab calls a model,
    and the only thing a model ever receives is the EvidenceContext."""

    def test_benchmark_never_calls_a_model(self) -> None:
        source = Path(ef.__file__).read_text(encoding="utf-8")
        self.assertNotIn("anthropic", source)
        self.assertNotIn("claude_ai", source)
        with mock.patch.object(ClaudeAnalyst, "_call", side_effect=AssertionError("model called")), \
             mock.patch.object(MockAIAnalyst, "analyze", side_effect=AssertionError("analyst called")):
            ef.run_benchmark(1_000)
            ef.budget_experiment()

    def test_claude_receives_only_the_evidence_context_at_scale(self) -> None:
        events = ef.generate_events(10_000)
        alerts, _ = DetectionEngine(all_rules()).run(events)
        incident = max(CorrelationEngine().correlate(alerts, events), key=lambda i: len(i.event_ids))
        context = build_evidence_context(incident, all_events=events, risk=score_incident(incident))
        sent: list[dict] = []

        def create(**kwargs):
            sent.append(kwargs)
            raise RuntimeError("offline test client")

        client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
        with self.assertRaises(Exception):
            ClaudeAnalyst(client=client).analyze(incident, context)
        self.assertEqual(len(sent), 1)
        message = sent[0]["messages"][0]["content"]
        self.assertEqual(message, build_user_message(context))
        raw_tokens, _ = ef.estimate_raw_context_tokens(events)
        self.assertLess(estimate_tokens(message), raw_tokens / 20)
        # no raw event line is included verbatim for noise that was aggregated away
        included = {e for ids in context.evidence_to_events.values() for e in ids}
        excluded = [e for e in events if e.event_id not in included]
        self.assertTrue(excluded)
        self.assertFalse(any(e.event_id in message for e in excluded[:2_000]))

    def test_offline_mock_mode_makes_no_network_calls(self) -> None:
        import socket

        def refuse(*_args, **_kwargs):
            raise AssertionError("network access attempted")

        with mock.patch.dict(os.environ, {"SOC_AI_PROVIDER": "mock"}, clear=False), \
             mock.patch.object(socket.socket, "connect", refuse), \
             mock.patch.object(socket, "create_connection", refuse):
            soc = SocService(efficiency=_runner())
            soc.efficiency.run_now(1_000)
            live = soc.efficiency_live()
            soc.analyze(soc.list_incidents()[0]["incident_id"])
            live_after = soc.efficiency_live()
        self.assertFalse(live["available"])
        self.assertEqual(live["message"], "Live model usage unavailable — benchmark running offline.")
        self.assertFalse(live_after["available"], "mock runs must never be reported as live model usage")

    def test_no_secrets_in_benchmark_output(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": FAKE_KEY}):
            with tempfile.TemporaryDirectory() as tmp:
                cache = Path(tmp) / "bench.json"
                runner = ef.BenchmarkRunner(cache_file=cache)
                runner.run_now(1_000)
                written = cache.read_text(encoding="utf-8")
                status = json.dumps(runner.status())
                costs = json.dumps(ef.compare_costs(1, 1, ef.Pricing()))
        for text in (written, status, costs):
            self.assertNotIn(FAKE_KEY, text)
            self.assertFalse(contains_secret(text))


class TestRunnerAndService(unittest.TestCase):
    def test_background_run_and_cache_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "bench.json"
            runner = ef.BenchmarkRunner(cache_file=cache)
            status = runner.request([100, 1_000])
            self.assertTrue(status["busy"])
            runner.wait(120)
            done = runner.status()
            self.assertFalse(done["busy"])
            self.assertEqual([r["scale"] for r in done["results"]], [100, 1_000])
            reloaded = ef.BenchmarkRunner(cache_file=cache)
            self.assertEqual(reloaded.results[1_000]["payload_sha256"], runner.results[1_000]["payload_sha256"])

    def test_stale_or_corrupt_cache_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "bench.json"
            cache.write_text(json.dumps({"results": [{"scale": 100, "benchmark_version": "old", "seed": 1}]}))
            self.assertEqual(ef.BenchmarkRunner(cache_file=cache).results, {})
            cache.write_text("{not json")
            self.assertEqual(ef.BenchmarkRunner(cache_file=cache).results, {})

    def test_unavailable_scale_is_reported_not_faked(self) -> None:
        def refuse(scale: int, seed: int) -> dict:
            raise ef.UnsupportedScaleError("needs more memory than is free; not run, no result shown")

        runner = _runner(runner=refuse)
        runner.request([1_000_000])
        runner.wait(10)
        entry = next(s for s in runner.status()["scales"] if s["scale"] == 1_000_000)
        self.assertEqual(entry["state"], "unavailable")
        self.assertIn("not run", entry["reason"])
        self.assertEqual(runner.status()["results"], [])

    def test_cost_requires_a_measured_scale(self) -> None:
        soc = SocService(efficiency=_runner())
        with self.assertRaises(ConflictError):
            soc.efficiency_cost(1_000, ef.Pricing(), 1)
        soc.efficiency.run_now(1_000)
        result = soc.efficiency_cost(1_000, ef.Pricing(), 10)
        self.assertEqual(result["baseline"]["input_tokens"], soc.efficiency.results[1_000]["estimated_raw_context_tokens"])

    def test_fidelity_is_cached(self) -> None:
        soc = SocService(efficiency=_runner())
        self.assertIs(soc.efficiency_fidelity(), soc.efficiency_fidelity())


@unittest.skipUnless(HAVE_HTTP, "fastapi/httpx not installed (use app/.venv)")
class TestEfficiencyHttp(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from app.api.main import create_app

        self.soc = SocService(efficiency=_runner())
        self.client = TestClient(create_app(self.soc))

    def test_status_and_run(self) -> None:
        status = self.client.get("/api/efficiency/benchmark").json()
        self.assertEqual([s["scale"] for s in status["scales"]], list(ef.SCALES))
        resp = self.client.post("/api/efficiency/benchmark", json={"scales": [100]})
        self.assertEqual(resp.status_code, 200)
        self.soc.efficiency.wait(60)
        self.assertEqual(self.client.get("/api/efficiency/benchmark").json()["results"][0]["scale"], 100)

    def test_invalid_requests_rejected(self) -> None:
        self.assertEqual(self.client.post("/api/efficiency/benchmark", json={"scales": [5]}).status_code, 400)
        self.assertEqual(self.client.post("/api/efficiency/benchmark", json={"scales": []}).status_code, 422)
        self.assertEqual(self.client.post("/api/efficiency/benchmark",
                                          json={"scales": [100], "cmd": "x"}).status_code, 422)
        bad_cost = {"scale": 100, "input_per_mtok": -1, "output_per_mtok": 1}
        self.assertEqual(self.client.post("/api/efficiency/cost", json=bad_cost).status_code, 422)
        bad_model = {"scale": 100, "model": "<script>", "input_per_mtok": 1, "output_per_mtok": 1}
        self.assertEqual(self.client.post("/api/efficiency/cost", json=bad_model).status_code, 422)

    def test_cost_endpoint(self) -> None:
        body = {"scale": 1000, "model": "demo", "input_per_mtok": 5, "output_per_mtok": 25, "investigations": 100}
        self.assertEqual(self.client.post("/api/efficiency/cost", json=body).status_code, 409)
        self.soc.efficiency.run_now(1_000)
        result = self.client.post("/api/efficiency/cost", json=body).json()
        self.assertEqual(result["investigations"], 100)
        self.assertGreater(result["cost_reduction_percent"], 0)

    def test_fidelity_and_live(self) -> None:
        fidelity = self.client.get("/api/efficiency/fidelity").json()
        self.assertEqual(fidelity["retention"]["preserved_facts"], len(ef.CRITICAL_FACTS))
        live = self.client.get("/api/efficiency/live").json()
        self.assertFalse(live["available"])
        self.assertNotIn("api_key", json.dumps(live).lower().replace("claude_credentials_configured", ""))


if __name__ == "__main__":
    unittest.main()
