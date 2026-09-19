"""Tests for the generic correlation engine (app/soc_core/correlation_engine).

Offline. Uses the Stage 3 synthetic telemetry and small hand-built events.
Any labels in this file are TEST FIXTURES that exercise metric arithmetic;
they are not, and do not stand in for, the canonical scenario ground truth.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import math
import socket
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.soc_core import correlation as stage1_correlation  # noqa: E402
from app.soc_core import efficiency as ef  # noqa: E402
from app.soc_core.cloud_detections import all_rules  # noqa: E402
from app.soc_core.correlation_engine import (  # noqa: E402
    FEATURE_NAMES,
    NA,
    CorrelationConfig,
    CorrelationEngine,
    DecisionTreeCorrelation,
    EntityType,
    GroundTruth,
    LightGBMCorrelation,
    LogisticRegressionCorrelation,
    NotTrainedError,
    RandomForestCorrelation,
    RuleBasedCorrelation,
    RuleWeights,
    StrategyUnavailableError,
    evaluate,
    pair_features,
)
from app.soc_core.correlation_engine import benchmarks  # noqa: E402
from app.soc_core.correlation_engine.entities import EntityIndex, entities_of  # noqa: E402
from app.soc_core.correlation_engine.normalization import normalize_events  # noqa: E402
from app.soc_core.detections import DetectionEngine  # noqa: E402
from app.soc_core.evidence_context import canonical_json, estimate_tokens  # noqa: E402
from app.soc_core.redaction import contains_secret  # noqa: E402

HAVE_SKLEARN = bool(importlib.util.find_spec("sklearn") and importlib.util.find_spec("numpy"))
HAVE_HTTP = bool(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"))
T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
PACKAGE = REPO_ROOT / "app" / "soc_core" / "correlation_engine"


def ev(event_id: str, minutes: float, **fields) -> dict:
    """A small dict event in a generic (non-project) schema."""
    return {"event_id": event_id, "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(), **fields}


def synthetic(n: int):
    events = ef.generate_events(n)
    alerts, _ = DetectionEngine(all_rules()).run(events)
    return events, alerts


class TestNormalization(unittest.TestCase):
    def test_security_event_fields_and_traceability(self) -> None:
        events, alerts = synthetic(100)
        normalized, report = normalize_events(events, detections=alerts)
        self.assertEqual(report.accepted, 100)
        self.assertEqual([n.event_id for n in normalized], [e.event_id for e in events])
        for n, e in zip(normalized, events):
            self.assertIs(n.original, e, "original must be a reference, not a copy")
        spray = next(n for n in normalized if n.event_id == "evt-0002")
        self.assertEqual(spray.source_ip, "203.0.113.45")
        self.assertTrue(spray.rule_ids and spray.detection_ids)
        self.assertIn("T1110.003", spray.techniques)

    def test_generic_dict_aliases(self) -> None:
        raw = {
            "id": "x-1", "@timestamp": "2026-01-01T12:00:00Z", "type": "network", "level": "HIGH",
            "src_ip": "198.51.100.7", "dst_ip": "192.0.2.9", "dport": "443", "user": {"name": "Alice"},
            "host": {"name": "WS-1"}, "process": {"name": "curl.exe", "parent_name": "cmd.exe"},
            "rule_id": "R-9", "technique": ["t1071", "bogus"], "outcome": "success",
        }
        [n], _ = normalize_events([raw])
        self.assertEqual((n.event_id, n.event_type, n.severity), ("x-1", "network", 3))
        self.assertEqual((n.source_ip, n.destination_ip, n.destination_port), ("198.51.100.7", "192.0.2.9", 443))
        self.assertEqual((n.username, n.hostname, n.process), ("Alice", "WS-1", "curl.exe"))
        self.assertEqual(n.parent_process, "cmd.exe")
        self.assertEqual(n.techniques, ("T1071",))
        self.assertIn("invalid:technique", n.issues)
        self.assertEqual(n.timestamp, T0)

    def test_epoch_timestamps(self) -> None:
        [s, ms], _ = normalize_events([{"event_id": "a", "ts": T0.timestamp()},
                                       {"event_id": "b", "ts": T0.timestamp() * 1000}])
        self.assertEqual(s.timestamp, T0)
        self.assertEqual(ms.timestamp, T0)

    def test_input_is_not_mutated(self) -> None:
        raw = ev("m-1", 0, user="bob", src_ip="203.0.113.1", nested={"a": [1, 2]})
        before = copy.deepcopy(raw)
        normalize_events([raw])
        self.assertEqual(raw, before)

    def test_sparse_event(self) -> None:
        [n], report = normalize_events([{"event_id": "only-id"}])
        self.assertIsNone(n.timestamp)
        self.assertIn("missing:timestamp", n.issues)
        self.assertEqual(report.issues_by_kind.get("missing"), 1)
        result = CorrelationEngine().run([{"event_id": "only-id"}, {"message": "no id at all"}])
        self.assertEqual(len(result.events), 2)
        self.assertTrue(result.events[1].event_id.startswith("anon-"))

    def test_malformed_inputs_rejected_or_flagged(self) -> None:
        inputs = [
            "not an event", 42, None,
            ev("bad-1", 0, src_ip="999.1.1.1", dport=70000, severity="loud", host=["x"]),
            {"event_id": "bad-2", "timestamp": "yesterday-ish"},
            {"event_id": "bad-3", "command": "A" * 5000},
        ]
        normalized, report = normalize_events(inputs)
        self.assertEqual(len(report.rejected), 3)
        self.assertTrue(all("unsupported input type" in r.reason for r in report.rejected))
        bad1, bad2, bad3 = normalized
        self.assertIsNone(bad1.source_ip)
        self.assertIsNone(bad1.destination_port)
        for issue in ("invalid_ip:source_ip", "invalid_port:destination_port", "invalid_severity",
                      "invalid_type:hostname"):
            self.assertIn(issue, bad1.issues)
        self.assertIn("invalid:timestamp", bad2.issues)
        self.assertEqual(len(bad3.command), 512)
        self.assertIn("truncated:command", bad3.issues)

    def test_malformed_detection_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_events([ev("a", 0)], detections=[{"alert_id": "x", "evidence_event_ids": "a"}])
        with self.assertRaises(TypeError):
            normalize_events([ev("a", 0)], detections=["nope"])


class TestEntities(unittest.TestCase):
    def test_types_folding_and_ignored_values(self) -> None:
        [n], _ = normalize_events([ev("e", 0, user="J.Rivera", host="WKS-1", src_ip="198.51.100.1",
                                      dst_ip="127.0.0.1", process="PowerShell.exe", account_id="111122223333",
                                      resource="bucket-a", rule_id="R1", alert_id="A1", technique="T1059")])
        found = entities_of(n)
        self.assertIn((EntityType.USER, "j.rivera"), found)
        self.assertIn((EntityType.HOST, "wks-1"), found)
        self.assertIn((EntityType.IP, "198.51.100.1"), found)
        self.assertNotIn((EntityType.IP, "127.0.0.1"), found, "loopback is ignored")
        self.assertIn((EntityType.PROCESS, "powershell.exe"), found)
        self.assertIn((EntityType.ACCOUNT, "111122223333"), found)
        self.assertIn((EntityType.RESOURCE, "bucket-a"), found)
        self.assertIn((EntityType.DETECTION, "alert:A1"), found)
        self.assertIn((EntityType.DETECTION, "rule:R1"), found)
        self.assertIn((EntityType.TECHNIQUE, "T1059"), found)

    def test_relationships_and_determinism(self) -> None:
        normalized, _ = normalize_events([ev("a", 0, user="u1", host="h1"), ev("b", 1, user="u1")])
        a, b = EntityIndex.build(normalized), EntityIndex.build(normalized)
        self.assertEqual(a.entities, b.entities)
        rels = a.relationships(normalized)
        self.assertIn({"event_id": "a", "relation": "event->user", "entity_type": "USER", "value": "u1"}, rels)
        self.assertEqual(a.postings[a.ids[(EntityType.USER, "u1")]], [0, 1])

    def test_alert_ids_link_rule_ids_do_not(self) -> None:
        normalized, _ = normalize_events([ev("a", 0, alert_id="A1", rule_id="R1"), ev("b", 1, alert_id="A1", rule_id="R1")])
        index = EntityIndex.build(normalized)
        self.assertTrue(index.is_linking(index.ids[(EntityType.DETECTION, "alert:A1")]))
        self.assertFalse(index.is_linking(index.ids[(EntityType.DETECTION, "rule:R1")]))

    def test_hub_filter_is_opt_in(self) -> None:
        events = [ev(f"e{i}", i, host="busy-host") for i in range(20)]
        normalized, _ = normalize_events(events)
        self.assertEqual(EntityIndex.build(normalized).hubs, frozenset())
        config = CorrelationConfig(hub_fraction=0.5, hub_min_events=5)
        index = EntityIndex.build(normalized, config)
        self.assertEqual(len(index.hubs), 1)
        self.assertEqual(CorrelationEngine(config).run(events).graph.edges, 0)


class TestFeatures(unittest.TestCase):
    def _index(self, *events):
        normalized, _ = normalize_events(events)
        return normalized, EntityIndex.build(normalized)

    def test_temporal_features(self) -> None:
        normalized, index = self._index(ev("a", 0, user="u"), ev("b", 4, user="u"))
        epochs = [e.epoch for e in normalized]
        f = pair_features(0, 1, index, epochs=epochs)
        self.assertAlmostEqual(f["timestamp_distance"], math.log1p(240))
        self.assertEqual((f["within_1_minute"], f["within_5_minutes"], f["within_15_minutes"], f["within_1_hour"]),
                         (0.0, 1.0, 1.0, 1.0))
        self.assertAlmostEqual(f["temporal_proximity"], math.exp(-240 / 900))
        untimed = pair_features(0, 1, index)
        self.assertEqual(untimed["within_1_hour"], 0.0)

    def test_entity_features_and_ip_roles(self) -> None:
        normalized, index = self._index(
            ev("a", 0, user="u", host="h", src_ip="198.51.100.1", dst_ip="192.0.2.1", process="p", account_id="acct"),
            ev("b", 0, user="u", host="other", src_ip="192.0.2.1", dst_ip="192.0.2.1", process="p", account_id="acct"),
        )
        f = pair_features(0, 1, index)
        self.assertEqual((f["same_user"], f["same_host"], f["same_process"], f["same_account"]), (1.0, 0.0, 1.0, 1.0))
        self.assertEqual(f["same_source_ip"], 0.0, "b's SOURCE is a's DESTINATION: not the same source")
        self.assertEqual(f["same_destination_ip"], 1.0)
        # shared: u, p, acct, 192.0.2.1  |  union: u, h, other, p, acct, 198.51.100.1, 192.0.2.1
        self.assertEqual(f["number_of_shared_entities"], 4.0)
        self.assertAlmostEqual(f["entity_overlap_ratio"], 4 / 7)
        self.assertEqual(pair_features(0, 1, index), pair_features(1, 0, index), "symmetric")

    def test_shared_detection_and_technique(self) -> None:
        normalized, index = self._index(ev("a", 0, alert_id="A", technique="T1110"),
                                        ev("b", 1, alert_id="A", technique="T1110"))
        f = pair_features(0, 1, index)
        self.assertEqual((f["shared_detection"], f["shared_technique"]), (1.0, 1.0))

    def test_feature_matrix_shape_and_bounds(self) -> None:
        events, alerts = synthetic(1_000)
        result = CorrelationEngine().run(events, alerts)
        self.assertEqual(result.features.rows, 1_000)
        self.assertEqual(result.features.names, FEATURE_NAMES)
        self.assertTrue(all(math.isfinite(v) for v in result.features.data))
        for name in ("severity", "rarity", "same_user", "within_1_hour", "entity_overlap_ratio", "temporal_proximity"):
            column = result.features.column(name)
            self.assertTrue(all(0.0 <= v <= 1.0 for v in column), name)
        seed = next(e.index for e in result.events if e.has_detection)
        self.assertEqual(result.features.value(seed, "timestamp_distance"), 0.0, "a detection is its own reference")

    def test_edges_are_bounded(self) -> None:
        events = [ev(f"e{i}", i * 0.01, host="same-host", user="same-user") for i in range(500)]
        result = CorrelationEngine(CorrelationConfig(neighbors_per_entity=3)).run(events)
        self.assertLessEqual(result.graph.edges, 500 * 2 * 3, "k-nearest per entity, not all pairs")
        self.assertEqual(len(result.graph.cluster_sizes), 1)

    def test_link_window_separates_clusters(self) -> None:
        events = [ev("a", 0, user="u"), ev("b", 10, user="u"), ev("c", 500, user="u")]
        result = CorrelationEngine(CorrelationConfig(link_window_seconds=3600)).run(events)
        clusters = [result.graph.cluster_id(i) for i in range(3)]
        self.assertEqual(clusters[0], clusters[1])
        self.assertNotEqual(clusters[1], clusters[2])


class TestRuleBaselineAndRanking(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [
            ev("det", 0, user="victim", host="h1", src_ip="203.0.113.9", severity="high", alert_id="A1", rule_id="R1"),
            ev("near", 2, user="victim", host="h1"),
            ev("far", 300, user="victim", host="h1"),
            ev("unrelated", 1, user="someone", host="h9"),
        ]

    def test_scores_are_explainable_and_ordered(self) -> None:
        result = CorrelationEngine().run(self.events)
        scores = {e.event_id: result.ranking.final[e.index] for e in result.events}
        self.assertGreater(scores["det"], scores["near"])
        self.assertGreater(scores["near"], scores["far"])
        self.assertGreater(scores["near"], scores["unrelated"])
        for candidate in result.candidates(None):
            self.assertAlmostEqual(sum(candidate.breakdown.values()), candidate.deterministic_score, places=9)
            self.assertIsNone(candidate.model_score)

    def test_deterministic_and_reproducible(self) -> None:
        events, alerts = synthetic(2_000)
        a = CorrelationEngine().run(events, alerts)
        b = CorrelationEngine().run(events, alerts)
        self.assertEqual(a.selected_event_ids, b.selected_event_ids)
        self.assertEqual(a.ranking.final, b.ranking.final)
        self.assertEqual(canonical_json(a.evidence_objects), canonical_json(b.evidence_objects))

    def test_weights_are_configurable(self) -> None:
        heavy_time = RuleWeights({"within_5_minutes": 5.0, "detection_match": 0.1})
        default = CorrelationEngine().run(self.events)
        tuned = CorrelationEngine(CorrelationConfig(rule_weights=heavy_time)).run(self.events)
        near = next(e.index for e in default.events if e.event_id == "near")
        self.assertNotEqual(default.ranking.final[near], tuned.ranking.final[near])
        with self.assertRaises(ValueError):
            RuleBasedCorrelation({"not_a_feature": 1.0})
        with self.assertRaises(ValueError):
            RuleBasedCorrelation({"severity": "high"})  # type: ignore[dict-item]

    def test_detection_evidence_always_kept(self) -> None:
        config = CorrelationConfig(selection_threshold=1.0, max_selected=0)
        result = CorrelationEngine(config).run(self.events)
        self.assertEqual(result.selected_event_ids, ["det"])
        cand = next(c for c in result.candidates(None) if c.event_id == "det")
        self.assertIn("always kept", cand.reason)

    def test_config_validation(self) -> None:
        for bad in ({"link_window_seconds": 0}, {"neighbors_per_entity": 0}, {"hub_fraction": 2.0},
                    {"selection_threshold": 1.5}, {"model_weight": -0.1}, {"max_selected": -1}):
            with self.assertRaises(ValueError):
                CorrelationConfig(**bad)


class TestStrategies(unittest.TestCase):
    def test_interface(self) -> None:
        rule = RuleBasedCorrelation()
        self.assertTrue(rule.available and rule.trained and not rule.requires_training)
        for cls in (LogisticRegressionCorrelation, DecisionTreeCorrelation, RandomForestCorrelation,
                    LightGBMCorrelation):
            strategy = cls()
            self.assertTrue(strategy.requires_training)
            self.assertFalse(strategy.trained)
            self.assertEqual(set(strategy.describe()), {"name", "requires_training", "available",
                                                        "unavailable_reason", "trained"})

    def test_untrained_model_never_scores(self) -> None:
        result = CorrelationEngine().run([ev("a", 0, user="u")])
        with self.assertRaises(NotTrainedError):
            LogisticRegressionCorrelation().score(result.features)
        with self.assertRaises(NotTrainedError):
            CorrelationEngine().run([ev("a", 0)], strategy=DecisionTreeCorrelation())

    def test_lightgbm_reported_unavailable_when_missing(self) -> None:
        real = importlib.util.find_spec
        with mock.patch("importlib.util.find_spec", side_effect=lambda m, *a: None if m == "lightgbm" else real(m, *a)):
            strategy = LightGBMCorrelation()
            self.assertFalse(strategy.available)
            self.assertIn("lightgbm is not installed", strategy.unavailable_reason)
            with self.assertRaises(StrategyUnavailableError):
                strategy.fit(CorrelationEngine().run([ev("a", 0)]).features, [0])
            report = benchmarks.run_scale(100, strategies=[strategy])
        self.assertEqual(report.rows[0].status, "UNAVAILABLE")
        self.assertIsNone(report.rows[0].selected)

    def test_sklearn_missing_is_reported_not_faked(self) -> None:
        real = importlib.util.find_spec
        with mock.patch("importlib.util.find_spec", side_effect=lambda m, *a: None if m == "sklearn" else real(m, *a)):
            for cls in (LogisticRegressionCorrelation, DecisionTreeCorrelation, RandomForestCorrelation):
                self.assertIn("sklearn is not installed", cls().unavailable_reason)

    @unittest.skipUnless(HAVE_SKLEARN, "scikit-learn not installed")
    def test_trained_models_score_and_stay_separate(self) -> None:
        events, alerts = synthetic(2_000)
        engine = CorrelationEngine()
        base = engine.run(events, alerts)
        # TEST FIXTURE labels: events a detection cited. Exercises plumbing only.
        truth = GroundTruth.from_records(
            [{"event_id": e.event_id, "is_attack_related": True} for e in base.events if e.has_detection],
            source="test fixture")
        for cls in (LogisticRegressionCorrelation, DecisionTreeCorrelation, RandomForestCorrelation):
            strategy = engine.fit(cls(seed=1), base, truth)
            self.assertTrue(strategy.trained)
            scores = strategy.score(base.features)
            self.assertEqual(len(scores), 2_000)
            self.assertTrue(all(0.0 <= s <= 1.0 for s in scores))
            result = engine.run(events, alerts, strategy=strategy)
            c = result.candidates(1)[0]
            self.assertIsNotNone(c.model_score)
            expected = 0.5 * c.deterministic_score + 0.5 * c.model_score
            self.assertAlmostEqual(c.final_score, expected, places=9)
            self.assertIsNotNone(strategy.feature_importance())
            again = cls(seed=1)
            engine.fit(again, base, truth)
            self.assertEqual(again.score(base.features), scores, f"{cls.__name__} must be deterministic")

    @unittest.skipUnless(HAVE_SKLEARN, "scikit-learn not installed")
    def test_fit_requires_two_classes_and_aligned_labels(self) -> None:
        features = CorrelationEngine().run([ev("a", 0), ev("b", 1)]).features
        with self.assertRaises(ValueError):
            DecisionTreeCorrelation().fit(features, [0, 0])
        with self.assertRaises(ValueError):
            DecisionTreeCorrelation().fit(features, [0, 1, 1])


class TestGroundTruthAndRecall(unittest.TestCase):
    def test_label_validation(self) -> None:
        good = [{"event_id": "a", "is_attack_related": True, "attack_stage": "x", "critical": True}]
        self.assertEqual(GroundTruth.from_records(good).critical_ids, frozenset({"a"}))
        for bad in (
            [{"event_id": "a", "is_attack_related": "yes"}],
            [{"event_id": "a", "is_attack_related": False, "critical": True}],
            [{"event_id": "", "is_attack_related": True}],
            [{"event_id": "a", "is_attack_related": True, "extra": 1}],
            [{"event_id": "a", "is_attack_related": True}, {"event_id": "a", "is_attack_related": False}],
            ["not an object"],
        ):
            with self.assertRaises(ValueError):
                GroundTruth.from_records(bad)

    def test_from_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gt.json"
            path.write_text(json.dumps({"labels": [{"event_id": "a", "is_attack_related": True}]}))
            self.assertTrue(GroundTruth.from_json(path).is_positive("a"))
            path.write_text(json.dumps({"labels": "nope"}))
            with self.assertRaises(ValueError):
                GroundTruth.from_json(path)

    def test_no_ground_truth_is_na(self) -> None:
        result = evaluate(["a"], ["a", "b"], None).to_dict()
        for key in ("precision", "recall", "f1", "critical_evidence_recall"):
            self.assertEqual(result[key], NA)

    def test_metrics_arithmetic(self) -> None:
        truth = GroundTruth.from_records([
            {"event_id": "a", "is_attack_related": True, "critical": True},
            {"event_id": "b", "is_attack_related": True, "critical": True},
            {"event_id": "c", "is_attack_related": True},
            {"event_id": "gone", "is_attack_related": True, "critical": True},
        ], source="test fixture")
        result = evaluate(["a", "c", "x"], ["a", "b", "c", "x", "y"], truth)
        self.assertAlmostEqual(result.precision, 2 / 3)
        self.assertAlmostEqual(result.recall, 2 / 3)
        self.assertAlmostEqual(result.f1, 2 / 3)
        self.assertEqual(result.critical_evidence_recall, 0.5)
        self.assertEqual(result.missing_critical, ["b"])
        self.assertEqual(result.labels_not_in_input, 1, "labels for absent events are visible, not silent")

    def test_critical_recall_through_the_engine(self) -> None:
        events = [ev("det", 0, user="v", alert_id="A"), ev("ctx", 1, user="v"), ev("noise", 1, user="z")]
        truth = GroundTruth.from_records([
            {"event_id": "det", "is_attack_related": True, "critical": True},
            {"event_id": "ctx", "is_attack_related": True, "critical": True},
        ], source="test fixture")
        strict = CorrelationEngine(CorrelationConfig(selection_threshold=1.0)).run(events)
        self.assertEqual(strict.evaluate(truth).critical_evidence_recall, 0.5, "only detection evidence survived")
        loose = CorrelationEngine(CorrelationConfig(selection_threshold=0.2)).run(events)
        self.assertEqual(loose.evaluate(truth).critical_evidence_recall, 1.0)


class TestTokenIntegration(unittest.TestCase):
    def test_summary_contract(self) -> None:
        events, alerts = synthetic(1_000)
        result = CorrelationEngine().run(events, alerts)
        summary = result.summary()
        for key in ("raw_events", "correlated_events", "evidence_objects", "estimated_context_tokens",
                    "reduction_ratio", "critical_evidence_recall", "selected_events"):
            self.assertIn(key, summary)
        self.assertEqual(summary["raw_events"], 1_000)
        self.assertEqual(summary["estimated_context_tokens"], estimate_tokens(canonical_json(result.evidence_objects)))
        self.assertEqual(summary["critical_evidence_recall"], NA)
        self.assertAlmostEqual(summary["reduction_ratio"], 1 - summary["selected_events"] / 1_000, places=6)
        json.dumps(summary)

    def test_nothing_selected_is_zero_tokens(self) -> None:
        config = CorrelationConfig(selection_threshold=1.0, keep_detection_evidence=False)
        result = CorrelationEngine(config).run([ev("a", 0)])
        self.assertEqual((result.summary()["selected_events"], result.estimated_context_tokens), (0, 0))

    def test_aggregation_bounds_tokens_as_volume_grows(self) -> None:
        small = CorrelationEngine().run(*synthetic(1_000)).estimated_context_tokens
        large = CorrelationEngine().run(*synthetic(10_000)).estimated_context_tokens
        self.assertLess(large, small * 1.5)


class TestLargeInputAndBenchmark(unittest.TestCase):
    def test_50k_events(self) -> None:
        events, alerts = synthetic(50_000)
        result = CorrelationEngine().run(events, alerts)
        self.assertEqual(len(result.events), 50_000)
        max_entities = max(len(x) for x in result.index.event_entities)
        self.assertLessEqual(result.graph.edges, 50_000 * max_entities * result.config.neighbors_per_entity)
        self.assertLess(len(result.evidence_objects), 200)

    def test_benchmark_schema_without_ground_truth(self) -> None:
        report = benchmarks.run_scale(1_000)
        data = report.to_dict()
        json.dumps(data)
        self.assertEqual([r["model"] for r in data["rows"]],
                         ["RuleBased", "LogisticRegression", "DecisionTree", "RandomForest", "LightGBM"])
        rule = data["rows"][0]
        self.assertEqual(rule["status"], "measured")
        for key in ("events", "correlated", "selected", "evidence_objects", "tokens", "latency_ms"):
            self.assertIsNotNone(rule[key], key)
        for row in data["rows"]:
            for key in ("precision", "recall", "f1", "critical_recall"):
                self.assertEqual(row[key], NA)
        for row in data["rows"][1:4]:
            self.assertEqual(row["status"], "UNAVAILABLE" if not HAVE_SKLEARN else "NOT TRAINED")
            self.assertIsNone(row["selected"], "untrained models produce no numbers")

    @unittest.skipUnless(HAVE_SKLEARN, "scikit-learn not installed")
    def test_benchmark_with_ground_truth_uses_held_out_split(self) -> None:
        events, alerts = synthetic(1_000)
        base = CorrelationEngine().run(events, alerts)
        truth = GroundTruth.from_records(   # TEST FIXTURE, not scenario ground truth
            [{"event_id": e.event_id, "is_attack_related": True, "critical": e.severity >= 3}
             for e in base.events if e.has_detection], source="test fixture")
        report = benchmarks.run_scale(1_000, truth=truth,
                                      strategies=[RuleBasedCorrelation(), DecisionTreeCorrelation(seed=3)])
        for row in report.rows:
            self.assertEqual(row.status, "measured")
            self.assertIsInstance(row.precision, float)
            self.assertIn("held-out", row.evaluated_on)
        self.assertIsNotNone(report.rows[1].train_ms)
        train, test = benchmarks.split_ids([e.event_id for e in base.events], ef.DEFAULT_SEED)
        self.assertFalse(train & test)
        self.assertEqual(len(train | test), 1_000)
        self.assertEqual(benchmarks.split_ids(sorted(train | test), ef.DEFAULT_SEED), (train, test))

    def test_self_test_mode_never_reports_quality(self) -> None:
        report = benchmarks.run_scale(1_000, self_test=True, strategies=[DecisionTreeCorrelation()])
        row = report.rows[0]
        if HAVE_SKLEARN:
            self.assertEqual(row.status, "SELF-TEST")
            self.assertTrue(str(row.precision).startswith("N/A"))
            self.assertIsNone(row.selected)

    def test_unavailable_scale_reported(self) -> None:
        with mock.patch.object(benchmarks, "_free_memory_bytes", return_value=10 * 1024 * 1024):
            report = benchmarks.run_scale(100_000)
        self.assertEqual(report.status, "unavailable")
        self.assertIn("not run", report.reason)
        self.assertEqual(report.rows, [])

    def test_cli_table_and_json(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(benchmarks.main(["--scales", "100"]), 0)
        text = out.getvalue()
        for column in ("MODEL", "EVENTS", "SELECTED", "LATENCY", "PRECISION", "RECALL", "F1", "CRIT_RECALL", "TOKENS"):
            self.assertIn(column, text)
        self.assertIn("ground truth unavailable", text)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            benchmarks.main(["--scales", "100", "--json"])
        self.assertEqual(json.loads(out.getvalue())[0]["scale"], 100)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            benchmarks.main(["--scales", "123"])


class TestSecurityBoundaries(unittest.TestCase):
    def test_no_network_or_model_clients_in_package(self) -> None:
        forbidden = ("anthropic", "openai", "gemini", "google.generativeai", "httpx", "requests", "urllib",
                     "socket", "http.client", "claude_ai")
        for path in PACKAGE.glob("*.py"):
            source = path.read_text(encoding="utf-8")
            for name in forbidden:
                self.assertNotIn(f"import {name}", source, f"{path.name} imports {name}")
                self.assertNotIn(f"from {name}", source, f"{path.name} imports from {name}")

    def test_runs_with_network_blocked(self) -> None:
        def refuse(*_args, **_kwargs):
            raise AssertionError("network access attempted")

        with mock.patch.object(socket.socket, "connect", refuse), \
             mock.patch.object(socket, "create_connection", refuse):
            benchmarks.run_scale(1_000, self_test=HAVE_SKLEARN)

    def test_no_secrets_in_benchmark_output(self) -> None:
        text = json.dumps(benchmarks.run_scale(1_000).to_dict())
        self.assertFalse(contains_secret(text))

    def test_stage1_correlator_untouched(self) -> None:
        self.assertTrue(hasattr(stage1_correlation, "CorrelationEngine"))
        self.assertTrue(hasattr(stage1_correlation, "Incident"))
        self.assertIsNot(stage1_correlation.CorrelationEngine, CorrelationEngine)


@unittest.skipUnless(HAVE_HTTP, "fastapi/httpx not installed (use app/.venv)")
class TestDebugEndpoint(unittest.TestCase):
    def test_debug_endpoint(self) -> None:
        from fastapi.testclient import TestClient

        from app.api.main import create_app
        from app.api.service import SocService

        client = TestClient(create_app(SocService(efficiency=ef.BenchmarkRunner(cache_file=None))))
        data = client.get("/api/correlation/debug?limit=5").json()
        self.assertEqual(data["summary"]["raw_events"], 63)
        self.assertEqual(len(data["candidates"]), 5)
        self.assertEqual(data["summary"]["critical_evidence_recall"], NA)
        self.assertNotIn("command", json.dumps(data["candidates"]))
        self.assertEqual(client.get("/api/correlation/debug?limit=0").status_code, 422)


if __name__ == "__main__":
    unittest.main()
