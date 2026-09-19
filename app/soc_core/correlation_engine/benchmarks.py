"""Benchmark harness: compare correlation strategies on the same dataset.

    python -m app.soc_core.correlation_engine.benchmarks --scales 100,1000,10000,50000

Dataset: the Stage 3 synthetic benchmark telemetry (`efficiency.generate_events`,
seeded) with alerts from the project's existing detection rules. The engine
under test receives events + alerts; it has no knowledge of the scenario.

Honesty rules enforced here:
- No ground truth -> precision / recall / F1 / critical recall are
  "N/A — ground truth unavailable". Nothing is estimated.
- ML strategies need labels. Without ground truth they are reported
  "NOT TRAINED" and produce no numbers. A missing library is "UNAVAILABLE".
- With ground truth, events are split deterministically (hash of event_id +
  seed) into train/test; ML trains on train, and EVERY strategy (rules too)
  is scored on the same held-out test split.
- `--self-test-random-labels` exercises training/scoring latency with random
  labels. Quality columns are forced to N/A in that mode: random labels say
  nothing about quality.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Sequence

from ..cloud_detections import all_rules
from ..detections import DetectionEngine
from ..efficiency import (
    DEFAULT_SEED,
    SCALES,
    UnsupportedScaleError,
    _free_memory_bytes,
    check_scale,
    generate_events,
)
from .engine import CorrelationEngine, CorrelationResult
from .evaluation import NA, GroundTruth, evaluate
from .features import FeatureMatrix
from .models import CorrelationConfig
from .strategies import CorrelationStrategy, RuleBasedCorrelation, default_strategies

TRAIN_FRACTION: Final[float] = 0.7
# Measured: 1M events peaked at a 1.43 GB working set for generation +
# detection + engine (100K: 174 MB), i.e. linear at ~1.4 KB/event. Rounded up;
# used only to refuse scales that will not fit in currently free RAM.
ENGINE_BYTES_PER_EVENT: Final[int] = 1_500
MEMORY_HEADROOM: Final[float] = 0.85
SELF_TEST_NOTE: Final[str] = "N/A — self-test (random labels)"
DATASET_LABEL: Final[str] = "Stage 3 synthetic benchmark telemetry + existing detection rules"


@dataclass
class StrategyRow:
    model: str
    status: str                      # measured | NOT TRAINED | UNAVAILABLE | SELF-TEST
    events: int
    reason: str | None = None
    correlated: int | None = None
    selected: int | None = None
    evidence_objects: int | None = None
    tokens: int | None = None
    reduction_ratio: float | None = None
    latency_ms: float | None = None      # shared preparation + this strategy's scoring/ranking
    score_ms: float | None = None
    train_ms: float | None = None
    precision: Any = NA
    recall: Any = NA
    f1: Any = NA
    critical_recall: Any = NA
    evaluated_on: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class ScaleReport:
    scale: int
    dataset: str
    seed: int
    ground_truth: str | None
    detection_ms: float
    prepare_ms: dict[str, float]
    peak_memory_mb: float | None
    rows: list[StrategyRow] = field(default_factory=list)
    status: str = "measured"
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {**{k: v for k, v in self.__dict__.items() if k != "rows"}, "rows": [r.to_dict() for r in self.rows]}


def split_ids(event_ids: Sequence[str], seed: int, train_fraction: float = TRAIN_FRACTION) -> tuple[set[str], set[str]]:
    """Deterministic train/test split by hashing event_id with the seed."""
    train, test = set(), set()
    threshold = int(train_fraction * 2**32)
    for event_id in event_ids:
        digest = hashlib.sha256(f"{seed}:{event_id}".encode()).digest()
        (train if int.from_bytes(digest[:4], "big") < threshold else test).add(event_id)
    return train, test


def _subset(features: FeatureMatrix, rows: list[int]) -> FeatureMatrix:
    from array import array

    width = len(features.names)
    data = array("d")
    for r in rows:
        data.extend(features.data[r * width:(r + 1) * width])
    return FeatureMatrix(names=features.names, rows=len(rows), data=data)


def run_scale(
    scale: int,
    *,
    strategies: Sequence[CorrelationStrategy] | None = None,
    truth: GroundTruth | None = None,
    self_test: bool = False,
    seed: int = DEFAULT_SEED,
    config: CorrelationConfig | None = None,
) -> ScaleReport:
    try:
        check_scale(scale)
        free = _free_memory_bytes()
        need = scale * ENGINE_BYTES_PER_EVENT
        if free is not None and need > free * MEMORY_HEADROOM:
            raise UnsupportedScaleError(
                f"scale {scale:,} needs ~{need / 1e9:.1f} GB for the correlation benchmark but only "
                f"{free / 1e9:.1f} GB is free; not run, no result shown")
    except UnsupportedScaleError as exc:
        return ScaleReport(scale, DATASET_LABEL, seed, truth.source if truth else None, 0.0, {}, None,
                           status="unavailable", reason=str(exc))
    engine = CorrelationEngine(config or CorrelationConfig(seed=seed))
    strategies = list(strategies) if strategies is not None else default_strategies(engine.config.seed,
                                                                                   engine.config.rule_weights)
    events = generate_events(scale, seed)
    t = time.perf_counter()
    alerts, _ = DetectionEngine(all_rules()).run(events)
    detection_ms = (time.perf_counter() - t) * 1000
    prepared = engine.prepare(events, alerts)
    del events  # the engine keeps references via NormalizedEvent.original; no second copy
    normalized, _, _, _, features, prepare_timings = prepared
    prepare_ms = sum(prepare_timings.values())
    ids = [e.event_id for e in normalized]

    train_ids, test_ids = (split_ids(ids, seed) if truth is not None else (set(), set(ids)))
    train_rows = [e.index for e in normalized if e.event_id in train_ids]

    report = ScaleReport(scale, DATASET_LABEL, seed, truth.source if truth else None, round(detection_ms, 1),
                         {k: round(v, 1) for k, v in prepare_timings.items()}, None)
    for strategy in strategies:
        row = StrategyRow(model=strategy.name, status="measured", events=len(normalized))
        if not strategy.available:
            row.status, row.reason = "UNAVAILABLE", strategy.unavailable_reason
            report.rows.append(row)
            continue
        if strategy.requires_training:
            if truth is not None:
                labels = [1 if truth.is_positive(ids[r]) else 0 for r in train_rows]
                if len(set(labels)) < 2:
                    row.status, row.reason = "NOT TRAINED", "training split lacks both classes"
                    report.rows.append(row)
                    continue
                t = time.perf_counter()
                strategy.fit(_subset(features, train_rows), labels)
                row.train_ms = round((time.perf_counter() - t) * 1000, 1)
            elif self_test:
                rng = random.Random(seed)
                labels = [1 if rng.random() < 0.1 else 0 for _ in range(features.rows)]
                t = time.perf_counter()
                strategy.fit(features, labels)
                row.train_ms = round((time.perf_counter() - t) * 1000, 1)
                row.status = "SELF-TEST"
            else:
                row.status, row.reason = "NOT TRAINED", "ground truth unavailable"
                report.rows.append(row)
                continue

        t = time.perf_counter()
        result = engine.score_prepared(prepared, None if isinstance(strategy, RuleBasedCorrelation) else strategy)
        row.score_ms = round((time.perf_counter() - t) * 1000, 1)
        row.latency_ms = round(prepare_ms + row.score_ms, 1)
        if row.status == "SELF-TEST":
            row.reason = "random labels: latency only"
            row.precision = row.recall = row.f1 = row.critical_recall = SELF_TEST_NOTE
            report.rows.append(row)
            continue
        _fill(row, result, truth, test_ids)
        report.rows.append(row)
    report.peak_memory_mb = peak_memory_mb()
    return report


def _fill(row: StrategyRow, result: CorrelationResult, truth: GroundTruth | None, test_ids: set[str]) -> None:
    summary = result.summary()
    row.correlated = summary["correlated_events"]
    row.selected = summary["selected_events"]
    row.evidence_objects = summary["evidence_objects"]
    row.tokens = summary["estimated_context_tokens"]
    row.reduction_ratio = summary["reduction_ratio"]
    if truth is None:
        return
    evaluation = evaluate([e for e in result.selected_event_ids if e in test_ids], test_ids, truth).to_dict()
    row.precision, row.recall, row.f1 = evaluation["precision"], evaluation["recall"], evaluation["f1"]
    row.critical_recall = evaluation["critical_evidence_recall"]
    row.evaluated_on = f"held-out test split ({len(test_ids)} events)"


def peak_memory_mb() -> float | None:
    """Process peak working set / max RSS (cumulative for the process)."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class _PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

            counters = _PMC()
            counters.cb = ctypes.sizeof(_PMC)
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            kernel32.K32GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
            if kernel32.K32GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                return round(counters.PeakWorkingSetSize / 1e6, 1)
            return None
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(peak / (1e6 if sys.platform == "darwin" else 1e3), 1)
    except (OSError, AttributeError, ImportError, ValueError):
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _fmt(value: Any) -> str:
    """ASCII only: Windows consoles often cannot render em dashes."""
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, int):
        return f"{value:,}"
    return "N/A" if str(value).startswith("N/A") else str(value)


def _fmt_ms(value: float | None) -> str:
    return "-" if value is None else f"{value:,.1f}"


def print_table(reports: list[ScaleReport]) -> None:
    header = (f"{'MODEL':<20}{'EVENTS':>10}{'SELECTED':>10}{'OBJECTS':>9}{'LATENCY ms':>12}{'TRAIN ms':>10}"
              f"{'PRECISION':>11}{'RECALL':>9}{'F1':>8}{'CRIT_RECALL':>13}{'TOKENS':>9}  STATUS")
    for report in reports:
        print(f"\n== scale {report.scale:,} | {report.dataset} | seed {report.seed} | "
              f"ground truth: {report.ground_truth or 'NONE'}")
        if report.status != "measured":
            print(f"   UNAVAILABLE: {report.reason}")
            continue
        print(f"   detection {report.detection_ms:,.0f} ms | prepare {report.prepare_ms} | "
              f"process peak memory {report.peak_memory_mb} MB")
        print(header)
        for r in report.rows:
            status = r.status + (f" ({r.reason})" if r.reason else "")
            print(f"{r.model:<20}{_fmt(r.events):>10}{_fmt(r.selected):>10}{_fmt(r.evidence_objects):>9}"
                  f"{_fmt_ms(r.latency_ms):>12}{_fmt_ms(r.train_ms):>10}{_fmt(r.precision):>11}"
                  f"{_fmt(r.recall):>9}{_fmt(r.f1):>8}{_fmt(r.critical_recall):>13}{_fmt(r.tokens):>9}  {status}")
    if all(r.ground_truth is None for r in reports):
        print("\nPRECISION/RECALL/F1/CRIT_RECALL: N/A - ground truth unavailable. Canonical labels will be "
              "added after the project attack scenario is finalized.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.soc_core.correlation_engine.benchmarks",
                                     description="Offline correlation-strategy benchmark.")
    parser.add_argument("--scales", default="100,1000,10000,50000", help=f"subset of {list(SCALES)}")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--ground-truth", type=Path, help="JSON labels: [{event_id, is_attack_related, attack_stage, critical}]")
    parser.add_argument("--self-test-random-labels", action="store_true",
                        help="train ML on RANDOM labels to measure latency only (quality forced to N/A)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        scales = [int(s) for s in args.scales.split(",") if s.strip()]
    except ValueError:
        parser.error("--scales must be integers")
    bad = [s for s in scales if s not in SCALES]
    if bad:
        parser.error(f"unsupported scale(s) {bad}; choose from {list(SCALES)}")
    if args.ground_truth and args.self_test_random_labels:
        parser.error("--ground-truth and --self-test-random-labels are mutually exclusive")
    truth = None
    if args.ground_truth:
        try:
            truth = GroundTruth.from_json(args.ground_truth)
        except (OSError, ValueError) as exc:
            parser.error(f"invalid ground truth: {exc}")
    reports = [run_scale(s, truth=truth, self_test=args.self_test_random_labels, seed=args.seed) for s in scales]
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=1))
    else:
        print_table(reports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
