"""Canonical 50K SOC benchmark: dataset adapter, baseline signals, measured run.

All dataset-specific parsing lives in this module. The engine itself stays
generic: this adapter turns the two delivered representations into generic
event dicts, adds a small set of GENERIC baseline signals (not ground truth,
not attack-chain knowledge), and runs the existing CorrelationEngine and the
existing EvidenceContext Engine on the result.

    python -m app.soc_core.correlation_engine.canonical            # measure + write cache
    python -m app.soc_core.correlation_engine.canonical --json

Ground truth: NOT provided with the dataset. Precision / recall / F1 /
critical evidence recall are therefore never computed here.

Security: offline only. RAW and SIEM representations are benchmark inputs;
only the redacted EvidenceContext produced by the existing engine is eligible
for a model, through the existing analyze path.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final, Iterable, Iterator

from ..correlation import CorrelationEngine as IncidentCorrelator
from ..detections import DetectionResult
from ..events import SecurityEvent
from ..evidence_context import CHARS_PER_TOKEN, EvidenceContext, build_evidence_context
from ..providers.ai_analyst import screen_for_injection
from ..risk import score_incident
from .benchmarks import peak_memory_mb
from .engine import CorrelationEngine
from .evaluation import NA
from .models import EntityType

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
DATASET_DIR: Final[Path] = REPO_ROOT / "benchmarks" / "canonical_50k"
CACHE_FILE: Final[Path] = REPO_ROOT / ".cache" / "canonical_50k.json"
EXPECTED_RECORDS: Final[int] = 50_000
# Documented names first; the delivered copies arrived as "README (n).jsonl".
RAW_CANDIDATES: Final[tuple[str, ...]] = ("raw_source_telemetry_50000.jsonl", "README (1).jsonl")
SIEM_CANDIDATES: Final[tuple[str, ...]] = ("siem_connector_events_50000.jsonl", "README (2).jsonl")
GROUND_TRUTH_DIR: Final[Path] = DATASET_DIR / "ground_truth"
SIGNALS_LABEL: Final[str] = ("Baseline signals: generic heuristics (external source address, failed-auth burst, "
                             "success after burst, rare event shape). Not ground truth.")

_KV: Final[re.Pattern[str]] = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|\S+)')
_CLIENT: Final[re.Pattern[str]] = re.compile(r"\[client ([0-9a-fA-F.:]+)\]")
_INTERNAL: Final[tuple[ipaddress.IPv4Network, ...]] = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


class DatasetError(ValueError):
    """The canonical dataset is missing or malformed."""


# ---------------------------------------------------------------------------
# Files and validation
# ---------------------------------------------------------------------------


def dataset_path(kind: str, directory: Path = DATASET_DIR) -> Path:
    names = RAW_CANDIDATES if kind == "raw" else SIEM_CANDIDATES if kind == "siem" else None
    if names is None:
        raise ValueError(f"unknown representation {kind!r}")
    for name in names:
        if (directory / name).is_file():
            return directory / name
    raise DatasetError(f"{kind} dataset not found in {directory} (looked for {', '.join(names)})")


def iter_records(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"{path.name}:{line_no}: invalid JSON ({exc.msg})") from exc
            if not isinstance(record, dict):
                raise DatasetError(f"{path.name}:{line_no}: record is not an object")
            yield line_no, record


def validate(kind: str, directory: Path = DATASET_DIR) -> dict[str, Any]:
    """Structural checks only. Never modifies the files."""
    path = dataset_path(kind, directory)
    ids: set[str] = set()
    problems: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    count = 0
    for _, record in iter_records(path):
        count += 1
        event = to_event(kind, record)
        if not event.get("event_id"):
            problems["missing_event_id"] += 1
        elif event["event_id"] in ids:
            problems["duplicate_event_id"] += 1
        else:
            ids.add(event["event_id"])
        if not event.get("timestamp") or _parse_ts(event["timestamp"]) is None:
            problems["missing_or_invalid_timestamp"] += 1
        if not event.get("event_type"):
            problems["missing_source_type"] += 1
        if not event.get("message"):
            problems["missing_message"] += 1
        sources[event.get("event_type") or "?"] += 1
    return {
        "representation": kind, "file": path.name, "records": count, "expected": EXPECTED_RECORDS,
        "count_ok": count == EXPECTED_RECORDS, "unique_event_ids": len(ids),
        "problems": dict(problems), "valid": count == EXPECTED_RECORDS and not problems,
        "source_types": dict(sorted(sources.items())), "bytes": path.stat().st_size,
    }


def ground_truth_available(directory: Path = GROUND_TRUTH_DIR) -> bool:
    return directory.is_dir() and any(p.is_file() for p in directory.iterdir())


# ---------------------------------------------------------------------------
# Generic parsing: both representations -> one generic event dict
# ---------------------------------------------------------------------------


def parse_message(message: str) -> dict[str, str]:
    """Generic key=value / key="quoted value" parser, plus Apache's [client IP]."""
    fields = {m.group(1): (m.group(3) if m.group(3) is not None else m.group(2)) for m in _KV.finditer(message)}
    client = _CLIENT.search(message)
    if client and "client" not in fields:
        fields["client"] = client.group(1)
    return fields


def to_event(kind: str, record: dict[str, Any]) -> dict[str, Any]:
    if kind == "raw":
        event_id, ts = record.get("event_id"), record.get("timestamp")
        host, source_type, message = record.get("host"), record.get("source_type"), record.get("raw_message")
        source, severity = record.get("source_file"), None
    else:
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        agent = record.get("agent") if isinstance(record.get("agent"), dict) else {}
        rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}
        event_id = record.get("connector_event_id")
        ts = record.get("timestamp") or record.get("_time")
        host = agent.get("name") or record.get("host")
        source_type = record.get("decoder") or record.get("sourcetype")
        message = data.get("raw_message") or record.get("_raw")
        source = f"{record.get('provider')}:{record.get('index')}"
        level = rule.get("level")
        severity = min(4, int(level) // 4) if isinstance(level, int) else None
    fields = parse_message(message) if isinstance(message, str) else {}
    return _generic(event_id, ts, host, source_type, source, severity, message, fields)


def _generic(event_id: Any, ts: Any, host: Any, source_type: Any, source: Any, severity: int | None,
             message: Any, f: dict[str, str]) -> dict[str, Any]:
    image, parent = f.get("Image"), f.get("ParentImage")
    user = f.get("user") or f.get("User") or f.get("AccountName")
    if not user and f.get("to") and "@" in f["to"]:
        user = f["to"].split("@", 1)[0]
    event_code = f.get("EventID")
    action = f.get("action") or f.get("file_action") or (f"EventID {event_code}" if event_code else None)
    if "DeviceConnected" in (message or ""):
        action = action or "DeviceConnected"
    failure = event_code == "4625" or f.get("authentication", "").upper() == "FAILURE"
    return {
        "event_id": event_id,
        "timestamp": ts,
        "event_type": source_type,
        "source": source,
        "severity": severity,
        "host": host or f.get("host") or f.get("device") or f.get("mailserver"),
        "source_ip": f.get("src") or f.get("client") or f.get("IpAddress") or f.get("SourceIp") or f.get("source_ip"),
        "destination_ip": f.get("dst") or f.get("DestinationIp"),
        "source_port": f.get("sport"),
        "destination_port": f.get("dport") or f.get("DestinationPort"),
        "username": user,
        "process_name": _basename(image),
        "parent_process": _basename(parent),
        "command": f.get("command") or f.get("request") or f.get("url") or f.get("uri"),
        "action": action,
        "status": "failure" if failure else (f.get("status") or f.get("Status") or f.get("authentication")),
        "resource": [v for v in (f.get("path"), f.get("device_id"), f.get("query")) if v],
        "event_code": event_code,
        "message": message,
    }


def _basename(path: str | None) -> str | None:
    return path.replace("/", "\\").rsplit("\\", 1)[-1] if path else None


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load(kind: str, directory: Path = DATASET_DIR) -> list[dict[str, Any]]:
    return [to_event(kind, record) for _, record in iter_records(dataset_path(kind, directory))]


# ---------------------------------------------------------------------------
# Generic baseline signals (the "detections" the engine ranks around)
# ---------------------------------------------------------------------------


def is_external(ip: str | None) -> bool:
    """Outside RFC1918 / loopback. Deliberately NOT ipaddress.is_private,
    which also treats documentation ranges as private."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.version == 4 and not any(address in net for net in _INTERNAL)


def _shape(e: dict[str, Any]) -> tuple:
    command = e.get("command") or ""
    method_path = command.split("?")[0].split(" HTTP")[0] if command else None
    return (e.get("event_type"), e.get("event_code"), e.get("action"), e.get("process_name"), method_path)


def baseline_signals(events: list[dict[str, Any]], *, burst_threshold: int = 5, burst_window_s: int = 600,
                     rare_max: int = 2) -> list[DetectionResult]:
    """Generic SOC heuristics, identical for both representations."""
    signals: list[DetectionResult] = []
    by_external: dict[str, list[str]] = defaultdict(list)
    failures: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    successes: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    shapes: Counter[tuple] = Counter(_shape(e) for e in events)
    rare: list[str] = []
    for e in events:
        ip = e.get("source_ip")
        if is_external(ip):
            by_external[ip].append(e["event_id"])
        ts = _parse_ts(e.get("timestamp"))
        if ip and ts and e.get("event_code") in ("4624", "4625"):
            (failures if e.get("status") == "failure" else successes)[ip].append((ts, e["event_id"]))
        if shapes[_shape(e)] <= rare_max:
            rare.append(e["event_id"])

    for ip, ids in sorted(by_external.items()):
        signals.append(DetectionResult(
            alert_id=f"SIG-EXT-SRC-{ip}", rule_id="SIG-EXT-SRC", title=f"Activity from external address {ip}",
            description="Source address outside RFC1918/loopback.", severity="medium", confidence="medium",
            evidence_event_ids=tuple(ids), matched_fields={"source_ip": ip}))
    burst_sources: dict[str, datetime] = {}
    for ip, items in sorted(failures.items()):
        items.sort()
        start = 0
        for end in range(len(items)):
            while items[end][0] - items[start][0] > timedelta(seconds=burst_window_s):
                start += 1
            if end - start + 1 >= burst_threshold:
                ids = tuple(i for _, i in items)
                signals.append(DetectionResult(
                    alert_id=f"SIG-AUTH-BURST-{ip}", rule_id="SIG-AUTH-BURST",
                    title=f"{len(ids)} failed logons from {ip}",
                    description=f">= {burst_threshold} failed logons from one source within {burst_window_s}s.",
                    severity="high", confidence="high", evidence_event_ids=ids, matched_fields={"source_ip": ip}))
                burst_sources[ip] = items[0][0]
                break
    for ip, first_failure in sorted(burst_sources.items()):
        after = tuple(i for ts, i in sorted(successes.get(ip, [])) if ts >= first_failure)
        if after:
            signals.append(DetectionResult(
                alert_id=f"SIG-AUTH-SUCCESS-AFTER-BURST-{ip}", rule_id="SIG-AUTH-SUCCESS-AFTER-BURST",
                title=f"Successful logon from {ip} after a failed-logon burst",
                description="Success from a source that just produced a failed-logon burst.",
                severity="high", confidence="high", evidence_event_ids=after, matched_fields={"source_ip": ip}))
    if rare:
        signals.append(DetectionResult(
            alert_id="SIG-RARE-SHAPE", rule_id="SIG-RARE-SHAPE",
            title=f"{len(rare)} events with a rare shape (<= {rare_max} occurrences)",
            description="Event type/action/process/request shape seen at most a couple of times in the dataset.",
            severity="low", confidence="low", evidence_event_ids=tuple(rare)))
    return signals


# ---------------------------------------------------------------------------
# Canonical EvidenceContext (existing Stage 2 engine) from the selected evidence
# ---------------------------------------------------------------------------

_CATEGORY: Final[dict[str, str]] = {
    "sysmon_process": "process", "sysmon_network": "network", "firewall": "network", "dns": "dns",
    "apache_access": "web", "apache_error": "web", "web_application": "web", "file_audit": "file",
    "endpoint_file": "file", "usb": "usb", "mail_gateway": "email", "browser": "browser",
}


def to_security_event(e: dict[str, Any]) -> SecurityEvent:
    """Direct construction for the EvidenceContext engine (it only reads
    accessors). Categories beyond the core schema keep their honest names."""
    code = e.get("event_code")
    if e.get("event_type") == "windows_security":
        category = "authentication" if code in ("4624", "4625", "4634") else "process"
    else:
        category = _CATEGORY.get(e.get("event_type") or "", e.get("event_type") or "other")
    details: dict[str, Any] = {}
    if category == "process":
        details = {"name": e.get("process_name"), "parent_name": e.get("parent_process")}
    elif category == "dns":
        details = {"query_name": (e.get("resource") or [None])[-1], "source_ip": e.get("source_ip")}
    else:
        details = {"source_ip": e.get("source_ip"), "destination_ip": e.get("destination_ip"),
                   "destination_port": _int(e.get("destination_port")), "request": e.get("command"),
                   "path": (e.get("resource") or [None])[0]}
    details = {k: v for k, v in details.items() if v is not None}
    outcome = "failure" if e.get("status") == "failure" else "success"
    return SecurityEvent(
        event_id=e["event_id"], timestamp=_parse_ts(e["timestamp"]) or datetime.fromtimestamp(0, timezone.utc),
        source=e.get("source") or "canonical", category=category, action=e.get("action") or category,
        outcome=outcome, severity="informational", host={"hostname": e["host"]} if e.get("host") else {},
        user={"name": e["username"]} if e.get("username") else {}, details=details, raw=e.get("message") or "",
    )


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def console_inputs(events: list[dict[str, Any]], signals: list[DetectionResult],
                   selected_ids: Iterable[str]) -> tuple[list[SecurityEvent], list[DetectionResult]]:
    """Selected events as SecurityEvents + the signals whose evidence is in scope."""
    keep = set(selected_ids)
    security_events = [to_security_event(e) for e in events if e["event_id"] in keep]
    in_scope = {e.event_id for e in security_events}
    return security_events, [s for s in signals if set(s.evidence_event_ids) <= in_scope]


def build_contexts(events: list[dict[str, Any]], signals: list[DetectionResult],
                   selected_ids: Iterable[str]) -> tuple[list[SecurityEvent], list[Any], list[EvidenceContext]]:
    """Stage 1 incident correlation over the signals, then the EXISTING
    Stage 2 EvidenceContext engine (relevance, aggregation, budget, redaction).
    Only the correlation engine's selected events are in scope: the rest of
    the 50K never reaches the context builder."""
    keep = set(selected_ids)
    security_events, alerts = console_inputs(events, signals, keep)
    incidents = IncidentCorrelator().correlate(alerts, security_events)
    findings = screen_for_injection(security_events)
    contexts = [build_evidence_context(i, all_events=security_events, risk=score_incident(i), findings=findings)
                for i in incidents]
    return security_events, incidents, contexts


# ---------------------------------------------------------------------------
# Measured run
# ---------------------------------------------------------------------------


def raw_representation_tokens(kind: str, directory: Path = DATASET_DIR) -> dict[str, Any]:
    """Token estimate of the representation AS DELIVERED (every record
    serialized): the naive "send the logs" baseline. Never sent anywhere."""
    chars = 0
    count = 0
    for _, record in iter_records(dataset_path(kind, directory)):
        chars += len(json.dumps(record, separators=(",", ":"), ensure_ascii=False)) + 1
        count += 1
    return {"events": count, "chars": chars, "estimated_tokens": math.ceil(chars / CHARS_PER_TOKEN)}


@dataclass
class CanonicalRun:
    kind: str
    events: list[dict[str, Any]]
    signals: list[DetectionResult]
    result: Any
    timings_ms: dict[str, float] = field(default_factory=dict)


def run_representation(kind: str, directory: Path = DATASET_DIR) -> CanonicalRun:
    timings: dict[str, float] = {}
    t = time.perf_counter()
    events = load(kind, directory)
    timings["load_parse"] = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    signals = baseline_signals(events)
    timings["baseline_signals"] = (time.perf_counter() - t) * 1000
    result = CorrelationEngine().run(events, signals)
    timings.update(result.timings_ms)
    return CanonicalRun(kind, events, signals, result, timings)


def stage_candidates(run: CanonicalRun, limit: int = 12) -> list[dict[str, Any]]:
    """Clusters that contain signal evidence, in time order: CANDIDATE stages
    derived from engine output. They are not labels."""
    result = run.result
    members: dict[int, list[int]] = defaultdict(list)
    for i in result.ranking.selected:
        members[result.graph.cluster_of[i]].append(i)
    out = []
    for cluster, idx in members.items():
        events = [result.events[i] for i in idx]
        signal_events = [e for e in events if e.has_detection]
        if not signal_events:
            continue
        times = sorted(e.timestamp for e in events if e.timestamp)
        out.append({
            "cluster_id": result.graph.cluster_ids[cluster],
            "selected_events": len(events),
            "signal_events": len(signal_events),
            "first_seen": times[0].isoformat() if times else None,
            "last_seen": times[-1].isoformat() if times else None,
            "signals": sorted({r for e in signal_events for r in e.rule_ids}),
            "event_types": dict(Counter(e.event_type for e in events).most_common(6)),
            "hosts": sorted({e.hostname for e in events if e.hostname})[:8],
            "external_ips": sorted({e.source_ip for e in events if is_external(e.source_ip)})[:5],
            "users": [u for u, _ in Counter(e.username for e in events if e.username).most_common(5)],
        })
    out.sort(key=lambda c: (-c["signal_events"], c["first_seen"] or ""))
    return out[:limit]


def relationships(run: CanonicalRun, limit: int = 40) -> dict[str, Any]:
    """Entity co-occurrence among SELECTED events: nodes are entities, edges
    are pairs of entities appearing in the same selected event, weighted by
    count. Derived only from engine output; nothing is added by hand."""
    result = run.result
    index = result.index
    edge_counts: Counter[tuple[int, int]] = Counter()
    node_counts: Counter[int] = Counter()
    for i in result.ranking.selected:
        ids = [x for x in index.event_entities[i] if index.entities[x][0] is not EntityType.DETECTION
               or index.entities[x][1].startswith("rule:")]
        node_counts.update(ids)
        for a in range(len(ids)):
            for b in range(a + 1, len(ids)):
                edge_counts[tuple(sorted((ids[a], ids[b])))] += 1  # type: ignore[arg-type]
    top_edges = edge_counts.most_common(limit)
    used = {x for (a, b), _ in top_edges for x in (a, b)}
    label = lambda x: f"{index.entities[x][0].value}:{index.entities[x][1]}"  # noqa: E731
    return {
        "method": "entity co-occurrence within selected events (engine output only)",
        "nodes": [{"id": label(x), "type": index.entities[x][0].value, "events": node_counts[x]}
                  for x in sorted(used, key=lambda x: -node_counts[x])],
        "edges": [{"from": label(a), "to": label(b), "events": n} for (a, b), n in top_edges],
    }


def canonical_result(directory: Path = DATASET_DIR, *, with_context: bool = True) -> dict[str, Any]:
    """The machine-readable canonical benchmark result (both representations)."""
    started = time.perf_counter()
    validation = {kind: validate(kind, directory) for kind in ("raw", "siem")}
    representations: dict[str, Any] = {}
    engine_runs: dict[str, CanonicalRun] = {}
    for kind in ("raw", "siem"):
        baseline = raw_representation_tokens(kind, directory)
        run = run_representation(kind, directory)
        engine_runs[kind] = run
        summary = run.result.summary()
        representations[kind] = {
            "label": "RAW SOURCE TELEMETRY" if kind == "raw" else "SIEM CONNECTOR EVENTS",
            "file": validation[kind]["file"],
            "events": baseline["events"],
            "as_delivered_tokens": baseline["estimated_tokens"],
            "as_delivered_label": "estimated, never sent to a model",
            "engine": {
                "events": summary["raw_events"],
                "relevant_events": summary["selected_events"],
                "correlated_events": summary["correlated_events"],
                "evidence_objects": summary["evidence_objects"],
                "context_tokens": summary["estimated_context_tokens"],
                "reduction_vs_as_delivered_percent": round(
                    (1 - summary["estimated_context_tokens"] / baseline["estimated_tokens"]) * 100, 3),
                "clusters_with_signals": summary["clusters_with_detection"],
                "latency_ms": {k: round(v, 1) for k, v in run.timings_ms.items()},
                "engine_latency_ms": round(sum(v for k, v in run.result.timings_ms.items()), 1),
            },
            "signals": [{"rule_id": s.rule_id, "alert_id": s.alert_id, "title": s.title, "events": len(s.evidence_event_ids)}
                        for s in run.signals],
            "entities": run.result.index.stats() | {"hubs": []},
            "attack_stage_candidates": stage_candidates(run),
            "relationships": relationships(run),
        }
    context_section: dict[str, Any] = {"generated": False}
    if with_context:
        run = engine_runs["raw"]
        t = time.perf_counter()
        _, incidents, contexts = build_contexts(run.events, run.signals, run.result.selected_event_ids)
        context_section = {
            "generated": bool(contexts),
            "source_representation": "raw",
            "build_ms": round((time.perf_counter() - t) * 1000, 1),
            "incidents": len(incidents),
            "evidence_objects": sum(c.metrics["evidence_objects"] for c in contexts),
            "estimated_tokens": sum(c.metrics["estimated_tokens"] for c in contexts),
            "redacted_fields": sum(c.metrics["redacted_field_count"] for c in contexts),
            "pseudonyms": sum(c.metrics["distinct_pseudonyms"] for c in contexts),
            "per_incident": [{"incident_id": c.incident_id, "title": i.title, "severity": i.severity,
                              "evidence_objects": c.metrics["evidence_objects"],
                              "estimated_tokens": c.metrics["estimated_tokens"]}
                             for i, c in zip(incidents, contexts)],
        }
    has_truth = ground_truth_available()
    return {
        "dataset": "canonical_50k",
        "dataset_note": "Synthetic SOC benchmark dataset from the scenario author (two representations).",
        "validation": validation,
        "signals_label": SIGNALS_LABEL,
        "representations": representations,
        "evidence_context": context_section,
        "ground_truth_available": has_truth,
        "ground_truth": "NOT YET PROVIDED" if not has_truth else "present (not yet evaluated)",
        "quality_metrics": {"precision": NA, "recall": NA, "f1": NA, "critical_evidence_recall": NA},
        "peak_memory_mb": peak_memory_mb(),
        "total_ms": round((time.perf_counter() - started) * 1000, 1),
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.soc_core.correlation_engine.canonical")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args(argv)
    result = canonical_result()
    if not args.no_cache:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(result, indent=1), encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=1))
        return 0
    for kind in ("raw", "siem"):
        v, r = result["validation"][kind], result["representations"][kind]
        e = r["engine"]
        print(f"{r['label']}: {v['records']:,} records valid={v['valid']} problems={v['problems']}")
        print(f"   as delivered ~{r['as_delivered_tokens']:,} tokens (estimate, never sent)")
        print(f"   engine: {e['events']:,} -> {e['relevant_events']:,} relevant -> {e['evidence_objects']} objects "
              f"-> ~{e['context_tokens']:,} tokens ({e['reduction_vs_as_delivered_percent']}% less) | "
              f"engine {e['engine_latency_ms']:,} ms | signals {[s['rule_id'] + ':' + str(s['events']) for s in r['signals']]}")
    c = result["evidence_context"]
    print(f"EvidenceContext: generated={c['generated']} incidents={c.get('incidents')} objects={c.get('evidence_objects')} "
          f"tokens~{c.get('estimated_tokens')} build {c.get('build_ms')} ms")
    print(f"Ground truth: {result['ground_truth']} | peak memory {result['peak_memory_mb']} MB | total {result['total_ms']:,} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
