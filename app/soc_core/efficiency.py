"""AI Efficiency & Economics Lab: benchmark, evidence retention, cost model.

The claim this module measures (and nothing more):

    AI reasoning cost is driven by the context sent to the model. A
    deterministic evidence layer stops raw telemetry volume from translating
    directly into AI context volume.

It is an ARCHITECTURAL comparison on the same synthetic telemetry:

    Path A  "Naive raw-context baseline"   every raw event serialized into the
            prompt. THEORETICAL: estimated locally, NEVER sent to any model.
    Path B  "Evidence-context architecture" the real Stage 2 EvidenceContext
            (the only thing the AI provider ever receives).

It is NOT a vendor benchmark and makes no claim about any SIEM's ingest speed.

Everything is deterministic (seeded) and offline. Run from the repo root:

    app/.venv/Scripts/python.exe -m app.soc_core.efficiency --scales 100,1000,10000,50000
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Final, Iterable, Sequence

from .cloud_detections import all_rules
from .correlation import CorrelationEngine, Incident
from .detections import DetectionEngine
from .events import SecurityEvent, load_events, parse_event
from .evidence_context import (
    CHARS_PER_TOKEN,
    CONTEXT_SCHEMA_VERSION,
    ESTIMATED_OUTPUT_TOKENS,
    ContextBudget,
    EvidenceContext,
    build_evidence_context,
    canonical_json,
    estimate_tokens,
)
from .providers.ai_analyst import screen_for_injection
from .risk import score_incident

BENCHMARK_VERSION: Final[str] = "efficiency-bench/1.0"
DEFAULT_SEED: Final[int] = 20260919
SCALES: Final[tuple[int, ...]] = (100, 1_000, 10_000, 50_000, 100_000, 1_000_000)
TELEMETRY_LABEL: Final[str] = "Synthetic benchmark telemetry"
BASELINE_LABEL: Final[str] = "Naive raw-context baseline — estimated, not sent to the model"

DATA_DIR: Final[Path] = Path(__file__).resolve().parents[2] / "data"
CANONICAL_DATASETS: Final[tuple[Path, ...]] = (
    DATA_DIR / "sample_security_events.json",
    DATA_DIR / "aws_cloudtrail_samples.json",
)
CACHE_FILE: Final[Path] = Path(__file__).resolve().parents[2] / ".cache" / "efficiency_benchmark.json"

# Measured on this codebase: 1M events peaked at a 472 MB working set (~450 B/event,
# pooled dicts). Rounded up; used only to refuse scales the machine cannot hold.
BYTES_PER_EVENT_ESTIMATE: Final[int] = 520
MEMORY_HEADROOM: Final[float] = 0.85  # use at most 85% of currently free RAM

# Noise mix (fractions of the non-canonical events). See generate_events().
NOISE_MIX: Final[dict[str, float]] = {
    "benign_unrelated": 0.45,
    "repeated": 0.20,
    "entity_linked_near_timeline": 0.15,
    "detection_matching": 0.10,
    "near_timeline_unrelated": 0.10,
}


class UnsupportedScaleError(ValueError):
    """A scale outside SCALES, or one this machine cannot hold in memory."""


# ---------------------------------------------------------------------------
# Critical investigation facts (deterministic ground truth for retention)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CriticalFact:
    fact_id: str
    fact: str
    incident: str                       # which canonical incident it belongs to
    supporting_event_ids: tuple[str, ...]
    via_context: bool = False           # True when no detection rule fires on it


CRITICAL_FACTS: Final[tuple[CriticalFact, ...]] = (
    CriticalFact("F01", "Initial access: password spray from 203.0.113.45", "endpoint",
                 ("evt-0002", "evt-0003", "evt-0004", "evt-0005")),
    CriticalFact("F02", "Compromised identity: successful logon from the spray source", "endpoint",
                 ("evt-0006",), via_context=True),
    CriticalFact("F03", "MFA fatigue against the same identity", "endpoint",
                 ("evt-0019", "evt-0020", "evt-0007")),
    CriticalFact("F04", "Affected endpoint: encoded PowerShell and rundll32 on WKS-FIN-014", "endpoint",
                 ("evt-0008", "evt-0009")),
    CriticalFact("F05", "Credential access: LSASS memory access", "endpoint", ("evt-0013",)),
    CriticalFact("F06", "Persistence: Run-key written by the implant", "endpoint",
                 ("evt-0021",), via_context=True),
    CriticalFact("F07", "Lateral movement: ADMIN$ share access from the endpoint", "endpoint",
                 ("evt-0023",), via_context=True),
    CriticalFact("F08", "Command and control: repeated outbound to 198.51.100.77", "endpoint",
                 ("evt-0011", "evt-0012")),
    CriticalFact("F09", "Cloud initial access: leaked CI key used from outside", "cloud",
                 ("cev-0012", "cev-0013", "cev-0014", "cev-0015", "cev-0016", "cev-0017")),
    CriticalFact("F10", "Cloud role: ops-admin assumed, then chained to data-reader", "cloud",
                 ("cev-0018", "cev-0027")),
    CriticalFact("F11", "Cloud privilege escalation: admin policies granted", "cloud",
                 ("cev-0021", "cev-0022")),
    CriticalFact("F12", "Defense evasion: CloudTrail logging stopped", "cloud", ("cev-0026",)),
    CriticalFact("F13", "Sensitive resource access: finance bucket bulk reads", "cloud",
                 ("cev-0028", "cev-0029", "cev-0030", "cev-0031")),
    CriticalFact("F14", "Exposure: SSH opened to the internet and used", "cloud",
                 ("cev-0024", "cev-0025")),
)


def evaluate_retention(contexts: Sequence[EvidenceContext]) -> dict[str, Any]:
    """Deterministic evidence retention against CRITICAL_FACTS.

    A fact is PRESERVED when every supporting event is represented by some
    evidence item in the context packs (individually or inside an aggregate).
    `citation_coverage_percent` is the share of individual supporting events
    that map to a citable evidence ID. This measures evidence retention, not
    "AI accuracy".
    """
    event_to_evidence: dict[str, str] = {}
    for context in contexts:
        for evidence_id, event_ids in context.evidence_to_events.items():
            for event_id in event_ids:
                event_to_evidence.setdefault(event_id, f"{context.incident_id}:{evidence_id}")

    facts = []
    supporting_total = citable_total = 0
    for fact in CRITICAL_FACTS:
        cited = {e: event_to_evidence.get(e) for e in fact.supporting_event_ids}
        found = [e for e, ev in cited.items() if ev]
        supporting_total += len(fact.supporting_event_ids)
        citable_total += len(found)
        facts.append({
            "fact_id": fact.fact_id,
            "fact": fact.fact,
            "incident": fact.incident,
            "via_context": fact.via_context,
            "preserved": len(found) == len(fact.supporting_event_ids),
            "supporting_event_ids": list(fact.supporting_event_ids),
            "missing_event_ids": [e for e, ev in cited.items() if not ev],
            "evidence_ids": sorted({ev for ev in cited.values() if ev}),
        })
    preserved = sum(1 for f in facts if f["preserved"])
    return {
        "critical_facts": len(facts),
        "preserved_facts": preserved,
        "missing_facts": [f["fact_id"] for f in facts if not f["preserved"]],
        "evidence_retention_percent": _pct(preserved, len(facts)),
        "citation_coverage_percent": _pct(citable_total, supporting_total),
        "facts": facts,
    }


# ---------------------------------------------------------------------------
# Synthetic benchmark telemetry
# ---------------------------------------------------------------------------

_T0: Final[datetime] = datetime(2026, 9, 17, 0, 0, tzinfo=timezone.utc)
_SPAN_S: Final[int] = 48 * 3600
_EMPTY: Final[dict] = {}


class _Pool:
    """Shared, immutable-by-convention dicts so 1M events don't hold 1M
    identical host/user objects. Nothing downstream mutates them."""

    def __init__(self) -> None:
        self._cache: dict[tuple, dict] = {}

    def get(self, *key: Any) -> dict:
        found = self._cache.get(key)
        if found is None:
            found = self._build(key)
            self._cache[key] = found
        return found

    @staticmethod
    def _build(key: tuple) -> dict:
        kind = key[0]
        if kind == "host":
            return {"hostname": key[1], "ip": key[2]}
        if kind == "user":
            return {"name": key[1], "domain": "CORP"}
        if kind == "auth":
            return {"logon_type": key[1], "source_ip": key[2], **({"failure_reason": key[3]} if key[3] else {})}
        if kind == "proc":
            return {"name": key[1], "parent_name": key[2], "command_line": key[3]}
        if kind == "dns":
            return {"query_name": key[1], "query_type": "A", "response_code": "NOERROR"}
        if kind == "net":
            return {"direction": "outbound", "protocol": "tcp", "source_ip": key[1],
                    "destination_ip": key[2], "destination_port": key[3]}
        if kind == "cloud":
            return {"provider": "aws", "account_id": "111122223333", "region": "us-east-1",
                    "event_source": key[1], "event_name": key[2], "identity_type": key[3],
                    "principal_arn": key[4], "session_issuer_arn": key[5] or None,
                    "source_ip": key[6], "request_parameters": {"bucketName": key[7]} if key[7] else {},
                    "resources": []}
        raise KeyError(kind)


def _event(event_id: str, ts: datetime, source: str, category: str, action: str, outcome: str,
           host: dict, user: dict, details: dict, raw: str) -> SecurityEvent:
    """Direct construction (validated equivalently by tests on small scales)."""
    return SecurityEvent(event_id=event_id, timestamp=ts, source=source, category=category, action=action,
                         outcome=outcome, severity="informational" if outcome == "success" else "low",
                         host=host, user=user, details=details, raw=raw, metadata=_EMPTY, aux=_EMPTY)


def canonical_events() -> list[SecurityEvent]:
    """The two canonical incident datasets (63 events), unchanged."""
    return [event for path in CANONICAL_DATASETS for event in load_events(path)]


def generate_events(n: int, seed: int = DEFAULT_SEED) -> list[SecurityEvent]:
    """Deterministic synthetic telemetry: the 63 canonical events embedded in
    n - 63 noise events of five kinds (see NOISE_MIX):

      benign_unrelated            normal logons/processes/DNS/internal flows, 48h
      repeated                    three chatty sources (monitoring, DNS, backup)
      entity_linked_near_timeline benign activity by incident users/hosts
                                  inside the incident windows (becomes context)
      detection_matching          extra spray failures from the attacker IP and
                                  extra bulk reads of the finance bucket, inside
                                  the rule windows (joins existing alerts)
      near_timeline_unrelated     other hosts, same time windows, no shared entity
    """
    canon = canonical_events()
    if n < len(canon):
        raise UnsupportedScaleError(f"scale {n} is smaller than the {len(canon)} canonical events")
    rng = random.Random(seed)
    pool = _Pool()
    noise = n - len(canon)
    counts = _split(noise, NOISE_MIX)
    out: list[SecurityEvent] = list(canon)
    seq = 0

    def eid(prefix: str) -> str:
        nonlocal seq
        seq += 1
        return f"{prefix}-{seq:07d}"

    # benign_unrelated
    for _ in range(counts["benign_unrelated"]):
        t = _T0 + timedelta(seconds=rng.randrange(_SPAN_S))
        h = rng.randrange(2000)
        host = pool.get("host", f"WKS-{h:04d}", f"192.0.2.{h % 250}")
        user = pool.get("user", f"emp{rng.randrange(8000):04d}")
        kind = rng.randrange(4)
        if kind == 0:
            out.append(_event(eid("bn"), t, "windows_security", "authentication", "logon_success", "success",
                              host, user, pool.get("auth", "interactive", host["ip"], None),
                              f"EventID=4624 Account=CORP\\{user['name']} LogonType=2"))
        elif kind == 1:
            proc = rng.choice(("excel.exe", "outlook.exe", "teams.exe", "chrome.exe"))
            out.append(_event(eid("bn"), t, "sysmon", "process", "process_created", "success", host, user,
                              pool.get("proc", proc, "explorer.exe", proc), f"Sysmon EventID=1 Image={proc}"))
        elif kind == 2:
            domain = rng.choice(("intranet.corp.test", "mail.corp.test", "files.corp.test"))
            out.append(_event(eid("bn"), t, "sysmon", "dns", "dns_query", "success", host, user,
                              pool.get("dns", domain), f"Sysmon EventID=22 QueryName={domain}"))
        else:
            out.append(_event(eid("bn"), t, "zeek_conn", "network", "network_connection", "success", host, user,
                              pool.get("net", host["ip"], "192.0.2.30", 445), "zeek conn smb internal"))

    # repeated: three periodic sources
    reps = counts["repeated"]
    mon_host = pool.get("host", "MON-01", "192.0.2.250")
    mon_user = pool.get("user", "svc_monitor")
    for i in range(reps):
        t = _T0 + timedelta(seconds=(i * _SPAN_S) // max(reps, 1))
        which = i % 3
        if which == 0:
            out.append(_event(eid("rp"), t, "windows_security", "authentication", "logon_success", "success",
                              mon_host, mon_user, pool.get("auth", "service", "192.0.2.250", None),
                              "EventID=4624 Account=CORP\\svc_monitor LogonType=5"))
        elif which == 1:
            out.append(_event(eid("rp"), t, "sysmon", "dns", "dns_query", "success",
                              pool.get("host", "WKS-9001", "192.0.2.201"), pool.get("user", "svc_update"),
                              pool.get("dns", "updates.corp.test"), "Sysmon EventID=22 QueryName=updates.corp.test"))
        else:
            out.append(_event(eid("rp"), t, "sysmon", "process", "process_created", "success",
                              pool.get("host", "SRV-BKP-01", "192.0.2.40"), pool.get("user", "svc_backup_job"),
                              pool.get("proc", "robocopy.exe", "services.exe", "robocopy.exe /MIR"),
                              "Sysmon EventID=1 Image=robocopy.exe"))

    # entity_linked_near_timeline: benign activity by incident identities
    fin_host = pool.get("host", "WKS-FIN-014", "192.0.2.14")
    rivera = pool.get("user", "j.rivera")
    ec2 = pool.get("host", "i-0a1b2c3d4e5f00001", "192.0.2.120")
    for i in range(counts["entity_linked_near_timeline"]):
        if i % 2 == 0:  # endpoint incident window 2026-09-17 07:35 - 09:10
            t = datetime(2026, 9, 17, 7, 35, tzinfo=timezone.utc) + timedelta(seconds=rng.randrange(95 * 60))
            if rng.random() < 0.5:
                domain = rng.choice(("intranet.corp.test", "mail.corp.test"))
                out.append(_event(eid("el"), t, "sysmon", "dns", "dns_query", "success", fin_host, rivera,
                                  pool.get("dns", domain), f"Sysmon EventID=22 QueryName={domain}"))
            else:
                out.append(_event(eid("el"), t, "sysmon", "process", "process_created", "success", fin_host, rivera,
                                  pool.get("proc", "excel.exe", "explorer.exe", "excel.exe"),
                                  "Sysmon EventID=1 Image=excel.exe"))
        else:           # cloud incident window 2026-09-18 08:40 - 09:40
            t = datetime(2026, 9, 18, 8, 40, tzinfo=timezone.utc) + timedelta(seconds=rng.randrange(60 * 60))
            out.append(_event(eid("el"), t, "aws_vpc_flow_logs", "network", "flow_accept", "success", ec2, _EMPTY,
                              pool.get("net", "192.0.2.120", "192.0.2.60", 443), "vpc flow internal 443"))

    # detection_matching: joins the spray alert and the S3 bulk-read alert
    for i in range(counts["detection_matching"]):
        if i % 2 == 0:  # spray window: 08:02:48 - 08:07:40 on 2026-09-17
            t = datetime(2026, 9, 17, 8, 2, 48, tzinfo=timezone.utc) + timedelta(milliseconds=rng.randrange(292_000))
            acct = f"acct{rng.randrange(20_000):05d}"
            out.append(_event(eid("dm"), t, "windows_security", "authentication", "logon_failed", "failure",
                              pool.get("host", "DC-CORP-01", "192.0.2.10"), pool.get("user", acct),
                              pool.get("auth", "network", "203.0.113.45", "bad_password"),
                              f"EventID=4625 Account=CORP\\{acct} Source=203.0.113.45"))
        else:           # S3 bulk-read window: 09:13:06 - 09:22:59 on 2026-09-18
            t = datetime(2026, 9, 18, 9, 13, 6, tzinfo=timezone.utc) + timedelta(milliseconds=rng.randrange(593_000))
            details = pool.get("cloud", "s3.amazonaws.com", "GetObject", "AssumedRole",
                               "arn:aws:sts::111122223333:assumed-role/data-reader/export",
                               "arn:aws:iam::111122223333:role/data-reader", "203.0.113.77", "corp-finance-archive")
            out.append(SecurityEvent(event_id=eid("dm"), timestamp=t, source="aws_cloudtrail", category="cloud",
                                     action="GetObject", outcome="success", severity="medium", host=_EMPTY,
                                     user=pool.get("user", "data-reader"), details=details,
                                     raw="eventName=GetObject bucket=corp-finance-archive", metadata=_EMPTY, aux=_EMPTY))

    # near_timeline_unrelated: same windows, other hosts, no shared entity
    for i in range(counts["near_timeline_unrelated"]):
        base = datetime(2026, 9, 17, 7, 35, tzinfo=timezone.utc) if i % 2 == 0 else datetime(2026, 9, 18, 8, 40, tzinfo=timezone.utc)
        t = base + timedelta(seconds=rng.randrange(90 * 60))
        h = 3000 + rng.randrange(500)
        host = pool.get("host", f"WKS-{h:04d}", f"192.0.2.{h % 250}")
        out.append(_event(eid("nt"), t, "windows_security", "authentication", "logon_success", "success", host,
                          pool.get("user", f"emp{rng.randrange(8000):04d}"),
                          pool.get("auth", "interactive", host["ip"], None), "EventID=4624 LogonType=2"))

    out.sort(key=lambda e: (e.timestamp, e.event_id))
    return out


def _split(total: int, mix: dict[str, float]) -> dict[str, int]:
    counts = {k: int(total * v) for k, v in mix.items()}
    counts[next(iter(mix))] += total - sum(counts.values())  # remainder to the first bucket
    return counts


# ---------------------------------------------------------------------------
# Path A: naive raw-context baseline (estimate only, never sent anywhere)
# ---------------------------------------------------------------------------


def raw_event_record(event: SecurityEvent) -> dict[str, Any]:
    """The compact per-event record a naive "send the logs to the LLM"
    design would serialize: the normalized event plus its raw line."""
    return {
        "id": event.event_id, "ts": event.timestamp.isoformat(), "src": event.source,
        "cat": event.category, "act": event.action, "out": event.outcome, "sev": event.severity,
        "host": event.host, "user": event.user, "detail": event.details, "raw": event.raw,
    }


def estimate_raw_context_tokens(events: Iterable[SecurityEvent]) -> tuple[int, int]:
    """(tokens, chars) of the naive baseline, using the SAME deterministic
    estimator as the evidence context (chars / CHARS_PER_TOKEN). Streaming:
    nothing is accumulated but the running length, and nothing leaves the
    process."""
    chars = 0
    dumps = json.dumps
    for event in events:
        chars += len(dumps(raw_event_record(event), separators=(",", ":"), default=str)) + 1
    return math.ceil(chars / CHARS_PER_TOKEN), chars


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------


def _free_memory_bytes() -> int | None:
    """Available physical memory (Windows via GlobalMemoryStatusEx; POSIX via sysconf)."""
    try:
        if sys.platform == "win32":
            class _MEMSTAT(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            stat = _MEMSTAT()
            stat.dwLength = ctypes.sizeof(_MEMSTAT)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
                return int(stat.ullAvailPhys)
            return None
        import os

        return int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, AttributeError):
        return None


def check_scale(scale: int) -> None:
    """Raise UnsupportedScaleError for unknown scales or ones that won't fit."""
    if scale not in SCALES:
        raise UnsupportedScaleError(f"unsupported scale {scale}; choose one of {list(SCALES)}")
    free = _free_memory_bytes()
    need = scale * BYTES_PER_EVENT_ESTIMATE
    if free is not None and need > free * MEMORY_HEADROOM:
        raise UnsupportedScaleError(
            f"scale {scale:,} needs ~{need / 1e9:.1f} GB but only {free / 1e9:.1f} GB is free "
            f"(limit {int(MEMORY_HEADROOM * 100)}%); not run, no result shown"
        )


def run_benchmark(scale: int, seed: int = DEFAULT_SEED, *, budget: ContextBudget = ContextBudget()) -> dict[str, Any]:
    """Run the full deterministic pipeline at one scale and measure it.

    Every number comes from executing the real Stage 2 code on the generated
    telemetry. Timings vary by machine; counts and tokens are reproducible.
    """
    check_scale(scale)
    t0 = time.perf_counter()
    events = generate_events(scale, seed)
    t1 = time.perf_counter()
    alerts, rule_errors = DetectionEngine(all_rules()).run(events)
    t2 = time.perf_counter()
    incidents = CorrelationEngine().correlate(alerts, events)
    t3 = time.perf_counter()
    # Generated noise has fixed, known-clean text; only the canonical events
    # carry attacker-controlled strings, so only they need screening.
    canonical_ids = {e.event_id for e in canonical_events()}
    findings = screen_for_injection(e for e in events if e.event_id in canonical_ids)
    contexts: list[EvidenceContext] = []
    per_incident = []
    for incident in incidents:
        c0 = time.perf_counter()
        context = build_evidence_context(incident, all_events=events, risk=score_incident(incident),
                                         findings=findings, budget=budget)
        c1 = time.perf_counter()
        contexts.append(context)
        m = context.metrics
        per_incident.append({
            "incident_id": incident.incident_id, "title": incident.title, "severity": incident.severity,
            "relevant_events": m["relevant_events"], "evidence_objects": m["evidence_objects"],
            "estimated_tokens": m["estimated_tokens"], "build_ms": round((c1 - c0) * 1000, 1),
        })
    t4 = time.perf_counter()
    raw_tokens, raw_chars = estimate_raw_context_tokens(events)
    t5 = time.perf_counter()

    relevant_ids: set[str] = set()
    for context in contexts:
        for ids in context.evidence_to_events.values():
            relevant_ids.update(ids)
    context_tokens = sum(c.metrics["estimated_tokens"] for c in contexts)
    relevant = sum(c.metrics["relevant_events"] for c in contexts)
    pipeline_s = (t2 - t1) + (t3 - t2) + (t4 - t3)
    retention = evaluate_retention(contexts)
    payload_text = "".join(c.to_json() for c in contexts)
    return {
        "benchmark_version": BENCHMARK_VERSION,
        "context_schema": CONTEXT_SCHEMA_VERSION,
        "telemetry": TELEMETRY_LABEL,
        "seed": seed,
        "scale": scale,
        "status": "measured",
        "raw_event_count": len(events),
        "incidents_detected": len(incidents),
        "alerts": len(alerts),
        "rule_errors": rule_errors,
        "relevant_event_count": relevant,
        "evidence_object_count": sum(c.metrics["evidence_objects"] for c in contexts),
        "excluded_event_count": len(events) - len(relevant_ids),
        "redaction_count": sum(c.metrics["redacted_field_count"] for c in contexts),
        "pseudonym_count": sum(c.metrics["distinct_pseudonyms"] for c in contexts),
        "estimated_context_tokens": context_tokens,
        "estimated_raw_context_tokens": raw_tokens,
        "raw_context_chars": raw_chars,
        "baseline_label": BASELINE_LABEL,
        "context_reduction_percent": _reduction(context_tokens, raw_tokens),
        "evidence_retention_percent": retention["evidence_retention_percent"],
        "citation_coverage_percent": retention["citation_coverage_percent"],
        "preserved_facts": retention["preserved_facts"],
        "critical_facts": retention["critical_facts"],
        "missing_facts": retention["missing_facts"],
        "context_build_time_ms": round((t4 - t3) * 1000, 1),
        "generation_time_ms": round((t1 - t0) * 1000, 1),
        "detection_time_ms": round((t2 - t1) * 1000, 1),
        "correlation_time_ms": round((t3 - t2) * 1000, 1),
        "raw_estimate_time_ms": round((t5 - t4) * 1000, 1),
        "events_per_second": round(len(events) / pipeline_s) if pipeline_s > 0 else None,
        "events_per_second_definition": "raw events / (detection + correlation + context build) wall time",
        "per_incident": per_incident,
        "payload_sha256": hashlib.sha256(payload_text.encode()).hexdigest(),
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------------------
# Budget experiment
# ---------------------------------------------------------------------------


def budget_experiment(fractions: Sequence[float] = (1.0, 0.75, 0.5, 0.25)) -> dict[str, Any]:
    """How much context can be removed before critical evidence disappears?

    Uses the canonical incidents (no noise). For each incident the
    unconstrained context size T is measured, then contexts are rebuilt with
    max_input_tokens = fraction * T. Detection evidence is never trimmed, so
    below some fraction the size stops shrinking (the floor). Reported
    honestly, including any fact that is lost.
    """
    events = canonical_events()
    alerts, _ = DetectionEngine(all_rules()).run(events)
    incidents = CorrelationEngine().correlate(alerts, events)
    findings = screen_for_injection(events)
    unbounded = ContextBudget(max_input_tokens=10**9)
    full_tokens = {
        i.incident_id: build_evidence_context(i, all_events=events, risk=score_incident(i), findings=findings,
                                              budget=unbounded).metrics["estimated_tokens"]
        for i in incidents
    }
    rows = []
    for fraction in fractions:
        contexts = []
        for incident in incidents:
            limit = max(1, int(full_tokens[incident.incident_id] * fraction))
            contexts.append(build_evidence_context(
                incident, all_events=events, risk=score_incident(incident), findings=findings,
                budget=ContextBudget(max_input_tokens=limit),
            ))
        tokens = sum(c.metrics["estimated_tokens"] for c in contexts)
        target = sum(max(1, int(t * fraction)) for t in full_tokens.values())
        retention = evaluate_retention(contexts)
        rows.append({
            "budget_percent": round(fraction * 100),
            "target_tokens": target,
            "actual_tokens": tokens,
            "hit_floor": tokens > target,
            "evidence_objects": sum(c.metrics["evidence_objects"] for c in contexts),
            "dropped_by_budget": sum(c.metrics["dropped_by_budget"] for c in contexts),
            "preserved_facts": retention["preserved_facts"],
            "critical_facts": retention["critical_facts"],
            "evidence_retention_percent": retention["evidence_retention_percent"],
            "citation_coverage_percent": retention["citation_coverage_percent"],
            "missing_facts": retention["missing_facts"],
        })
    return {
        "full_context_tokens": sum(full_tokens.values()),
        "note": "Detection evidence is never trimmed; below the floor the context cannot shrink further.",
        "rows": rows,
    }


def canonical_fidelity() -> dict[str, Any]:
    """Retention on the canonical incidents at the default budget."""
    events = canonical_events()
    alerts, _ = DetectionEngine(all_rules()).run(events)
    incidents = CorrelationEngine().correlate(alerts, events)
    findings = screen_for_injection(events)
    contexts = [build_evidence_context(i, all_events=events, risk=score_incident(i), findings=findings)
                for i in incidents]
    return evaluate_retention(contexts)


# ---------------------------------------------------------------------------
# Economics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pricing:
    """Per-1M-token prices. Always user-configurable; the defaults are
    example rates for demonstration, not a quote for any vendor."""

    model: str = "example-model"
    input_per_mtok: float = 5.0
    output_per_mtok: float = 25.0
    label: str = "EXAMPLE RATES — editable, not a vendor quote"

    def __post_init__(self) -> None:
        for name in ("input_per_mtok", "output_per_mtok"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be a finite, non-negative number")


def token_cost(input_tokens: int, output_tokens: int, pricing: Pricing) -> dict[str, float]:
    """input_tokens / 1e6 * input_price + output_tokens / 1e6 * output_price."""
    if input_tokens < 0 or output_tokens < 0:
        raise ValueError("token counts must be non-negative")
    input_cost = input_tokens / 1_000_000 * pricing.input_per_mtok
    output_cost = output_tokens / 1_000_000 * pricing.output_per_mtok
    return {"input_cost": input_cost, "output_cost": output_cost, "total_cost": input_cost + output_cost}


def compare_costs(
    raw_tokens: int,
    context_tokens: int,
    pricing: Pricing,
    *,
    output_tokens: int = ESTIMATED_OUTPUT_TOKENS,
    investigations: int = 1,
    context_window: int | None = None,
) -> dict[str, Any]:
    """Path A (theoretical baseline) vs Path B (evidence context).

    Output tokens are assumed equal for both paths (the same investigation
    report); the difference is entirely the input context.
    """
    if investigations < 0:
        raise ValueError("investigations must be non-negative")
    a = token_cost(raw_tokens, output_tokens, pricing)
    b = token_cost(context_tokens, output_tokens, pricing)
    scale = {n: {"baseline": a["total_cost"] * n, "evidence": b["total_cost"] * n}
             for n in (1, 1_000, 10_000)}
    result = {
        "pricing": {"model": pricing.model, "input_per_mtok": pricing.input_per_mtok,
                    "output_per_mtok": pricing.output_per_mtok, "label": pricing.label},
        "output_tokens_assumed": output_tokens,
        "investigations": investigations,
        "baseline": {"label": "THEORETICAL BASELINE — not sent to model", "input_tokens": raw_tokens,
                     **a, "total_for_investigations": a["total_cost"] * investigations},
        "evidence": {"label": "EVIDENCE-CONTEXT ARCHITECTURE", "input_tokens": context_tokens,
                     **b, "total_for_investigations": b["total_cost"] * investigations},
        "savings_for_investigations": (a["total_cost"] - b["total_cost"]) * investigations,
        "token_reduction_percent": _reduction(context_tokens, raw_tokens),
        "cost_reduction_percent": _reduction(b["total_cost"], a["total_cost"]),
        "per_1000_investigations": scale[1_000],
        "per_10000_investigations": scale[10_000],
    }
    if context_window:
        result["baseline"]["exceeds_context_window"] = raw_tokens > context_window
        result["baseline"]["context_windows_needed"] = math.ceil(raw_tokens / context_window) if raw_tokens else 0
        result["evidence"]["exceeds_context_window"] = context_tokens > context_window
    return result


def _reduction(new: float, old: float) -> float | None:
    """1 - new/old as a percentage; None when the baseline is zero."""
    if old <= 0:
        return None
    return round((1 - new / old) * 100, 2)


def _pct(part: int, whole: int) -> float | None:
    return round(part / whole * 100, 1) if whole else None


# ---------------------------------------------------------------------------
# Cached background runner (shared by the API and the CLI)
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkRunner:
    """Runs scales in a background thread and caches deterministic results.

    Cache key = benchmark version + context schema + seed + scale; a cached
    result is reused only if all four match, so a code change to the engine's
    schema/benchmark version invalidates it.
    """

    seed: int = DEFAULT_SEED
    cache_file: Path | None = CACHE_FILE
    results: dict[int, dict[str, Any]] = field(default_factory=dict)
    running: int | None = None
    queue: list[int] = field(default_factory=list)
    errors: dict[int, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    runner: Callable[[int, int], dict[str, Any]] = run_benchmark

    def __post_init__(self) -> None:
        self._load()

    def _key_ok(self, result: dict[str, Any]) -> bool:
        return (result.get("benchmark_version") == BENCHMARK_VERSION
                and result.get("context_schema") == CONTEXT_SCHEMA_VERSION
                and result.get("seed") == self.seed)

    def _load(self) -> None:
        if not self.cache_file or not self.cache_file.is_file():
            return
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return  # a corrupt cache is ignored, never trusted
        for item in data.get("results", []):
            if isinstance(item, dict) and self._key_ok(item) and item.get("scale") in SCALES:
                self.results[int(item["scale"])] = item

    def _save(self) -> None:
        if not self.cache_file:
            return
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"results": [self.results[s] for s in sorted(self.results)]}
        self.cache_file.write_text(json.dumps(payload, indent=1), encoding="utf-8")

    def status(self) -> dict[str, Any]:
        with self._lock:
            scales = []
            for scale in SCALES:
                if scale in self.results:
                    state = "measured"
                elif self.running == scale:
                    state = "running"
                elif scale in self.queue:
                    state = "queued"
                elif scale in self.errors:
                    state = "unavailable"
                else:
                    state = "not_run"
                scales.append({"scale": scale, "state": state, "reason": self.errors.get(scale)})
            return {
                "seed": self.seed,
                "benchmark_version": BENCHMARK_VERSION,
                "telemetry": TELEMETRY_LABEL,
                "scales": scales,
                "results": [self.results[s] for s in SCALES if s in self.results],
                "busy": self.running is not None or bool(self.queue),
            }

    def request(self, scales: Iterable[int], *, force: bool = False) -> dict[str, Any]:
        """Queue scales for measurement (cached ones are skipped unless forced)."""
        wanted = list(scales)
        for scale in wanted:
            if scale not in SCALES:
                raise UnsupportedScaleError(f"unsupported scale {scale}; choose one of {list(SCALES)}")
        with self._lock:
            for scale in wanted:
                if force:
                    self.results.pop(scale, None)
                if scale in self.results or scale in self.queue or scale == self.running:
                    continue
                self.errors.pop(scale, None)
                self.queue.append(scale)
            if self.queue and (self._thread is None or not self._thread.is_alive()):
                self._thread = threading.Thread(target=self._work, name="efficiency-benchmark", daemon=True)
                self._thread.start()
        return self.status()

    def run_now(self, scale: int) -> dict[str, Any]:
        """Synchronous measurement (CLI/tests)."""
        result = self.runner(scale, self.seed)
        with self._lock:
            self.results[scale] = result
            self._save()
        return result

    def _work(self) -> None:
        while True:
            with self._lock:
                if not self.queue:
                    self.running = None
                    return
                scale = self.queue.pop(0)
                self.running = scale
            try:
                result = self.runner(scale, self.seed)
            except UnsupportedScaleError as exc:
                with self._lock:
                    self.errors[scale] = str(exc)
                continue
            except MemoryError:
                with self._lock:
                    self.errors[scale] = "ran out of memory on this machine; not run, no result shown"
                continue
            with self._lock:
                self.results[scale] = result
                self._save()

    def wait(self, timeout: float | None = None) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.soc_core.efficiency",
                                     description="AI Efficiency Lab benchmark (offline, deterministic).")
    parser.add_argument("--scales", default="100,1000,10000,50000",
                        help=f"comma-separated subset of {list(SCALES)} (default: %(default)s)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--no-cache", action="store_true", help="measure without reading/writing the cache")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        scales = [int(s) for s in args.scales.split(",") if s.strip()]
    except ValueError:
        parser.error("--scales must be integers")
    runner = BenchmarkRunner(seed=args.seed, cache_file=None if args.no_cache else CACHE_FILE)
    rows = []
    for scale in scales:
        try:
            rows.append(runner.results.get(scale) or runner.run_now(scale))
        except UnsupportedScaleError as exc:
            rows.append({"scale": scale, "status": "unavailable", "reason": str(exc)})
    if args.json:
        print(json.dumps(rows, indent=1))
        return 0
    print(f"{TELEMETRY_LABEL}  seed={args.seed}  ({BASELINE_LABEL})")
    print(f"{'raw':>10} {'relevant':>9} {'evidence':>8} {'ctx tok':>8} {'raw tok (est)':>14} "
          f"{'reduction':>9} {'retention':>9} {'ctx ms':>8} {'ev/s':>10}")
    for r in rows:
        if r.get("status") != "measured":
            print(f"{r['scale']:>10,}  UNAVAILABLE: {r['reason']}")
            continue
        print(f"{r['raw_event_count']:>10,} {r['relevant_event_count']:>9,} {r['evidence_object_count']:>8} "
              f"{r['estimated_context_tokens']:>8,} {r['estimated_raw_context_tokens']:>14,} "
              f"{r['context_reduction_percent']:>8}% {r['evidence_retention_percent']:>8}% "
              f"{r['context_build_time_ms']:>8,.0f} {r['events_per_second']:>10,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
