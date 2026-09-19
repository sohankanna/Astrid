"""Benchmark the evidence context engine on synthetic event volumes.

    app/.venv/Scripts/python.exe scripts/benchmark_context.py

Offline. Nothing is sent to any model. Each run generates N events:
  * ~30% an attacker password-spray burst (one IP, many accounts, 5 minutes)
  * one successful logon from the attacker IP (a state transition no rule fires on)
  * ~70% benign noise; half of it on the same domain controller, so the
    contextual-event scan has real work to do.
Reports wall time per stage and the reduction from raw events to LLM context.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.soc_core.cloud_detections import all_rules  # noqa: E402
from app.soc_core.correlation import CorrelationEngine  # noqa: E402
from app.soc_core.detections import DetectionEngine  # noqa: E402
from app.soc_core.events import parse_event  # noqa: E402
from app.soc_core.evidence_context import build_evidence_context  # noqa: E402
from app.soc_core.risk import score_incident  # noqa: E402

START = datetime(2026, 9, 17, 8, 0, tzinfo=timezone.utc)


def _event(event_id: str, user: str, ip: str, host: str, seconds: float, outcome: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": (START + timedelta(seconds=seconds)).isoformat(),
        "source": "windows_security",
        "category": "authentication",
        "action": "logon_failed" if outcome == "failure" else "logon_success",
        "outcome": outcome,
        "severity": "low",
        "host": {"hostname": host},
        "user": {"name": user},
        "auth": {"logon_type": "network", "source_ip": ip, "failure_reason": "bad_password"},
    }


def generate(n: int) -> list:
    burst = max(3, int(n * 0.3))
    raw = [
        _event(f"b{i:06d}", f"acct{i % 250:03d}", "203.0.113.66", "DC-LAB-01", i * (290 / burst), "failure")
        for i in range(burst)
    ]
    raw.append(_event("b-success", "acct007", "203.0.113.66", "DC-LAB-01", 295, "success"))
    for i in range(n - len(raw)):
        host = "DC-LAB-01" if i % 2 == 0 else f"WKS-{i % 400:04d}"
        raw.append(_event(f"n{i:06d}", f"emp{i % 5000:04d}", f"192.0.2.{i % 250}", host, 120 + i * 0.5, "success"))
    return [parse_event(r) for r in raw]


def run(n: int) -> dict:
    events = generate(n)
    t0 = time.perf_counter()
    alerts, _ = DetectionEngine(all_rules()).run(events)
    t1 = time.perf_counter()
    incidents = CorrelationEngine().correlate(alerts, events)
    t2 = time.perf_counter()
    incident = incidents[0]
    context = build_evidence_context(incident, all_events=events, risk=score_incident(incident))
    t3 = time.perf_counter()
    m = context.metrics
    return {
        "n": n, "alerts": len(alerts), "detect_s": t1 - t0, "correlate_s": t2 - t1, "context_s": t3 - t2,
        "raw": m["raw_events"], "relevant": m["relevant_events"], "evidence": m["evidence_objects"],
        "tokens": m["estimated_tokens"],
    }


def main() -> None:
    print(f"{'events':>8} {'alerts':>6} {'detect':>9} {'correlate':>10} {'context':>9} "
          f"{'raw':>7} {'relevant':>9} {'evidence':>9} {'~tokens':>8}")
    for n in (100, 1_000, 10_000, 50_000):
        r = run(n)
        print(f"{r['n']:>8,} {r['alerts']:>6} {r['detect_s']:>8.3f}s {r['correlate_s']:>9.3f}s "
              f"{r['context_s']:>8.3f}s {r['raw']:>7,} {r['relevant']:>9,} {r['evidence']:>9} {r['tokens']:>8,}")


if __name__ == "__main__":
    main()
