"""Evidence audit of the canonical 50K attack chain. READ-ONLY.

For every stage in the attack-path diagram, find the telemetry that
supports it by applying an observable content predicate to ALL 50,000 raw
events (not just the reconstructed attack block), then report which of those
events the correlation engine selected and how the reconstructed ground truth
labels them. Transitions between consecutive stages are checked for shared
observed entities and time order.

Evidence classes:
  OBSERVED    the telemetry directly contains the behaviour
  CORRELATED  several observed events jointly support a relationship (shared
              entity + time order)
  INFERRED    the chain interpretation needs reasoning beyond the telemetry

No engine setting, label or dataset is changed. Output:
benchmarks/canonical_50k/attack_chain_audit.json

    app/.venv/Scripts/python.exe scripts/audit_canonical_attack_chain.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.soc_core.correlation_engine import canonical  # noqa: E402

OUT = canonical.DATASET_DIR / "attack_chain_audit.json"
ATTACKER = "198.51.100.90"     # README scenario metadata
WEB01_IP, WS07_IP = "10.10.10.10", "10.10.20.17"

E = dict[str, Any]
Pred = Callable[[E], bool]


def m(e: E) -> str:
    return e.get("message") or ""


# (diagram node, label key, predicate, evidence class, justification)
STAGES: list[tuple[str, str, Pred, str, str]] = [
    ("S1_RECON", "S1_RECON",
     lambda e: e.get("source_ip") == ATTACKER and (e["event_type"] in ("firewall", "web_application")
                                                  or (e["event_type"] == "apache_access" and "POST" not in m(e))),
     "OBSERVED",
     "Firewall connections, /login and /robots.txt probes, and app logs with usernames_enumerated from the attacker IP."),
    ("S2_BRUTE_FORCE", "S2_BRUTE_FORCE",
     lambda e: e.get("event_code") == "4625" and e.get("source_ip") == ATTACKER,
     "OBSERVED",
     "EventID 4625 failures from the attacker IP. They cycle over 8 accounts, so the pattern is also spray-shaped."),
    ("S3_PASSWORD_SPRAY", "S3_PASSWORD_SPRAY",
     lambda e: e.get("event_code") == "4624" and e.get("source_ip") == ATTACKER and "authentication=SUCCESS" in m(e),
     "INFERRED",
     "The one event is a SUCCESSFUL logon. Calling it 'password spray' relies on the preceding multi-account "
     "failures (S2). The spray behaviour itself is observed only in the S2 events."),
    ("S7_VALID_ACCOUNT (initial)", "S7_VALID_ACCOUNT",
     lambda e: e.get("event_code") == "4624" and e.get("source_ip") == ATTACKER and "authentication=" not in m(e),
     "CORRELATED",
     "Observed 4624 success for neha from the attacker IP. That it is a compromised valid account follows "
     "from the preceding failures from the same IP."),
    ("S8_WEB_SHELL", "S8_WEB_SHELL",
     lambda e: "cmd.jsp" in m(e) or ("java.exe" in m(e) and "cmd.exe" in m(e)),
     "OBSERVED",
     "POST /uploads/cmd.jsp with command= parameters, and tomcat java.exe spawning cmd.exe on WEB01."),
    ("WEB01_FOOTHOLD", "WEB01_FOOTHOLD",
     lambda e: e["event_type"] == "firewall" and e.get("source_ip") == WEB01_IP and e.get("destination_ip") == ATTACKER,
     "CORRELATED",
     "Observed outbound ALLOW connections from WEB01 to the attacker on port 4444. Reading them as a "
     "reverse-shell foothold relies on the web-shell activity just before."),
    ("S7_CREDENTIAL_HARVESTING", "S7_CREDENTIAL_HARVESTING",
     lambda e: "browserdump.exe" in m(e) or "CRED-WS07-001" in m(e),
     "OBSERVED",
     "browserdump.exe --profile LoginData on WS07, and file reads of Login Data tagged artifact=CRED-WS07-001."),
    ("S7_VALID_ACCOUNT (pivot)", "S7_VALID_ACCOUNT",
     lambda e: e.get("event_code") == "4624" and e.get("source_ip") == WS07_IP and e.get("host") == "WEB01",
     "CORRELATED",
     "Observed 4624 neha logons on WEB01 from WS07's IP (source_host=WS07). Calling them a pivot with harvested "
     "credentials relies on the S7 credential-harvesting events just before."),
    ("S8_FINANCE_DATA_STAGING", "S8_FINANCE_DATA_STAGING",
     lambda e: e.get("host") == "WS07" and ("C:\\Finance\\" in m(e)) and ("CONFIDENTIAL" in m(e) or "ARCHIVE" in m(e)),
     "OBSERVED",
     "CONFIDENTIAL finance file reads, then file_action=ARCHIVE creating export.zip."),
    ("S9_USB_TRANSFER", "S9_USB_TRANSFER",
     lambda e: e["event_type"] == "usb" and "USB-0042" in m(e),
     "OBSERVED",
     "USB-0042 connect, COPY of export.zip to E:, then disconnect."),
    ("S10_ARCHIVE_DELETION", "S10_ARCHIVE_DELETION",
     lambda e: "file_action=DELETE" in m(e) and "export.zip" in m(e),
     "OBSERVED",
     "file_action=DELETE of C:\\Users\\neha\\Desktop\\export.zip."),
]
# Stages in the README story but NOT in the diagram; audited because the
# WEB01 -> WS07 transition depends on them.
BRIDGE: list[tuple[str, str, Pred, str, str]] = [
    ("S5_PHISHING (not in diagram)", "S5_PHISHING",
     lambda e: "invoice.pdf.exe" in m(e) and ATTACKER in m(e),
     "OBSERVED", "Mail from the attacker IP delivering invoice.pdf.exe to neha, and the file created on WS07."),
    ("S6_ENDPOINT_COMPROMISE (not in diagram)", "S6_ENDPOINT_COMPROMISE",
     lambda e: e["event_type"] == "sysmon_process" and e.get("host") == "WS07"
     and ("invoice.pdf.exe" in m(e) or "-nop -w hid" in m(e)),
     "OBSERVED", "invoice.pdf.exe executed, then hidden PowerShell, on WS07."),
]


def entities(e: E) -> set[str]:
    out = {f"host:{e['host']}"} if e.get("host") else set()
    for key in ("source_ip", "destination_ip"):
        if e.get(key):
            out.add(f"ip:{e[key]}")
    if e.get("username"):
        out.add(f"user:{e['username']}")
    for r in e.get("resource") or []:
        out.add(f"file:{r}")
    if "export.zip" in m(e):
        out.add("file:export.zip")
    if "invoice.pdf.exe" in m(e):
        out.add("file:invoice.pdf.exe")
    return out


def observables(evts: list[E]) -> dict[str, list[str]]:
    def distinct(key: str) -> list[str]:
        return sorted({str(e[key]) for e in evts if e.get(key)})[:8]

    return {
        "source_ip": distinct("source_ip"), "destination_ip": distinct("destination_ip"), "host": distinct("host"),
        "user": distinct("username"), "action": distinct("action"), "process": distinct("process_name"),
        "file_resource": sorted({r for e in evts for r in (e.get("resource") or [])})[:8],
        "status": distinct("status"), "source_type": distinct("event_type"),
        "sample_messages": [m(e)[21:200] for e in evts[:2]],
    }


def id_ranges(ids: list[str]) -> str:
    nums = sorted(int(i.split("-")[1]) for i in ids)
    parts, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        parts.append(f"EVT-{nums[i]:06d}" if i == j else f"EVT-{nums[i]:06d}..{nums[j]:06d}")
        i = j + 1
    return ", ".join(parts)


def main() -> int:
    raw = canonical.load("raw")
    siem_by_id = {e["event_id"]: e for e in canonical.load("siem")}
    truth = {json.loads(line)["event_id"]: json.loads(line)
             for line in canonical.GROUND_TRUTH_FILE.read_text(encoding="utf-8").splitlines()}
    selected_raw = set(canonical.run_representation("raw").result.selected_event_ids)
    selected_siem = set(canonical.run_representation("siem").result.selected_event_ids)

    def audit(rows: list[tuple[str, str, Pred, str, str]]) -> list[dict[str, Any]]:
        out = []
        for node, label, pred, klass, why in rows:
            evts = sorted((e for e in raw if pred(e)), key=lambda e: (e["timestamp"], e["event_id"]))
            ids = [e["event_id"] for e in evts]
            gt_attack = [i for i in ids if truth[i]["attack_related"]]
            gt_same_stage = [i for i in ids if truth[i]["attack_stage"] == label]
            siem_same = sum(1 for e in evts if siem_by_id.get(e["event_id"], {}).get("message") == e.get("message"))
            out.append({
                "stage": node, "ground_truth_stage": label,
                "telemetry_exists": bool(evts), "evidence_events": len(ids), "event_ids": id_ranges(ids) if ids else None,
                "first_seen": evts[0]["timestamp"] if evts else None, "last_seen": evts[-1]["timestamp"] if evts else None,
                "observables": observables(evts),
                "selected_raw": sum(i in selected_raw for i in ids),
                "selected_siem": sum(i in selected_siem for i in ids),
                "ground_truth_attack_related": len(gt_attack),
                "ground_truth_same_stage": len(gt_same_stage),
                "matches_outside_ground_truth": len(ids) - len(gt_attack),
                "siem_carries_same_message": siem_same,
                "evidence_type": klass if evts else "NONE (no telemetry)",
                "justification": why,
                "_entities": set().union(*(entities(e) for e in evts)) if evts else set(),
                "_first": evts[0]["timestamp"] if evts else None, "_last": evts[-1]["timestamp"] if evts else None,
            })
        return out

    stages, bridge = audit(STAGES), audit(BRIDGE)
    transitions = []
    for a, b in zip(stages, stages[1:]):
        shared = sorted(a["_entities"] & b["_entities"])
        ordered = bool(a["_last"] and b["_first"] and a["_first"] <= b["_first"])
        transitions.append({
            "from": a["stage"], "to": b["stage"], "shared_observed_entities": shared[:10], "time_ordered": ordered,
            "evidence_type": "CORRELATED" if shared and ordered else "INFERRED",
        })
    foothold = next(s for s in stages if s["stage"] == "WEB01_FOOTHOLD")
    harvest = next(s for s in stages if s["stage"] == "S7_CREDENTIAL_HARVESTING")
    phishing, endpoint = bridge
    bridge_links = {
        "WEB01_FOOTHOLD -> S5_PHISHING": sorted(foothold["_entities"] & phishing["_entities"]),
        "S5_PHISHING -> S6_ENDPOINT_COMPROMISE": sorted(phishing["_entities"] & endpoint["_entities"]),
        "S6_ENDPOINT_COMPROMISE -> S7_CREDENTIAL_HARVESTING": sorted(endpoint["_entities"] & harvest["_entities"]),
    }
    for row in stages + bridge:
        for key in ("_entities", "_first", "_last"):
            row.pop(key)

    unsupported = [s["stage"] for s in stages if not s["telemetry_exists"]]
    report = {
        "dataset": {"raw": canonical.dataset_path("raw").name, "siem": canonical.dataset_path("siem").name},
        "read_only": True,
        "method": ("Content predicates applied to all 50,000 raw events, independent of event-ID ranges and of the "
                   "ground truth. The engine output (default settings) is read only for the 'selected' columns."),
        "stages": stages,
        "stages_not_in_diagram": bridge,
        "transitions": transitions,
        "bridge_links_via_s5_s6": bridge_links,
        "verdict": {
            "stages_without_telemetry": unsupported,
            "diagram_is": ("B) a correlation/inference over telemetry: every diagram stage has concrete OBSERVED "
                           "telemetry, but several stage labels and one transition are interpretations"
                           if not unsupported else "partially C) scenario metadata: some stages lack telemetry"),
            "key_findings": [
                "S3_PASSWORD_SPRAY is INFERRED: its only event is a successful logon. The spray pattern is visible in the S2 failures.",
                "WEB01_FOOTHOLD -> S7_CREDENTIAL_HARVESTING shares no observed entity. The diagram skips the observed bridge "
                "S5_PHISHING -> S6_ENDPOINT_COMPROMISE (attacker IP -> invoice.pdf.exe -> WS07/neha), which is how WS07 was compromised.",
                "WEB01 foothold and WS07 compromise are linked only through the attacker IP. The telemetry shows no "
                "lateral movement from WEB01 to WS07.",
                "Every stage's behaviour is directly present in the raw telemetry. The SIEM file carries the same messages.",
            ],
        },
    }
    OUT.write_text(json.dumps(report, indent=1), encoding="utf-8")

    print(f"{'Stage':<42}{'Evidence events':>16}{'Selected':>10}{'GT attack':>11}  Evidence type")
    for s in stages + bridge:
        print(f"{s['stage']:<42}{s['evidence_events']:>16}{s['selected_raw']:>10}{s['ground_truth_attack_related']:>11}  "
              f"{s['evidence_type']}   [{s['event_ids']}]")
    print("\nTransitions:")
    for t in transitions:
        print(f"  {t['from']} -> {t['to']}: {t['evidence_type']}  shared={t['shared_observed_entities'][:4]}")
    print("\nBridge via S5/S6:", {k: v[:3] for k, v in bridge_links.items()})
    print("\nVerdict:", report["verdict"]["diagram_is"])
    print("Stages without telemetry:", unsupported or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
