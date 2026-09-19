"""Reconstruct event-level ground truth for the canonical 50K dataset.

NOT AUTHORITATIVE. The generator (which holds the true labels) is not
available. These labels are RECONSTRUCTED from evidence that is independent
of our correlation engine and its heuristics:

1. attack_related  <-  generator ID-allocation artifact.
   The 137 attack events carry IDs EVT-000001..EVT-000137: that block is
   perfectly time-ordered while the 49,863 background IDs are shuffled
   (~50% adjacent time inversions), its size equals the README's
   attack/suspicious count (137), and every scenario indicator the README
   names occurs only inside it. All of this is asserted below; if any check
   fails, nothing is written.

2. attack_stage    <-  README stage taxonomy + per-stage counts.
   The block splits into contiguous segments whose sizes equal the README's
   per-stage counts exactly. Each segment is also checked against a content
   predicate (e.g. every S2 event is an EventID 4625 failure from the
   attacker IP), so a wrong boundary fails loudly.

3. critical        <-  README scenario metadata.
   An attack event is critical if it contains an indicator named in the
   README's SCENARIO section AND that indicator never appears in background
   events (checked). Hostnames (WEB01/WS07) and the victim username are
   excluded because they occur throughout benign traffic.

The engine's output is never read. The dataset files are only read.

    app/.venv/Scripts/python.exe scripts/build_canonical_ground_truth.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.soc_core.correlation_engine.canonical import DATASET_DIR, dataset_path, iter_records  # noqa: E402

OUT_DIR = DATASET_DIR / "ground_truth"
README = DATASET_DIR / "README (1).txt"
ATTACK_BLOCK = 137                         # README: "Attack/suspicious event count: 137"
README_STAGE_COUNTS = {                    # README: "Attack-stage distribution"
    "S10_ARCHIVE_DELETION": 8, "S1_RECON": 14, "S2_BRUTE_FORCE": 27, "S3_PASSWORD_SPRAY": 1,
    "S5_PHISHING": 2, "S6_ENDPOINT_COMPROMISE": 10, "S7_CREDENTIAL_HARVESTING": 14, "S7_VALID_ACCOUNT": 8,
    "S8_FINANCE_DATA_STAGING": 15, "S8_WEB_SHELL": 20, "S9_USB_TRANSFER": 10, "WEB01_FOOTHOLD": 8,
}
# README SCENARIO indicators (hostnames and victim username deliberately excluded; see docstring).
README_INDICATORS = ("198.51.100.90", "10.10.20.17", "CRED-WS07-001", "export.zip", "USB-0042")
ATTACKER = "198.51.100.90"

Pred = Callable[[str, str], bool]   # (source_type, raw_message) -> bool
# (stage, [(first_id, last_id)], content predicate every event in the ranges must satisfy)
SEGMENTS: list[tuple[str, list[tuple[int, int]], Pred]] = [
    ("S1_RECON", [(1, 14)],
     lambda t, m: ATTACKER in m and t in ("firewall", "apache_access", "web_application")),
    ("S2_BRUTE_FORCE", [(15, 41)],
     lambda t, m: "EventID=4625" in m and f"IpAddress={ATTACKER}" in m),
    # Judgment call: 42 is the success that terminates the failure run and carries the same
    # authentication=<RESULT> tag as the S2 failures; 43 matches the untagged S7 logons below.
    ("S3_PASSWORD_SPRAY", [(42, 42)],
     lambda t, m: "EventID=4624" in m and f"IpAddress={ATTACKER}" in m and "authentication=SUCCESS" in m),
    ("S7_VALID_ACCOUNT", [(43, 43), (98, 104)],
     lambda t, m: "EventID=4624" in m and "AccountName=neha" in m and "authentication=" not in m),
    ("S8_WEB_SHELL", [(44, 63)],
     lambda t, m: "cmd.jsp" in m or ("java.exe" in m and "cmd.exe" in m)),
    ("WEB01_FOOTHOLD", [(64, 71)],
     lambda t, m: t == "firewall" and f"dst={ATTACKER}" in m and "src=10.10.10.10" in m),
    ("S5_PHISHING", [(72, 73)],
     lambda t, m: "invoice.pdf.exe" in m and ATTACKER in m),
    ("S6_ENDPOINT_COMPROMISE", [(74, 83)],
     lambda t, m: t == "sysmon_process" and "host=WS07" in m and ("invoice.pdf.exe" in m or "powershell.exe" in m)),
    ("S7_CREDENTIAL_HARVESTING", [(84, 97)],
     lambda t, m: "browserdump.exe" in m or "CRED-WS07-001" in m),
    ("S8_FINANCE_DATA_STAGING", [(105, 119)],
     lambda t, m: "C:\\Finance\\" in m and ("file_action=READ" in m or "file_action=ARCHIVE" in m)),
    ("S9_USB_TRANSFER", [(120, 129)],
     lambda t, m: t == "usb" and "USB-0042" in m),
    ("S10_ARCHIVE_DELETION", [(130, 137)],
     lambda t, m: "file_action=DELETE" in m and "export.zip" in m),
]


def num(event_id: str) -> int:
    return int(event_id.split("-")[1])


def main() -> int:
    raw_path = dataset_path("raw")
    siem_path = dataset_path("siem")
    raw = {r["event_id"]: r for _, r in iter_records(raw_path)}
    siem_ids = [r.get("connector_event_id") for _, r in iter_records(siem_path)]
    checks: dict[str, Any] = {}

    # --- structural checks for the attack block ------------------------------------------
    ordered = sorted(raw.values(), key=lambda r: num(r["event_id"]))
    block = [r for r in ordered if num(r["event_id"]) <= ATTACK_BLOCK]
    rest = [r for r in ordered if num(r["event_id"]) > ATTACK_BLOCK]
    checks["ids_contiguous_1_to_50000"] = [num(i) for i in sorted(raw, key=num)] == list(range(1, 50_001))
    checks["attack_block_time_ordered"] = all(block[i]["timestamp"] <= block[i + 1]["timestamp"]
                                              for i in range(len(block) - 1))
    inversions = sum(rest[i]["timestamp"] > rest[i + 1]["timestamp"] for i in range(len(rest) - 1))
    checks["background_adjacent_time_inversion_rate"] = round(inversions / (len(rest) - 1), 4)
    checks["attack_block_size_equals_readme_count"] = len(block) == ATTACK_BLOCK
    exclusivity = {ind: {"in_attack_block": sum(ind in r["raw_message"] for r in block),
                         "in_background": sum(ind in r["raw_message"] for r in rest)} for ind in README_INDICATORS}
    checks["readme_indicators"] = exclusivity
    checks["siem_ids_equal_raw_ids"] = sorted(siem_ids) == sorted(raw)
    required = [checks["ids_contiguous_1_to_50000"], checks["attack_block_time_ordered"],
                checks["background_adjacent_time_inversion_rate"] > 0.3,
                checks["attack_block_size_equals_readme_count"], checks["siem_ids_equal_raw_ids"],
                all(v["in_background"] == 0 and v["in_attack_block"] > 0 for v in exclusivity.values())]
    if not all(required):
        print("STRUCTURAL CHECK FAILED; no ground truth written.", json.dumps(checks, indent=1))
        return 1

    # --- stage segments ----------------------------------------------------------------------
    stage_of: dict[int, str] = {}
    violations: list[str] = []
    for stage, ranges, predicate in SEGMENTS:
        for lo, hi in ranges:
            for n in range(lo, hi + 1):
                if n in stage_of:
                    violations.append(f"EVT-{n:06d} assigned twice")
                stage_of[n] = stage
                r = raw[f"EVT-{n:06d}"]
                if not predicate(r["source_type"], r["raw_message"]):
                    violations.append(f"EVT-{n:06d} fails {stage} predicate")
    counts = Counter(stage_of.values())
    checks["segments_cover_block_exactly"] = sorted(stage_of) == list(range(1, ATTACK_BLOCK + 1))
    checks["stage_counts_equal_readme"] = dict(counts) == README_STAGE_COUNTS
    checks["segment_predicate_violations"] = violations
    if violations or not checks["segments_cover_block_exactly"] or not checks["stage_counts_equal_readme"]:
        print("STAGE CHECK FAILED; no ground truth written.", json.dumps(checks, indent=1))
        return 1

    # --- write -------------------------------------------------------------------------------
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    labels = []
    for r in ordered:
        n = num(r["event_id"])
        attack = n <= ATTACK_BLOCK
        labels.append({
            "event_id": r["event_id"],
            "attack_related": attack,
            "attack_stage": stage_of.get(n) if attack else None,
            "critical": attack and any(ind in r["raw_message"] for ind in README_INDICATORS),
        })
    out = OUT_DIR / "ground_truth_50000.jsonl"
    out.write_text("".join(json.dumps(label) + "\n" for label in labels), encoding="utf-8")

    ids = [label["event_id"] for label in labels]
    known = set(README_STAGE_COUNTS)
    report = {
        "total_events": len(raw),
        "labelled_events": len(labels),
        "attack_related_count": sum(label["attack_related"] for label in labels),
        "benign_count": sum(not label["attack_related"] for label in labels),
        "critical_attack_count": sum(label["critical"] for label in labels),
        "counts_by_attack_stage": dict(sorted(Counter(l["attack_stage"] for l in labels if l["attack_stage"]).items())),
        "critical_by_attack_stage": dict(sorted(Counter(l["attack_stage"] for l in labels if l["critical"]).items())),
        "duplicate_event_ids": len(ids) - len(set(ids)),
        "missing_event_ids": len(set(raw) - set(ids)),
        "unknown_stage_count": sum(1 for l in labels if l["attack_related"] and l["attack_stage"] not in known),
        "source_files": {
            "raw": raw_path.name, "siem": siem_path.name, "readme": README.name,
            "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (raw_path, siem_path, README)},
        },
        "authoritative": False,
        "label_status": "RECONSTRUCTED (generator not available)",
        "methodology": {
            "attack_related": "Generator ID-allocation artifact: EVT-000001..EVT-000137, validated by the structural checks below.",
            "attack_stage": "README taxonomy; contiguous segments whose sizes equal README per-stage counts exactly, each validated by a content predicate.",
            "critical": ("Attack event containing a README-named scenario indicator that never occurs in background "
                         f"events: {list(README_INDICATORS)}. Hostnames and victim username excluded (present in benign traffic)."),
            "independence": "No correlation-engine output or engine heuristic was used. Dataset files read-only.",
        },
        "validation_checks": checks,
        "confidence": {
            "attack_related": "HIGH: four independent structural checks agree with the README count.",
            "attack_stage": "HIGH for 135/137 events: segment sizes match README counts exactly, and content is consistent. "
                            "MEDIUM for EVT-000042 vs EVT-000043: which of the two is S3_PASSWORD_SPRAY and which is S7_VALID_ACCOUNT "
                            "is inferred from message formatting (the authentication=SUCCESS tag).",
            "critical": "MEDIUM: the definition is ours, derived from README metadata; the generator's own notion of criticality is unknown.",
        },
        "limitations": [
            "Labels are reconstructed, not the generator's hidden ground truth. Replace them when that artifact is delivered.",
            "The README counts 137 'attack/suspicious' events; a background event that the generator considered suspicious would be missed only if it had an ID above 137, which the checks do not rule out.",
            "Stage names follow the README's attack-stage distribution. The story's 'S7 Valid Account Pivot' has no separate code, so those events are S7_VALID_ACCOUNT.",
            "'critical' is a documented proxy. Critical-evidence recall inherits that definition.",
        ],
    }
    (OUT_DIR / "ground_truth_validation.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("total_events", "labelled_events", "attack_related_count", "benign_count",
                                              "critical_attack_count", "counts_by_attack_stage", "critical_by_attack_stage",
                                              "duplicate_event_ids", "missing_event_ids", "unknown_stage_count")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
