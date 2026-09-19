"""A pinned, offline subset of MITRE ATT&CK (Enterprise).

Why a local subset rather than the live STIX bundle: the core simulation must
run with no network access, and a *closed* technique vocabulary is what lets us
mechanically reject hallucinated technique IDs coming back from an LLM. A
technique ID that is not in this table is a defect, not a discovery.

This is a deliberately small slice covering the behaviors our synthetic data
exercises. Extend it when a detection needs a technique it does not contain --
and add the technique here first, so validation stays meaningful.

Source: MITRE ATT&CK Enterprise. Names/tactics transcribed manually; there is
no runtime dependency on `mitreattack-python` or any TAXII server.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

ATTACK_VERSION: Final[str] = "enterprise-v15 (pinned subset)"


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique or sub-technique."""

    technique_id: str
    name: str
    tactic: str

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.technique_id

    @property
    def parent_id(self) -> str:
        """The parent technique ID, or the ID itself if not a sub-technique."""
        return self.technique_id.split(".", 1)[0]


# Tactic ordering follows the ATT&CK kill-chain sequence. Used to estimate
# which stage an incident has reached -- see attack_stage().
TACTIC_ORDER: Final[tuple[str, ...]] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

_TECHNIQUE_LIST: Final[tuple[Technique, ...]] = (
    Technique("T1078", "Valid Accounts", "Initial Access"),
    Technique("T1110", "Brute Force", "Credential Access"),
    Technique("T1110.003", "Password Spraying", "Credential Access"),
    Technique("T1621", "Multi-Factor Authentication Request Generation", "Credential Access"),
    Technique("T1059", "Command and Scripting Interpreter", "Execution"),
    Technique("T1059.001", "PowerShell", "Execution"),
    Technique("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    Technique("T1027.010", "Command Obfuscation", "Defense Evasion"),
    Technique("T1218", "System Binary Proxy Execution", "Defense Evasion"),
    Technique("T1218.011", "Rundll32", "Defense Evasion"),
    Technique("T1204", "User Execution", "Execution"),
    Technique("T1204.002", "Malicious File", "Execution"),
    Technique("T1003", "OS Credential Dumping", "Credential Access"),
    Technique("T1003.001", "LSASS Memory", "Credential Access"),
    Technique("T1071", "Application Layer Protocol", "Command and Control"),
    Technique("T1071.001", "Web Protocols", "Command and Control"),
    Technique("T1568", "Dynamic Resolution", "Command and Control"),
    Technique("T1568.002", "Domain Generation Algorithms", "Command and Control"),
    Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    Technique("T1530", "Data from Cloud Storage", "Collection"),
    Technique("T1547", "Boot or Logon Autostart Execution", "Persistence"),
    Technique("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
    Technique("T1021", "Remote Services", "Lateral Movement"),
    Technique("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    Technique("T1087", "Account Discovery", "Discovery"),
    Technique("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
    # --- Cloud (IaaS / AWS control plane). Only techniques a cloud rule in
    # cloud_detections.py actually maps to. ATT&CK lists several tactics for
    # some of these (e.g. T1078.004 is also Persistence / Privilege
    # Escalation / Defense Evasion); this catalog pins the single tactic that
    # matches how our rules use it.
    Technique("T1078.004", "Cloud Accounts", "Initial Access"),
    Technique("T1098", "Account Manipulation", "Persistence"),
    Technique("T1098.001", "Additional Cloud Credentials", "Persistence"),
    Technique("T1098.003", "Additional Cloud Roles", "Persistence"),
    Technique("T1562", "Impair Defenses", "Defense Evasion"),
    Technique("T1562.007", "Disable or Modify Cloud Firewall", "Defense Evasion"),
    Technique("T1562.008", "Disable or Modify Cloud Logs", "Defense Evasion"),
    Technique("T1580", "Cloud Infrastructure Discovery", "Discovery"),
)

TECHNIQUES: Final[dict[str, Technique]] = {
    technique.technique_id: technique for technique in _TECHNIQUE_LIST
}


class UnknownTechniqueError(ValueError):
    """Raised when a technique ID is not in the pinned catalog."""


def is_known_technique(technique_id: str) -> bool:
    """True when `technique_id` exists in the pinned catalog."""
    return technique_id in TECHNIQUES


def get_technique(technique_id: str) -> Technique:
    """Return the Technique, or raise UnknownTechniqueError.

    Used to validate AI output: an unknown ID is treated as a hallucination.
    """
    try:
        return TECHNIQUES[technique_id]
    except KeyError as exc:
        raise UnknownTechniqueError(
            f"technique {technique_id!r} is not in the pinned ATT&CK subset "
            f"({ATTACK_VERSION})"
        ) from exc


def validate_technique_ids(technique_ids: list[str]) -> tuple[list[str], list[str]]:
    """Split IDs into (known, unknown), preserving order and de-duplicating.

    Returns rather than raises, because the caller usually wants to keep the
    valid mappings and flag the invalid ones rather than discard everything.
    """
    known: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for technique_id in technique_ids:
        if technique_id in seen:
            continue
        seen.add(technique_id)
        (known if is_known_technique(technique_id) else unknown).append(technique_id)
    return known, unknown


def tactics_for(technique_ids: list[str]) -> list[str]:
    """Return the distinct tactics covered, in kill-chain order."""
    tactics = {
        TECHNIQUES[tid].tactic for tid in technique_ids if tid in TECHNIQUES
    }
    return [tactic for tactic in TACTIC_ORDER if tactic in tactics]


def attack_stage(technique_ids: list[str]) -> str | None:
    """Estimate the furthest kill-chain stage reached by these techniques.

    This is a deterministic maximum over the tactic ordering -- not an AI
    judgement. It answers "how far along is this?", which drives urgency.
    """
    covered = tactics_for(technique_ids)
    return covered[-1] if covered else None


def describe(technique_id: str) -> str:
    """Human-readable 'T1059.001 (PowerShell, Execution)' form for reports."""
    technique = get_technique(technique_id)
    return f"{technique.technique_id} ({technique.name}, {technique.tactic})"
