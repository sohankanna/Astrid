"""Labelled scenarios over the synthetic dataset.

The scenario map lives in code rather than in the dataset so the event records
stay pure log data -- a real log has no "scenario" field, and adding one would
teach the pipeline to rely on something that will not exist tomorrow.

Each scenario is a subset of event IDs from data/sample_security_events.json,
letting the demo and the tests exercise one behavior at a time:

    python -m app.soc_core.demo --scenario B

Scenario G (the full chain) is the union of the intrusion scenarios and is
what the default demo run shows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Sequence

from .events import SecurityEvent


@dataclass(frozen=True)
class Scenario:
    """A named subset of the synthetic dataset."""

    key: str
    name: str
    description: str
    event_ids: tuple[str, ...]
    expect_alerts: bool


_BENIGN: Final[tuple[str, ...]] = (
    "evt-0001",
    "evt-0014",
    "evt-0015",
    "evt-0018",
    "evt-0025",
    "evt-0026",
)
_SPRAY: Final[tuple[str, ...]] = (
    "evt-0002",
    "evt-0003",
    "evt-0004",
    "evt-0005",
    "evt-0006",
)
_MFA: Final[tuple[str, ...]] = ("evt-0019", "evt-0020", "evt-0007")
_EXECUTION: Final[tuple[str, ...]] = ("evt-0008", "evt-0009", "evt-0021")
_DNS_C2: Final[tuple[str, ...]] = (
    "evt-0010",
    "evt-0011",
    "evt-0012",
    "evt-0022",
)
_CREDENTIAL: Final[tuple[str, ...]] = ("evt-0013",)
_LATERAL: Final[tuple[str, ...]] = ("evt-0023",)
_CLOUD: Final[tuple[str, ...]] = ("evt-0017",)
_INJECTION: Final[tuple[str, ...]] = ("evt-0016", "evt-0024")


SCENARIOS: Final[dict[str, Scenario]] = {
    "A": Scenario(
        key="A",
        name="Benign workstation activity",
        description=(
            "Normal logons, a git fetch, a signed installer, routine DNS. "
            "Must produce no alerts -- the false-positive control case."
        ),
        event_ids=_BENIGN,
        expect_alerts=False,
    ),
    "B": Scenario(
        key="B",
        name="Password spray",
        description=(
            "Four distinct accounts fail from one external address in 14 "
            "seconds, then one succeeds without MFA."
        ),
        event_ids=_SPRAY,
        expect_alerts=True,
    ),
    "C": Scenario(
        key="C",
        name="PowerShell execution",
        description=(
            "Encoded, hidden-window PowerShell launched from an Office parent."
        ),
        event_ids=("evt-0008",),
        expect_alerts=True,
    ),
    "D": Scenario(
        key="D",
        name="Suspicious process chain",
        description=(
            "winword.exe -> powershell.exe -> rundll32.exe from Temp, plus a "
            "Run-key persistence write."
        ),
        event_ids=_EXECUTION,
        expect_alerts=True,
    ),
    "E": Scenario(
        key="E",
        name="DNS and C2 activity",
        description=(
            "High-entropy domain lookups followed by repeated outbound TLS "
            "connections with near-identical byte counts."
        ),
        event_ids=_DNS_C2,
        expect_alerts=True,
    ),
    "F": Scenario(
        key="F",
        name="Credential access",
        description="EDR blocks LSASS memory access by a suspicious process.",
        event_ids=_CREDENTIAL,
        expect_alerts=True,
    ),
    "G": Scenario(
        key="G",
        name="Complete multi-stage attack chain",
        description=(
            "Spray -> MFA fatigue -> successful auth -> encoded PowerShell -> "
            "rundll32 -> persistence -> DNS -> C2 -> LSASS -> lateral movement "
            "-> cloud data access."
        ),
        event_ids=(
            _SPRAY
            + _MFA
            + _EXECUTION
            + _DNS_C2
            + _CREDENTIAL
            + _LATERAL
            + _CLOUD
        ),
        expect_alerts=True,
    ),
    "H": Scenario(
        key="H",
        name="Prompt injection hidden in log content",
        description=(
            "Two adversarial records: a command line instructing the analyst "
            "model to close the incident, and a filename that smuggles the "
            "untrusted-data end delimiter. Both must be reported, never obeyed."
        ),
        event_ids=_INJECTION,
        expect_alerts=False,
    ),
}


class UnknownScenarioError(KeyError):
    """Raised when a scenario key does not exist."""


def get_scenario(key: str, registry: dict[str, Scenario] | None = None) -> Scenario:
    """Look up a scenario. `registry` defaults to the endpoint SCENARIOS;
    pass CLOUD_SCENARIOS (cloud_scenarios.py) for the cloud dataset."""
    scenarios = SCENARIOS if registry is None else registry
    try:
        return scenarios[key.upper()]
    except KeyError as exc:
        raise UnknownScenarioError(
            f"unknown scenario {key!r}; expected one of {sorted(scenarios)}"
        ) from exc


def events_for_scenario(
    events: Sequence[SecurityEvent],
    key: str,
    registry: dict[str, Scenario] | None = None,
) -> list[SecurityEvent]:
    """Filter events down to one scenario, preserving chronological order."""
    scenario = get_scenario(key, registry)
    wanted = set(scenario.event_ids)
    return sorted(
        (event for event in events if event.event_id in wanted),
        key=lambda event: event.timestamp,
    )
