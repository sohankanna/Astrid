import { useEffect, useState } from "react";
import type { Metrics, ScenarioInfo } from "../types";

interface Props {
  scenarios: ScenarioInfo[];
  metrics: Metrics | null;
  running: boolean;
  onRun: (scenarioId: string) => void;
}

const GROUP_ORDER = [
  "Hybrid Attack",
  "Endpoint Attack",
  "Cloud Attack",
  "Prompt Injection Attempt",
  "Benign Activity",
];

export function ScenarioBar({ scenarios, metrics, running, onRun }: Props) {
  const active = metrics?.scenario.scenario_id ?? "";
  const [selected, setSelected] = useState(active);
  useEffect(() => {
    if (active) setSelected(active);
  }, [active]);

  const groups = GROUP_ORDER.map((group) => ({
    group,
    items: scenarios.filter((s) => s.group === group),
  })).filter((g) => g.items.length > 0);
  const current = scenarios.find((s) => s.scenario_id === selected);

  return (
    <section className="scenario-bar">
      <span className="section-tag">DEMO SCENARIOS</span>
      <select
        value={selected}
        onChange={(e) => setSelected(e.target.value)}
        disabled={running || scenarios.length === 0}
        aria-label="Select scenario"
      >
        {groups.map(({ group, items }) => (
          <optgroup key={group} label={group}>
            {items.map((s) => (
              <option key={s.scenario_id} value={s.scenario_id}>
                {s.name}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      <button
        className="btn primary"
        disabled={running || !selected}
        onClick={() => onRun(selected)}
      >
        {running ? "RUNNING…" : "▶ RUN SCENARIO"}
      </button>
      <div className="scenario-desc">
        {current ? (
          <>
            <span className="pill">{current.group}</span> {current.description}
          </>
        ) : (
          "No scenarios available."
        )}
      </div>
      {metrics && (
        <div className="scenario-active">
          ACTIVE: <strong>{metrics.scenario.name}</strong>
        </div>
      )}
    </section>
  );
}
