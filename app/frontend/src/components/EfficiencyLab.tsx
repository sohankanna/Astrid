import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, BENCHMARK_SCALES, api } from "../api";
import type { BenchmarkResult, BenchmarkStatus, CostComparison, Fidelity, LiveUsage, IncidentDetail } from "../types";
import { Disclosure, Tabs, TabPanel } from "./Disclosure";
import { AiContext } from "./AiContext";
import { ScalingChart } from "./ScalingChart";
import { CanonicalPanel } from "./CanonicalPanel";
import { CanonicalFidelity } from "./CanonicalFidelity";

// AI Efficiency & Economics Lab. Every number shown comes from the backend
// benchmark (measured on synthetic telemetry) or from the user's own pricing
// inputs. Nothing on this page calls a model.

const INVESTIGATION_STEPS = [1, 100, 1_000, 10_000];

function n(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : value.toLocaleString("en-US");
}

function scaleLabel(scale: number): string {
  if (scale >= 1_000_000) return `${scale / 1_000_000}M`;
  if (scale >= 1_000) return `${scale / 1_000}K`;
  return String(scale);
}

function money(value: number): string {
  if (value === 0) return "$0";
  // Negative values occur at small scales (evidence pack larger than the raw log):
  // format the magnitude, then prefix the sign, e.g. "−$426".
  if (value < 0) return `−${money(-value)}`;
  if (value < 0.01) return `$${value.toFixed(4)}`;
  if (value < 100) return `$${value.toFixed(2)}`;
  return `$${Math.round(value).toLocaleString("en-US")}`;
}

function pct(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${value.toFixed(value % 1 === 0 ? 0 : 2)}%`;
}

function errorText(error: unknown): string {
  return error instanceof ApiError ? error.message : "Unexpected error.";
}

const LAB_TABS = ["Summary", "Context", "Cost", "Fidelity", "Scaling"] as const;

export function EfficiencyLab({ incidentDetail }: { incidentDetail: IncidentDetail | null }) {
  const [tab, setTab] = useState<(typeof LAB_TABS)[number]>("Summary");
  const [status, setStatus] = useState<BenchmarkStatus | null>(null);
  const [fidelity, setFidelity] = useState<Fidelity | null>(null);
  const [live, setLive] = useState<LiveUsage | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [model, setModel] = useState("example-model");
  const [inputPrice, setInputPrice] = useState("5.00");
  const [outputPrice, setOutputPrice] = useState("25.00");
  const [contextWindow, setContextWindow] = useState("200000");
  const [investigations, setInvestigations] = useState(1_000);
  const [cost, setCost] = useState<CostComparison | null>(null);
  const [costError, setCostError] = useState<string | null>(null);
  const autoFollow = useRef(false);

  const results = status?.results ?? [];
  const byScale = new Map(results.map((r) => [r.scale, r]));
  const current: BenchmarkResult | undefined = selected !== null ? byScale.get(selected) : undefined;

  const loadStatus = useCallback(async () => {
    try {
      const next = await api.efficiencyStatus();
      setStatus(next);
      setError(null);
      return next;
    } catch (e) {
      setError(errorText(e));
      return null;
    }
  }, []);

  useEffect(() => {
    void (async () => {
      const next = await loadStatus();
      if (next?.results.length) setSelected(next.results[next.results.length - 1].scale);
      try {
        setFidelity(await api.fidelity());
        setLive(await api.live());
      } catch (e) {
        setError(errorText(e));
      }
    })();
  }, [loadStatus]);

  // Poll while the backend benchmark thread is working.
  useEffect(() => {
    if (!status?.busy) return;
    const timer = window.setTimeout(async () => {
      const next = await loadStatus();
      if (next && autoFollow.current && next.results.length) {
        setSelected(next.results[next.results.length - 1].scale);
      }
      if (next && !next.busy) autoFollow.current = false;
    }, 1200);
    return () => window.clearTimeout(timer);
  }, [status, loadStatus]);

  // Cost comparison for the selected, measured scale (debounced).
  useEffect(() => {
    if (!current) {
      setCost(null);
      return;
    }
    const input = Number(inputPrice);
    const output = Number(outputPrice);
    const window_ = contextWindow.trim() ? Number(contextWindow) : null;
    if (!Number.isFinite(input) || !Number.isFinite(output) || input < 0 || output < 0) {
      setCostError("Prices must be non-negative numbers.");
      return;
    }
    if (window_ !== null && (!Number.isInteger(window_) || window_ < 1000)) {
      setCostError("Context window must be a whole number ≥ 1,000 (or empty).");
      return;
    }
    const timer = window.setTimeout(async () => {
      try {
        setCost(
          await api.cost({
            scale: current.scale,
            model: model.trim() || "example-model",
            input_per_mtok: input,
            output_per_mtok: output,
            investigations,
            context_window: window_,
          }),
        );
        setCostError(null);
      } catch (e) {
        setCostError(errorText(e));
      }
    }, 250);
    return () => window.clearTimeout(timer);
  }, [current, model, inputPrice, outputPrice, contextWindow, investigations]);

  const runAll = async () => {
    const missing = BENCHMARK_SCALES.filter((s) => !byScale.has(s));
    const scales = missing.length ? [...missing] : [...BENCHMARK_SCALES];
    autoFollow.current = true;
    try {
      setStatus(await api.runBenchmark(scales, !missing.length));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const runOne = async (scale: number) => {
    setSelected(scale);
    if (byScale.has(scale)) return;
    try {
      setStatus(await api.runBenchmark([scale]));
    } catch (e) {
      setError(errorText(e));
    }
  };

  const stateOf = (scale: number) => status?.scales.find((s) => s.scale === scale);
  const selectedState = selected !== null ? stateOf(selected) : undefined;

  return (
    <div className="lab">
      <header className="lab-hero">
        <div>
          <div className="lab-kicker">TELEMETRY BENCHMARK</div>
          <h1>AI Efficiency &amp; Economics Lab</h1>
          <p className="lab-summary">Benchmark how telemetry reduction affects model context, cost and evidence fidelity.</p>
          <p className="muted">
            AI reasoning cost is driven by the context sent to the model. The deterministic evidence layer keeps raw
            telemetry volume from turning into AI context volume. Measured on{" "}
            <strong>{status?.telemetry ?? "Synthetic benchmark telemetry"}</strong> (seed {status?.seed ?? "—"}); the
            raw-context path is an estimate that is never sent to any model.
          </p>
        </div>
        <button className="btn primary run" onClick={() => void runAll()} disabled={!!status?.busy}>
          {status?.busy ? "Benchmark running…" : results.length === BENCHMARK_SCALES.length ? "Re-run benchmark" : "Run benchmark"}
        </button>
      </header>
      {error && <div className="banner error">{error}</div>}

      {/* 1. Scale selector */}
      <section className="lab-card">
        <h2>Raw event scale</h2>
        <div className="scales">
          {BENCHMARK_SCALES.map((scale) => {
            const st = stateOf(scale);
            return (
              <button key={scale} className={`scale ${selected === scale ? "active" : ""} ${st?.state ?? "not_run"}`}
                onClick={() => void runOne(scale)} title={st?.reason ?? undefined}>
                <strong>{scaleLabel(scale)}</strong>
                <span>{(st?.state ?? "not_run").replace("_", " ")}</span>
              </button>
            );
          })}
        </div>
        {selectedState?.state === "unavailable" && (
          <p className="warn-text">UNAVAILABLE on this machine: {selectedState.reason}</p>
        )}
        {selectedState && ["running", "queued"].includes(selectedState.state) && (
          <p className="muted">Measuring {scaleLabel(selectedState.scale)} events in the background…</p>
        )}
        {selectedState?.state === "not_run" && <p className="muted">Not measured yet. Click to run this scale.</p>}
      </section>


      <Tabs id="lab" tabs={LAB_TABS} value={tab} onChange={setTab} />
      <TabPanel id="lab" index={0} active={tab === "Summary"}>
        <CanonicalPanel />
        {current ? <section className="lab-card">
          <h2>Measured results · {n(current.raw_event_count)} events</h2>
          <div className="summary-kpis">
            <Kpi label="RAW EVENTS" value={n(current.raw_event_count)} note="synthetic telemetry" />
            <Kpi label="RELEVANT EVENTS" value={n(current.relevant_event_count)} note="detected and correlated" />
            <Kpi label="EVIDENCE OBJECTS" value={n(current.evidence_object_count)} note="cited by ID" />
            <Kpi label="CONTEXT TOKENS" value={n(current.estimated_context_tokens)} note="estimated model context" />
            <Kpi label="CONTEXT REDUCTION" value={pct(current.context_reduction_percent)} note="versus raw-context estimate"
              tone={(current.context_reduction_percent ?? 0) < 0 ? "warn" : "good"} />
            <Kpi label="EVIDENCE RETENTION" value={pct(current.evidence_retention_percent)} note={current.preserved_facts + " / " + current.critical_facts + " critical facts · not AI accuracy"} tone="good" />
          </div>
          {(current.context_reduction_percent ?? 0) < 0 && <p className="warn-text">At this scale, the evidence pack is larger than the raw log because it carries fixed structure. Shown as measured.</p>}
          <div className="disclosure-actions">
            <button className="btn primary" onClick={() => setTab("Context")}>Explore context →</button>
            <button className="btn" onClick={() => setTab("Cost")}>Compare costs</button>
            <button className="btn" onClick={() => setTab("Fidelity")}>Inspect evidence retention</button>
          </div>
        </section> : <p className="empty">Select a measured scale, or run the benchmark.</p>}
      </TabPanel>
      <TabPanel id="lab" index={1} active={tab === "Context"}>
              {/* 2. Compression pipeline */}
      <section className="lab-card">
        <h2>Compression pipeline {current && <em>· {n(current.raw_event_count)} events</em>}</h2>
        {current ? (
          <>
            <div className="funnel">
              <Stage label="RAW EVENTS" value={n(current.raw_event_count)} note="synthetic telemetry" width={100} />
              <Arrow text="detect + correlate" />
              <Stage label="RELEVANT EVENTS" value={n(current.relevant_event_count)}
                note={`${n(current.incidents_detected)} incidents · ${n(current.excluded_event_count)} excluded`}
                width={Math.max(18, 100 * Math.sqrt(current.relevant_event_count / current.raw_event_count))} />
              <Arrow text="aggregate · rank · budget" />
              <Stage label="EVIDENCE OBJECTS" value={n(current.evidence_object_count)} note="cited by ID" width={14} />
              <Arrow text="redact · pseudonymize" />
              <Stage label="MODEL CONTEXT · TOKENS" value={n(current.estimated_context_tokens)}
                note={`${n(current.pseudonym_count)} pseudonyms · ${n(current.redaction_count)} secrets redacted`} width={10} accent />
            </div>
            <div className="kpis">
              <Kpi label="CONTEXT REDUCTION" value={pct(current.context_reduction_percent)}
                note="1 − evidence tokens / raw-context estimate"
                tone={(current.context_reduction_percent ?? 0) < 0 ? "warn" : "good"} />
              <Kpi label="RAW-CONTEXT ESTIMATE" value={n(current.estimated_raw_context_tokens)} note="THEORETICAL — NOT SENT TO MODEL" tone="raw" />
              <Kpi label="EVIDENCE RETENTION" value={pct(current.evidence_retention_percent)}
                note={`${current.preserved_facts} / ${current.critical_facts} critical facts`} tone="good" />
              <Kpi label="CONTEXT BUILD" value={`${n(Math.round(current.context_build_time_ms))} ms`} note="all incidents" />
              <Kpi label="THROUGHPUT" value={`${n(current.events_per_second)} ev/s`} note={current.events_per_second_definition} />
            </div>
            {(current.context_reduction_percent ?? 0) < 0 && (
              <p className="warn-text small">
                At this scale the evidence pack is larger than the raw log: the pack carries fixed structure (entities,
                timeline, MITRE, policy). The architecture pays off as volume grows. Shown as measured.
              </p>
            )}
          </>
        ) : (
          <p className="muted">Select a measured scale, or press RUN BENCHMARK.</p>
        )}
      </section>

        <section className="lab-card context-access">
          <h2>Exact incident context</h2>
          <p className="muted">The existing viewer shows the selected SOC incident. Benchmark-scale context packs are not exposed by the current API.</p>
          {incidentDetail ? <Disclosure label="View exact context" title={"SOC context · " + incidentDetail.incident.incident_id}>
            <p className="muted">Current SOC incident: {incidentDetail.incident.title}. These are incident values, not the selected benchmark scale.</p>
            <AiContext key={incidentDetail.incident.incident_id} detail={incidentDetail} />
          </Disclosure> : <p className="muted">Select an incident in the SOC Console to inspect its context.</p>}
        </section>
      </TabPanel>
      <TabPanel id="lab" index={2} active={tab === "Cost"}><div className="lab-grid">{/* 3. Economic comparison */}
        <section className="lab-card">
          <h2>Cost per investigation</h2>
          <div className="pricing">
            <div><label htmlFor="pricing-model">Model label</label><input id="pricing-model" value={model} maxLength={64} onChange={(e) => setModel(e.target.value)} /></div>
            <div><label htmlFor="pricing-input">Input $ / 1M tok</label><input id="pricing-input" value={inputPrice} inputMode="decimal" onChange={(e) => setInputPrice(e.target.value)} /></div>
            <div><label htmlFor="pricing-output">Output $ / 1M tok</label><input id="pricing-output" value={outputPrice} inputMode="decimal" onChange={(e) => setOutputPrice(e.target.value)} /></div>
            <div><label htmlFor="pricing-window">Context window</label><input id="pricing-window" value={contextWindow} inputMode="numeric" onChange={(e) => setContextWindow(e.target.value)} /></div>
          </div>
          <p className="rates-note">EXAMPLE RATES — editable, not a vendor quote. Formula: tokens ÷ 1,000,000 × price.</p>
          {costError && <p className="warn-text">{costError}</p>}
          {cost ? (
            <div className="paths">
              <PathCard tone="raw" title="Path A · Naive raw-context baseline" badge="THEORETICAL — NOT SENT TO MODEL" path={cost.baseline}
                per1k={cost.per_1000_investigations.baseline} per10k={cost.per_10000_investigations.baseline} />
              <PathCard tone="evidence" title="Path B · Evidence-context architecture" badge="WHAT THE AI PROVIDER RECEIVES" path={cost.evidence}
                per1k={cost.per_1000_investigations.evidence} per10k={cost.per_10000_investigations.evidence} />
              <div className="reduction">
                <div><strong>{pct(cost.token_reduction_percent)}</strong><span>token reduction</span></div>
                <div><strong>{pct(cost.cost_reduction_percent)}</strong><span>cost reduction</span></div>
                <span className="muted small">Output assumed equal on both paths ({n(cost.output_tokens_assumed)} tokens).</span>
              </div>
            </div>
          ) : (
            !costError && <p className="muted">Needs a measured scale.</p>
          )}
        </section>

        {/* 6. Cost calculator */}
        <section className="lab-card">
          <h2>At volume</h2>
          <div className="segmented">
            {INVESTIGATION_STEPS.map((k) => (
              <button key={k} className={investigations === k ? "active" : ""} onClick={() => setInvestigations(k)}>
                {n(k)} investigation{k === 1 ? "" : "s"}
              </button>
            ))}
          </div>
          {cost ? (
            <div className="volume">
              <div className="row raw"><span>Path A · raw baseline (theoretical)</span><strong>{money(cost.baseline.total_for_investigations)}</strong></div>
              <div className="row evidence"><span>Path B · evidence context</span><strong>{money(cost.evidence.total_for_investigations)}</strong></div>
              <div className="row savings"><span>Difference</span><strong>{money(cost.savings_for_investigations)}</strong></div>
              {cost.baseline.exceeds_context_window && (
                <p className="warn-text small">
                  Path A does not fit a {n(Number(contextWindow))}-token context window: it would need {n(cost.baseline.context_windows_needed)} windows
                  per investigation. The cost shown is a lower bound on a design that could not run as a single request.
                </p>
              )}
              <p className="muted small">
                {cost.pricing.model} · ${cost.pricing.input_per_mtok}/1M in · ${cost.pricing.output_per_mtok}/1M out · {cost.pricing.label}
              </p>
            </div>
          ) : (
            <p className="muted">Needs a measured scale.</p>
          )}

          <h3>Live model usage</h3>
          {live?.available ? (
            <table className="budget">
              <thead><tr><th>Incident</th><th>Model</th><th>Input (measured)</th><th>Input (estimated)</th><th>Output</th><th>Latency</th></tr></thead>
              <tbody>
                {live.runs.map((r) => (
                  <tr key={r.incident_id}>
                    <td>{r.incident_id.toUpperCase()}</td><td>{r.served_by ?? r.model}</td><td>{n(r.input_tokens)}</td>
                    <td>{n(r.estimated_input_tokens)}</td><td>{n(r.output_tokens)}</td><td>{n(r.latency_ms)} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="offline-note">{live?.message ?? "Live model usage unavailable — benchmark running offline."}</p>
          )}
        </section></div></TabPanel>
      <TabPanel id="lab" index={3} active={tab === "Fidelity"}>{/* 4. Fidelity */}
        <CanonicalFidelity />
        <section className="lab-card">
          <h2>Evidence retention <em>· not "AI accuracy"</em></h2>
          {fidelity ? (
            <>
              <div className="kpis two retention">
                <Kpi label="CRITICAL FACTS PRESERVED" value={`${fidelity.retention.preserved_facts} / ${fidelity.retention.critical_facts}`}
                  note={pct(fidelity.retention.evidence_retention_percent)} tone="good" />
                <Kpi label="CITATION COVERAGE" value={pct(fidelity.retention.citation_coverage_percent)}
                  note="supporting events that map to an evidence ID" tone="good" />
              </div>
              <Disclosure label="View critical facts"><ul className="facts">
                {fidelity.retention.facts.map((f) => (
                  <li key={f.fact_id} className={f.preserved ? "ok" : "lost"}>
                    <span className="mark">{f.preserved ? "✓" : "✗"}</span>
                    <span className="fact">{f.fact}{f.via_context && <em className="ctx"> context-only</em>}</span>
                    <code title={f.supporting_event_ids.join(", ")}>{f.evidence_ids.map((e) => e.split(":")[1]).join(" ") || "—"}</code>
                  </li>
                ))}
              </ul></Disclosure>
              <Disclosure label="View budget experiment"><h3>Budget experiment · canonical incidents</h3>
              <table className="budget">
                <thead>
                  <tr><th>Budget</th><th>Target tok</th><th>Actual tok</th><th>Objects</th><th>Facts</th><th>Citations</th><th>Lost</th></tr>
                </thead>
                <tbody>
                  {fidelity.budget.rows.map((r) => (
                    <tr key={r.budget_percent} className={r.missing_facts.length ? "lossy" : ""}>
                      <td>{r.budget_percent}%</td>
                      <td>{n(r.target_tokens)}</td>
                      <td>{n(r.actual_tokens)}{r.hit_floor && <span className="floor"> floor</span>}</td>
                      <td>{r.evidence_objects}</td>
                      <td>{r.preserved_facts} / {r.critical_facts}</td>
                      <td>{pct(r.citation_coverage_percent)}</td>
                      <td>{r.missing_facts.join(" ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="muted small">
                {fidelity.budget.note} Trimming removes contextual evidence first, so the facts no rule fires on (successful
                logon, persistence, lateral movement) are the first to go. That is why the default budget is not squeezed below the full context.
              </p>
            </Disclosure></>
          ) : (
            <p className="muted">Loading…</p>
          )}
        </section></TabPanel>
      <TabPanel id="lab" index={4} active={tab === "Scaling"}>{/* 5. Scaling graph */}
        <section className="lab-card">
          <h2>Scaling · measured points only</h2>
          <ScalingChart results={results} selected={current ? current.raw_event_count : null} />
          <div className="legend">
            <span className="raw">— — Naive raw-context baseline (estimated, not sent to the model)</span>
            <span className="evidence">——— Evidence-context architecture</span>
          </div>
        </section>

        </TabPanel>
    </div>
  );
}

function Stage({ label, value, note, width, accent }: { label: string; value: string; note: string; width: number; accent?: boolean }) {
  return (
    <div className={`stage ${accent ? "accent" : ""}`}>
      <div className="bar" style={{ width: `${width}%` }} />
      <span className="stage-label">{label}</span>
      <strong>{value}</strong>
      <span className="stage-note">{note}</span>
    </div>
  );
}

function Arrow({ text }: { text: string }) {
  return <div className="arrow"><span aria-hidden="true">→</span><em>{text}</em></div>;
}

function Kpi({ label, value, note, tone }: { label: string; value: string; note: string; tone?: "good" | "warn" | "raw" }) {
  return (
    <div className={`kpi ${tone ?? ""}`}>
      <span className="kpi-label">{label}</span>
      <strong>{value}</strong>
      <span className="kpi-note">{note}</span>
    </div>
  );
}

function PathCard({ tone, title, badge, path, per1k, per10k }: {
  tone: "raw" | "evidence"; title: string; badge: string;
  path: CostComparison["baseline"]; per1k: number; per10k: number;
}) {
  return (
    <div className={`path ${tone}`}>
      <div className="path-title">{title}</div>
      <div className="path-badge">{badge}</div>
      <dl className="path-total"><dt>Per investigation</dt><dd className="big">{money(path.total_cost)}</dd></dl>
      <Disclosure label="View calculation" title={title}><dl>
        <dt>Input tokens</dt><dd>{n(path.input_tokens)}</dd>
        <dt>Input cost</dt><dd>{money(path.input_cost)}</dd>
        <dt>Output cost</dt><dd>{money(path.output_cost)}</dd>
        <dt>Per investigation</dt><dd className="big">{money(path.total_cost)}</dd>
        <dt>Per 1,000</dt><dd>{money(per1k)}</dd>
        <dt>Per 10,000</dt><dd>{money(per10k)}</dd>
      </dl></Disclosure>
    </div>
  );
}
