import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api } from "./api";
import type { Health, IncidentDetail, IncidentSummary, InjectionFinding, Metrics, ScenarioInfo } from "./types";
import { TopBar } from "./components/TopBar";
import { MetricsBar } from "./components/MetricsBar";
import { ScenarioBar } from "./components/ScenarioBar";
import { IncidentList } from "./components/IncidentList";
import { Investigation } from "./components/Investigation";
import { EfficiencyLab } from "./components/EfficiencyLab";
import { incidentLabel } from "./format";

interface Toast {
  id: number;
  kind: "ok" | "error" | "info";
  text: string;
}

function message(error: unknown): string {
  return error instanceof ApiError ? error.message : "Unexpected console error.";
}

type View = "console" | "lab";

function viewFromHash(): View {
  return window.location.hash === "#lab" ? "lab" : "console";
}

export default function App() {
  const [view, setView] = useState<View>(viewFromHash);
  const [health, setHealth] = useState<Health | null>(null);
  const [backendDown, setBackendDown] = useState(false);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [screening, setScreening] = useState<InjectionFinding[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [showScreening, setShowScreening] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const detailRequest = useRef(0);
  const toastId = useRef(0);

  const toast = useCallback((kind: Toast["kind"], text: string) => {
    const id = ++toastId.current;
    setToasts((current) => [...current.slice(-1), { id, kind, text }]);
    window.setTimeout(() => setToasts((current) => current.filter((t) => t.id !== id)), 4500);
  }, []);

  const loadDetail = useCallback(async (id: string) => {
    const request = ++detailRequest.current;
    setDetailLoading(true);
    setDetailError(null);
    try {
      const result = await api.incident(id);
      if (request === detailRequest.current) setDetail(result);
    } catch (error) {
      if (request === detailRequest.current) {
        setDetail(null);
        setDetailError(message(error));
      }
    } finally {
      if (request === detailRequest.current) setDetailLoading(false);
    }
  }, []);

  /** Reload the scenario-wide views; keep the selection if it still exists. */
  const refresh = useCallback(
    async (preferred: string | null) => {
      const [m, list, findings] = await Promise.all([api.metrics(), api.incidents(), api.screening()]);
      setMetrics(m);
      setIncidents(list);
      setScreening(findings);
      const keep = preferred && list.some((i) => i.incident_id === preferred) ? preferred : list[0]?.incident_id ?? null;
      setSelectedId(keep);
      if (keep) {
        await loadDetail(keep);
      } else {
        setDetail(null);
        setDetailError(null);
      }
    },
    [loadDetail],
  );

  const boot = useCallback(async () => {
    try {
      const h = await api.health();
      setHealth(h);
      setBackendDown(false);
      setScenarios(await api.scenarios());
      await refresh(null);
    } catch (error) {
      setBackendDown(true);
      setHealth(null);
      if (!(error instanceof ApiError && error.status === 0)) toast("error", message(error));
    }
  }, [refresh, toast]);

  useEffect(() => {
    void boot();
  }, [boot]);

  useEffect(() => {
    const onHash = () => setView(viewFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const switchView = (next: View) => {
    window.location.hash = next === "lab" ? "lab" : "";
    setView(next);
  };

  // Health heartbeat: indicators go red if the backend disappears, and the
  // console reloads itself when it comes back.
  useEffect(() => {
    const timer = window.setInterval(async () => {
      try {
        const h = await api.health();
        setHealth(h);
        if (backendDown) await boot();
      } catch {
        setBackendDown(true);
        setHealth(null);
      }
      setNow(Date.now());
    }, 8000);
    return () => window.clearInterval(timer);
  }, [backendDown, boot]);

  const select = (id: string) => {
    setSelectedId(id);
    void loadDetail(id);
  };

  const runScenario = async (scenarioId: string) => {
    setBusy("scenario");
    try {
      const m = await api.runScenario(scenarioId);
      setScenarios(await api.scenarios());
      await refresh(null);
      toast(
        "ok",
        `Scenario loaded: ${m.scenario.name} · ${m.events_ingested} events · ${m.alerts} alerts · ${m.active_incidents} incidents`,
      );
    } catch (error) {
      toast("error", `Scenario failed: ${message(error)}`);
    } finally {
      setBusy(null);
    }
  };

  type Outcome = { kind: Toast["kind"]; text: string };

  const withIncident = async (label: string, key: string, run: (id: string) => Promise<Outcome>) => {
    if (!selectedId) return;
    setBusy(key);
    try {
      const outcome = await run(selectedId);
      await refresh(selectedId);
      toast(outcome.kind, outcome.text);
    } catch (error) {
      toast("error", `${label}: ${message(error)}`);
    } finally {
      setBusy(null);
    }
  };

  const analyze = () =>
    withIncident("AI investigation failed", "analyze", async (id) => {
      const result = await api.analyze(id);
      const who = result.provider.live_model ? `CLAUDE (${result.investigation.model})` : "MOCK / OFFLINE";
      const fallback = result.provider.fallback_reason ? ` · fell back: ${result.provider.fallback_reason}` : "";
      return {
        kind: result.provider.fallback_reason ? "info" : "ok",
        text: `AI investigation (${who}) complete for ${incidentLabel(id)} · confidence ${result.investigation.confidence}${fallback}`,
      };
    });

  const plan = () =>
    withIncident("Response plan failed", "plan", async (id) => {
      const result = await api.responsePlan(id);
      return { kind: "ok", text: `Response plan ready: ${result.actions.length} action(s), all simulated` };
    });

  const decide = (actionId: string, decision: "approve" | "reject") =>
    withIncident("Decision failed", actionId, async (id) => {
      const result = await api.decide(id, actionId, decision, decision === "reject" ? "Rejected in console" : undefined);
      const status = result.action.status;
      // A policy block is not a success: colour the toast by outcome.
      const kind: Toast["kind"] =
        status === "BLOCKED_BY_POLICY" ? "error" : status === "DRY_RUN_COMPLETE" ? "ok" : "info";
      const verb = decision === "approve" ? "approval requested" : "rejected";
      return { kind, text: `${actionId} ${verb} → ${status.replace(/_/g, " ")}` };
    });

  if (backendDown && !metrics) {
    return (
      <div className="app">
        <TopBar health={null} backendDown view={view} onView={switchView} />
        <div className="offline">
          <div className="offline-card">
            <strong>SOC API UNREACHABLE</strong>
            <p>The console cannot reach the local SOC backend (127.0.0.1, port SOC_API_PORT, default 8000).</p>
            <code>app/.venv/Scripts/python.exe -m app.api</code>
            <p className="muted">Start it from the repository root. This page reconnects automatically.</p>
            <button className="btn primary" onClick={() => void boot()}>
              RETRY NOW
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <TopBar health={health} backendDown={backendDown} view={view} onView={switchView} />
      {backendDown && (
        <div className="banner error">
          ⚠ Connection to the SOC API lost. Showing the last known state; reconnecting automatically.
        </div>
      )}
      {view === "lab" ? (
        <EfficiencyLab incidentDetail={detail} />
      ) : (
        <>
      <MetricsBar metrics={metrics} />
      <ScenarioBar scenarios={scenarios} metrics={metrics} running={busy === "scenario"} onRun={runScenario} />

      {screening.length > 0 && (
        <section className="screening">
          <button className="screening-head" onClick={() => setShowScreening((v) => !v)}>
            <strong>⚠ UNTRUSTED CONTENT SCREENING</strong>
            <span>
              {screening.length} field(s) in ingested telemetry try to instruct an AI analyst. Reported as evidence,
              never obeyed, never stripped.
            </span>
            <span className="caret">{showScreening ? "▾ hide" : "▸ show"}</span>
          </button>
          {showScreening && (
            <ul>
              {screening.map((f) => (
                <li key={`${f.event_id}-${f.field_path}`}>
                  <code>{f.event_id}</code>
                  <span className="muted">{f.field_path}</span>
                  {f.incident_id ? (
                    <button className="link" onClick={() => select(f.incident_id!)}>
                      {incidentLabel(f.incident_id)}
                    </button>
                  ) : (
                    <span className="muted">no incident (no rule fired on this event)</span>
                  )}
                  <code className="excerpt">{f.excerpt}</code>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <main className="workspace">
        <IncidentList incidents={incidents} selectedId={selectedId} onSelect={select} now={now} />
        <Investigation
          detail={detail}
          loading={detailLoading}
          error={detailError}
          busy={busy}
          onAnalyze={analyze}
          onPlan={plan}
          onDecide={decide}
          canonical={metrics?.scenario.scenario_id === "canonical-50k"}
        />
      </main>
        </>
      )}

      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            {t.text}
          </div>
        ))}
      </div>
    </div>
  );
}
