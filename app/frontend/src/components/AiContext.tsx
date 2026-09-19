import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import type { ContextPack, IncidentDetail } from "../types";

interface Props {
  detail: IncidentDetail;
}

function compact(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n);
}

/** What the AI actually receives: deterministic reduction + redaction
 *  metrics, the provider that really ran, and the exact redacted pack. */
export function AiContext({ detail }: Props) {
  const { metrics: m, last_run: run, configured_provider: configured } = detail.ai_context;
  const incidentId = detail.incident.incident_id;
  const [pack, setPack] = useState<ContextPack | null>(null);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setPack(null);
    setOpen(false);
    setError(null);
  }, [incidentId]);

  const toggle = async () => {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (!pack) {
      try {
        setPack(await api.context(incidentId));
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "Could not load the context pack.");
      }
    }
  };

  // Never claim a live model ran unless the backend says one did.
  const provider = run
    ? run.live_model
      ? { label: `CLAUDE · ${run.model ?? ""}`, cls: "live" }
      : { label: "MOCK / OFFLINE", cls: "mock" }
    : configured === "claude"
      ? { label: "CLAUDE (configured · not yet run)", cls: "pending" }
      : { label: "MOCK / OFFLINE", cls: "mock" };

  return (
    <div className="ai-context">
      <div className="ai-context-head">
        <strong>AI CONTEXT</strong>
        <span className="muted">deterministic reduction · redacted before any model sees it</span>
        <span className={`provider-badge ${provider.cls}`}>AI PROVIDER: {provider.label}</span>
      </div>
      <div className="ctx-funnel">
        <div className="ctx-step">
          <span className="ctx-num">{m.raw_events.toLocaleString()}</span>
          <span className="ctx-label">raw events</span>
        </div>
        <span className="ctx-arrow">→</span>
        <div className="ctx-step">
          <span className="ctx-num">{m.relevant_events.toLocaleString()}</span>
          <span className="ctx-label">relevant</span>
        </div>
        <span className="ctx-arrow">→</span>
        <div className="ctx-step">
          <span className="ctx-num">{m.evidence_objects}</span>
          <span className="ctx-label">evidence objects</span>
        </div>
        <span className="ctx-arrow">→</span>
        <div className="ctx-step accent">
          <span className="ctx-num">~{compact(m.estimated_tokens)}</span>
          <span className="ctx-label">est. tokens</span>
        </div>
        <div className="ctx-step">
          <span className="ctx-num">{m.redacted_field_count}</span>
          <span className="ctx-label">secrets redacted</span>
        </div>
        <div className="ctx-step">
          <span className="ctx-num">{m.distinct_pseudonyms}</span>
          <span className="ctx-label">identities pseudonymized</span>
        </div>
      </div>
      <div className="ctx-foot">
        <span className="muted">
          {m.aggregated_groups} burst(s) aggregated · {m.contextual_events} contextual event(s) · {m.entities} entities ·{" "}
          {m.relationships} relationships · est. total ~{compact(m.estimated_total_tokens)} tokens ({m.token_estimator})
        </span>
        {run?.usage && run.live_model && (
          <span className="measured">
            measured: {run.usage.input_tokens ?? "?"} in / {run.usage.output_tokens ?? "?"} out tokens
          </span>
        )}
        {run?.fallback_reason && <span className="fallback-note">⚠ fell back to mock: {run.fallback_reason}</span>}
        <button className="link" onClick={() => void toggle()}>
          {open ? "▾ hide context pack" : "▸ view exact context pack sent to the model"}
        </button>
      </div>
      {open && (
        <div className="ctx-pack">
          {error ? (
            <span className="warn-text">{error}</span>
          ) : pack ? (
            <pre>{JSON.stringify(pack.pack, null, 2)}</pre>
          ) : (
            <span className="muted">Loading…</span>
          )}
        </div>
      )}
    </div>
  );
}
