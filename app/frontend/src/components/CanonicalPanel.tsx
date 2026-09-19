import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import type { CanonicalResult } from "../types";

// Canonical 50K scenario: every number comes from GET /api/efficiency/canonical
// (a measured run of the real dataset). RAW and SIEM columns are token
// estimates of the files as delivered; they are never sent to a model.

const n = (v: number | null | undefined) => (v === null || v === undefined ? "—" : v.toLocaleString("en-US"));

export function CanonicalPanel() {
  const [data, setData] = useState<CanonicalResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async (refresh = false) => {
    setLoading(true);
    try {
      setData(await api.canonical(refresh));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Unexpected error.");
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    void load();
  }, []);

  if (error) return <section className="lab-card"><h2>CANONICAL 50K SCENARIO</h2><p className="warn-text">{error}</p></section>;
  if (!data) return <section className="lab-card"><h2>CANONICAL 50K SCENARIO</h2><p className="muted">Measuring 50,000 events…</p></section>;

  const raw = data.representations.raw;
  const siem = data.representations.siem;
  const ctx = data.evidence_context;
  return (
    <section className="lab-card canonical">
      <h2>CANONICAL 50K SCENARIO <em>· {data.dataset_note}</em></h2>
      <div className="paths three">
        <div className="path raw">
          <div className="path-title">RAW SOURCE TELEMETRY</div>
          <div className="path-badge">AS DELIVERED — ESTIMATE, NOT SENT TO MODEL</div>
          <dl><dt>Events</dt><dd>{n(raw.events)}</dd><dt>Est. tokens</dt><dd className="big">{n(raw.as_delivered_tokens)}</dd>
            <dt>Valid records</dt><dd>{data.validation.raw.valid ? "yes" : "NO"}</dd></dl>
        </div>
        <div className="path raw">
          <div className="path-title">SIEM CONNECTOR EVENTS</div>
          <div className="path-badge">AS DELIVERED — ESTIMATE, NOT SENT TO MODEL</div>
          <dl><dt>Events</dt><dd>{n(siem.events)}</dd><dt>Est. tokens</dt><dd className="big">{n(siem.as_delivered_tokens)}</dd>
            <dt>Valid records</dt><dd>{data.validation.siem.valid ? "yes" : "NO"}</dd></dl>
        </div>
        <div className="path evidence">
          <div className="path-title">OUR CORRELATION ENGINE (raw input)</div>
          <div className="path-badge">MEASURED</div>
          <dl>
            <dt>Events</dt><dd>{n(raw.engine.events)}</dd>
            <dt>Relevant events</dt><dd>{n(raw.engine.relevant_events)}</dd>
            <dt>Evidence objects</dt><dd>{n(raw.engine.evidence_objects)}</dd>
            <dt>Context tokens</dt><dd className="big">{n(raw.engine.context_tokens)}</dd>
            <dt>Reduction</dt><dd>{raw.engine.reduction_vs_as_delivered_percent}%</dd>
            <dt>Engine latency</dt><dd>{n(raw.engine.engine_latency_ms)} ms</dd>
          </dl>
        </div>
      </div>
      <p className="small muted">
        SIEM input through the same engine: {n(siem.engine.relevant_events)} relevant → {n(siem.engine.evidence_objects)} objects →{" "}
        {n(siem.engine.context_tokens)} tokens ({n(siem.engine.engine_latency_ms)} ms).{" "}
        EvidenceContext (existing redacting engine): {ctx.generated ? `${n(ctx.incidents)} incident(s), ${n(ctx.evidence_objects)} objects, ~${n(ctx.estimated_tokens)} tokens` : "not generated"}.{" "}
        Only this redacted context is eligible for the AI investigator.
      </p>
      {data.evaluation ? (
        <p className="offline-note">
          Ground truth: {data.ground_truth}. Raw: TP {data.evaluation.raw.TP} · FP {data.evaluation.raw.FP} · FN{" "}
          {data.evaluation.raw.FN} (not selected, not "classified benign") · precision {String(data.evaluation.raw.precision)} ·
          recall {String(data.evaluation.raw.recall)} · F1 {String(data.evaluation.raw.f1)} · critical evidence recall{" "}
          {String(data.evaluation.raw.critical_evidence_recall)}. SIEM: TP {data.evaluation.siem.TP} · FP {data.evaluation.siem.FP} · FN{" "}
          {data.evaluation.siem.FN}. Default engine settings, not tuned.
        </p>
      ) : (
        <p className="offline-note">Ground truth: {data.ground_truth}. Precision / recall / F1 / critical evidence recall: N/A.</p>
      )}
      <p className="small muted">{data.signals_label}</p>
      <details><summary>View attack-stage candidates</summary>
        <pre className="json">{JSON.stringify(raw.attack_stage_candidates, null, 1)}</pre>
      </details>{" "}
      <details><summary>View relationships</summary>
        <pre className="json">{JSON.stringify(raw.relationships, null, 1)}</pre>
      </details>{" "}
      <details><summary>View signals & latency</summary>
        <pre className="json">{JSON.stringify({ raw: { signals: raw.signals, latency_ms: raw.engine.latency_ms },
          siem: { signals: siem.signals, latency_ms: siem.engine.latency_ms }, peak_memory_mb: data.peak_memory_mb,
          measured_at: data.measured_at }, null, 1)}</pre>
      </details>{" "}
      <button className="btn" disabled={loading} onClick={() => void load(true)}>{loading ? "Measuring…" : "Re-measure"}</button>
    </section>
  );
}
