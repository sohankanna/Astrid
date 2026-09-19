import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import type { CanonicalEvaluation, CanonicalResult } from "../types";

// Presentation of the EXISTING canonical 50K evaluation (GET /api/efficiency/canonical).
// Every number is read from the measured result; nothing is computed or rounded
// here except percentage formatting.

const STAGE_LABELS: Record<string, string> = {
  S1_RECON: "S1 Recon",
  S2_BRUTE_FORCE: "S2 Brute force",
  S3_PASSWORD_SPRAY: "S3 Password spray",
  S7_VALID_ACCOUNT: "S7 Valid account / pivot",
  S8_WEB_SHELL: "S8 Web shell",
  WEB01_FOOTHOLD: "WEB01 foothold",
  S5_PHISHING: "S5 Phishing",
  S6_ENDPOINT_COMPROMISE: "S6 Endpoint compromise",
  S7_CREDENTIAL_HARVESTING: "S7 Credential harvesting",
  S8_FINANCE_DATA_STAGING: "S8 Finance data staging",
  S9_USB_TRANSFER: "S9 USB transfer",
  S10_ARCHIVE_DELETION: "S10 Archive deletion",
};
// Attack-story order from the dataset README.
const STAGE_ORDER = Object.keys(STAGE_LABELS);

// Why each group was missed, from the first-run analysis of the default engine.
const MISS_CAUSE: Record<string, string> = {
  S8_WEB_SHELL: "Tomcat → cmd.exe process events: no baseline signal fires on them.",
  WEB01_FOOTHOLD: "Outbound WEB01 → attacker:4444: the external-address signal checks source addresses only.",
  S5_PHISHING: "Mail-gateway event: its sender_ip field is not mapped by the adapter.",
  S7_VALID_ACCOUNT: "Internal pivot logons from WS07: internal source address, no signal.",
};

const pct = (v: number | string) => (typeof v === "number" ? `${(v * 100).toFixed(1)}%` : "N/A");
const n = (v: number) => v.toLocaleString("en-US");

/** EVT-000056..EVT-000063 -> "EVT-56–63" (consecutive runs compressed). */
function ranges(ids: string[]): string {
  const nums = ids.map((id) => Number(id.split("-")[1])).filter(Number.isFinite).sort((a, b) => a - b);
  const out: string[] = [];
  for (let i = 0; i < nums.length; ) {
    let j = i;
    while (j + 1 < nums.length && nums[j + 1] === nums[j] + 1) j++;
    out.push(i === j ? `EVT-${nums[i]}` : `EVT-${nums[i]}–${nums[j]}`);
    i = j + 1;
  }
  return out.join(", ");
}

export function CanonicalFidelity() {
  const [data, setData] = useState<CanonicalResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rep, setRep] = useState<"raw" | "siem">("raw");

  useEffect(() => {
    api.canonical().then(setData, (e) => setError(e instanceof ApiError ? e.message : "Unexpected error."));
  }, []);

  if (error) return <section className="lab-card"><h2>Canonical 50K evidence fidelity</h2><p className="warn-text">{error}</p></section>;
  if (!data) return <section className="lab-card"><h2>Canonical 50K evidence fidelity</h2><p className="muted">Loading measured evaluation…</p></section>;
  if (!data.evaluation) {
    return (
      <section className="lab-card">
        <h2>Canonical 50K evidence fidelity</h2>
        <p className="offline-note">Ground truth: {data.ground_truth}. Precision / recall / F1 / critical evidence recall: N/A.</p>
      </section>
    );
  }
  const ev: CanonicalEvaluation = data.evaluation[rep];
  const stages = STAGE_ORDER.filter((s) => ev.per_stage[s]);
  // Missed groups in event order (first missed event ID), i.e. as they occurred.
  const missed = Object.keys(ev.missed_by_stage)
    .filter((s) => ev.missed_by_stage[s].length)
    .sort((a, b) => ev.missed_by_stage[a][0].localeCompare(ev.missed_by_stage[b][0]));

  return (
    <section className="lab-card gt-card">
      <div className="gt-head">
        <div>
          <h2>Canonical 50K evidence fidelity</h2>
          <div className="gt-badges">
            <span className="gt-badge warn">RECONSTRUCTED GROUND TRUTH — NOT AUTHORITATIVE</span>
            <span className="gt-badge">FIRST RUN · DEFAULT ENGINE · NOT TUNED</span>
          </div>
        </div>
        <div className="segmented gt-rep" role="group" aria-label="Telemetry representation">
          <button className={rep === "raw" ? "active" : ""} onClick={() => setRep("raw")}>Raw telemetry</button>
          <button className={rep === "siem" ? "active" : ""} onClick={() => setRep("siem")}>SIEM connector</button>
        </div>
      </div>

      <div className="gt-flow">
        <div><strong>{n(ev.events)}</strong><span>events</span></div>
        <div className="arrow-sep">→</div>
        <div><strong>{n(ev.selected)}</strong><span>selected as evidence</span></div>
        <div className="arrow-sep">=</div>
        <div className="tp"><strong>{n(ev.TP)}</strong><span>true positives</span></div>
        <div className="arrow-sep">+</div>
        <div className="fp"><strong>{n(ev.FP)}</strong><span>false positives</span></div>
        <div className="gt-gap" />
        <div className="fn"><strong>{n(ev.FN)}</strong><span>false negatives</span></div>
      </div>

      <div className="kpis gt-kpis">
        <div className="kpi good"><span className="kpi-label">PRECISION</span><strong>{pct(ev.precision)}</strong>
          <span className="kpi-note">TP ÷ selected ({ev.TP}/{ev.selected})</span></div>
        <div className="kpi good"><span className="kpi-label">RECALL</span><strong>{pct(ev.recall)}</strong>
          <span className="kpi-note">TP ÷ attack events ({ev.TP}/{ev.TP + ev.FN})</span></div>
        <div className="kpi good"><span className="kpi-label">F1</span><strong>{pct(ev.f1)}</strong>
          <span className="kpi-note">harmonic mean</span></div>
        <div className="kpi good"><span className="kpi-label">CRITICAL EVIDENCE RECALL</span>
          <strong>{pct(ev.critical_evidence_recall)}</strong>
          <span className="kpi-note">{ev.critical_retained}/{ev.critical_total} critical events retained</span></div>
      </div>

      <dl className="gt-semantics">
        <dt className="tp">TP</dt><dd>Attack event retained by the evidence engine</dd>
        <dt className="fp">FP</dt><dd>Benign/background event retained as investigation context</dd>
        <dt className="fn">FN</dt><dd>Attack event discarded by the evidence engine</dd>
        <dt>≠</dt><dd>Discarded is <strong>not</strong> “classified benign”. The engine selects evidence; it does not classify.</dd>
      </dl>

      <p className="gt-method">
        Labels were reconstructed from the supplied dataset/README and validated against event ordering, stage counts and
        named indicators. The original generator was not available. Metrics are therefore evaluation evidence, not
        authoritative ground-truth claims.
      </p>

      <details className="gt-details" open>
        <summary>Missed attack evidence · {ev.FN} events in {missed.length} groups</summary>
        <table className="budget">
          <thead><tr><th>Stage</th><th>Missed events</th><th>Count</th><th>Observed cause (first-run analysis)</th></tr></thead>
          <tbody>
            {missed.map((s) => (
              <tr key={s} className="lossy">
                <td>{STAGE_LABELS[s] ?? s}</td>
                <td><code>{ranges(ev.missed_by_stage[s])}</code></td>
                <td>{ev.missed_by_stage[s].length}</td>
                <td>{MISS_CAUSE[s] ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      <details className="gt-details">
        <summary>Stage breakdown · {ev.stages_with_any_selected_event}/{ev.stages_total} stages with retained evidence</summary>
        <table className="budget gt-stages">
          <thead><tr><th>Stage</th><th>Retained</th><th /></tr></thead>
          <tbody>
            {stages.map((s) => {
              const row = ev.per_stage[s];
              const share = row.events ? row.selected / row.events : 0;
              return (
                <tr key={s} className={row.selected < row.events ? "lossy" : ""}>
                  <td>{STAGE_LABELS[s] ?? s}</td>
                  <td>{row.selected}/{row.events}</td>
                  <td><div className="gt-bar"><span style={{ width: `${share * 100}%` }} /></div></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </details>

      <details className="gt-details">
        <summary>Limitations</summary>
        <ul className="gt-limits">
          <li>Ground truth is reconstructed, not the generator's hidden labels; replace when that artifact is delivered.</li>
          <li>“Critical” is a documented proxy: attack events containing a README-named indicator absent from background traffic ({ev.critical_total} events). The endpoint-compromise stage has no event under that definition.</li>
          <li>EVT-42 vs EVT-43 (password spray vs valid account) is a formatting-based judgment call.</li>
          <li>False positives ({ev.FP}) are background activity by the victim account on the compromised host during the attack window, retained as context by design.</li>
          <li>First-run numbers with default settings. No thresholds or heuristics were tuned against these labels.</li>
          <li>Raw and SIEM representations carry the same events, so their results are identical.</li>
        </ul>
      </details>
    </section>
  );
}
