import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import type { AttackPath, AttackPathStage } from "../types";
import { Drawer } from "./Disclosure";

// Canonical 50K attack path: READ-ONLY view of GET /api/canonical/attack-path
// (the existing attack-chain audit + the existing first-run evaluation).
// Only titles and layout live here; every event, count and evidence class comes
// from the backend artifacts.

// Presentation titles keyed by audit stage name. Order = layout order.
const BRANCH_A: { key: string; title: string }[] = [
  { key: "S1_RECON", title: "S1 · Reconnaissance" },
  { key: "S2_BRUTE_FORCE", title: "S2 · Brute force / password spray" },
  { key: "S3_PASSWORD_SPRAY", title: "S3 · Password-spray interpretation" },
  { key: "S7_VALID_ACCOUNT (initial)", title: "S4 · Valid account" },
  { key: "S8_WEB_SHELL", title: "S5 · WEB01 web shell" },
  { key: "WEB01_FOOTHOLD", title: "S6 · WEB01 foothold" },
];
const BRANCH_B: { key: string; title: string }[] = [
  { key: "S5_PHISHING (not in diagram)", title: "Phishing" },
  { key: "S6_ENDPOINT_COMPROMISE (not in diagram)", title: "Endpoint compromise" },
];
const WS07_PATH: { key: string; title: string }[] = [
  { key: "S7_CREDENTIAL_HARVESTING", title: "S7 · Credential harvesting" },
  { key: "S7_VALID_ACCOUNT (pivot)", title: "S8 · Valid account / lateral movement" },
  { key: "S8_FINANCE_DATA_STAGING", title: "S9 · Finance data staging" },
  { key: "S9_USB_TRANSFER", title: "S10 · USB transfer" },
  { key: "S10_ARCHIVE_DELETION", title: "S11 · Archive deletion / covering tracks" },
];
const TITLES = Object.fromEntries([...BRANCH_A, ...BRANCH_B, ...WS07_PATH].map((s) => [s.key, s.title]));

const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
const n = (v: number) => v.toLocaleString("en-US");

/** "EVT-000001..000014, EVT-000042" -> "EVT-1–14, EVT-42" */
function shortRange(range: string): string {
  return range.split(",").map((part) => {
    const [prefix, num] = part.trim().split("-");
    const [lo, hi] = num.split("..");
    return hi ? `${prefix}-${Number(lo)}–${Number(hi)}` : `${prefix}-${Number(lo)}`;
  }).join(", ");
}

function evidenceClass(type: string): string {
  return type === "OBSERVED" ? "observed" : type === "CORRELATED" ? "correlated" : type === "INFERRED" ? "inferred" : "none";
}

function retention(stage: AttackPathStage): "full" | "partial" | "none" {
  if (stage.missed === 0) return "full";
  return stage.selected === 0 ? "none" : "partial";
}

/** Up to four key observables for the card (hosts, users, files, destination IPs). */
function keyFacts(stage: AttackPathStage): string[] {
  const o = stage.observables;
  const files = (o.file_resource ?? []).map((f) => f.split(/[\\/]/).pop() ?? f);
  return [...(o.host ?? []).slice(0, 2), ...(o.user ?? []).slice(0, 1), ...files.slice(0, 1),
    ...(o.destination_ip ?? []).slice(0, 1)].filter(Boolean).slice(0, 4);
}

export function CanonicalAttackPath() {
  const [data, setData] = useState<AttackPath | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<AttackPathStage | null>(null);

  useEffect(() => {
    api.attackPath().then(setData, (e) => setError(e instanceof ApiError ? e.message : "Unexpected error."));
  }, []);

  if (error) return <div className="empty error"><strong>ATTACK PATH UNAVAILABLE</strong><p>{error}</p></div>;
  if (!data) return <p className="muted">Loading canonical attack path…</p>;

  const byKey = new Map(data.stages.map((s) => [s.stage, s]));
  const m = data.metrics;
  const missedStages = data.stages.filter((s) => s.missed > 0);
  const transition = (from: string, to: string) => data.transitions.find((t) => t.from === from && t.to === to);
  const gap = transition("WEB01_FOOTHOLD", "S7_CREDENTIAL_HARVESTING");

  const card = (key: string) => {
    const stage = byKey.get(key);
    if (!stage) return null;
    const state = retention(stage);
    return (
      <article key={key} className={`ap-card ret-${state}`}>
        <header>
          <span className="ap-title">{TITLES[key] ?? key}</span>
          <span className={`ap-class ${evidenceClass(stage.evidence_type)}`}>{stage.evidence_type}</span>
        </header>
        <code className="ap-range">{shortRange(stage.event_range)} · {stage.ground_truth_stage}</code>
        {state === "full" && <div className="ap-count"><strong>{stage.selected}/{stage.attack_events}</strong> attack events retained</div>}
        {state === "partial" && (
          <div className="ap-count"><strong>{stage.attack_events}</strong> attack events / <strong className="ok">{stage.selected}</strong> retained /{" "}
            <strong className="miss">{stage.missed}</strong> missed</div>
        )}
        {state === "none" && (
          <div className="ap-count miss"><strong>{stage.attack_events}</strong> attack events present — <strong>0</strong> retained by first-run correlation</div>
        )}
        <div className="ap-split" aria-hidden="true">
          <span className="ok" style={{ flex: stage.selected }} /><span className="miss" style={{ flex: stage.missed }} />
        </div>
        <div className="ap-facts">{keyFacts(stage).map((f) => <span key={f}>{f}</span>)}</div>
        {stage.evidence_type !== "OBSERVED" && <p className="ap-why">{stage.justification}</p>}
        <button className="btn ap-btn" onClick={() => setOpen(stage)}>View evidence</button>
      </article>
    );
  };

  const arrow = (from: string | null, to: string | null, label?: string) => {
    const t = from && to ? transition(from, to) : undefined;
    const text = label ?? t?.evidence_type;
    return <div className={`ap-arrow ${evidenceClass(text ?? "")}`} title={t ? `shared: ${t.shared_observed_entities.join(", ") || "none"}` : undefined}>
      <span>→</span>{text && <em>{text}</em>}</div>;
  };
  const bridge = (link: string) => (data.bridge_links[link]?.length ? "CORRELATED" : "INFERRED");

  return (
    <div className="attack-path">
      <header className="ap-head">
        <div>
          <h2>Canonical 50K attack path</h2>
          <div className="gt-badges">
            <span className="gt-badge warn">RECONSTRUCTED GROUND TRUTH — NOT AUTHORITATIVE</span>
            <span className="gt-badge">FIRST RUN · DEFAULT ENGINE · NOT TUNED</span>
          </div>
        </div>
        <dl className="ap-legend" aria-label="Attack path legend">
          <dt className="observed">OBSERVED</dt><dd>Directly present in telemetry</dd>
          <dt className="correlated">CORRELATED</dt><dd>Relationship established from multiple observations</dd>
          <dt className="inferred">INFERRED</dt><dd>Interpretation requiring reasoning</dd>
          <dt className="missed">MISSED</dt><dd>Attack telemetry exists but was not retained</dd>
        </dl>
      </header>

      <div className="ap-metrics">
        <div><strong>{n(m.total_events)}</strong><span>total events</span></div>
        <div><strong>{n(m.attack_events)}</strong><span>reconstructed attack</span></div>
        <div><strong>{n(m.background_events)}</strong><span>background</span></div>
        <div><strong>{n(m.selected)}</strong><span>selected</span></div>
        <div className="tp"><strong>{m.TP}</strong><span>TP</span></div>
        <div className="fp"><strong>{m.FP}</strong><span>FP</span></div>
        <div className="fn"><strong>{m.FN}</strong><span>FN</span></div>
        <div><strong>{pct(m.precision)}</strong><span>precision</span></div>
        <div><strong>{pct(m.recall)}</strong><span>recall</span></div>
        <div><strong>{pct(m.f1)}</strong><span>F1</span></div>
        <div><strong>{pct(m.critical_evidence_recall)}</strong><span>critical recall ({m.critical_retained}/{m.critical_total})</span></div>
      </div>

      <section className="ap-missed" aria-label="Missed attack evidence">
        <strong>MISSED ATTACK EVIDENCE · {m.FN} false negatives</strong>
        <div className="ap-missed-list">
          {missedStages.map((s) => (
            <button key={s.stage} className="ap-missed-chip" onClick={() => setOpen(s)}>
              {(TITLES[s.stage] ?? s.stage).replace(/^S\d+ · /, "")} <b>{s.missed} missed</b>
            </button>
          ))}
        </div>
        <p>Missed = attack-related telemetry not retained by the correlation engine. It was NOT classified as benign.</p>
      </section>

      <div className="ap-lane">
        <div className="ap-lane-label">Branch A · WEB01</div>
        <div className="ap-flow">
          <div className="ap-origin">ATTACKER<br /><code>{byKey.get("S1_RECON")?.observables.source_ip?.[0] ?? ""}</code></div>
          {BRANCH_A.map((s, i) => (
            <div className="ap-step" key={s.key}>
              {arrow(i === 0 ? null : BRANCH_A[i - 1].key, i === 0 ? null : s.key)}
              {card(s.key)}
            </div>
          ))}
          <div className="ap-end">no observed link to WS07</div>
        </div>
      </div>

      <div className="ap-correction">
        <strong>Attack-path correction.</strong> WEB01 foothold → credential harvesting is not directly supported by telemetry.
        The delivered dataset shows phishing → WS07 endpoint compromise → credential harvesting as the path to WS07.
        {gap && <span className="muted"> Audit: {gap.evidence_type} · shared observed entities: {gap.shared_observed_entities.join(", ") || "none"}.</span>}
      </div>

      <div className="ap-lane">
        <div className="ap-lane-label">Branch B · path to WS07</div>
        <div className="ap-flow">
          <div className="ap-origin">ATTACKER<br /><code>email sender</code></div>
          {BRANCH_B.map((s, i) => (
            <div className="ap-step" key={s.key}>
              {arrow(null, null, i === 0 ? undefined : bridge("S5_PHISHING -> S6_ENDPOINT_COMPROMISE"))}
              {card(s.key)}
            </div>
          ))}
          <div className="ap-step">{arrow(null, null, bridge("S6_ENDPOINT_COMPROMISE -> S7_CREDENTIAL_HARVESTING"))}
            <div className="ap-origin host">WS07<br /><code>neha</code></div></div>
          {WS07_PATH.map((s, i) => (
            <div className="ap-step" key={s.key}>
              {arrow(i === 0 ? null : WS07_PATH[i - 1].key, i === 0 ? null : s.key)}
              {card(s.key)}
            </div>
          ))}
        </div>
      </div>

      {open && (
        <Drawer title={`${TITLES[open.stage] ?? open.stage} · evidence`} onClose={() => setOpen(null)}>
          <p className="muted small">
            {open.ground_truth_stage} · {open.evidence_type} · {open.selected}/{open.attack_events} retained · {open.missed} missed ·{" "}
            {open.first_seen} → {open.last_seen}
          </p>
          <p className="small">{open.justification}</p>
          <table className="budget ap-events">
            <thead>
              <tr><th>Event</th><th>Time</th><th>Host</th><th>User</th><th>Src → Dst</th><th>Action / process / resource</th>
                <th>Ground truth</th><th>Engine</th></tr>
            </thead>
            <tbody>
              {open.events.map((e) => (
                <tr key={e.event_id} className={e.selected ? "" : "missed-row"}>
                  <td><code>{e.event_id}</code></td>
                  <td>{e.timestamp.slice(11, 19)}</td>
                  <td>{e.host ?? "—"}</td>
                  <td>{e.user ?? "—"}</td>
                  <td>{e.source_ip ?? "—"} → {e.destination_ip ?? "—"}</td>
                  <td title={e.message}>{[e.action, e.process, ...e.resource].filter(Boolean).join(" · ") || e.source_type}</td>
                  <td>{e.ground_truth.attack_related ? `attack${e.ground_truth.critical ? " · critical" : ""}` : "background"}</td>
                  <td>{e.selected ? <span className="ok">retained</span> : <span className="miss">MISSED</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">Hover a row for the raw message. Missed = not retained by the engine; it was not classified as benign.</p>
        </Drawer>
      )}
    </div>
  );
}
