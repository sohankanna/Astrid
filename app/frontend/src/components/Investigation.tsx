import { useEffect, useMemo, useState } from "react";
import type { ChainNode, EventView, IncidentDetail, MitreEntry } from "../types";
import { STATUS_LABELS, TACTIC_ORDER, clock, dateTime, humanize, incidentLabel, sevClass } from "../format";
import { AiPanel } from "./AiPanel";
import { ResponsePanel } from "./ResponsePanel";
import { Layer } from "./Layer";

interface Props {
  detail: IncidentDetail | null;
  loading: boolean;
  error: string | null;
  busy: string | null;
  onAnalyze: () => void;
  onPlan: () => void;
  onDecide: (actionId: string, decision: "approve" | "reject") => void;
}

export function Investigation({ detail, loading, error, busy, onAnalyze, onPlan, onDecide }: Props) {
  if (error) {
    return (
      <section className="panel investigation">
        <div className="empty error">
          <strong>INVESTIGATION UNAVAILABLE</strong>
          <p>{error}</p>
        </div>
      </section>
    );
  }
  if (!detail) {
    return (
      <section className="panel investigation">
        <div className="empty">
          <strong>{loading ? "LOADING INCIDENT…" : "NO INCIDENT SELECTED"}</strong>
          <p>Select an incident to investigate its evidence.</p>
        </div>
      </section>
    );
  }

  const { incident, risk } = detail;
  return (
    <section className={`panel investigation ${loading ? "is-loading" : ""}`}>
      <header className="inv-head">
        <div>
          <div className="inv-id">
            {incidentLabel(incident.incident_id)} · INCIDENT INVESTIGATION
          </div>
          <h1>{incident.title}</h1>
          <div className="inv-sub">
            {dateTime(incident.first_seen)} → {dateTime(incident.last_seen)} · furthest stage{" "}
            <strong>{incident.attack_stage ?? "—"}</strong>
          </div>
        </div>
        <div className="inv-stats">
          <div className={`stat ${sevClass(incident.severity)}`}>
            <span>SEVERITY</span>
            <strong>{incident.severity.toUpperCase()}</strong>
          </div>
          <div className={`stat risk-stat ${sevClass(risk.band)}`}>
            <span>RISK</span>
            <strong>{risk.score}</strong>
            <div className="risk-bar">
              <div style={{ width: `${risk.score}%` }} />
            </div>
          </div>
          <div className="stat">
            <span>AI CONFIDENCE</span>
            <strong>{incident.confidence ? incident.confidence.toUpperCase() : "NOT RUN"}</strong>
          </div>
          <div className="stat">
            <span>STATUS</span>
            <strong>{STATUS_LABELS[incident.status] ?? incident.status}</strong>
          </div>
        </div>
      </header>

      <div className="legend">
        <Layer kind="observed" />
        <span className="legend-arrow">→</span>
        <Layer kind="correlated" />
        <span className="legend-arrow">→</span>
        <Layer kind="ai" />
        <span className="legend-arrow">→</span>
        <Layer kind="response" />
      </div>

      {detail.injection_findings.length > 0 && (
        <div className="injection-alert">
          <strong>⚠ PROMPT-INJECTION TEXT IN THIS INCIDENT'S EVIDENCE</strong>
          <span>
            {detail.injection_findings.length} field(s) contain instructions aimed at an AI analyst.
            They are shown as data, flagged, and never obeyed. Severity and risk are computed
            deterministically and cannot be changed by them.
          </span>
        </div>
      )}

      <AttackGraph nodes={detail.attack_chain} timeline={detail.timeline} />

      <div className="two-col">
        <MitrePanel entries={detail.mitre} timeline={detail.timeline} />
        <section className="block">
          <header className="block-head">
            <h3>RISK SCORE BREAKDOWN</h3>
            <Layer kind="correlated" />
          </header>
          <p className="block-note">
            Transparent: score = sum of named factors ({risk.score}/100, {risk.band}). Not AI-generated.
          </p>
          <ul className="factors">
            {risk.factors.map((f) => (
              <li key={f.name}>
                <span className="factor-points">+{f.points}</span>
                <span className="factor-name">{humanize(f.name)}</span>
                <span className="factor-reason">{f.reason}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <Timeline events={detail.timeline} />

      <AiPanel detail={detail} busy={busy === "analyze"} onAnalyze={onAnalyze} />

      <ResponsePanel
        detail={detail}
        busy={busy}
        onPlan={onPlan}
        onDecide={onDecide}
      />
    </section>
  );
}

// ---------------------------------------------------------------------------
// Attack chain graph
// ---------------------------------------------------------------------------

function AttackGraph({ nodes, timeline }: { nodes: ChainNode[]; timeline: EventView[] }) {
  const [selected, setSelected] = useState<number | null>(null);
  useEffect(() => setSelected(nodes.length ? 1 : null), [nodes]);

  // Every tactic of every mapped technique, not just each node's first one.
  const reached = useMemo(
    () => new Set(nodes.flatMap((n) => [n.tactic, ...n.techniques.map((t) => t.tactic)])),
    [nodes],
  );
  const eventsById = useMemo(() => new Map(timeline.map((e) => [e.event_id, e])), [timeline]);
  const node = nodes.find((n) => n.step === selected) ?? null;

  return (
    <section className="block attack-graph">
      <header className="block-head">
        <h3>ATTACK CHAIN</h3>
        <Layer kind="correlated" />
        <span className="block-note inline">
          Built only from correlated alerts, ordered by first evidence. Click a node.
        </span>
      </header>

      <div className="killchain" aria-label="ATT&CK tactics reached">
        {TACTIC_ORDER.map((tactic) => (
          <span key={tactic} className={`kc-step ${reached.has(tactic) ? "reached" : ""}`}>
            {tactic}
          </span>
        ))}
      </div>

      {nodes.length === 0 ? (
        <div className="empty small">No correlated alerts in this incident.</div>
      ) : (
        <div className="chain-scroll">
          <ol className="chain">
            {nodes.map((n, index) => (
              <li key={n.step} className="chain-item">
                <button
                  className={`chain-node ${sevClass(n.severity)} ${n.step === selected ? "selected" : ""}`}
                  onClick={() => setSelected(n.step)}
                >
                  <span className="cn-step">{String(n.step).padStart(2, "0")}</span>
                  <span className="cn-tactic">{n.tactic}</span>
                  <span className="cn-label">{n.label}</span>
                  <span className="cn-tech">
                    {n.techniques.map((t) => t.technique_id).join(" · ") || "unmapped"}
                  </span>
                  <span className="cn-time">{clock(n.first_seen)}</span>
                </button>
                {index < nodes.length - 1 && <span className="chain-link" aria-hidden="true" />}
              </li>
            ))}
          </ol>
        </div>
      )}

      {node && (
        <div className={`node-detail ${sevClass(node.severity)}`}>
          <div className="nd-head">
            <strong>
              STEP {node.step}: {node.title}
            </strong>
            <span className={`sev-badge ${sevClass(node.severity)}`}>{node.severity.toUpperCase()}</span>
            <span className="muted">rule {node.rule_id} · confidence {node.confidence}</span>
          </div>
          <div className="nd-grid">
            <div>
              <label>MITRE TECHNIQUE</label>
              {node.techniques.length ? (
                node.techniques.map((t) => (
                  <div key={t.technique_id}>
                    <code>{t.technique_id}</code> {t.name} <span className="muted">({t.tactic})</span>
                  </div>
                ))
              ) : (
                <div className="muted">No mapping. The evidence does not justify one.</div>
              )}
            </div>
            <div>
              <label>FIRST EVIDENCE</label>
              <div>{dateTime(node.first_seen)}</div>
              <label>ALERT IDS</label>
              {node.alert_ids.map((a) => (
                <div key={a}>
                  <code>{a}</code>
                </div>
              ))}
            </div>
            <div>
              <label>MATCHED FIELDS</label>
              {Object.entries(node.matched_fields).map(([k, v]) => (
                <div key={k} className="kv">
                  <span>{k}</span>
                  <code>{v}</code>
                </div>
              ))}
            </div>
          </div>
          <label>SUPPORTING EVENTS</label>
          <ul className="nd-events">
            {node.event_ids.map((id) => {
              const e = eventsById.get(id);
              return (
                <li key={id}>
                  <code>{id}</code> {e ? `${clock(e.timestamp)} · ${e.summary ?? e.action}` : ""}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK
// ---------------------------------------------------------------------------

function MitrePanel({ entries, timeline }: { entries: MitreEntry[]; timeline: EventView[] }) {
  const [open, setOpen] = useState<string | null>(null);
  const eventsById = useMemo(() => new Map(timeline.map((e) => [e.event_id, e])), [timeline]);
  return (
    <section className="block">
      <header className="block-head">
        <h3>MITRE ATT&amp;CK</h3>
        <Layer kind="correlated" />
      </header>
      <p className="block-note">
        Mapped by detection rules and validated against a pinned catalog. Expand to see why.
      </p>
      {entries.length === 0 && <div className="empty small">No techniques mapped.</div>}
      <ul className="mitre">
        {entries.map((entry) => {
          const isOpen = open === entry.technique_id;
          return (
            <li key={entry.technique_id} className={isOpen ? "open" : ""}>
              <button className="mitre-row" onClick={() => setOpen(isOpen ? null : entry.technique_id)}>
                <code>{entry.technique_id}</code>
                <span className="mitre-name">{entry.name}</span>
                <span className="mitre-tactic">{entry.tactic}</span>
                <span className="caret">{isOpen ? "▾" : "▸"}</span>
              </button>
              {isOpen && (
                <div className="mitre-body">
                  <label>WHY IT WAS DETECTED</label>
                  {entry.detected_by.map((d) => (
                    <div key={d.alert_id} className="mitre-rule">
                      <div>
                        <code>{d.rule_id}</code> {d.title}{" "}
                        <span className="muted">· confidence {d.confidence}</span>
                      </div>
                      <div className="muted">{d.description}</div>
                      <div className="chips">
                        {Object.entries(d.matched_fields).map(([k, v]) => (
                          <span key={k} className="chip">
                            {k}={v}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                  <label>SUPPORTING EVENTS</label>
                  <ul className="nd-events">
                    {entry.event_ids.map((id) => {
                      const e = eventsById.get(id);
                      return (
                        <li key={id}>
                          <code>{id}</code> {e ? `${clock(e.timestamp)} · ${e.summary ?? e.action}` : ""}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Evidence timeline
// ---------------------------------------------------------------------------

function Timeline({ events }: { events: EventView[] }) {
  return (
    <section className="block">
      <header className="block-head">
        <h3>EVIDENCE TIMELINE</h3>
        <Layer kind="observed" />
        <span className="block-note inline">
          {events.length} events the detections cite. This is what the AI reasons over; it cannot add to it.
        </span>
      </header>
      {events.length === 0 ? (
        <div className="empty small">No evidence events.</div>
      ) : (
        <ol className="timeline">
          {events.map((e) => (
            <li key={e.event_id} className={sevClass(e.severity)}>
              <div className="tl-time">
                <strong>{clock(e.timestamp)}</strong>
                <span>{e.timestamp.slice(0, 10)}</span>
              </div>
              <div className="tl-dot" />
              <div className="tl-body">
                <div className="tl-title">
                  <span className="tl-action">{e.action}</span>
                  <span className={`sev-badge small ${sevClass(e.severity)}`}>{e.severity.toUpperCase()}</span>
                  <span className="muted">{e.category}</span>
                  <code className="muted">{e.event_id}</code>
                  {e.rules.map((r) => (
                    <span key={r} className="rule-chip">
                      {r}
                    </span>
                  ))}
                </div>
                <div className="tl-meta">
                  <span>
                    <label>source</label> {e.source}
                  </span>
                  {e.user && (
                    <span>
                      <label>user</label> {e.user}
                    </span>
                  )}
                  {e.host && (
                    <span>
                      <label>host</label> {e.host}
                    </span>
                  )}
                  {e.account_id && (
                    <span>
                      <label>aws account</label> {e.account_id}
                    </span>
                  )}
                  {e.source_ip && (
                    <span>
                      <label>src</label> {e.source_ip}
                    </span>
                  )}
                  {e.destination && (
                    <span>
                      <label>dst</label> {e.destination}
                    </span>
                  )}
                  <span>
                    <label>outcome</label> {e.outcome}
                  </span>
                </div>
                {Object.keys(e.untrusted_fields).length > 0 && (
                  <div className={`untrusted ${e.injection_flags.length ? "flagged" : ""}`}>
                    <span className="untrusted-tag">
                      {e.injection_flags.length
                        ? "⚠ INJECTION TEXT FLAGGED · UNTRUSTED DATA · NOT INSTRUCTIONS"
                        : "UNTRUSTED FIELD DATA"}
                    </span>
                    {Object.entries(e.untrusted_fields).map(([k, v]) => (
                      <div key={k} className="kv">
                        <span>{humanize(k)}</span>
                        <code>{v}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
