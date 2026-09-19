import { useEffect, useMemo, useState } from "react";
import type { ChainNode, EventView, IncidentDetail, MitreEntry } from "../types";
import { STATUS_LABELS, TACTIC_ORDER, clock, dateTime, humanize, incidentLabel, sevClass } from "../format";
import { AiPanel } from "./AiPanel";
import { ResponsePanel } from "./ResponsePanel";
import { Layer } from "./Layer";
import { Disclosure, Drawer, Tabs, TabPanel } from "./Disclosure";
import { CanonicalAttackPath } from "./CanonicalAttackPath";

interface Props {
  detail: IncidentDetail | null;
  loading: boolean;
  error: string | null;
  busy: string | null;
  onAnalyze: () => void;
  onPlan: () => void;
  onDecide: (actionId: string, decision: "approve" | "reject") => void;
  /** True when the canonical 50K scenario is active: Attack Path shows the audited canonical path. */
  canonical?: boolean;
}

const INCIDENT_TABS = ["Overview", "Evidence", "Attack Path", "AI", "Response"] as const;

export function Investigation({ detail, loading, error, busy, onAnalyze, onPlan, onDecide, canonical = false }: Props) {
  const [showCanonical, setShowCanonical] = useState(false);
  const [tab, setTab] = useState<(typeof INCIDENT_TABS)[number]>("Overview");
  const [eventIds, setEventIds] = useState<string[] | null>(null);
  useEffect(() => { setTab("Overview"); setEventIds(null); }, [detail?.incident.incident_id]);
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


      <Tabs id="incident" tabs={INCIDENT_TABS} value={tab} onChange={setTab} />
      <TabPanel id="incident" index={0} active={tab === "Overview"}>
        <div className="overview-metrics">
          <div><strong>{incident.alert_count}</strong><span>Related alerts</span></div>
          <div><strong>{incident.event_count}</strong><span>Evidence events</span></div>
          <div><strong>{detail.analysis ? detail.analysis.confidence : "Not run"}</strong><span>AI status / confidence</span></div>
        </div>
        <dl className="overview-assets">
          <dt>Affected hosts</dt><dd>{incident.hosts.join(", ") || "—"}</dd>
          <dt>Cloud accounts</dt><dd>{incident.cloud_accounts.join(", ") || "—"}</dd>
          <dt>Identities</dt><dd>{incident.users.join(", ") || "—"}</dd>
        </dl>
        <h3>Attack progression</h3>
        <div className="progression">{detail.attack_chain.filter((node, i, nodes) => i === 0 || node.tactic !== nodes[i - 1].tactic).map((node, i) => <span key={node.step}>
          {i > 0 && <span aria-hidden="true"> → </span>}{node.tactic}
        </span>)}</div>
        <h3>Key findings <span className="muted">· correlated alerts</span></h3>
        <ul className="key-findings">{detail.correlated.alerts.slice(0, 4).map((alert) =>
          <li key={alert.alert_id}>{alert.title}</li>)}</ul>
        {!detail.correlated.alerts.length && <p className="muted">No correlated alerts.</p>}
        <div className="disclosure-actions">
          <button className="btn primary" onClick={() => { setEventIds(null); setTab("Evidence"); }}>View evidence →</button>
          <Disclosure label="View risk breakdown">        <section className="block">
          <header className="block-head">
            <h3>Risk score breakdown</h3>
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
        </section></Disclosure>
          <Disclosure label="View correlated alerts">
            {detail.correlated.alerts.map((alert) => <article className="finding-row" key={alert.alert_id}>
              <strong>{alert.title}</strong><p>{alert.description}</p><code>{alert.alert_id} · {alert.rule_id}</code>
              <p>Confidence: {alert.confidence} · Severity: {alert.severity}</p>
              <p className="muted">{alert.evidence_event_ids.join(" · ")}</p>
            </article>)}
          </Disclosure>
        </div>
      </TabPanel>
      <TabPanel id="incident" index={1} active={tab === "Evidence"}>
        <EvidenceBrowser key={incident.incident_id} events={detail.timeline} eventIds={eventIds} onClear={() => setEventIds(null)} />
      </TabPanel>
      <TabPanel id="incident" index={2} active={tab === "Attack Path"}>
        {canonical || showCanonical ? <>
          <CanonicalAttackPath />
          {!canonical && <button className="btn" onClick={() => setShowCanonical(false)}>Back to incident attack path</button>}
        </> : <>
        <button className="btn ap-open" onClick={() => setShowCanonical(true)}>View canonical 50K attack path</button>
        <AttackGraph key={incident.incident_id} nodes={detail.attack_chain} timeline={detail.timeline} mitre={detail.mitre}
          onEvidence={(ids) => { setEventIds(ids); setTab("Evidence"); }} />
        <Disclosure label="View MITRE details"><MitrePanel entries={detail.mitre} timeline={detail.timeline} /></Disclosure>
        </>}
      </TabPanel>
      <TabPanel id="incident" index={3} active={tab === "AI"}>
        <AiPanel key={incident.incident_id} detail={detail} busy={busy === "analyze"} onAnalyze={onAnalyze} />
      </TabPanel>
      <TabPanel id="incident" index={4} active={tab === "Response"}>
        <ResponsePanel detail={detail} busy={busy} onPlan={onPlan} onDecide={onDecide} />
      </TabPanel>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Attack chain graph
// ---------------------------------------------------------------------------

function AttackGraph({ nodes, timeline, mitre, onEvidence }: { nodes: ChainNode[]; timeline: EventView[]; mitre: MitreEntry[]; onEvidence: (ids: string[]) => void }) {
  const [selected, setSelected] = useState<number | null>(null);
  const [nodeView, setNodeView] = useState<"detail" | "mitre">("detail");

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
        <h3>Attack chain</h3>
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
                  onClick={() => { setSelected(n.step); setNodeView("detail"); }}
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
        <Drawer title={node.title} onClose={() => setSelected(null)}>
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
          <p><strong>Host: </strong>{[...new Set(node.event_ids.flatMap((id) => eventsById.get(id)?.host ? [eventsById.get(id)!.host] : []))].join(", ") || "—"} · <strong>Evidence events: </strong>{node.event_ids.length}</p>
          <div className="disclosure-actions">
            <button className="btn primary" onClick={() => { onEvidence(node.event_ids); setSelected(null); }}>View evidence</button>
            <button className="btn" onClick={() => setNodeView(nodeView === "mitre" ? "detail" : "mitre")}>{nodeView === "mitre" ? "Hide MITRE details" : "View MITRE details"}</button>
          </div>
          {nodeView === "mitre" && <MitrePanel entries={mitre.filter((m) => node.techniques.some((t) => t.technique_id === m.technique_id))} timeline={timeline} />}
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
        </Drawer>
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
        <h3>Evidence timeline</h3>
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


function EvidenceBrowser({ events, eventIds, onClear }: { events: EventView[]; eventIds: string[] | null; onClear: () => void }) {
  const [filter, setFilter] = useState("All");
  const [selected, setSelected] = useState<EventView | null>(null);
  useEffect(() => setFilter("All"), [eventIds]);
  const visible = events.filter((e) => (!eventIds || eventIds.includes(e.event_id)) &&
    (filter === "All" || (filter === "Critical" && e.severity === "critical") ||
    (filter === "Authentication" && e.category === "authentication") ||
    (filter === "Cloud" && (e.category === "cloud" || !!e.account_id)) ||
    (filter === "Endpoint" && !!e.host && !e.account_id && e.category !== "cloud")));
  return <section className="evidence-browser">
    <header className="block-head"><h3>Evidence</h3><Layer kind="observed" /></header>
    <div className="filter-row" aria-label="Evidence filters">{["All", "Critical", "Authentication", "Endpoint", "Cloud"].map((name) =>
      <button key={name} className="btn" aria-pressed={filter === name} onClick={() => setFilter(name)}>{name}</button>)}</div>
    {eventIds && <p className="muted">Showing attack-node evidence. <button className="link" onClick={onClear}>Show all incident evidence</button></p>}
    <p className="muted">{visible.length} of {events.length} evidence events</p>
    <ul className="evidence-list">{visible.map((e) => <li key={e.event_id}>
      <div><code>{e.event_id}</code><time>{clock(e.timestamp)}</time><span className={"sev-badge " + sevClass(e.severity)}>{e.severity}</span></div>
      <strong>{e.summary ?? humanize(e.action)}</strong>
      <p className="muted">{[e.source_ip, e.destination || e.host || e.account_id].filter(Boolean).join(" → ") || e.source}</p>
      {!!e.injection_flags.length && <p className="warn-text">Untrusted instruction text flagged</p>}
      <button className="btn" aria-haspopup="dialog" onClick={() => setSelected(e)}>View source event</button>
    </li>)}</ul>
    {!visible.length && <p className="empty">No evidence matches this filter.</p>}
    {selected && <Drawer title={"Source event · " + selected.event_id} onClose={() => setSelected(null)}>
      <Timeline events={[selected]} />
    </Drawer>}
  </section>;
}
