import type { IncidentSummary } from "../types";
import { STATUS_LABELS, incidentLabel, relative, sevClass } from "../format";

interface Props {
  incidents: IncidentSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  now: number;
}

const DOMAIN_LABEL: Record<string, string> = {
  endpoint: "ENDPOINT / NETWORK",
  cloud: "AWS CLOUD",
  hybrid: "HYBRID",
};

export function IncidentList({ incidents, selectedId, onSelect, now }: Props) {
  return (
    <section className="panel incident-list">
      <header className="panel-head">
        <h2>Active incidents</h2>
        <span className="count">{incidents.length}</span>
      </header>
      {incidents.length === 0 ? (
        <div className="empty">
          <strong>No active incidents</strong>
          <p>Deterministic detections produced nothing to correlate for this scenario.</p>
          <p>For benign or injection-only scenarios this is the expected, correct result.</p>
        </div>
      ) : (
        <ul>
          {incidents.map((incident) => (
            <li key={incident.incident_id}>
              <button
                className={`incident-card ${sevClass(incident.severity)} ${
                  incident.incident_id === selectedId ? "selected" : ""
                }`}
                onClick={() => onSelect(incident.incident_id)}
              >
                <div className="ic-row">
                  <span className="ic-id">{incidentLabel(incident.incident_id)}</span>
                  <span className={`sev-badge ${sevClass(incident.severity)}`}>
                    {incident.severity.toUpperCase()}
                  </span>
                  <span className="ic-risk">
                    RISK <strong>{incident.risk_score}</strong>
                  </span>
                </div>
                <div className="ic-title">{incident.title}</div>
                <div className="ic-meta">
                  <span>{DOMAIN_LABEL[incident.domain] ?? incident.domain}</span>
                  <span>{incident.alert_count} alerts</span>
                  <span>{incident.event_count} events</span>
                  {incident.injection_detected && <span className="warn-text">⚠ injection text</span>}
                </div>
                <div className="ic-techniques">
                  {incident.technique_ids.slice(0, 6).map((t) => (
                    <span key={t} className="tech-chip">
                      {t}
                    </span>
                  ))}
                  {incident.technique_ids.length > 6 && (
                    <span className="tech-chip more">+{incident.technique_ids.length - 6}</span>
                  )}
                </div>
                <div className="ic-row foot">
                  <span title={incident.first_seen ?? ""}>{relative(incident.first_seen, now)}</span>
                  <span className={`status status-${incident.status.toLowerCase()}`}>
                    {STATUS_LABELS[incident.status] ?? incident.status}
                  </span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
