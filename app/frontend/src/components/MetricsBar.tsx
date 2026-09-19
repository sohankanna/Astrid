import type { Metrics } from "../types";

interface Props {
  metrics: Metrics | null;
}

function Card({ label, value, cls, sub }: { label: string; value: number | string; cls?: string; sub?: string }) {
  return (
    <div className={`metric ${cls ?? ""}`}>
      <span className="metric-label">{label}</span>
      <span className="metric-value">{value}</span>
      {sub && <span className="metric-sub">{sub}</span>}
    </div>
  );
}

export function MetricsBar({ metrics }: Props) {
  if (!metrics) {
    return <section className="metrics loading">Loading telemetry metrics…</section>;
  }
  const sev = metrics.alert_severity;
  return (
    <section className="metrics" aria-label="SOC metrics">
      <Card label="CRITICAL" value={sev.critical} cls="sev-critical" sub="alerts" />
      <Card label="HIGH" value={sev.high} cls="sev-high" sub="alerts" />
      <Card label="MEDIUM" value={sev.medium} cls="sev-medium" sub="alerts" />
      <Card label="LOW" value={sev.low + sev.informational} cls="sev-low" sub="alerts" />
      <div className="metric-divider" />
      <Card label="ACTIVE INCIDENTS" value={metrics.active_incidents} cls="accent" />
      <Card label="ALERTS" value={metrics.alerts} />
      <Card label="EVENTS INGESTED" value={metrics.events_ingested} />
      <Card label="AI INVESTIGATIONS" value={metrics.ai_investigations} />
      <Card
        label="INJECTION ATTEMPTS"
        value={metrics.injection_findings}
        cls={metrics.injection_findings > 0 ? "warn" : ""}
        sub="flagged, not obeyed"
      />
      <Card
        label="ACTIONS EXECUTED"
        value={metrics.responses.executed}
        sub={`${metrics.responses.dry_run} dry run · ${metrics.responses.pending} pending`}
      />
    </section>
  );
}
