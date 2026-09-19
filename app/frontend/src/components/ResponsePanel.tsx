import type { IncidentDetail } from "../types";
import { ACTION_LABELS, STATUS_LABELS, humanize } from "../format";
import { Layer } from "./Layer";

interface Props {
  detail: IncidentDetail;
  busy: string | null;
  onPlan: () => void;
  onDecide: (actionId: string, decision: "approve" | "reject") => void;
}

const RISK_CLASS: Record<string, string> = {
  LOW: "sev-low",
  HIGH: "sev-high",
  CRITICAL: "sev-critical",
};

export function ResponsePanel({ detail, busy, onPlan, onDecide }: Props) {
  const plan = detail.response_plan;
  const hasAnalysis = detail.analysis !== null;
  const executed = plan?.filter((a) => a.executed).length ?? 0;

  return (
    <section className="block response-panel">
      <header className="block-head">
        <h3>RECOMMENDED RESPONSE</h3>
        <Layer kind="response" />
      </header>
      <div className="dry-run-banner">
        <strong>SIMULATED · DRY RUN</strong>
        <span>
          Approving runs policy gates and records what <em>would</em> happen. No host, account, key or network is
          ever changed. Cloud actions are dry-run only in this build.
        </span>
      </div>

      {plan === null ? (
        <div className="ai-empty">
          <p>No response plan yet.</p>
          <p className="muted">
            {hasAnalysis
              ? "Generate a plan from the AI recommendations. Every action is checked against policy on the server."
              : "Run the AI investigation first; the plan is derived from its recommendations."}
          </p>
          <button className="btn primary" disabled={!hasAnalysis || busy === "plan"} onClick={onPlan}>
            {busy === "plan" ? "BUILDING PLAN…" : "GENERATE RESPONSE PLAN"}
          </button>
        </div>
      ) : (
        <>
          {detail.manual_tasks.length > 0 && (
            <div className="manual-tasks">
              <label>MANUAL TASKS: for a human; never automated</label>
              {detail.manual_tasks.map((t) => (
                <div key={t.action}>☐ {t.action}</div>
              ))}
            </div>
          )}
          {plan.length === 0 && <div className="empty small">No automatable actions proposed.</div>}
          <div className="actions-grid">
            {plan.map((a) => {
              const open = a.status === "PENDING_APPROVAL" || a.status === "READY";
              const deciding = busy === a.action_id;
              return (
                <article key={a.action_id} className={`action-card status-${a.status.toLowerCase()}`}>
                  <header>
                    <span className="action-name">{ACTION_LABELS[a.action] ?? humanize(a.action).toUpperCase()}</span>
                    <span className={`sev-badge small ${RISK_CLASS[a.risk] ?? ""}`}>RISK {a.risk}</span>
                  </header>
                  <div className="action-kv">
                    <span>Target</span>
                    <code>{a.target}</code>
                    <span>Reason</span>
                    <span>{a.reason}</span>
                    <span>Policy</span>
                    <span>
                      tier {a.tier} · {a.reversible ? "reversible" : "NOT reversible"} ·{" "}
                      {a.requires_approval ? "human approval required" : "no approval required"}
                    </span>
                    <span>Status</span>
                    <strong className={`action-status status-${a.status.toLowerCase()}`}>
                      {STATUS_LABELS[a.status] ?? a.status}
                    </strong>
                  </div>
                  {a.outcome_detail && (
                    <div className="outcome">
                      {a.outcome_detail}
                      {a.would_have && <div className="muted">{a.would_have}</div>}
                      {a.decided_by && <div className="muted">decided by: {a.decided_by}</div>}
                    </div>
                  )}
                  {open && (
                    <div className="action-buttons">
                      <button className="btn approve" disabled={deciding} onClick={() => onDecide(a.action_id, "approve")}>
                        {deciding ? "…" : "✓ APPROVE"}
                      </button>
                      <button className="btn reject" disabled={deciding} onClick={() => onDecide(a.action_id, "reject")}>
                        ✕ REJECT
                      </button>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
          <div className="response-foot">
            Actions actually executed: <strong>{executed}</strong>
          </div>
        </>
      )}
    </section>
  );
}
