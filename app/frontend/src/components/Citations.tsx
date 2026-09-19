import { useMemo, useState } from "react";
import type { Analysis, EventView } from "../types";
import { clock } from "../format";

const CLASS_LABEL: Record<string, string> = {
  OBSERVED: "OBSERVED",
  CORRELATED: "CORRELATED",
  INFERRED: "INFERRED",
  AI_RECOMMENDATION: "AI RECOMMENDATION",
};

/** AI statement -> evidence IDs -> the actual supporting events.
 *  Unsupported claims are shown as such, never as findings. */
export function Citations({ analysis, timeline }: { analysis: Analysis; timeline: EventView[] }) {
  const [open, setOpen] = useState<number | null>(null);
  const events = useMemo(() => new Map(timeline.map((e) => [e.event_id, e])), [timeline]);
  if (!analysis.citations.length) return null;
  return (
    <div className="ai-section wide">
      <label>FINDINGS WITH EVIDENCE: click a claim to see the events behind it</label>
      <ul className="citations">
        {analysis.citations.map((c, i) => (
          <li key={`cite-${i}`} className={c.supported ? "" : "unsupported"}>
            <button className="citation-row" onClick={() => setOpen(open === i ? null : i)}>
              <span className={`claim-class cls-${c.classification.toLowerCase()}`}>
                {CLASS_LABEL[c.classification] ?? c.classification}
              </span>
              <span className="claim-text">{c.claim}</span>
              {c.supported ? (
                <span className="claim-ids">{c.evidence_ids.join(" · ") || "—"}</span>
              ) : (
                <span className="claim-unsupported">UNSUPPORTED · not a finding</span>
              )}
            </button>
            {open === i && (
              <div className="citation-events">
                {c.invalid_evidence_ids.length > 0 && (
                  <div className="warn-text">Cited IDs not in the evidence context: {c.invalid_evidence_ids.join(", ")}</div>
                )}
                {c.event_ids.length === 0 ? (
                  <div className="muted">No supporting events.</div>
                ) : (
                  c.event_ids.map((id) => {
                    const e = events.get(id);
                    return (
                      <div key={id} className="citation-event">
                        <code>{id}</code>{" "}
                        {e ? (
                          <>
                            {clock(e.timestamp)} · {e.summary ?? e.action}
                            {e.rules.length > 0 && <span className="muted"> · {e.rules.join(", ")}</span>}
                          </>
                        ) : (
                          <span className="muted">contextual event (no detection fired on it)</span>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function rows(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((v): v is Record<string, unknown> => !!v && typeof v === "object") : [];
}

/** Extended sections only a context-aware provider (Claude) returns. */
export function InvestigationSections({ analysis }: { analysis: Analysis }) {
  const inv = analysis.investigation ?? {};
  const assessment = text(inv.attack_assessment);
  const impact = text(inv.impact_assessment);
  const timeline = rows(inv.timeline_interpretation);
  const assets = rows(inv.affected_assets);
  const identities = rows(inv.compromised_identities);
  const mitre = rows(inv.mitre_interpretation);
  if (!assessment && !impact && !timeline.length && !assets.length && !identities.length && !mitre.length) return null;
  const ids = (r: Record<string, unknown>) =>
    Array.isArray(r.evidence_ids) && r.evidence_ids.length ? ` [${(r.evidence_ids as string[]).join(", ")}]` : "";
  return (
    <>
      {assessment && (
        <div className="ai-section wide">
          <label>ATTACK ASSESSMENT (AI)</label>
          <p>{assessment}</p>
        </div>
      )}
      {timeline.length > 0 && (
        <div className="ai-section">
          <label>TIMELINE INTERPRETATION</label>
          <ul className="ai-list">
            {timeline.map((t, i) => (
              <li key={`ti-${i}`}>
                {String(t.interpretation ?? "")}
                <span className="muted">{ids(t)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {(assets.length > 0 || identities.length > 0) && (
        <div className="ai-section">
          <label>AFFECTED ASSETS / IDENTITIES</label>
          <ul className="ai-list">
            {assets.map((a, i) => (
              <li key={`as-${i}`}>
                <strong>{String(a.asset ?? "")}</strong> · {String(a.role ?? "")}
                <span className="muted">{ids(a)}</span>
              </li>
            ))}
            {identities.map((a, i) => (
              <li key={`id-${i}`}>
                <strong>{String(a.identity ?? "")}</strong> · {String(a.status ?? "")} compromise
                <span className="muted">{ids(a)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {mitre.length > 0 && (
        <div className="ai-section">
          <label>MITRE INTERPRETATION (engine-mapped only)</label>
          <ul className="ai-list">
            {mitre.map((m, i) => (
              <li key={`mi-${i}`}>
                <code>{String(m.technique_id ?? "")}</code> {String(m.interpretation ?? "")}
                <span className="muted">{ids(m)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {impact && (
        <div className="ai-section wide">
          <label>IMPACT ASSESSMENT (AI)</label>
          <p>{impact}</p>
        </div>
      )}
    </>
  );
}
