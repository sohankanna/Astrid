import type { IncidentDetail } from "../types";
import { Layer } from "./Layer";
import { AiContext } from "./AiContext";
import { Citations, InvestigationSections } from "./Citations";

interface Props {
  detail: IncidentDetail;
  busy: boolean;
  onAnalyze: () => void;
}

// Renders ONLY what the backend analyst returned. No text is generated here.
export function AiPanel({ detail, busy, onAnalyze }: Props) {
  const analysis = detail.analysis;
  return (
    <section className="block ai-panel">
      <header className="block-head">
        <h3>
          <span className="ai-glyph">◈</span> AI SECURITY ANALYST
        </h3>
        <Layer kind="ai" />
        {analysis && <span className="model-tag">model: {analysis.model} · advisory only</span>}
      </header>

      <AiContext detail={detail} />

      {!analysis ? (
        <div className="ai-empty">
          <p>AI investigation not yet run.</p>
          <p className="muted">
            The analyst reads the correlated evidence above and explains it. It cannot create alerts, change the
            risk score, or take actions.
          </p>
          <button className="btn ai" onClick={onAnalyze} disabled={busy}>
            {busy ? "INVESTIGATING…" : "◈ RUN AI INVESTIGATION"}
          </button>
        </div>
      ) : (
        <div className="ai-grid">
          {analysis.injection_attempt_detected && (
            <div className="injection-alert compact">
              <strong>⚠ Manipulation attempt detected in evidence</strong>
              <span>
                The analyst reported it and did not follow it. Severity stayed at{" "}
                {analysis.severity_assessment.toUpperCase()}.
              </span>
            </div>
          )}

          <div className="ai-section wide">
            <label>SUMMARY: what happened</label>
            <p>{analysis.summary}</p>
          </div>

          <Citations analysis={analysis} timeline={detail.timeline} />
          <InvestigationSections analysis={analysis} />

          <div className="ai-section">
            <label>ATTACK ASSESSMENT: why it is suspicious</label>
            <div className="ai-kv">
              <span>Severity assessment</span>
              <strong>{analysis.severity_assessment.toUpperCase()}</strong>
              <span>Likely attack stage</span>
              <strong>{analysis.likely_attack_stage ?? "—"}</strong>
              <span>Confidence</span>
              <strong>{analysis.confidence.toUpperCase()}</strong>
            </div>
            <ul className="ai-list">
              {analysis.evidence.map((item, i) => (
                <li key={`why-${i}`}>{item.detail ?? item.observation}</li>
              ))}
            </ul>
          </div>

          <div className="ai-section">
            <label>EVIDENCE: supporting events (cited, validated)</label>
            <ul className="ai-list">
              {analysis.evidence.map((item, i) => (
                <li key={`ev-${i}`}>
                  <strong>{item.observation}</strong>
                  <div className="chips">
                    {item.event_ids.map((id) => (
                      <code key={id} className="chip">
                        {id}
                      </code>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div className="ai-section">
            <label>MITRE MAPPING</label>
            <div className="chips">
              {analysis.technique_ids.map((t) => (
                <span key={t} className="tech-chip">
                  {t}
                </span>
              ))}
            </div>
          </div>

          <div className="ai-section">
            <label>IMPACT: from deterministic risk factors</label>
            <ul className="ai-list">
              {detail.risk.factors.map((f) => (
                <li key={f.name}>{f.reason}</li>
              ))}
            </ul>
          </div>

          <div className="ai-section">
            <label>RECOMMENDATION: next steps for the analyst</label>
            <ul className="ai-list">
              {analysis.recommended_actions.map((a, i) => (
                <li key={`rec-${i}`}>
                  {a.action} <span className="muted">({a.tier}{a.requires_human_approval ? ", needs approval" : ""})</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="ai-section">
            <label>QUESTIONS FOR THE ANALYST</label>
            <ul className="ai-list">
              {analysis.analyst_questions.map((q, i) => (
                <li key={`q-${i}`}>{q}</li>
              ))}
            </ul>
          </div>

          <div className="ai-section wide">
            <label>UNCERTAINTY: what the AI cannot confirm</label>
            <ul className="ai-list">
              {analysis.uncertainty.map((u, i) => (
                <li key={`u-${i}`}>{u}</li>
              ))}
            </ul>
          </div>

          <div className={`validation ${analysis.validation_warnings.length ? "bad" : "good"}`}>
            {analysis.validation_warnings.length ? (
              <>
                <strong>OUTPUT VALIDATION WARNINGS</strong>
                {analysis.validation_warnings.map((w, i) => (
                  <div key={`w-${i}`}>{w}</div>
                ))}
              </>
            ) : (
              <strong>
                ✓ OUTPUT VALIDATED: every cited event exists · every ATT&amp;CK ID is real · no claim that an
                action was taken
              </strong>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
