// Shapes returned by the SOC API (app/api/service.py). Kept in one place so
// the UI never guesses at a field that the backend does not produce.

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export interface Health {
  status: string;
  soc_online: boolean;
  environment: string;
  siem: { provider: string; connected: boolean; mode: string };
  ai_analyst: { provider: string; name: string; fallback: string | null; ready: boolean };
  response_engine: { provider: string; mode: string; armed: boolean };
  active_scenario: string | null;
  rule_errors: string[];
}

export interface ScenarioInfo {
  scenario_id: string;
  name: string;
  description: string;
  group: string;
  profile: string;
  expect_alerts: boolean;
  active?: boolean;
}

export interface Metrics {
  scenario: ScenarioInfo & { started_at: string };
  alert_severity: Record<Severity, number>;
  incident_severity: Record<Severity, number>;
  active_incidents: number;
  alerts: number;
  events_ingested: number;
  ai_investigations: number;
  injection_findings: number;
  responses: { pending: number; dry_run: number; blocked: number; rejected: number; executed: number };
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  risk_band: string;
  confidence: string | null;
  alert_count: number;
  event_count: number;
  technique_ids: string[];
  first_seen: string | null;
  last_seen: string | null;
  status: string;
  sources: string[];
  domain: "endpoint" | "cloud" | "hybrid";
  hosts: string[];
  users: string[];
  cloud_accounts: string[];
  attack_stage: string | null;
  injection_detected: boolean;
}

export interface Technique {
  technique_id: string;
  name: string;
  tactic: string;
}

export interface ChainNode {
  step: number;
  rule_id: string;
  label: string;
  title: string;
  tactic: string;
  techniques: Technique[];
  severity: Severity;
  confidence: string;
  first_seen: string;
  alert_ids: string[];
  event_ids: string[];
  matched_fields: Record<string, string>;
}

export interface MitreEntry extends Technique {
  detected_by: {
    rule_id: string;
    alert_id: string;
    title: string;
    description: string;
    confidence: string;
    matched_fields: Record<string, string>;
  }[];
  event_ids: string[];
}

export interface EventView {
  event_id: string;
  timestamp: string;
  category: string;
  action: string;
  outcome: string;
  severity: Severity;
  source: string;
  user: string | null;
  host: string | null;
  account_id: string | null;
  source_ip: string | null;
  destination: string | null;
  rules: string[];
  injection_flags: string[];
  untrusted_fields: Record<string, string>;
  summary?: string;
}

export interface AlertView {
  alert_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: string;
  evidence_event_ids: string[];
  technique_ids: string[];
  matched_fields: Record<string, string>;
  first_seen: string | null;
  incident_id: string | null;
}

export interface RiskFactor {
  name: string;
  points: number;
  reason: string;
  evidence: string[];
}

export interface Analysis {
  incident_id: string;
  summary: string;
  severity_assessment: Severity;
  evidence: { observation: string; detail?: string; event_ids: string[]; rule_confidence?: string }[];
  likely_attack_stage: string | null;
  technique_ids: string[];
  recommended_actions: {
    action: string;
    rationale: string;
    tier: string;
    requires_human_approval: boolean;
    response_action?: string | null;
    target?: string;
  }[];
  confidence: string;
  uncertainty: string[];
  analyst_questions: string[];
  injection_attempt_detected: boolean;
  injection_findings: InjectionFinding[];
  model: string;
  validation_warnings: string[];
  proposed_only: boolean;
  citations: Citation[];
  investigation: Record<string, unknown>;
}

export interface Citation {
  claim: string;
  classification: "OBSERVED" | "CORRELATED" | "INFERRED" | "AI_RECOMMENDATION";
  evidence_ids: string[];
  invalid_evidence_ids: string[];
  event_ids: string[];
  supported: boolean;
}

export interface ContextMetrics {
  raw_events: number;
  relevant_events: number;
  detection_events: number;
  contextual_events: number;
  evidence_objects: number;
  aggregated_groups: number;
  timeline_entries: number;
  entities: number;
  relationships: number;
  dropped_by_budget: number;
  redacted_field_count: number;
  pseudonymized_value_count: number;
  distinct_pseudonyms: number;
  estimated_tokens: number;
  estimated_output_tokens: number;
  estimated_total_tokens: number;
  token_estimator: string;
}

export interface AiRun {
  requested: string;
  used: string;
  fallback_reason: string | null;
  live_model: boolean;
  model?: string;
  usage?: { input_tokens: number | null; output_tokens: number | null; served_by?: string } | null;
}

export interface AnalyzeResult {
  provider: AiRun;
  investigation: Analysis;
  context_metrics: ContextMetrics;
}

export interface ContextPack {
  incident_id: string;
  metrics: ContextMetrics;
  pack: Record<string, unknown>;
}

export interface InjectionFinding {
  event_id: string;
  field_path: string;
  pattern: string;
  excerpt: string;
  incident_id?: string | null;
}

export interface PlannedAction {
  action_id: string;
  action: string;
  target: string;
  reason: string;
  tier: string;
  risk: string;
  reversible: boolean;
  requires_approval: boolean;
  status: "PENDING_APPROVAL" | "READY" | "DRY_RUN_COMPLETE" | "BLOCKED_BY_POLICY" | "REJECTED" | "EXECUTED";
  decided_by: string | null;
  decision_reason: string | null;
  outcome_detail: string | null;
  would_have: string | null;
  executed: boolean;
}

export interface ManualTask {
  action: string;
  rationale: string;
  target: string | null;
}

export interface ResponsePlan {
  incident_id: string;
  mode: string;
  operator: string;
  actions: PlannedAction[];
  manual_tasks: ManualTask[];
  executed_count: number;
}

export interface IncidentDetail {
  incident: IncidentSummary;
  risk: { score: number; band: string; factors: RiskFactor[] };
  attack_chain: ChainNode[];
  mitre: MitreEntry[];
  timeline: EventView[];
  correlated: {
    alerts: AlertView[];
    rule_ids: string[];
    hosts: string[];
    users: string[];
    source_ips: string[];
    cloud_accounts: string[];
    attack_stage: string | null;
    notes: string[];
  };
  injection_findings: InjectionFinding[];
  analysis: Analysis | null;
  response_plan: PlannedAction[] | null;
  manual_tasks: ManualTask[];
  ai_context: { metrics: ContextMetrics; last_run: AiRun | null; configured_provider: string };
}
