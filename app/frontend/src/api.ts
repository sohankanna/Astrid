// The only module that talks to the network. Every call is to a fixed,
// same-origin /api path (proxied by Vite to 127.0.0.1:8000). IDs are
// validated before being placed in a path, so the UI can never be steered
// into requesting an arbitrary URL.

import type {
  AlertView,
  AnalyzeResult,
  AttackPath,
  BenchmarkStatus,
  CanonicalResult,
  CostComparison,
  CostRequest,
  Fidelity,
  LiveUsage,
  ContextPack,
  EventView,
  Health,
  IncidentDetail,
  IncidentSummary,
  InjectionFinding,
  Metrics,
  ResponsePlan,
  PlannedAction,
  ScenarioInfo,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const INCIDENT_ID = /^inc-\d{4}$/;
const SCENARIO_ID = /^[a-z0-9-]{1,40}$/;
const ACTION_ID = /^act-\d{2,3}$/;
export const BENCHMARK_SCALES = [100, 1_000, 10_000, 50_000, 100_000, 1_000_000] as const;

function checked(value: string, pattern: RegExp, kind: string): string {
  if (!pattern.test(value)) throw new ApiError(`Invalid ${kind} identifier.`, 400);
  return value;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError("SOC API unreachable. Is the backend running? (python -m app.api)", 0);
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    // Our API always answers errors with JSON. A non-JSON 5xx comes from the
    // dev proxy, which means the backend itself is not reachable.
    if (body === null && response.status >= 500) {
      throw new ApiError("SOC API unreachable. Is the backend running? (python -m app.api)", 0);
    }
    const message =
      body && typeof body === "object" && "error" in body && typeof (body as { error: unknown }).error === "string"
        ? (body as { error: string }).error
        : response.status >= 500
          ? "SOC API error. No state was changed."
          : `Request failed (${response.status}).`;
    throw new ApiError(message, response.status);
  }
  return body as T;
}

export const api = {
  health: () => request<Health>("/api/health"),
  metrics: () => request<Metrics>("/api/metrics"),
  incidents: () => request<IncidentSummary[]>("/api/incidents"),
  incident: (id: string) =>
    request<IncidentDetail>(`/api/incidents/${checked(id, INCIDENT_ID, "incident")}`),
  alerts: () => request<AlertView[]>("/api/alerts"),
  events: () => request<EventView[]>("/api/events"),
  screening: () => request<InjectionFinding[]>("/api/screening"),
  scenarios: () => request<ScenarioInfo[]>("/api/scenarios"),
  runScenario: (id: string) =>
    request<Metrics>(`/api/scenarios/${checked(id, SCENARIO_ID, "scenario")}/run`, { method: "POST" }),
  analyze: (id: string) =>
    request<AnalyzeResult>(`/api/incidents/${checked(id, INCIDENT_ID, "incident")}/analyze`, { method: "POST" }),
  context: (id: string) =>
    request<ContextPack>(`/api/incidents/${checked(id, INCIDENT_ID, "incident")}/context`),
  responsePlan: (id: string) =>
    request<ResponsePlan>(`/api/incidents/${checked(id, INCIDENT_ID, "incident")}/response-plan`, {
      method: "POST",
    }),
  decide: (id: string, actionId: string, decision: "approve" | "reject", reason?: string) =>
    request<{ action: PlannedAction; plan: ResponsePlan }>(
      `/api/incidents/${checked(id, INCIDENT_ID, "incident")}/approve-response`,
      {
        method: "POST",
        body: JSON.stringify({ action_id: checked(actionId, ACTION_ID, "action"), decision, reason }),
      },
    ),
  efficiencyStatus: () => request<BenchmarkStatus>("/api/efficiency/benchmark"),
  runBenchmark: (scales: number[], force = false) => {
    if (!scales.length || scales.some((s) => !(BENCHMARK_SCALES as readonly number[]).includes(s))) {
      throw new ApiError("Invalid benchmark scale.", 400);
    }
    return request<BenchmarkStatus>("/api/efficiency/benchmark", {
      method: "POST",
      body: JSON.stringify({ scales, force }),
    });
  },
  fidelity: () => request<Fidelity>("/api/efficiency/fidelity"),
  cost: (body: CostRequest) =>
    request<CostComparison>("/api/efficiency/cost", { method: "POST", body: JSON.stringify(body) }),
  live: () => request<LiveUsage>("/api/efficiency/live"),
  attackPath: () => request<AttackPath>("/api/canonical/attack-path"),
  canonical: (refresh = false) =>
    request<CanonicalResult>(`/api/efficiency/canonical${refresh ? "?refresh=true" : ""}`),
};
