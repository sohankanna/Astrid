// Presentation-only helpers. Nothing here derives security meaning: labels
// map backend enum values to display text, and nothing more.

export const ACTION_LABELS: Record<string, string> = {
  isolate_host: "ISOLATE HOST",
  disable_account: "DISABLE ACCOUNT",
  block_ip: "BLOCK SOURCE IP",
  block_domain: "BLOCK DOMAIN",
  collect_artifact: "COLLECT ARTIFACT",
  create_ticket: "CREATE INCIDENT TICKET",
  notify_analyst: "NOTIFY ANALYST",
  revoke_access_key: "REVOKE ACCESS KEY",
  disable_iam_user: "DISABLE IAM USER",
  detach_policy: "DETACH POLICY",
  isolate_ec2_instance: "ISOLATE EC2 INSTANCE",
  modify_security_group: "MODIFY SECURITY GROUP",
  block_network_indicator: "BLOCK NETWORK INDICATOR",
};

export const STATUS_LABELS: Record<string, string> = {
  NEW: "NEW",
  INVESTIGATING: "INVESTIGATING",
  AWAITING_APPROVAL: "AWAITING APPROVAL",
  RESPONSE_REVIEWED: "RESPONSE REVIEWED",
  PENDING_APPROVAL: "PENDING APPROVAL",
  READY: "READY (NO APPROVAL NEEDED)",
  DRY_RUN_COMPLETE: "APPROVED · DRY RUN",
  BLOCKED_BY_POLICY: "BLOCKED BY POLICY",
  REJECTED: "REJECTED",
  EXECUTED: "EXECUTED",
};

// ATT&CK Enterprise tactic order: a fixed public taxonomy, not data.
export const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export function sevClass(severity: string | null | undefined): string {
  return `sev-${(severity ?? "informational").toLowerCase()}`;
}

export function clock(iso: string): string {
  const d = new Date(iso);
  return d.toISOString().slice(11, 19);
}

export function dateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)} UTC`;
}

export function relative(iso: string | null, now: number): string {
  if (!iso) return "—";
  const seconds = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

export function incidentLabel(id: string): string {
  return id.toUpperCase();
}

export function humanize(value: string): string {
  return value.replace(/_/g, " ");
}
