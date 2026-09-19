# AWS SOC Checklist

Two uses:
1. **Posture review**: what a real AWS account should have in place.
2. **Coverage map**: which items the offline simulation detects today, so we
   know exactly what we can and can't claim in a demo.

Coverage key: **DETECTED** = a deterministic rule fires on it in the synthetic
data and a test proves it · **PARTIAL** = some of it · **GAP** = not covered
(stated honestly) · **POSTURE** = preventive control outside a SOC's detection
scope, listed so the pitch doesn't skip it.

Rule details: [app/soc_core/cloud_detections.py](../app/soc_core/cloud_detections.py).
Threats: [SOC_THREAT_MODEL.md §14](SOC_THREAT_MODEL.md) (CT1–CT11).

---

## IAM

| # | Check | Coverage |
|---|---|---|
| I-1 | **Least privilege.** No identity has `AdministratorAccess` or `Action: "*"` without a documented need; permission boundaries on delegated admins | **DETECTED** when granted: CLOUD-IAM-002 (managed admin policy, wildcard inline policy, default policy version). Unparsable policy documents fire rather than pass |
| I-2 | **MFA** on every human console user; hardware MFA on root | **DETECTED**: CLOUD-AUTH-001 on successful console login with `mfa_authenticated: false`. A missing MFA field is treated as unknown, not negative |
| I-3 | **Root account protection.** No root access keys; root used only for root-only tasks; alerts on any root use | **DETECTED**: CLOUD-ROOT-001 (any root activity), CLOUD-IAM-003 (root key creation). `root` is a protected response target |
| I-4 | **Access-key management.** Prefer roles/SSO over long-lived keys; rotate; no keys for humans; alert on keys created for someone else | **DETECTED**: CLOUD-IAM-003 fires on keys created for *another* identity or by root. Self-rotation deliberately does not alert |
| I-5 | **Role assumption hygiene.** Trust policies scoped; `sts:ExternalId` for third parties; alert on cross-account, chained, or external-source assumption | **DETECTED**: CLOUD-IAM-001 names which condition fired (`cross-account`, `role-chaining`, `external-source`) so known patterns can be dismissed fast |
| I-6 | **Privilege-escalation paths** (e.g. `iam:PassRole` + `lambda:CreateFunction`, `iam:UpdateAssumeRolePolicy`, `iam:CreateLoginProfile` on another user) | **PARTIAL**: policy-grant escalation detected; PassRole chains, trust-policy edits and login-profile creation are **GAPs** |
| I-7 | IAM Access Analyzer enabled; unused credentials removed | **POSTURE** |

## Logging

| # | Check | Coverage |
|---|---|---|
| L-1 | **CloudTrail** multi-region trail on, in every account, including management events | **POSTURE**. The simulation *consumes* CloudTrail-shaped events |
| L-2 | **Centralized logging.** Trails delivered to a separate log-archive account the workload accounts can't modify | **POSTURE**. Why it matters is modelled: the synthetic attacker stops the org trail but a separate data-events trail keeps recording |
| L-3 | **Log integrity.** Log-file validation on; S3 Object Lock / MFA delete on the log bucket | **POSTURE** |
| L-4 | **Monitoring configuration changes.** Alert on `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteFlowLogs` | **DETECTED**: CLOUD-LOG-001. Stop/delete is critical; narrowing is medium (it is also routine admin). Failed attempts still fire |
| L-5 | SCP denying `cloudtrail:StopLogging` / `DeleteTrail` outside a break-glass role | **POSTURE**. The strongest control here, because it prevents the event entirely |
| L-6 | GuardDuty / Config disabled (`DeleteDetector`, `StopConfigurationRecorder`) | **GAP**. Next rule to write (would map to T1562.001, not T1562.008) |

## Network

| # | Check | Coverage |
|---|---|---|
| N-1 | **Security groups.** No `0.0.0.0/0` or `::/0` ingress to admin/database ports | **DETECTED**: CLOUD-NET-001 on SSH/RDP/DB/Docker/Elastic/Redis ports or all-protocol rules. Port 443 to the world stays quiet by design |
| N-2 | **Public exposure actually used.** Accepted inbound connections from the internet to admin ports | **DETECTED**: CLOUD-NET-002 on VPC Flow Logs (`ACCEPT`, inbound, admin port, external source). Deliberately unmapped to ATT&CK: a flow proves a connection, not a login |
| N-3 | **VPC Flow Logs** enabled on every VPC; delivered centrally | **POSTURE** (consumed as `network` events) |
| N-4 | Beacon-shaped egress from instances | **DETECTED**: the existing endpoint rule SOC-NET-001 fires unchanged on VPC flow records. One engine, both telemetry types |
| N-5 | NACL changes, internet gateways attached to private VPCs, VPC peering to unknown accounts | **GAP** |

## Storage

| # | Check | Coverage |
|---|---|---|
| S-1 | **S3 exposure.** Block Public Access at account level; no `Principal: "*"` bucket policies | **GAP** for detection (`PutBucketPolicy`/`PutBucketAcl` making a bucket public); **POSTURE** for prevention |
| S-2 | **Unusual access.** Bulk reads of sensitive buckets from outside expected networks | **DETECTED**: CLOUD-S3-001 (≥3 reads, one identity + bucket, 10 min, external source), corroborated by CLOUD-GD-001 |
| S-3 | **Sensitive data access** logged: S3 **data events** enabled for sensitive buckets | **POSTURE**. Without data events, S-2 is blind |
| S-4 | Sensitive buckets inventoried | ⚠ `SENSITIVE_BUCKETS` is a hardcoded synthetic list. **Update it for real data or S-2 silently stops working** |

## Detection

| # | Check | Coverage |
|---|---|---|
| D-1 | **Suspicious API calls.** Enumeration bursts after credential compromise | **DETECTED**: CLOUD-API-001 (≥5 *distinct* List/Describe/Get calls, one identity, 5 min, external source). Repeating one API doesn't count |
| D-2 | **Identity anomalies.** Unusual source, chained roles, cross-account | **DETECTED**: CLOUD-IAM-001, CLOUD-AUTH-001, CLOUD-ROOT-001 |
| D-3 | **Privilege escalation** | **PARTIAL**: see I-1 / I-6 |
| D-4 | **Defense evasion.** Logging tampering, firewall opening | **DETECTED**: CLOUD-LOG-001 (T1562.008), CLOUD-NET-001 (T1562.007); both add the `impair_defenses` risk factor |
| D-5 | **Vendor findings integrated**, not siloed | **DETECTED**: CLOUD-GD-001 promotes GuardDuty ≥7.0 into our pipeline so it correlates; ATT&CK mapped only for finding types with a clean 1:1 meaning |
| D-6 | **Correlation across identities.** Assumed-role sessions linked to the role that issued them | **DETECTED** by correlation: the `role:` entity ties AssumeRole to every later call in that session, even from a different IP. Account IDs are deliberately *not* entities |
| D-7 | First-seen/geo baselines per identity | **GAP**. Rules use static internal prefixes, not learned baselines |

## AI

| # | Check | Coverage |
|---|---|---|
| A-1 | **Prompt injection in logs.** CloudTrail records attacker-chosen text verbatim: `User-Agent`, role/policy descriptions, tags, session names | **DETECTED**: `screen_for_injection()` flags cev-0023 (role description) and cev-0026 (User-Agent). Reported, never stripped; severity stays critical |
| A-2 | **Sensitive data leakage** to a hosted model | **PARTIAL**. No egress exists today (MockAIAnalyst). Redaction at TB-3 **must** be built before any hosted model; incident data includes identities, ARNs, bucket keys |
| A-3 | **Hallucinated remediation.** Invented actions, wrong targets, understated tiers | **DETECTED**: unknown `response_action` dropped and flagged; tier must equal policy tier (a "T1" `disable_iam_user` is flagged); target must appear in incident evidence |
| A-4 | **Excessive agency.** The AI holds cloud permissions | **ENFORCED**: the AI pipeline has **no** cloud credentials. It proposes enum values; `CLOUD_ACTIONS` are dry-run only, refused in the base class even with approval |
| A-5 | **Human approval** | **ENFORCED**: every cloud action is T2/T3. `approved_by` is never taken from model output. Rejections are audited (`record_rejection`). The demo's approvals are a clearly labelled SIMULATED table |
| A-6 | Protected responder identities | **ENFORCED**: `root`, `break-glass-admin`, `OrganizationAccountAccessRole` can never be actioned |

---

## Before any cloud action runs for real

All of these, not some of them:

- [ ] Dedicated responder role: MFA-gated, break-glass path, permissions = the allow-list and nothing more
- [ ] Protected identities excluded in the responder role's **IAM policy**, not only in our gate
- [ ] Pre-change snapshot of key status / policy attachments / SG rules stored before acting (that snapshot is the rollback)
- [ ] Every AWS API call tagged with `incident_id` and approver so CloudTrail independently records authorization
- [ ] Response audit stored outside the affected account (an attacker who stops CloudTrail must not erase *our* record)
- [ ] Kill switch that disables all cloud response
- [ ] `SENSITIVE_BUCKETS`, protected identities and internal ranges updated for the real environment
- [ ] Redaction in place if any incident data will reach a hosted LLM
