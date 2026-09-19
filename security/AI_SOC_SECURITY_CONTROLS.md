# AI SOC — Security Controls

Control-by-control record of what is **implemented in code today**, what is
deliberately deferred, and what must be built before anything touches a real
system.

Companion documents: [SOC_THREAT_MODEL.md](SOC_THREAT_MODEL.md) (threats T1–T20),
[../architecture/SOC_DATA_FLOW.md](../architecture/SOC_DATA_FLOW.md) (where each
control sits in the flow).

Status key: **IMPLEMENTED** · **PARTIAL** · **DEFERRED** (by design, with the
trigger that would change it)

---

## 0. Control summary

| # | Control | Threat | Status |
|---|---|---|---|
| 1 | Prompt injection defenses | T1 | IMPLEMENTED |
| 2 | Indirect prompt injection | T1 | IMPLEMENTED |
| 3 | Malicious log content handling | T4, T6 | IMPLEMENTED |
| 4 | Excessive agency limits | T15 | IMPLEMENTED |
| 5 | Sensitive data exposure | T11, T12 | PARTIAL |
| 6 | Unsafe automated response | T18 | IMPLEMENTED |
| 7 | Model hallucination | — | IMPLEMENTED |
| 8 | False positives | T16 | IMPLEMENTED |
| 9 | False negatives | T5 | PARTIAL |
| 10 | Auditability | A4 | PARTIAL |
| 11 | Human approval | T15, T18 | IMPLEMENTED |
| 12 | Least privilege | T14 | DEFERRED |
| 13 | Secrets management | A5 | IMPLEMENTED (by absence) |

---

## 1. Prompt injection — IMPLEMENTED

**Threat.** Log content is attacker-authored. Any LLM downstream of a log
pipeline is processing hostile text by construction.

**Controls in code:**

| Layer | Implementation | Where |
|---|---|---|
| Screening | `screen_for_injection()` — 11 patterns over every untrusted field | `providers/ai_analyst.py` |
| Unicode normalization | NFKC + zero-width/bidi stripping before matching | `_normalize()` |
| Report, never strip | Findings carry `event_id`, `field_path`, `pattern`, excerpt | `InjectionFinding` |
| Screen everything | Runs on **all** ingested events, not just correlated ones | `demo.run_pipeline()` |
| Structural immunity | `MockAIAnalyst` composes from templates; never interprets log text as language | `MockAIAnalyst` |
| Output validation | Citations, technique IDs, action claims, tier discipline | `validate_analysis()` |
| No tool authority | AI emits proposed names; a closed enum resolves them | `requests_from_analysis()` |
| Human gate | Tier ≥ T2 requires an approver | `ResponseProvider.execute()` |

**Test cases:** `evt-0016` (direct instruction injection), `evt-0024`
(delimiter smuggling — embeds `<<<END_UNTRUSTED_EVENT_DATA>>>` in a filename).
Demonstrate with `--scenario H`. Tests assert severity is *not* downgraded and
the incident is *not* closed when injected content is present.

**Honest limits.** Pattern screening is a heuristic and will miss novel
phrasings. It is one layer, not the defense. The structural controls — the AI
has no tools, output is validated, humans approve consequences — are what
actually hold. An injection that merely *biases* a narrative without tripping a
pattern remains possible, which is why the evidence path is independent of the
AI path.

---

## 2. Indirect prompt injection — IMPLEMENTED

The dangerous variant: nobody typed the payload at the AI: it arrived through
routine telemetry. Process names, filenames, DNS queries, user-agents, TLS SNI,
usernames and TI descriptions are all attacker-writable and all land in logs.

**Additional control beyond §1:** `summarize_event()` withholds command lines
and DNS names from timeline strings. Timelines are rendered in UIs, exported
and passed to other components; keeping them to structured fields prevents an
injection payload being carried into a component that never screened for it.
Asserted by `test_timeline_summary_withholds_untrusted_free_text`.

**Required before wiring a real model** (prompt contract is written, not yet
enforced in code because no real model is integrated):

- Event data inside untrusted delimiters, never in the instruction region.
- **Escape any occurrence of the delimiter in the data first** — `evt-0024`
  exists to make this failure mode concrete.
- Restate the "data, not instruction" rule *after* the untrusted block.
- Pass screening findings in as metadata rather than expecting the model to
  notice unaided.

---

## 3. Malicious log content — IMPLEMENTED

| Vector | Control |
|---|---|
| Field smuggling / delimiter injection | Structural JSON parsing; never regex-splitting trusted-looking text |
| Oversized fields | `MAX_FIELD_LENGTH` (4096) on top-level string fields and `raw`. **Not** enforced on strings nested inside `details`/`aux` (e.g. `process.command_line`) — see residual risk 8 |
| Malformed records | `EventValidationError`; **one bad record fails the batch** — no silent drops |
| Duplicate IDs | `parse_events()` rejects duplicates |
| Unicode evasion | NFKC + zero-width/bidi stripping in screening |
| Unknown enum values | Category, severity and outcome validated against closed sets |
| Naive timestamps | Rejected; tz-aware UTC required |
| Unbounded queries | `EventQuery.limit`, capped by `MAX_QUERY_LIMIT` |

**Design note.** Validation answers *"is this structurally a valid event?"* — it
never decides content is safe. `evt-0016` is a perfectly valid event carrying a
hostile payload, and it is accepted. Conflating structure with safety is how
pipelines end up dropping evidence.

**Deferred:** malicious file/document input (T7). Nothing in the core sim opens
attachments. If the problem statement introduces file input, a sandboxed,
resource-capped, network-isolated parser is required — do not add it to the
main path.

---

## 4. Excessive agency — IMPLEMENTED

Any tool the model can reach becomes reachable by anyone who can write a log
line.

| Control | Implementation |
|---|---|
| No tools on the AI | `MockAIAnalyst` returns data; there is no execution path from it |
| Closed action set | `ResponseAction` enum — 7 actions; `delete_all_logs` cannot be invented |
| Prose → enum boundary | `requests_from_analysis()`; unmappable text is **dropped** |
| Approval never from the model | `approved_by=None` always set by the mapper, regardless of what the model claims |
| Target validation | `allowed_targets` — cannot act on an entity absent from the evidence |
| Tier gating | T2/T3 require a human approver |
| Blast-radius cap | `max_actions` per provider instance |
| Protected assets | DCs, IdP, cloud control plane, file server, service accounts — never auto-actioned, even with approval |
| Base-class enforcement | Gates live in `ResponseProvider.execute()`; implementations override only `_perform()` |

**Tested:** `test_drops_unmappable_actions`, `test_never_carries_approval_from_the_model`,
`test_protected_asset_never_actioned`, `test_blast_radius_limit`.

---

## 5. Sensitive data exposure — PARTIAL

**Implemented:** no egress at all in the core simulation — `MockAIAnalyst` makes
no network calls, so TB-3 does not exist today. `Incident.to_dict()` excludes
`raw` log text by default, making inclusion of untrusted content a deliberate
choice. The dataset contains no real credentials, and a test scans for
token-shaped strings (`sk-…`, `AKIA…`, `ghp_…`).

**Not implemented — required before any real LLM is wired in:**

- **Field minimization** at TB-3: send only what the analysis needs.
- **Secret redaction** on the way out *and* on the way back (a model can quote a
  secret it saw into a summary that then gets mailed or ticketed).
- Pseudonymization of identifiers where the analysis still works.
- Log the call — model, prompt hash, token counts, latency — **not** the payload.
- Tenant/role scoping of incident visibility.

This is the largest honest gap in the current build, and it is gated on a
decision we do not yet have: whether a hosted model is permitted at all.

---

## 6. Unsafe automated response — IMPLEMENTED

The scenario that matters: an attacker forges events implicating a domain
controller and induces the SOC to cause its own outage.

| Control | Implementation |
|---|---|
| **Dry run by default** | `dry_run=True`; executing requires explicit construction |
| Mock cannot act | `MockResponseProvider._perform()` appends to a list; no code path touches a real system |
| Protected assets | Refused regardless of tier or approval |
| Corroboration | Risk scoring rewards independent rules; single low-confidence alerts score low |
| Evidence before containment | The mock analyst orders artifact collection (T1) *before* proposing isolation (T2) |
| Rollback awareness | `REVERSIBLE` map; `disable_account` is marked irreversible |
| Audit of refusals | Refusals are recorded, not discarded |

**Demo evidence:** in a default run, `isolate_host → DC-CORP-01` is refused as
protected, `isolate_host → WKS-FIN-014` is refused for lack of an approver,
`disable_account → svc_backup` is refused as protected. **Zero executed.**

**Required before real execution:** a tested rollback path per action, a visible
kill switch, scoped credentials held only by the orchestrator, and rate limits
enforced centrally rather than per-integration.

---

## 7. Model hallucination — IMPLEMENTED

Mechanical checks, not trust:

| Check | Catches |
|---|---|
| Cited `event_id`s must exist in the incident | Fabricated evidence |
| Technique IDs must exist in the pinned catalog | Invented ATT&CK IDs |
| `DetectionResult` rejects unknown techniques at construction | A *rule* citing a bad technique |
| `incident_id` must match | Cross-incident confusion |
| Confidence must be in the closed set | Malformed output |

The pinned ATT&CK subset ([mitre.py](../app/soc_core/mitre.py)) is deliberately
*closed*. A technique ID outside it is a defect, not a discovery — that is what
makes validation meaningful. Extend the catalog first, then use the ID.

`test_base_class_applies_validation_automatically` proves a deliberately rogue
implementation (fake event IDs, `T0000`, "I have disabled the account") is
caught without the implementation cooperating.

---

## 8. False positives — IMPLEMENTED

A noisy system gets ignored, which is a security failure in its own right.

- **Benign control scenario A** — six ordinary events (interactive logons, a
  `git fetch`, a signed installer, routine DNS). `test_benign_scenario_produces_no_alerts`
  asserts **zero** alerts and fails loudly with the offending rule IDs.
- **Honest confidence** — `SOC-DNS-001` is `low` confidence because entropy
  flags legitimate CDN hostnames.
- **Disjoint rules** — spray excludes MFA denials so the two alerts do not
  double-count the same evidence.
- **Documented false positives** — every Sigma rule must populate
  `falsepositives`; a test enforces it.
- **Uncertainty is never empty** — the analyst output always states what it
  cannot confirm, and names low-confidence contributing rules.
- **Transparent risk** — an analyst can see exactly which factors produced a
  score and disagree with a specific one.

---

## 9. False negatives — PARTIAL

Harder to control and worth stating plainly.

**Implemented:** eight rules across signature, threshold and statistical layers,
so evasion of one layer does not evade all; threshold rules use sliding windows
rather than fixed buckets (splitting activity across a bucket boundary does not
hide it); a broken rule cannot silence the rest; every attack scenario has a
test asserting it still produces alerts — a coverage regression fails the suite.

**Known gaps:**

- Detection coverage is 8 rules, not a real ruleset.
- No alerting on *absence* of expected logs (a silenced agent is invisible).
- No ingest-rate anomaly detection (volume-based burial, T5).
- The AI cannot add detections; it only interprets. Deliberate — but it means
  novel behavior no rule covers goes unflagged.

**Mitigation posture:** the system never auto-closes an incident, so a false
negative degrades to "not surfaced" rather than "actively dismissed".

---

## 10. Auditability — PARTIAL

**Implemented:** `ResponseProvider.audit_log` records every request — action,
target, tier, status, detail, approver, timestamp — **including refusals**.
`executed_count` distinguishes real changes from dry runs. Alerts carry the
rule and the evidence that produced them. The pipeline is deterministic, so a
run is reproducible from the same input. Analyses record the model identity and
any validation warnings.

**Not implemented:** durable append-only storage (the audit log is in-memory and
dies with the process), tamper-evidence, analyst decision capture, and retention
policy. These need the persistence layer described in
[docs/SOC_TECH_STACK.md](../docs/SOC_TECH_STACK.md) §4 — an `INSERT`-only role
with no `UPDATE`/`DELETE`.

---

## 11. Human approval — IMPLEMENTED

```
T0 read-only          automatic
T1 reversible, small  automatic, audited, rate-limited
T2 disruptive         human approval required
T3 destructive/wide   human approval required
```

`ResponseRequest.requires_approval` derives from the action's tier — it is not
a field a caller can set. Approval comes from a human via `approved_by` or the
action is refused; `requests_from_analysis()` hardcodes `approved_by=None`, so
the model cannot approve its own proposal however it phrases things.
`validate_analysis()` separately flags any analysis claiming a T2+ action needs
no approval.

**Anti-automation-bias measures:** AI text labelled with its model; evidence
carries citations; uncertainty always populated; analyst questions surfaced;
action status must come from the orchestrator's audit records, never from model
prose.

---

## 12. Least privilege — DEFERRED

Nothing in the core simulation has privileges: no credentials, no database, no
network, no real systems. There is nothing yet to scope.

**Required when real integrations land:**

- SIEM reads via a read-only service account scoped to the minimum indices.
- The AI pipeline's identity gets read access to incidents and **nothing else**;
  response credentials live only in the orchestrator.
- Per-tenant/role scoping enforced at the data layer, not the UI — the AI
  pipeline should run with the *requesting user's* effective permissions, never
  a service superuser.
- Separate credentials per integration so one compromise is not total.

This becomes **P0** if the scenario is multi-tenant.

---

## 13. Secrets management — IMPLEMENTED (by absence)

**Current state:** there are no secrets. No API keys, no tokens, no database
credentials, no network calls. Every placeholder provider raises
`NotImplementedError` in its constructor rather than silently attempting a
connection.

**Rules for when secrets arrive** (documented at each placeholder):

- Environment variables only — `ANTHROPIC_API_KEY`, `SPLUNK_TOKEN`,
  `OLLAMA_HOST`. Never in code, prompts, logs, or the repository.
- Fail fast at startup if a required secret is missing; never degrade silently
  into an unauthenticated path.
- `.env` is gitignored; `.env.example` is committed with placeholder values.
- Never log a token, never put one in a URL query string, never include one in
  a prompt.
- A test scans the dataset for credential-shaped strings, guarding against a
  real token being pasted into fixtures.

---

## 14. Residual risk

Stated plainly, because a controls document that claims completeness is not
trustworthy:

1. **Pattern-based injection screening is evadable.** Novel phrasings will pass.
   Structural controls are the real defense.
2. **No redaction exists yet** because nothing leaves the boundary yet. This
   must be built before any hosted model is wired in.
3. **The audit log is not durable.** In-memory only.
4. **Detection coverage is a demonstration**, not a real ruleset.
5. **`MockAIAnalyst`'s injection immunity does not transfer.** It is immune
   because it does not read prose. A real model will not inherit that property;
   only the downstream controls transfer.
6. **Correlation can over-merge.** Entity + time is a heuristic; a shared
   workstation or a jump host could merge unrelated activity. `GENERIC_ENTITIES`
   mitigates but does not solve this.
7. **No authentication or authorization anywhere** — there is no API and no user
   model yet.
8. **Nested field lengths are unbounded.** `MAX_FIELD_LENGTH` covers top-level
   fields and `raw` only; a nested `command_line` of any size is accepted.
   Before real data or a real model, enforce the cap on every string reached by
   `iter_untrusted_text()` (or truncate at prompt assembly) so one oversized
   field cannot blow out a context window.

---

## 15. Pre-deployment checklist

Before this touches anything real:

- [ ] Redaction and field minimization at the LLM boundary
- [ ] Durable, append-only audit storage with an `INSERT`-only role
- [ ] AuthN/AuthZ on every entry point; data-layer tenant scoping
- [ ] Scoped, least-privilege credentials per integration
- [ ] Tested rollback for every automatable action
- [ ] Visible kill switch for all automated response
- [ ] Rate limits and token/cost caps on every external path
- [ ] Adversarial corpus (`prompts/`) re-run on every prompt change
- [ ] Detection tuning against the target environment's real baseline
- [ ] Decision: is autonomous response required? If yes, T15/T18 need a fresh,
      explicit risk argument — the current answer is "a human approves anything
      disruptive"
