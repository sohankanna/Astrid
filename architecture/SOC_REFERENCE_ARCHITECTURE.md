# AI-Assisted SOC — Reference Architecture

**Status:** foundation / pre-problem-statement. Generic by design.
**Track:** AI in Blue Teaming & Security Operations.
**Purpose:** a reusable skeleton we adapt once the hackathon problem statement lands. Nothing here is built yet beyond the event schema in [app/soc_core/events.py](../app/soc_core/events.py).

The governing idea: **the AI is an analyst aid, not an authority.** Deterministic code decides what is detected and what is executed. The LLM explains, correlates and drafts. Every consequential action crosses a human or a policy gate.

---

## 1. Design principles

| # | Principle | Consequence in the architecture |
|---|---|---|
| 1 | Detection is deterministic | Sigma/rule engine produces alerts; the LLM never creates an alert on its own |
| 2 | LLM output is untrusted data | Model output is parsed, schema-validated, and never executed or interpolated into a command |
| 3 | Log content is untrusted input | Event text is delimited, labelled and screened before it reaches a prompt |
| 4 | Least agency | The model proposes actions; a policy engine and/or a human authorizes them |
| 5 | Everything is attributable | Every AI conclusion carries the event IDs it rests on; unsupported claims are a defect |
| 6 | Fail closed | If enrichment, validation, or the model fails, the alert goes to a human — it is never auto-closed |
| 7 | Explainable over clever | An analyst must be able to reconstruct why something was flagged |

---

## 2. Component view

```
                          ┌─────────────────────────────────────────────┐
 UNTRUSTED ZONE           │              TRUSTED ZONE (ours)            │
                          │                                             │
┌──────────────┐  TB-1    │  ┌─────────────┐      ┌──────────────────┐  │
│ Log sources  │──────────┼─▶│ 1 Ingestion │─────▶│ 2 Normalization  │  │
│ EDR, IdP,    │          │  │  + AuthN    │      │   + Validation   │  │
│ DNS, NetFlow │          │  └─────────────┘      └────────┬─────────┘  │
│ Cloud, Email │          │                                │            │
└──────────────┘          │                                ▼            │
                          │                       ┌──────────────────┐  │
┌──────────────┐  TB-2    │                       │ 3 Event Store    │  │
│ Threat intel │──────────┼──────────────────────▶│   (Postgres)     │  │
│ STIX/TAXII   │          │                       └────────┬─────────┘  │
└──────────────┘          │                                │            │
                          │                                ▼            │
                          │  ┌──────────────────────────────────────┐   │
                          │  │ 4 Detection Engine (deterministic)   │   │
                          │  │   Sigma rules · thresholds · stats   │   │
                          │  └──────────────┬───────────────────────┘   │
                          │                 │ alerts                    │
                          │                 ▼                           │
                          │  ┌──────────────────────────────────────┐   │
                          │  │ 5 Correlation / Incident Builder     │   │
                          │  │   groups alerts → incident           │   │
                          │  └──────────────┬───────────────────────┘   │
                          │                 ▼                           │
                          │  ┌──────────────────────────────────────┐   │
                          │  │ 6 Enrichment (asset, identity, TI)   │   │
                          │  └──────────────┬───────────────────────┘   │
                          │                 ▼                           │
              TB-3        │  ┌──────────────────────────────────────┐   │
   ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┼──│ 7 AI Analysis Pipeline               │   │
   │  LLM provider        │  │   sanitize → prompt → validate       │   │
   │  (external or local) │  └──────────────┬───────────────────────┘   │
   └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┼─────────────────│                           │
                          │                 ▼                           │
                          │  ┌──────────────────────────────────────┐   │
                          │  │ 8 Triage Output (structured verdict) │   │
                          │  └──────────────┬───────────────────────┘   │
                          │                 ▼                           │
              TB-4        │  ┌──────────────────────────────────────┐   │
                          │  │ 9 Analyst Console — human decision   │   │
                          │  └──────────────┬───────────────────────┘   │
                          │                 ▼                           │
              TB-5        │  ┌──────────────────────────────────────┐   │
                          │  │ 10 Response Orchestrator             │   │
                          │  │    policy gate → approved actions    │   │
                          │  └──────────────┬───────────────────────┘   │
                          │                 ▼                           │
                          │  ┌──────────────────────────────────────┐   │
                          │  │ 11 Audit Log (append-only)           │   │
                          │  └──────────────────────────────────────┘   │
                          └─────────────────────────────────────────────┘
```

### Component responsibilities

| # | Component | Responsibility | Must NOT do |
|---|---|---|---|
| 1 | **Ingestion API** | Authenticate senders, rate-limit, bound payload size, queue | Parse deeply or trust `source` claims |
| 2 | **Normalizer** | Map vendor formats to the common schema, reject malformed records loudly | Silently drop or "repair" records |
| 3 | **Event store** | Durable, queryable, retention-bounded event history | Store secrets or raw credentials |
| 4 | **Detection engine** | Deterministic rules (Sigma), thresholds, simple baselining | Ask an LLM whether something is an alert |
| 5 | **Correlation** | Group related alerts into one incident by entity + time window | Merge across tenants |
| 6 | **Enrichment** | Add asset criticality, identity context, TI reputation | Follow attacker-supplied URLs (SSRF) |
| 7 | **AI analysis** | Summarize, hypothesize, map to ATT&CK, propose actions | Execute anything, or invent evidence |
| 8 | **Triage output** | Schema-validated verdict object with citations | Contain free-form instructions to systems |
| 9 | **Analyst console** | Present evidence + AI draft side by side; capture decisions | Render model output as trusted HTML |
| 10 | **Response orchestrator** | Execute *approved*, allow-listed actions with rollback | Accept an action name straight from the model |
| 11 | **Audit log** | Append-only record of every input, verdict, decision, action | Be mutable by the app's normal role |

---

## 3. Data flow

**Happy path, end to end:**

1. **Collect** — agent/forwarder POSTs a batch to the ingestion API over TLS with a per-source credential.
2. **Admit** — API authenticates the source, checks rate limits and size caps, writes to a queue. Nothing is parsed yet.
3. **Normalize** — worker maps the batch to the common event schema. Structural validation only: field presence, enum membership, timestamp sanity, length bounds. Invalid records are rejected to a dead-letter queue with a reason, never silently dropped.
4. **Persist** — validated events land in the event store, partitioned by time, tagged with tenant and source.
5. **Detect** — the detection engine evaluates rules against the stream and emits alerts with `rule_id`, matched event IDs, and a base severity.
6. **Correlate** — alerts sharing an entity (host, user, IP) within a time window become one incident.
7. **Enrich** — the incident gains asset criticality, identity role, and TI reputation from *local* lookups.
8. **Analyze (AI)** — sanitized incident context goes to the model; a structured verdict comes back and is validated.
9. **Present** — analyst sees the evidence, the AI draft, and the confidence, clearly separated.
10. **Decide** — analyst confirms, edits, escalates, or dismisses.
11. **Respond** — approved actions run through the orchestrator against an allow-list.
12. **Record** — every step is appended to the audit log.

**Normalized event schema** (implemented, see [app/soc_core/events.py](../app/soc_core/events.py)):

```
event_id, timestamp (UTC, tz-aware), source, category, action,
outcome, severity, host{}, user{}, <category detail>{}, raw
category ∈ {authentication, process, network, dns, alert}
```

Sample data: [data/sample_security_events.json](../data/sample_security_events.json).

---

## 4. Trust boundaries

| ID | Boundary | What crosses | Control |
|---|---|---|---|
| **TB-1** | Log source → ingestion | Attacker-influenced event text | Per-source authN, TLS, rate limit, size cap, schema validation, no deserialization of active content |
| **TB-2** | Threat intel feed → enrichment | Third-party indicators | Signed/pinned feeds, treat descriptions as data, never auto-action on TI alone |
| **TB-3** | Our system → LLM provider | Incident context (may contain sensitive data) | Redaction/minimization before send, no secrets, provider contract reviewed, output re-validated on return |
| **TB-4** | System → analyst UI | AI-generated text | Rendered as escaped text, evidence and inference visually separated, no live links from untrusted fields |
| **TB-5** | Decision → production systems | Response actions | Allow-listed action types, policy gate, human approval for destructive actions, full audit, rollback plan |

**The most important boundary is TB-3 in reverse.** Everything coming *back* from the model is untrusted output, on the same footing as the log line that went in.

---

## 5. Detection pipeline (deterministic)

```
events ──▶ [rule matching] ──▶ [threshold/aggregation] ──▶ [baseline deviation] ──▶ alerts
             Sigma-style         e.g. 5 failed logons       e.g. first-seen
             field predicates    from one IP in 60s         country for user
```

Three cooperating layers, all explainable:

1. **Signature / rule layer** — Sigma-style conditions over normalized fields. Deterministic, version-controlled, testable. In the sample data: `evt-0008` (Office spawning encoded PowerShell) fires here.
2. **Threshold / aggregation layer** — counting over a window keyed by an entity. `evt-0002..0005` (four failed logons from `203.0.113.45` in ~50s across distinct users) is a password-spray threshold hit.
3. **Statistical / baseline layer** — simple first-seen and rate-of-change checks (new destination, unusual data volume, odd hour). `evt-0017` (14k S3 reads by a service principal) is a volume deviation.

Each alert records: rule identity, the event IDs that matched, the field values that caused the match, and a base severity. This is the **evidence** the AI is later allowed to reason over — and the only thing it may cite as fact.

**The LLM is not in this pipeline.** It may later help *author* rules offline, with human review before merge, but it does not evaluate them at runtime.

---

## 6. AI analysis pipeline

```
incident ──▶ [1 select]  bounded set of events, most relevant first
         ──▶ [2 minimize] drop/redact fields the task does not need
         ──▶ [3 screen]   flag injection-looking strings, keep them as data
         ──▶ [4 frame]    system prompt + clearly delimited UNTRUSTED block
         ──▶ [5 infer]    LLM call, timeout + token + cost caps
         ──▶ [6 validate] parse to strict schema; reject on failure
         ──▶ [7 ground]   every claim must cite event_ids that exist
         ──▶ [8 emit]     verdict object → console (never → executor)
```

**Stage notes**

- **(1) Select** — cap the number of events and total tokens. An incident with 50k events gets a sampled, summarized view, never a dump.
- **(2) Minimize** — TB-3 crossing. Strip anything the analysis does not need (tokens, cookies, full paths containing user data). Pseudonymize identifiers where the task allows.
- **(3) Screen** — run `iter_untrusted_text()` over each event, flag strings resembling instructions ("ignore previous", "you are now", tool-call syntax). Flagged content is **kept and shown**, annotated as a suspicious string — it is itself a finding. `evt-0016` in the sample data exists to exercise this.
- **(4) Frame** — system prompt states the rules; event data goes inside an explicit untrusted delimiter and is never concatenated into the instruction section. See [prompts/SOC_ANALYST_PROMPT.md](../prompts/SOC_ANALYST_PROMPT.md).
- **(6) Validate** — output must parse to the agreed schema (summary, findings, ATT&CK mappings, confidence, recommended actions, citations). Malformed output = retry once, then fail to human review.
- **(7) Ground** — reject or downgrade any finding citing an `event_id` not in the incident. This is a cheap, effective hallucination check and should be a test.
- **(8) Emit** — the verdict is a *proposal*. It flows to the console, never directly to the orchestrator.

**Optional local pre-filter.** A small local model (Ollama) can triage obvious noise before any external call, reducing cost and data egress. Its output is advisory only and subject to the same validation.

---

## 7. Human analyst interaction

The console is where the "AI-assisted" claim is won or lost. Requirements:

- **Evidence first.** Raw matched events are the primary panel; the AI narrative is secondary and visibly labelled as AI-generated.
- **Evidence vs. inference.** The verdict schema separates `evidence` (facts with event ID citations) from `assessment` (interpretation, with confidence). The UI must preserve that separation, not blend them into prose.
- **Every claim clickable.** A finding cites event IDs; clicking shows those exact events. An uncited claim is displayed as unsupported.
- **Uncertainty shown, not hidden.** Confidence is displayed. Low confidence routes to a human by default.
- **Decisions are first-class.** Confirm / edit / escalate / dismiss, each with an optional reason, all captured. Analyst disagreement is the training signal for improving prompts and rules.
- **No silent automation.** If the system took an action, the console shows what, when, by whose authority, and how to roll it back.
- **Injection surfaced.** If stage 3 flagged content, the console says so prominently: *"This incident contains text that attempts to manipulate automated analysis."*

---

## 8. Incident response flow

```
 detect ─▶ triage ─▶ [AI draft] ─▶ ANALYST DECISION ─▶ contain ─▶ eradicate ─▶ recover ─▶ review
                                          │
                        ┌─────────────────┴──────────────────┐
                        │  policy gate before any action     │
                        │  · action in allow-list?           │
                        │  · blast radius within limit?      │
                        │  · destructive → human approval    │
                        │  · rate limit not exceeded?        │
                        │  · rollback defined?               │
                        └────────────────────────────────────┘
```

**Action tiering** — the single most important control on excessive agency:

| Tier | Examples | Authorization |
|---|---|---|
| **T0 — Read-only** | Query logs, look up asset owner, check local TI cache | Automatic |
| **T1 — Reversible, low blast radius** | Tag incident, notify analyst, open ticket, add watchlist entry | Automatic, audited, rate-limited |
| **T2 — Disruptive, reversible** | Isolate one host, disable one session, block one IP | Human approval required |
| **T3 — Destructive or wide** | Disable account, org-wide block, delete artifacts, mass isolation | Human approval + second approver |

The AI may *propose* any tier. It may *trigger* nothing above T1, and it never executes directly — it emits a proposed action name that the orchestrator resolves against a static allow-list. An action name the orchestrator does not recognize is rejected and logged, not improvised.

**Post-incident review** feeds back into rules (new Sigma rule), prompts (a failure mode to guard), and the injection corpus (a new adversarial test case).

---

## 9. What we would build first

Smallest viable slice once the problem statement arrives, in order:

1. Ingest + normalize + validate the sample dataset (**done** — parser and tests exist).
2. Two or three deterministic detections over that data.
3. Correlate alerts into one incident.
4. One AI triage call with strict output validation + citation grounding.
5. A minimal console view: evidence panel, AI draft panel, decide button.
6. Response as *proposals only*, written to the audit log — no real execution during a hackathon demo.

Deliberately deferred: real SIEM integration, multi-tenancy, streaming at scale, autonomous response.

---

## 10. Open questions for the problem statement

See the summary in the project notes; the architecture-critical ones are: which log sources are in scope, whether response execution is required or simulated, whether an external LLM is permitted, and whether a human-in-the-loop is assumed or the scenario demands autonomy.
