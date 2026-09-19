# Evidence Context Engine + AI Investigator (Stage 2)

**Principle: raw security telemetry is never sent to an LLM.** The model
receives a compact, deterministic, redacted *context pack* built from the
evidence the detection and correlation engines already selected, and nothing else.

```
RAW EVENTS ─▶ DETECTION ─▶ CORRELATION ─▶ INCIDENT
                                            │
                              EVIDENCE CONTEXT ENGINE   (app/soc_core/evidence_context.py)
                     relevant events → dedupe/aggregate → rank → budget → redact
                                            │
                                     CONTEXT PACK (JSON, ~2–12K tokens)
                                            │  outbound secret tripwire
                                            ▼
                         AI PROVIDER  (ClaudeAnalyst | MockAIAnalyst fallback)
                                            │
                  VALIDATION (AIAnalyst base class): citations resolve, techniques
                  come from the engine, no action claims, policy tiers
                                            ▼
                          STRUCTURED, EVIDENCE-CITED INVESTIGATION
```

## 1. Evidence reduction (deterministic, no LLM)

| Step | What it does | Why |
|---|---|---|
| **Relevant events** | Alert evidence + *contextual* events that share an entity (user/host/IP/role/key) with the incident inside ±30 min | Surfaces state transitions no rule fired on, e.g. the **successful logon** after a password spray (`evt-0006`), Run-key persistence, ADMIN$ access |
| **Deduplication / aggregation** | Events with the same (category, action, outcome, source, destination, and host/process/principal where relevant) collapse once a group reaches 3 | 500 failed logins become **one** item: count, distinct accounts, first/last seen, representative events |
| **Timeline compression** | One timeline entry per evidence item; every change of category/outcome is flagged `state_transition` | Failure → success → execution survives compression |
| **Entity extraction** | users, hosts, IPs, domains, processes, file hashes, AWS principals, roles, resources, accounts, access keys | Normalized, each linked to the evidence IDs it appears in |
| **Detection context** | Each item lists the rule IDs that made it relevant | Nothing in the pack is unexplained |
| **MITRE enrichment** | Only techniques the deterministic engine mapped, with the rules and evidence behind each | The model interprets ATT&CK; it cannot add to it |
| **Ranking** | Additive, named components (below) | Explainable ordering and budget trimming |
| **Budget** | Lowest-ranked *contextual* items are dropped first; **detection evidence is never dropped**; every reference to a dropped item is removed from the pack | Bounded context regardless of raw volume |

**Evidence score** (every item carries its breakdown):

| Component | Points |
|---|---|
| `detection_match` | 40 if any rule cited the event, +5 per additional rule (max +10) |
| `entity_link` | 5 per other evidence item sharing an entity (max 20) |
| `temporal_relevance` | 15 if detection evidence; 12 within 5 min of one; 6 within 30 min |
| `attack_stage_relevance` | 0–15, scaled by the furthest ATT&CK tactic of its techniques |
| `severity` | critical 10 · high 7 · medium 4 · low 1 |
| `rarity` | 5 if the (category, action) occurs ≤2 times in the whole dataset |

## 2. Context pack schema (`evidence-context/1.0`)

```jsonc
{
  "schema": "evidence-context/1.0",
  "incident":   { "incident_id", "title", "severity", "first_seen", "last_seen", "attack_stage", "hosts", "accounts", "rule_ids" },
  "risk":       { "classification": "CORRELATED", "score", "band", "severity" },
  "entities":   [ { "id": "N01", "type", "value", "evidence_ids", "first_seen", "last_seen" } ],
  "timeline":   [ { "time", "until", "evidence_id", "summary", "detections", "state_transition" } ],
  "detections": [ { "id": "D01", "classification": "CORRELATED", "rule_id", "title", "severity", "confidence", "techniques", "matched", "evidence_ids" } ],
  "mitre":      [ { "classification": "CORRELATED", "technique_id", "name", "tactic", "mapped_by_rules", "evidence_ids" } ],
  "relationships": [ { "id": "R01", "classification": "CORRELATED", "from", "to", "via", "delta_seconds" } ],
  "evidence":   [ { "id": "E01", "classification": "OBSERVED", "kind": "event|aggregate", "role": "detection_evidence|context",
                    "first_seen", "last_seen", "count", "fields", "untrusted_text", "injection_flagged",
                    "detections", "techniques", "event_ids", "event_id_count", "aggregate", "evidence_score", "rank" } ],
  "inferences": [ { "classification": "INFERRED", "basis", "statement", "evidence_ids" } ],
  "benign_context": { "excluded_events", "excluded_by_category" },
  "response_context": { "mode": "DRY_RUN", "allowed_actions", "protected_assets", "target_rule" },
  "context_metrics": { "raw_events", "relevant_events", "evidence_objects", "estimated_tokens" }
}
```

**Fact classes.** `OBSERVED` (telemetry), `CORRELATED` (deterministic engine),
`INFERRED` (deterministic inference, stated as such). `AI_RECOMMENDATION`
never appears in the pack; it is reserved for model output.

Serialization is canonical (sorted keys, compact) and escapes `<` and `>`, so no
string inside the pack can close the prompt's `<evidence_context>` delimiter.

Inspect it live: `GET /api/incidents/{id}/context`, or the **view exact context
pack** link in the console.

## 3. Redaction policy (`app/soc_core/redaction.py`)

| Class | Examples | Treatment |
|---|---|---|
| **Secrets** | passwords, `-p` CLI passwords, bearer tokens, JWTs, AWS secret keys, API keys (`sk-…`, `ghp_…`, `xox…`, `AIza…`), private-key blocks, `user:pass@` URL credentials, any field named `password/secret/token/…` | **Destroyed** → `[REDACTED_<KIND>]`. Irreversible. |
| **Identifiers** | usernames, emails, AWS access key IDs, AWS account IDs | **Pseudonymized consistently** → `USER_003`, `ACCESS_KEY_002`, `AWS_ACCOUNT_001`. Same value → same token, so correlation survives. The reverse map stays **server-side only**. |
| **Operational** | hostnames, IPs, domains, processes, hashes, role names, SG/instance/bucket IDs | **Kept.** Deleting them would destroy the investigation. |

- Any value pseudonymized in a structured field is also replaced wherever it
  appears in free text (a username inside a file path, an account ID in a title).
- Model output that names a pseudonym (`revoke ACCESS_KEY_002`) is resolved
  back to the real value **server-side**. The response provider then still
  enforces target-in-evidence, tiers, protected assets and dry-run.
- **Outbound tripwire:** the Claude provider refuses to send any payload that
  still matches a secret pattern. Nothing is sent, and the request fails over.
- Tests plant literal secrets and assert by plain substring search that none
  reach the payload, independent of the redaction regexes.

## 4. Token estimation

Deterministic and offline: `tokens ≈ ceil(chars / 3.5)` over the canonical
JSON. It's conservative for identifier-dense JSON; expect about ±20% against a real
tokenizer. Reported as `estimated_tokens`, `estimated_output_tokens` (a planning
estimate of 2,500) and `estimated_total_tokens`. When Claude is actually called,
the **measured** `input_tokens` / `output_tokens` from the API response are
shown alongside. Cost modelling lives in the AI Efficiency Lab (`docs/AI_EFFICIENCY_LAB.md`).

## 5. AI providers

| Mode | Behaviour | Network |
|---|---|---|
| `SOC_AI_PROVIDER=mock` *(default)* | `MockAIAnalyst`, deterministic | none |
| `SOC_AI_PROVIDER=claude` | `ClaudeAnalyst` (`claude-opus-5`); on **any** failure the service falls back to the mock and reports `provider.used="mock"` plus `fallback_reason` | Claude only |

Claude call (official `anthropic` SDK, installed in `app/.venv` only, imported lazily):

- `client.beta.messages.create(model, system=SYSTEM_PROMPT, messages=[redacted pack], output_config={"format": {"type": "json_schema", ...}}, betas=["server-side-fallback-2026-07-01"], fallbacks="default")`
- **Structured output** is enforced by JSON schema. The response is additionally
  shape-checked, and malformed output raises and falls back.
- **Server-side refusal fallback is enabled** (`fallbacks: "default"`). Security
  content such as "LSASS credential dumping" can trigger safety classifiers, and
  the API then re-runs the request on Anthropic's recommended fallback model. A
  final `refusal` still fails over to the mock.
- Timeout 90 s (connect 5 s), 1 retry. Errors are mapped to short,
  secret-free reasons; the API key is never logged or returned.

**Validation (base class, applies to every provider):** citations must resolve
to evidence IDs in the pack (unresolved claims are kept but marked
`supported: false` and shown as **UNSUPPORTED · not a finding**); techniques
must be engine-mapped; no claims that an action was performed; action tiers
come from policy, never from the model.

### Configure

```powershell
# Mock / offline (default)
$env:SOC_AI_PROVIDER="mock"; app\.venv\Scripts\python.exe -m app.api

# Claude
$env:SOC_AI_PROVIDER="claude"; $env:ANTHROPIC_API_KEY="<your key>"
app\.venv\Scripts\python.exe -m app.api
# optional: $env:SOC_CLAUDE_MODEL="claude-opus-5"; $env:SOC_CLAUDE_TIMEOUT="90"
```

On a machine running Splunk (port 8000), add `$env:SOC_API_PORT="8001"` to both
the backend and `npm --prefix app/frontend run dev`.

## 6. Benchmarks (`scripts/benchmark_context.py`)

Synthetic data: 30% spray burst, one success, 70% noise (half on the targeted
DC). Nothing is sent to any model.

| Raw events | Detection | Correlation | **Context build** | Relevant | Evidence | ~Tokens |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 0.001 s | 0.001 s | **0.011 s** | 66 | 16 | 6,866 |
| 1,000 | 0.003 s | 0.003 s | **0.019 s** | 651 | 16 | 8,284 |
| 10,000 | 0.027 s | 0.028 s | **0.071 s** | 4,971 | 16 | 8,666 |
| 50,000 | 0.133 s | 0.147 s | **0.214 s** | 16,971 | 16 | 8,668 |

The context build is linear in events: one pass for relevance, hash grouping,
and binary search for temporal distance. The context size levels off
independent of raw volume. Correlation stays pairwise over *alerts*; it's cheap
here (one alert) but remains the known O(n²) item for alert-heavy datasets.

## 7. Known limitations

- Token counts are estimates until a live call returns measured usage.
- No live Claude call has been verified in this environment (no API key was
  configured). The provider is tested against a fake client that mirrors the
  SDK's response shape, and the no-credential fallback was verified live in the console.
- Hostnames and IPs are deliberately kept for investigative value; environments
  that treat them as sensitive should extend `PSEUDONYM_FIELDS`.
- Secret detection is pattern-based. Novel secret formats need new patterns,
  and the tripwire only catches what the patterns recognise.
- `SENSITIVE_*` detection constants and protected assets remain tuned to the
  synthetic datasets.
