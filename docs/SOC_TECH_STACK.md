# AI-Assisted SOC — Technology Stack

**Status:** foundation / pre-problem-statement. **Nothing here is installed yet.**
The repository currently runs on the Python standard library alone — [app/soc_core/events.py](../app/soc_core/events.py) and [tests/test_security_events.py](../tests/test_security_events.py) have zero third-party dependencies, deliberately.

This document records *what we would reach for and why*, so that when the problem statement lands we add dependencies with a justification already written, per the "do not introduce dependencies without explaining why" rule in CLAUDE.md.

---

## 1. Decision summary

| Layer | Choice | Why | Add when |
|---|---|---|---|
| Core service | **Python 3.11+ / FastAPI** | Security tooling ecosystem lives in Python | We need an HTTP ingestion or triage API |
| Typed console/CLI | **Node 20 / TypeScript** | Only if a UI is required | A UI is in scope (currently out of scope) |
| Primary store | **PostgreSQL 16** | Relational incidents + JSONB events + time partitioning | Persistence beyond a single process |
| Cache / queue | **Redis 7** | Rate limits, dedup, short-lived queue | Rate limiting or async workers |
| Packaging | **Docker + Compose** | Reproducible demo environment | Deployment is needed (currently out of scope) |
| Detection content | **Sigma** | Vendor-neutral, portable, reviewable rules | First detection rule |
| Adversary framing | **MITRE ATT&CK** | Shared taxonomy for findings | First AI triage output |
| Intel exchange | **STIX 2.1 / TAXII 2.1** | Standard indicator format | External intel is in scope |
| LLM (hosted) | **Claude (Anthropic API)** | Strong reasoning, structured output, tool discipline | AI analysis stage is built |
| LLM (local) | **Ollama** | Zero data egress, offline demo, no cost | Sensitive data or unreliable network |

**Python version:** 3.11+ for the modern typing syntax already used in `soc_core`. The environment on this machine is 3.13.

---

## 2. Python / FastAPI

**Role:** ingestion API, normalization workers, detection engine, AI analysis pipeline, response orchestrator.

**Why:** Python is where security tooling already is — Sigma converters, STIX libraries, pandas for baselining, every LLM SDK. FastAPI gives request validation via type hints (which we already use), automatic OpenAPI docs, and async I/O that suits a pipeline dominated by network waits.

**Likely packages, each with a reason:**

| Package | Reason | Security note |
|---|---|---|
| `fastapi` + `uvicorn` | HTTP API, ASGI server | Bind to localhost for demos; no debug mode in shared environments |
| `pydantic` v2 | Declarative validation at trust boundaries | Would replace the hand-rolled validation in `soc_core.events`; keep the same fail-loud semantics |
| `sqlalchemy` (already vendored in `app/.venv`) + `alembic` | ORM + migrations; parameterized queries by default | Never `text()` with f-strings |
| `redis` | Rate limiting, dedup, queue | AUTH enabled, never exposed publicly |
| `httpx` | Outbound HTTP with timeouts | Timeouts mandatory; redirects disabled on enrichment paths (SSRF, T8) |
| `pysigma` + backends | Compile Sigma rules to executable queries | Rule files are supply chain — review before load |
| `stix2` / `taxii2-client` | Parse and fetch intel | Treat all TI text as untrusted data |
| `anthropic` | Claude API client | Key from environment only |
| `pytest` + `pytest-asyncio` | Test runner | **Not installed** — tests currently target stdlib `unittest`, which pytest also collects |
| `python-dotenv` | Local `.env` loading | `.env` is gitignored; `.env.example` is committed |

**Structure we would grow into** (extends the existing `app/`):

```
app/
  soc_core/        events.py (done) · detections.py · incidents.py · redaction.py
  api/             ingest.py · incidents.py · auth.py · deps.py
  ai/              prompt.py · client.py · schema.py · grounding.py
  response/        actions.py (allow-list) · policy.py · orchestrator.py
  storage/         models.py · repositories.py
```

**Security posture:** authN on every route; request size caps and rate limits at the edge; all validation at the boundary; secrets from `os.environ` with startup failure if missing; structured logging that never records credentials or full prompt payloads.

---

## 3. Node / TypeScript

**Role:** analyst console, if a UI is required. Currently **out of scope** per the project instructions.

**Why:** if we build a console, TypeScript with a typed client generated from FastAPI's OpenAPI schema keeps the verdict contract honest across the boundary. Candidate stack: Vite + React + TanStack Query, or Next.js if SSR is wanted.

**Alternative that avoids Node entirely:** server-rendered Jinja2 templates from FastAPI, or a Rich/Textual terminal UI. For a hackathon demo this is often the better trade — one language, no build step.

**Security notes if we do build it:**
- Log-derived text is untrusted (TB-4). Render as escaped text; never `dangerouslySetInnerHTML`, never auto-linkify a field an attacker controls.
- Strict Content-Security-Policy; no inline scripts.
- Tokens in `httpOnly`, `SameSite=Strict` cookies — not `localStorage`.
- The UI enforces nothing: every authorization decision is re-made server-side.
- AI-generated text must be visually distinguishable from raw evidence (T16, automation bias).

---

## 4. PostgreSQL

**Role:** durable store for events, alerts, incidents, verdicts, analyst decisions, and the audit log.

**Why:** we need relational integrity for the incident model *and* flexible storage for heterogeneous event details. Postgres gives both — normalized columns for the common schema plus `JSONB` for the category-specific detail object, with GIN indexes for containment queries. Native time partitioning handles retention. A dedicated timeseries store is unnecessary at hackathon scale.

**Schema sketch:**

```
events(event_id PK, ts, tenant_id, source, category, action,
       outcome, severity, host JSONB, "user" JSONB, details JSONB, raw TEXT)
       PARTITION BY RANGE (ts)
alerts(alert_id PK, rule_id, ts, severity, matched_event_ids TEXT[], tenant_id)
incidents(incident_id PK, status, opened_at, closed_at, tenant_id)
incident_alerts(incident_id, alert_id)
ai_verdicts(verdict_id PK, incident_id, model, prompt_hash,
            output JSONB, confidence, created_at)
analyst_decisions(decision_id PK, incident_id, user_id, decision, reason, ts)
audit_log(id PK, ts, actor, action, target, detail JSONB)   -- append-only
```

**Security notes:** parameterized queries only; a least-privilege application role (no DDL, `INSERT`-only on `audit_log` with no `UPDATE`/`DELETE`); row-level security or a mandatory `tenant_id` predicate if multi-tenant (T14); TLS connections; retention policy by partition drop; credentials from the environment.

---

## 5. Redis

**Role:** rate limiting, ingestion dedup, short-lived work queue, LLM response caching.

**Why:** the rate limits and cost caps the threat model requires (T20) need a fast shared counter, and normalization/AI analysis should run asynchronously so a slow model call never blocks ingestion.

**Uses:**
- Sliding-window counters per source and per user (T20).
- Dedup set on `event_id` to make ingestion idempotent on agent retry.
- A queue for normalization and AI analysis workers. *Redis Streams for an MVP; a real broker if durability matters — note that Redis is not a durable queue and a lost job must be detectable.*
- Cache of verdicts keyed by a hash of the exact prompt, bounding cost and making demos deterministic.

**Security notes:** password/ACL enabled and never exposed to the network; separate logical DBs per purpose; TTLs on everything; no sensitive incident content cached beyond its TTL; keys namespaced by tenant.

---

## 6. Docker

**Role:** reproducible environment for Postgres, Redis, the API and (optionally) Ollama. **Out of scope for now** per the project instructions — no containers are to be created yet.

**Why later:** a demo that depends on a teammate's local Postgres install will fail on stage. Compose makes the whole stack one command.

**Security notes for when we do:** pinned base image digests, not `:latest`; non-root `USER`; multi-stage builds so build tooling is absent from the runtime image; secrets injected as environment variables or files at runtime, never baked into layers or committed compose files; only the API port published; no Docker socket mounted into any container.

---

## 7. Sigma

**Role:** the detection content format — the deterministic layer of the pipeline.

**Why:** rules as reviewable YAML in git, portable across backends, with a large public ruleset to borrow from. Critically, Sigma keeps detection *explainable*: an analyst can read the rule that fired. This is what lets us say the LLM is not deciding what counts as an alert.

**Example fitting our sample data** (`evt-0008`, Office spawning encoded PowerShell):

```yaml
title: Office Application Spawning Encoded PowerShell
id: 7a1c9f30-0000-4000-8000-hackathonexample
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    parent_name: 'winword.exe'
    name: 'powershell.exe'
  encoded:
    command_line|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection and encoded
falsepositives:
  - Legitimate Office macros in document-automation workflows
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

**How we would use it:** rules in `app/detections/sigma/`; `pysigma` compiles them to whatever backend we query; every rule needs a test case in `tests/`; rule changes go through review because a rule file is executable content (T13, supply chain).

**Field mapping note:** our normalized schema uses `process.name` / `process.parent_name` / `process.command_line`. A Sigma field-mapping config will be needed — write it once, test it.

---

## 8. MITRE ATT&CK

**Role:** the shared vocabulary for describing what an adversary appears to be doing.

**Why:** it turns "suspicious PowerShell" into `T1059.001`, which is searchable, comparable across incidents, and instantly meaningful to any blue teamer judging the demo. It also gives the AI a *bounded* vocabulary — mapping to a fixed technique set is far more checkable than free-form narrative.

**Mappings our sample data supports:**

| Events | Technique | Note |
|---|---|---|
| `evt-0002..0005` | T1110.003 Password Spraying | Many accounts, one source, few attempts each |
| `evt-0007` | T1621 MFA Request Generation | Repeated denied factor prompts |
| `evt-0008` | T1059.001 PowerShell | Encoded, hidden window, Office parent |
| `evt-0009` | T1218.011 Rundll32 | Signed-binary proxy execution from temp |
| `evt-0010` | T1568 Dynamic Resolution | High-entropy domain — *candidate, not proof* |
| `evt-0011/0012` | T1071.001 Web Protocols | Regular-interval outbound, similar byte counts |
| `evt-0013` | T1003.001 LSASS Memory | EDR-attested credential access |
| `evt-0017` | T1530 Data from Cloud Storage | Anomalous bulk object reads |

**Discipline we impose:** a technique is only asserted when specific evidence supports it, and the technique ID must be accompanied by the event IDs that justify it. Speculative mappings are labelled as hypotheses. This rule is written into the prompt template — see [prompts/SOC_ANALYST_PROMPT.md](../prompts/SOC_ANALYST_PROMPT.md).

**Implementation:** ship a static, version-pinned technique list (ID, name, tactic) and **validate every model-produced ID against it**. A technique ID that does not exist is a hallucination and must be rejected — cheap, deterministic, and a strong demo talking point. Optionally `mitreattack-python` for the full STIX bundle.

---

## 9. STIX / TAXII

**Role:** the format for threat intelligence in and out.

**Why:** STIX 2.1 is the standard object model for indicators, and TAXII 2.1 is the standard transport. If the problem statement involves intel sharing, these are the expected answers. STIX also gives us a clean way to *export* what we found: an incident's indicators as a bundle other tools can consume.

**Usage:** pull indicators from a TAXII collection into a local cache; enrichment reads only from that cache; export confirmed incident indicators as a STIX bundle.

**Security notes (TB-2):**
- Never fetch an attacker-supplied TAXII URL — endpoints are configured, not derived from event data (T8, SSRF).
- STIX `description` and `labels` are free text from a third party; delimit as untrusted before any prompt (T3).
- Indicator match is *enrichment*, never sole justification for automated response (T18) — feeds carry false positives, and a poisoned feed listing a DC's IP must not trigger isolation.
- Cap bundle size and object counts; a malicious feed can be a resource-exhaustion vector.

---

## 10. Optional SIEM integrations

**Only if the problem statement requires it.** Each integration is a trust boundary and a credential to protect, so we would implement at most one, behind a narrow interface.

| Platform | Integration | Notes |
|---|---|---|
| **Splunk** | REST search API / HEC | Ubiquitous in enterprise SOCs; HEC token is a secret |
| **Elastic Security** | ES query DSL, ECS schema | Our schema is ECS-shaped for this reason; strong free tier |
| **Microsoft Sentinel** | KQL via Log Analytics API | Common in Microsoft estates; Entra app registration needed |
| **Wazuh / OpenSearch** | Open source, self-hostable | Best fit for an offline demo |

**Interface discipline:** define a `LogSource` protocol (`query(filters, window) -> list[SecurityEvent]`) and implement adapters behind it. The rest of the system never learns which SIEM it is talking to — and our sample JSON file is just another adapter, which is what makes the foundation demo-able today.

**Security notes:** read-only service accounts, scoped to the minimum indices; credentials from the environment; outbound-only connections; time-bounded, row-limited queries so a bad filter cannot pull a terabyte; all SIEM results are untrusted input and re-validated through the same parser.

---

## 11. LLM providers

**Role:** the AI analysis stage only — summarization, correlation narrative, ATT&CK mapping, recommended actions.

**Default: Claude (Anthropic API).** Strong reasoning over messy log context, reliable structured output, and good instruction-following on the "evidence vs. inference" discipline the prompt demands. Model selection at build time; the latest Claude models are the Claude 5 family (Opus 5 `claude-opus-5`, Sonnet 5 `claude-sonnet-5`) plus Haiku 4.5 (`claude-haiku-4-5-20251001`) — Sonnet 5 is the sensible default for triage volume, Opus 5 for deep analysis of a hard incident, Haiku for cheap pre-filtering.

**Integration rules (all of these are load-bearing):**

1. **API key from `ANTHROPIC_API_KEY` in the environment.** Never in code, prompts, logs, or the repo. Startup fails if absent.
2. **Structured output.** Request a strict JSON verdict schema; validate on receipt; retry once on malformed output, then fall back to human review. Never `eval`, never execute.
3. **No tools in the triage call.** The model returns proposed action *names*; the orchestrator resolves them against a static allow-list (T15).
4. **Untrusted data delimiting.** Event content inside an explicit block, never in the instruction region (T1).
5. **Caps.** Max input tokens per incident, max output tokens, per-incident and daily cost ceilings, request timeout, circuit-breaker to rules-only mode when exhausted (T20).
6. **Redaction before send.** Minimize fields and strip secret-shaped strings at TB-3 (T11).
7. **Determinism where possible.** Temperature 0 for triage; cache by prompt hash so a demo can be replayed.
8. **Log the call, not the payload.** Record model, prompt hash, token counts, latency, cost — not the full incident text.

**Alternatives:** OpenAI and Gemini are drop-in at the interface level if a sponsor requires them — which is precisely why the client should sit behind a thin `LLMClient` protocol (`analyze(prompt) -> str`) that we can swap without touching the pipeline.

---

## 12. Local LLM via Ollama

**Role:** the privacy-preserving and offline-safe option.

**Why it matters for this track — three concrete reasons:**

1. **Zero data egress.** TB-3 disappears entirely. If the problem statement involves real or regulated log data, a local model may be the only defensible choice (T11).
2. **Offline demo resilience.** Conference Wi-Fi fails. A local model means the demo still runs.
3. **Cost.** No per-token bill during development, and no cost-exhaustion vector (T20).

**Practical setup:** `ollama serve` exposes an OpenAI-compatible endpoint at `http://localhost:11434`. Candidate models at hackathon scale: Llama 3.1 8B or Mistral 7B for summarization on a laptop; a larger quantized model if a GPU is available. Expect meaningfully weaker reasoning than a frontier model — so keep the deterministic detection layer authoritative and let the local model do the bounded, easy parts.

**Hybrid pattern we would recommend:**

```
all incidents ──▶ local model (Ollama): noise filter, first-pass summary
                     │
                     └── escalated / high-severity ──▶ Claude: deep analysis
```

Most volume is handled locally with no egress; only incidents that merit it — and only after redaction — cross TB-3. This is a genuinely defensible blue-team design and demos well.

**Security notes:** bind Ollama to localhost only (an exposed endpoint is an open inference server); pin model versions, since a silently updated model changes behavior; a local model is *not* inherently safer against prompt injection — every control in §11 still applies; validate its output identically.

---

## 13. What is installed right now

Nothing from this document. Current state:

- Python 3.13 available on the machine.
- `app/.venv/` exists with an unrelated set of packages (includes `sqlalchemy`, `alembic`, `jinja2`, `loguru`, `lxml`); it does **not** contain `pytest`, `pydantic`, or `fastapi`.
- `soc_core` and the test suite use the standard library only and run with:

```bash
python -m unittest discover -s tests -v
```

The first dependency we add should be `pytest`, and it should come with a one-line justification in the commit message.
