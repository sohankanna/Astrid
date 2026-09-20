# AI Attack Investigator

**Evidence-backed AI investigation and response layer for the modern SOC**

## Overview

> We don't use AI to process your logs. We use AI to investigate the incidents your existing security infrastructure has already identified.

AI Attack Investigator sits **above** existing SOC telemetry and detection (Wazuh, Splunk, CloudTrail, EDR). Deterministic stages turn raw telemetry into a small, traceable, redacted body of **evidence**:
- normalization;
- detection;
- correlation;
- evidence ranking;
- context building.

Only that evidence reaches the AI investigator. Its findings must cite evidence IDs, and any response action stays simulated and human-gated.

## Problem

- **Volume.** A SOC sees tens of thousands to millions of events per day. Analyst attention is the scarcest resource.
- **Naive LLM use doesn't scale.** Sending raw telemetry to an LLM makes context size, cost and latency grow linearly with log volume, and quickly exceeds model context windows.
- **Raw logs are unsafe input.** They contain secrets, personal identifiers and attacker-controlled text (prompt injection).
- **Analysts need traceability.** Every AI claim must trace back to the events that support it.

## Architecture

```
Wazuh / Splunk / CloudTrail / EDR
        ↓
Normalization                     deterministic
        ↓
Detection                         deterministic (rules / baseline signals)
        ↓
Correlation Engine                deterministic (entity + time linking, ranking)
        ↓
Incident Candidate                deterministic
        ↓
Evidence / Context Engine         deterministic (relevance, aggregation, budget, redaction)
        ↓
Attack Path                       deterministic, labelled OBSERVED / CORRELATED / INFERRED
        ↓
AI Investigator                   AI (Claude, or offline mock); cites evidence IDs
        ↓
Impact / Response Simulation      deterministic policy tiers, dry-run only
        ↓
Human Approval                    analyst decision
```

**Only the AI Investigator uses a model.** Everything before it is deterministic and reproducible. Everything after it is policy-enforced: the model cannot choose action tiers or claim that an action was executed.

## What Was Built

| Component | Where |
|---|---|
| SOC analyst console (FastAPI + React/TypeScript) | `app/api/`, `app/frontend/` |
| Canonical 50K benchmark pipeline (validation, adapter, measurement) | `app/soc_core/correlation_engine/canonical.py` |
| Generic correlation engine: normalization, entity extraction, bounded linking, 31 numeric features, evidence ranking | `app/soc_core/correlation_engine/` |
| Correlation strategies: rule-based baseline; logistic-regression, decision-tree and random-forest adapters; optional LightGBM adapter (reported unavailable when not installed) | `strategies.py` |
| Evidence Context Engine: relevance, aggregation, budget, OBSERVED/CORRELATED/INFERRED facts | `app/soc_core/evidence_context.py` |
| Redaction and pseudonymization, plus an outbound secret tripwire | `app/soc_core/redaction.py` |
| Claude provider and offline mock provider; AI citations with validation | `app/soc_core/providers/` |
| AI Efficiency & Economics Lab: synthetic scaling benchmark and cost model | `app/soc_core/efficiency.py`, Lab tab |
| Fidelity evaluation against reconstructed ground truth | `evaluation.py`, Lab → Fidelity |
| Attack-path visualization (canonical 50K, audit-backed) | SOC Console → Attack Path |
| Human-gated, dry-run response layer with protected assets | `app/soc_core/providers/response.py` |
| Untrusted-content / prompt-injection screening | `app/soc_core/providers/ai_analyst.py` |

## Canonical 50K Benchmark

The dataset was supplied by the scenario author in two representations: raw source telemetry and SIEM connector events.

- **50,000 events**
- **137 reconstructed attack-related events**
- **49,863 background events**

The original generator (which holds the true labels) was **not present**. Event-level labels were therefore reconstructed from the supplied dataset and its README, and checked against:

- **Event ordering.** The 137 attack events have IDs EVT-000001..000137, which are perfectly time-ordered, while the background IDs are shuffled.
- **Stage counts.** Contiguous segments match all 12 README per-stage counts exactly.
- **Named indicators.** Every README indicator appears only in the attack set.
- **Telemetry content.** Every event in each stage satisfies a content predicate.
- **Raw/SIEM correspondence.** The two representations have identical event IDs and messages.

**These are reconstructed labels, not authoritative generator ground truth.** Details are in `benchmarks/canonical_50k/ground_truth/ground_truth_validation.json`.

## Canonical Evaluation

| Metric | Value |
|---|---|
| Selected | 123 |
| TP | 113 |
| FP | 10 |
| FN | 24 |
| Precision | **91.9%** |
| Recall | **82.5%** |
| F1 | **86.9%** |
| Critical evidence recall | **83.7% (82/98)** |

- **TP**: an attack event retained by the evidence engine.
- **FP**: a background event retained as investigation context. All 10 are the victim account's normal activity on the compromised host during the attack window.
- **FN**: an attack event discarded by the evidence engine. **Discarded does not mean "classified benign".** The engine selects evidence; it does not classify.

The engine ran with **default settings and was not tuned against this dataset.** The raw and SIEM representations produced identical results, because they map one-to-one to the same events.

"Critical" is a project-defined proxy: an attack event that contains a README-named indicator which never appears in background traffic.

## Missed Evidence

| Group | Missed | Identified cause (audit) |
|---|---:|---|
| Web shell (EVT-56–63) | 8 | No baseline signal fires on tomcat → cmd.exe process events |
| WEB01 foothold (EVT-64–71) | 8 | The external-IP signal checks only **source** addresses; these are outbound to the attacker |
| Phishing (EVT-72) | 1 | The mail event's `sender_ip` field is not parsed by the adapter |
| Valid-account / pivot logons (EVT-98–104) | 7 | Internal pivot source addresses do not trigger the external-source signal |
| **Total** | **24** | |

These causes are documented, not fixed. Fixing them would mean tuning against the evaluation labels.

## Attack Path

The canonical attack path is a **correlation and inference over real telemetry, not scenario metadata**. `scripts/audit_canonical_attack_chain.py` applies content predicates to all 50,000 events and found concrete telemetry for every stage.

- **OBSERVED**: the telemetry directly contains the behaviour (e.g. POST /uploads/cmd.jsp, browserdump.exe, USB-0042 copy).
- **CORRELATED**: shared entities and time order support the relationship (e.g. the valid-account logon after failures from the same IP).
- **INFERRED**: the interpretation needs reasoning beyond one event. S3 "password spray" is a single successful logon; the spray pattern is visible only in the preceding failures.
- **MISSED**: attack telemetry exists but the engine did not retain it.

**Audit finding.** The direct *WEB01 foothold → credential harvesting* relationship is **not** supported by any observed shared entity. The telemetry supports this path to WS07:

> phishing → endpoint compromise → credential harvesting → pivot → finance staging → USB transfer → archive deletion

The console's Attack Path therefore shows two branches (WEB01 and WS07) and a correction note.

## AI Evidence Safety

- **Evidence only.** The AI receives an **EvidenceContext**, not the 50K event firehose. Unselected raw events never reach the provider (enforced by a test).
- **Labelled facts.** Facts are labelled OBSERVED / CORRELATED / INFERRED; `AI_RECOMMENDATION` is reserved for model output.
- **Redaction.** Secrets (passwords, tokens, keys, private keys, URL credentials) are destroyed. An outbound tripwire refuses to send any payload that still matches a secret pattern.
- **Pseudonymization.** Usernames, emails, AWS access keys and account IDs become tokens (`USER_001`, `ACCESS_KEY_002`). The reverse map stays server-side.
- **Citations.** Findings must cite evidence IDs; unresolved citations are flagged as unsupported.
- **No action claims.** The AI cannot claim an action was executed. Response tiers come from policy, never from the model.
- **Human-gated response.** Actions are dry-run and require human approval.
- **Offline mode.** A deterministic **mock provider** is used offline and is always labelled as the mock.
- **Live Claude.** The live Claude provider exists (`SOC_AI_PROVIDER=claude`) and requires `ANTHROPIC_API_KEY`. No key is in the repository.

## Efficiency / Economics Benchmark

The **synthetic scaling benchmark** embeds the project's sample incidents in seeded synthetic noise. It measures **model-context volume** at 100, 1K, 10K, 50K, 100K and 1M events.

It compares two paths on the same events:

- **Path A: naive raw-context baseline.** Every event serialized into a prompt, estimated with the same `ceil(chars / 3.5)` tokenizer. **Theoretical; never sent to a model.**
- **Path B: evidence-context architecture.** The EvidenceContext actually intended for the AI provider.

**Measured at 1,000,000 events:**
- The pipeline narrows 1,000,000 events to 250,513 relevant events, then 47 evidence objects.
- Path B is **27,514 tokens**. Path A is estimated at **111,551,326 tokens** (never sent).
- That is a **99.98% reduction in model context**. It is **not** deletion of telemetry: every event stays in the source systems.

**Cost model:**
- `cost = tokens / 1,000,000 × price`.
- Example rates: input **$5 / 1M tokens**, output **$25 / 1M tokens**. These are **editable example assumptions, not a vendor quote**.
- Output is held constant at **2,500 tokens** on both paths, to isolate the effect of input context.

| At 1M events | Path A (theoretical) | Path B (evidence) |
|---|---:|---:|
| Per investigation | $557.82 | $0.20 |
| Per 10,000 investigations | $5,578,191 | $2,000.70 |

Token reduction is 99.98% and cost reduction 99.96%.

**Context window.** Path A would need **558** windows of 200K tokens per investigation. It could not run as a single request, so its cost is a **theoretical lower bound** for a design that is not viable. It is not a claim that a production system would send 111M tokens in one request.

At **100 events** the evidence pack is *larger* than the raw log (−50.41%), because it carries fixed structure. That result is shown as measured.

## Results

### 1. Canonical 50K (supplied dataset, reconstructed labels)

| | Raw telemetry | SIEM connector |
|---|---:|---:|
| Events | 50,000 | 50,000 |
| As-delivered token estimate (never sent) | 4,130,453 | 5,204,426 |
| Relevant (selected) events | 123 | 123 |
| Evidence objects | 22 | 22 |
| Engine context tokens | 2,355 | 2,384 |
| Context reduction vs as-delivered | 99.943% | 99.954% |
| Engine latency (one run; varies) | ~2.0 s | ~2.0 s |
| Precision / recall / F1 | 91.9% / 82.5% / 86.9% | 91.9% / 82.5% / 86.9% |
| Critical evidence recall | 83.7% (82/98) | 83.7% (82/98) |

The EvidenceContext was built from the selected events: 1 incident, 25 evidence objects, about 9.5K tokens, usernames pseudonymized.

### 2. Synthetic scaling benchmark (seed 20260919)

| Events | Relevant | Evidence objects | Context tokens | Raw baseline (theoretical) | Context reduction | Fact retention |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 54 | 43 | 25,403 | 16,889 | −50.41% | 100% |
| 1,000 | 279 | 42 | 25,358 | 117,288 | 78.38% | 100% |
| 10,000 | 2,533 | 42 | 25,548 | 1,121,456 | 97.72% | 100% |
| 50,000 | 12,553 | 45 | 26,965 | 5,583,601 | 99.52% | 100% |
| 100,000 | 25,071 | 45 | 26,968 | 11,159,513 | 99.76% | 100% |
| 1,000,000 | 250,513 | 47 | 27,514 | 111,551,326 | 99.98% | 100% |

Fact retention is measured against the 14 critical facts of the project's own sample incidents, not the canonical dataset. Counts and tokens are deterministic; timings vary by machine.

## Security / Safety

- Prompt-injection and untrusted-content screening: flagged content is reported as evidence, never obeyed, never stripped.
- Redaction, pseudonymization and an outbound secret tripwire before any model call.
- Human approval for response actions. Protected assets are policy-blocked.
- **No autonomous response execution**: every action in the benchmark and demo is a dry-run simulation.
- No secrets are committed. Credentials come only from environment variables; `.env` is git-ignored.
- The benchmark and correlation code make no network calls (enforced by tests with sockets blocked).

## Limitations

- **Labels are reconstructed** ground truth, not authoritative. They should be replaced if the generator's labels are delivered.
- **"Critical" is project-defined.** Under that definition, the endpoint-compromise stage has no critical event.
- **Some stages are missed** by the first-run engine: 24 FNs, including all 8 foothold and all 7 pivot events.
- **The scaling benchmark is synthetic**, not production telemetry. The canonical 50K evaluation is a separate measurement.
- **Example prices** are editable assumptions, not vendor quotes.
- **The raw-context baseline is theoretical** and is never sent to a model.
- **Live model usage is not part of the offline benchmark.** Offline runs use the mock provider.
- **The attack graph mixes OBSERVED, CORRELATED and INFERRED** relationships, and labels them as such.
- **The engine is a first-run, default configuration.** Thresholds and heuristics were not tuned. The ML adapters are untrained without labels.

## Reproducibility

Run from the repository root (Windows paths shown). The environment used:
- Python 3.13 in `app/.venv`, with fastapi 0.141, uvicorn 0.53, httpx 0.28, anthropic 1.7, and optionally numpy 2.5 and scikit-learn 1.9;
- Node with the packages in `app/frontend/package.json`.

```powershell
# Tests
app\.venv\Scripts\python.exe -m unittest discover -s tests

# Frontend
npm --prefix app/frontend install
npm --prefix app/frontend run build

# Backend (mock AI by default; add $env:SOC_API_PORT="8001" if port 8000 is taken)
app\.venv\Scripts\python.exe -m app.api
npm --prefix app/frontend run dev        # http://127.0.0.1:5173  (Lab: #lab)

# Live Claude (optional)
$env:SOC_AI_PROVIDER="claude"; $env:ANTHROPIC_API_KEY="<your key>"; app\.venv\Scripts\python.exe -m app.api

# Canonical 50K benchmark (validate + measure + evaluate)
app\.venv\Scripts\python.exe -m app.soc_core.correlation_engine.canonical

# Synthetic scaling (efficiency) benchmark
app\.venv\Scripts\python.exe -m app.soc_core.efficiency --scales 100,1000,10000,50000,100000,1000000 --no-cache

# Correlation strategy benchmark
app\.venv\Scripts\python.exe -m app.soc_core.correlation_engine.benchmarks --scales 100,1000,10000,50000

# Ground-truth reconstruction (writes benchmarks/canonical_50k/ground_truth/)
app\.venv\Scripts\python.exe scripts\build_canonical_ground_truth.py

# Attack-chain audit (writes benchmarks/canonical_50k/attack_chain_audit.json)
app\.venv\Scripts\python.exe scripts\audit_canonical_attack_chain.py
```

**Dataset.** The two canonical 50K JSONL files are the scenario author's artifact and are **not committed**. Place them in `benchmarks/canonical_50k/`, as either `raw_source_telemetry_50000.jsonl` / `siem_connector_events_50000.jsonl` or the delivered `README (1).jsonl` / `README (2).jsonl`. Dataset-dependent tests skip when the files are absent.

Further documentation is in `docs/`: `EVIDENCE_CONTEXT_ENGINE.md`, `CORRELATION_ENGINE.md`, `AI_EFFICIENCY_LAB.md`, `HACKATHON_RUNBOOK.md`.

## Test Status

- **550 tests passing** (`unittest`) under both the project venv and system Python 3.13.
- **Frontend build passes** (`tsc --noEmit && vite build`).

## Project Status

Achieved during the hackathon:

- SOC analyst console with scenarios, incidents, timeline, MITRE mapping and evidence browser
- Evidence layer: Evidence Context Engine with budget, aggregation and fact classes
- AI provider integration: Claude provider plus a visible offline mock, with evidence citations
- Generic correlation engine and strategy benchmark harness
- AI Efficiency & Economics Lab: scaling benchmark from 100 to 1M events, and the cost model
- Canonical 50K integration: validation, adapter, measured pipeline, console scenario
- Reconstructed ground-truth evaluation (TP/FP/FN, critical evidence recall)

- 
- Read-only attack-chain audit of every stage against telemetry
- Attack-path frontend with OBSERVED / CORRELATED / INFERRED / MISSED semantics
- Safety controls: redaction, pseudonymization, injection screening, secret tripwire
- Human-gated, dry-run response
