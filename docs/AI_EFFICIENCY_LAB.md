# AI Efficiency & Economics Lab (Stage 3)

**Claim under test:** AI reasoning cost is driven by the context sent to the
model. The deterministic evidence layer keeps raw telemetry volume from turning
into AI context volume.

This is an **architectural comparison on the same synthetic telemetry**. It is
not a vendor benchmark, and no SIEM product is compared.

| Path | What it is | Sent to a model? |
|---|---|---|
| **A · Naive raw-context baseline** | Every raw event serialized into the prompt: a compact JSON record plus the raw line. Estimated locally with the same `ceil(chars / 3.5)` estimator. | **Never.** THEORETICAL. |
| **B · Evidence-context architecture** | The real Stage 2 `EvidenceContext` for every detected incident. | This is the only thing the AI provider ever receives. |

Code: `app/soc_core/efficiency.py`. API: `/api/efficiency/*`. UI: **AI EFFICIENCY LAB** tab (`http://127.0.0.1:5173/#lab`).

## Synthetic benchmark telemetry

`generate_events(n, seed=20260919)` is deterministic. It takes the 63 canonical
events from both datasets and embeds them in `n − 63` noise events:

| Kind | Share | Purpose |
|---|---:|---|
| benign unrelated | 45% | Normal logons, processes, DNS and SMB spread over 48 h |
| repeated | 20% | Three chatty periodic sources (monitoring, update DNS, backup job) |
| entity-linked, near timeline | 15% | Benign activity by the *incident's* user/host/instance inside the incident windows, so it becomes candidate context |
| detection-matching | 10% | Extra spray failures from 203.0.113.45 and extra finance-bucket reads inside the rule windows, so existing alerts grow |
| near-timeline, unrelated | 10% | Other hosts, same time windows, no shared entity |

Noise events are built directly, bypassing `parse_event`, with pooled
host/user/detail dicts. A test validates every generated event through
`parse_event`. Nothing is written to disk.

## Measured results

Measured on this machine (Windows 11, 2026-09-19) through the API's background
runner, seed 20260919. **Counts and tokens are deterministic; timings vary
between runs and machines.** Tokens are estimates (`chars / 3.5`).

| Raw events | Relevant | Evidence objects | Context tokens | Raw-context estimate (not sent) | Reduction | Retention | Citation coverage | Context build |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 54 | 43 | 25,403 | 16,889 | **−50.41%** | 100% | 100% | 35 ms |
| 1,000 | 279 | 42 | 25,358 | 117,288 | 78.38% | 100% | 100% | 36 ms |
| 10,000 | 2,533 | 42 | 25,548 | 1,121,456 | 97.72% | 100% | 100% | 139 ms |
| 50,000 | 12,553 | 45 | 26,965 | 5,583,601 | 99.52% | 100% | 100% | 442 ms |
| 100,000 | 25,071 | 45 | 26,968 | 11,159,513 | 99.76% | 100% | 100% | 957 ms |
| 1,000,000 | 250,513 | 47 | 27,514 | 111,551,326 | 99.98% | 100% | 100% | 4,755 ms |

- **Crossover:** at 100 events the evidence pack is *larger* than the raw log,
  because it carries fixed structure (entities, timeline, MITRE mapping,
  relationships, response policy). This is shown as measured, not hidden.
  The architecture pays off from about 1K events onward.
- Four incidents are detected at every scale, the same four as the canonical
  data. Context tokens grow by 8% while raw volume grows 10,000×.
- **1M events:** about 56 s end to end in a standalone process, peaking at a
  472 MB working set. It always runs on a background thread and is cached.
  Before running, a memory guard (`check_scale`: about 520 B/event against 85%
  of free RAM) refuses any scale the machine cannot hold. A refused scale shows
  **UNAVAILABLE** with the reason, and no number is shown for it.
- `events_per_second` = raw events / (detection + correlation + context build)
  wall time. Generation time and the raw-baseline estimate are excluded and
  reported separately.

Reproduce from the CLI:
```powershell
app\.venv\Scripts\python.exe -m app.soc_core.efficiency --scales 100,1000,10000,50000,100000,1000000 --no-cache
```

## Evidence retention (not "AI accuracy")

Retention is scored against 14 critical investigation facts (`CRITICAL_FACTS`),
each tied to supporting event IDs:

- **Endpoint:** spray, successful logon, MFA fatigue, execution, LSASS, Run-key persistence, ADMIN$ lateral movement, C2.
- **Cloud:** leaked-key use, role chaining, privilege escalation, CloudTrail stopped, S3 bulk reads, SSH exposure.

A fact is **preserved** when every supporting event is represented by an
evidence item (individually or inside an aggregate). **Citation coverage** is
the share of supporting events that map to a citable evidence ID. This measures
what the model *could* cite, not what it concludes.

### Budget experiment (canonical incidents)

Each incident's full context is rebuilt with budgets of 100%, 75%, 50% and 25%
of its own unconstrained size:

| Budget | Target tokens | Actual tokens | Facts | Citation coverage | Lost |
|---:|---:|---:|---:|---:|---|
| 100% | 24,268 | 24,268 | 14/14 | 100% | — |
| 75% | 18,200 | 20,388 (floor) | 11/14 | 90.6% | F02 F06 F07 |
| 50% | 12,132 | 20,172 (floor) | 11/14 | 90.6% | F02 F06 F07 |
| 25% | 6,064 | 20,172 (floor) | 11/14 | 90.6% | F02 F06 F07 |

This is the honest limit of compression. Detection evidence is never trimmed,
so the context bottoms out at about 20K tokens. The trimmed items are the
*context-only* facts no rule fires on: the successful logon after the spray, the
persistence and the lateral movement. That is why the default budget
(12K per incident) is set above each canonical incident's full size.

## Economic model

`cost = tokens / 1,000,000 × price_per_1M`, computed separately for input and
output. Output tokens are assumed equal on both paths (the same report, 2,500
tokens), so the whole difference comes from input context.

- **Pricing is user-supplied.** The default `5.00 / 25.00` per 1M tokens is
  labelled **EXAMPLE RATES: editable, not a vendor quote** everywhere it
  appears.
- The page shows cost per investigation, per 1,000 and per 10,000, plus a
  calculator for 1, 100, 1,000 and 10,000 investigations.
- With a context window set, Path A reports whether it would fit. At 1M events
  it needs 558 × 200K windows, so its cost figure is a lower bound for a design
  that could not run as a single request.

With the example rates at 1M events:
- **Path A:** $558 per investigation (theoretical).
- **Path B:** $0.20 per investigation, a 99.96% cost reduction.

These figures depend entirely on the example rates you enter.

## Live model usage

The lab **never calls a model**, and there is no second AI pipeline.
`GET /api/efficiency/live` reports measured `input_tokens` / `output_tokens`
and latency only from real Claude investigations already run through the
normal **RUN AI INVESTIGATION** path, which receives the EvidenceContext only.
It shows these next to the estimate. The mock is never reported as live usage.
With no key configured, the panel reads: **"Live model usage unavailable — benchmark running offline."**

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/efficiency/benchmark` | Status per scale (`measured`/`running`/`queued`/`unavailable`/`not_run`) plus results |
| POST | `/api/efficiency/benchmark` | `{"scales": [...], "force": false}`. Only scales in `SCALES` are allowed; runs in the background |
| GET | `/api/efficiency/fidelity` | Retention and budget experiment (computed once) |
| POST | `/api/efficiency/cost` | `{scale, model, input_per_mtok, output_per_mtok, investigations, output_tokens?, context_window?}`. Returns 409 if the scale is unmeasured. The model label is restricted to `[A-Za-z0-9 ._:/()-]`, max 64 characters |
| GET | `/api/efficiency/live` | Measured usage from real analyze calls, if any |

Results are cached in `.cache/efficiency_benchmark.json` (gitignored). The cache
is keyed on benchmark version, context schema and seed. A stale or corrupt
cache is ignored and never trusted. It contains metrics only: no events, no
prompts, no secrets.

## Demo (golden path, under 3 minutes)

1. Start the backend and frontend (see the README / `HACKATHON_RUNBOOK.md`). Open `http://127.0.0.1:5173/#lab`.
2. **(0:00)** Read the headline. Press **RUN BENCHMARK**, or use cached results: the scale pills turn MEASURED one after another, and the page follows the largest.
3. **(0:30)** Click **1M**. The pipeline shows 1,000,000 → 250,513 → 47 evidence objects → 27,514 tokens, a **99.98%** reduction against a raw-context estimate of 111.6M tokens, marked THEORETICAL — NOT SENT TO MODEL.
4. **(1:00)** Show the chart: the dashed raw line climbs four orders of magnitude while the evidence line stays flat. Point out the honest crossover at 100 events.
5. **(1:30)** Cost: enter your own rates. Show Path A vs Path B, then 10,000 investigations and the context-window warning.
6. **(2:00)** Retention: 14/14 facts with evidence IDs. The budget table shows that squeezing further loses the three context-only facts. Compression has a limit, and the lab shows where it is.
7. **(2:30)** Live usage: offline notice (or measured tokens if Claude ran). Switch to **SOC CONSOLE** and show that the model receives only the context pack (**view exact context pack**).

## Limitations

- **Synthetic telemetry.** The noise mix is designed to stress relevance
  filtering and aggregation, not to model a particular environment. Real
  telemetry would contain more distinct high-cardinality fields.
- **Token estimates.** Both paths use `chars / 3.5`, expected to be within about
  ±20% of a real tokenizer. The *ratio* is robust because both paths use the
  same estimator.
- **Path A is a strawman by construction.** It is the naive design, deliberately.
  Real systems would chunk, summarize or use retrieval. The lab claims only that
  deterministic evidence selection prevents *linear* growth. It does not claim
  to beat every alternative.
- Timings are single runs on one machine. 1M memory depends on free RAM at run
  time, and the guard may mark it UNAVAILABLE on a busy machine.
- `pseudonym_count` grows with scale (18,828 at 1M, from spray account names).
  The pack caps entities, but redaction still processes every value in the
  relevant events.
- Retention measures evidence *availability* to the model, not the quality of
  the model's reasoning.
