# Correlation Engine Foundation (Stage 3.5)

> **The canonical attack-specific rules and labels will be added after the
> project attack scenario is finalized.** This stage builds the generic,
> scenario-agnostic foundation plus the benchmark harness that will evaluate
> it. No ground truth exists yet, so no precision, recall, F1 or critical-recall
> figure is reported anywhere.

## 1. Purpose

**Goal:** reduce model-facing context without losing critical attack evidence.

The engine sits **before** the existing EvidenceContext Engine and answers five
questions:

1. Which events are related?
2. Which investigation cluster does each belong to?
3. Which entities connect them?
4. Which events are most investigation-relevant?
5. Which evidence should be preserved downstream?

It does **not** replace the EvidenceContext Engine, and it does **not** decide
"this is an attack". It ranks evidence relevance.

## 2. Architecture

```
events (SecurityEvent | dict) + alerts (optional)
   │  normalization.py    sparse-tolerant, validated, originals untouched
   ▼
NormalizedEvent[]  ──►  entities.py   typed entities + inverted index (posting lists)
   │
   ▼  features.py: link()   k-nearest-in-time per shared entity → union-find clusters
   ▼  features.py: build_features()   31 numeric features per event
   ▼  strategies.py   RuleBased (deterministic) [+ trained model]
   ▼  ranking.py      final score, selection, evidence objects, token estimate
   ▼  evaluation.py   ground truth → precision / recall / F1 / critical evidence recall
CorrelationResult.summary()  ──►  (next phase) Efficiency Lab "OUR ENGINE" path
```

- **Package:** `app/soc_core/correlation_engine/`. It is not named `correlation/`
  because `app/soc_core/correlation.py` is the existing Stage 1
  alert→incident correlator. That correlator is unchanged and still drives the
  console.
- **Public interface:** `CorrelationEngine` with `normalize_events`,
  `extract_entities`, `correlate`, `build_features`, `rank`,
  `produce_candidates`, `evaluate`, `fit`, `run`.
- **Determinism:** identical events, config and seed produce identical
  rankings, selections and evidence objects. Tests assert this, including for
  every trained model type.

## 3. Event normalization (`normalization.py`)

Accepts the project's `SecurityEvent` (read through its flat accessors) and
loosely shaped dicts. Each field is looked up through an alias list covering
the project schema plus common SIEM, EDR and cloud names:
- `@timestamp`, `src_ip`, `dst_ip`, `dport`;
- `user.name`, `sourceIPAddress`, `eventName`, `recipientAccountId`;
- `command_line`, `rule_id`, `technique`, and others.

Normalized fields: timestamp, event_type, severity (0–4), source, hostname,
source/destination IP and port, username, account, process, parent_process,
command, action, status, detection_ids, rule_ids, techniques, resources.

- **Sparse events** are accepted. Missing fields are `None`, and a missing
  timestamp is recorded in `issues`.
- **Invalid values are dropped, never guessed.** This covers IPs, ports,
  severities, timestamps and technique IDs. Each drop is recorded as an issue.
  Strings are capped at 512 characters.
- **Non-events** (strings, numbers, None) are **rejected with a reason** in the
  `NormalizationReport`. Nothing is skipped silently.
- **Traceability:** every normalized event keeps its source `event_id`. If the
  source had none, it gets `anon-nnnnnn` plus an issue. It also keeps
  `original`, a reference (not a copy) to the untouched input.
- **Alerts:** optional `DetectionResult` objects, or dicts with
  `evidence_event_ids`, attach detection, rule and technique IDs to the events
  they cite.

## 4. Entity extraction (`entities.py`)

Entity types: `USER, HOST, IP, PROCESS, ACCOUNT, RESOURCE, DETECTION, TECHNIQUE`.

- Relationships are `event → entity`, available via `EntityIndex.relationships()`.
- Usernames, hostnames and processes are case-folded, because they are
  case-insensitive where they come from.
- Loopback, unspecified addresses and placeholder values (`-`, `n/a`, `system`)
  are ignored.
- DETECTION entities come in two kinds:
  - `alert:<id>` **links events**, because events cited by the same alert
    belong together;
  - `rule:<id>` **does not link**, because a rule can fire on unrelated
    activity. It only feeds features.
- The **inverted index** maps entity → posting list of events. This is what
  avoids all-pairs comparison.

## 5. Features (`features.py`)

**Linking:**
- Events that share an actor/asset entity (or an alert ID) link to at most
  `neighbors_per_entity` (default 3) earlier events within
  `link_window_seconds` (default 1 h).
- Edges are therefore bounded by O(n · entities_per_event · k); a test asserts
  the bound.
- Linked events form clusters via union-find. Cluster IDs are ordered by first
  timestamp.

**Reference detection:** pairwise features for each event are computed against
the time-nearest detection-cited event that shares an actor/asset entity with
it. A detection-cited event is its own reference. The lookup uses binary search
over per-entity detection posting lists.

Thirty-one numeric features per event, all finite and suitable for tabular
models:

| Group | Features |
|---|---|
| Event | severity, detection_match, detection_count, technique_count, event_frequency, rarity, entity_count, status_failure |
| Graph / cluster | degree, cluster_size, cluster_density, cluster_has_detection, cluster_detection_fraction, event_type_similarity, source_similarity |
| Entity (vs reference) | same_user, same_host, same_source_ip, same_destination_ip, same_process, same_account, shared_detection, shared_technique |
| Relationship | number_of_shared_entities, entity_overlap_ratio |
| Temporal (vs reference) | timestamp_distance (log seconds), within_1_minute, within_5_minutes, within_15_minutes, within_1_hour, temporal_proximity (exp(−Δt/900 s)) |

`pair_features(a, b)` exposes the same relationship features for any event
pair. IP roles are tracked, so B's *source* matching A's *destination* is not
counted as `same_source_ip`.

No feature encodes an attack pattern.

## 6. Correlation strategies (`strategies.py`)

| Strategy | Training | Notes |
|---|---|---|
| `RuleBasedCorrelation` | none | Weighted sum of bounded features ÷ sum of weights. Weights come from `RuleWeights`, are configurable and **not claimed optimal**. `contributions()` gives the per-feature breakdown, which sums exactly to the score. |
| `LogisticRegressionCorrelation` | labels | StandardScaler + LogisticRegression (balanced) |
| `DecisionTreeCorrelation` | labels | depth 6, balanced |
| `RandomForestCorrelation` | labels | 100 trees, depth 10, balanced, single-threaded |
| `LightGBMCorrelation` | labels | **Unavailable here:** `lightgbm` is not installed and was deliberately not added. Reported as `UNAVAILABLE` with a reason. |

- ML libraries are imported lazily. The core engine runs without numpy or
  scikit-learn, and a missing library shows as `UNAVAILABLE`.
- An **untrained** model raises `NotTrainedError`. It never returns a default
  or guessed score.
- scikit-learn 1.9.1 and numpy 2.5.3 were **already installed** in both the
  venv and system Python. No dependency was added.

## 7. ML strategy

The model predicts **evidence relevance** ("how useful is this event to the
investigation?"), not "is this an attack?". Scores stay explainable:

```
final = (1 − model_weight) · deterministic + model_weight · model      (model_weight = 0.5)
```

Each `Candidate` carries `deterministic_score`, its per-feature `breakdown`,
and `model_score`, all kept separately. Trained models also expose
`feature_importance()`.

**Selection:**
- An event is selected when `final ≥ selection_threshold` (0.35).
- An optional `max_selected` cap applies by rank.
- **Detection-cited events are always kept**; no cap drops them.

## 8. Benchmark methodology (`benchmarks.py`)

```powershell
app\.venv\Scripts\python.exe -m app.soc_core.correlation_engine.benchmarks --scales 100,1000,10000,50000
#   --ground-truth labels.json      evaluate against real labels (held-out split)
#   --self-test-random-labels       ML latency only; quality forced to N/A
#   --json                          machine-readable output
```

- **Dataset:** the Stage 3 synthetic benchmark telemetry (seeded) plus alerts
  from the project's existing detection rules. The engine receives only events
  and alerts.
- **With ground truth:** events are split deterministically (SHA-256 of seed
  and event_id) into 70/30 train/test. ML trains on the train split, and
  **every strategy, rules included, is scored on the same held-out test split**.
- **Without ground truth** (today):
  - quality columns read **N/A — ground truth unavailable**;
  - ML rows read **NOT TRAINED**;
  - LightGBM reads **UNAVAILABLE**.
- **Latency** = shared preparation (normalize, entities, correlate, features)
  plus the strategy's scoring and ranking. Detection time is reported
  separately. Memory is the process peak working set.
- **Memory guard:** about 1.5 KB/event against 85% of free RAM. A scale that
  won't fit is reported `unavailable`, with no numbers.

### Measured results (this machine, 2026-09-19, seed 20260919, no ground truth)

| Events | Strategy | Selected | Evidence objects | Est. tokens | Latency | Peak memory |
|---:|---|---:|---:|---:|---:|---:|
| 100 | RuleBased | 48 | 33 | 4,007 | 3 ms | 25 MB |
| 1,000 | RuleBased | 203 | 32 | 3,957 | 20 ms | 27 MB |
| 10,000 | RuleBased | 1,736 | 32 | 3,964 | 227 ms | 46 MB |
| 50,000 | RuleBased | 8,511 | 32 | 3,965 | ~1.1 s | 104 MB |
| 100,000 | RuleBased | 17,050 | 32 | 3,965 | ~2.6 s | 174 MB |
| 1,000,000 | RuleBased | 170,415 | 32 | 3,967 | ~76 s | 1,430 MB |

- **All ML rows:** precision, recall, F1 and critical recall are N/A — ground
  truth unavailable. LogisticRegression, DecisionTree and RandomForest are
  NOT TRAINED; LightGBM is UNAVAILABLE.
- **1M:** measured once with the memory guard bypassed. With about 1.6 GB free
  on this machine, the guard normally refuses 1M. Per-event cost rises at 1M,
  which is consistent with memory pressure. The hypothesis that it was the
  garbage collector was tested and rejected.
- **ML latency at 50K** (`--self-test-random-labels`, which measures speed, not
  quality):

  | Model | Train | End-to-end |
  |---|---:|---:|
  | LogisticRegression | ~1.2 s | ~1.1–1.3 s |
  | DecisionTree | 0.1–0.2 s | ~1.3–1.4 s |
  | RandomForest | 2.7–3.2 s | ~1.6 s |

- **Reading the table:**
  - "Selected" includes every detection-cited event. At 50K, the synthetic
    generator adds about 5,000 events that existing alerts cite.
  - Aggregation collapses them into about 32 objects.
  - Token estimates use the Stage 2 estimator (`ceil(chars/3.5)`) over the
    selected evidence objects. That is the candidate payload handed downstream,
    **not** the final EvidenceContext pack.

## 9. Critical evidence recall

```
critical_evidence_recall = critical events selected / critical events present in the input
```

This is the metric that matters most. Reducing 50,000 events to 10 is a
failure if critical evidence is lost.

- `Evaluation` lists every **missing** critical event ID.
- Labels that reference events **absent** from the input are counted in
  `labels_not_in_input`, so a dataset/label mismatch is visible instead of
  silently lowering recall.

Ground-truth schema (`GroundTruth.from_json`): unknown fields and duplicates are
rejected, and `critical` requires `is_attack_related`.

```json
{"labels": [{"event_id": "...", "is_attack_related": true, "attack_stage": "...", "critical": true}]}
```

## 10. Performance considerations

- **Index-based linking:** k-nearest per entity plus union-find. There are no
  all-pairs comparisons anywhere.
- **Features** are stored as a flat `array('d')` (numpy view only for ML), about
  250 B/event.
- **Reference lookup** is a binary search over per-entity detection posting
  lists.
- **Memory fixes made after measuring at 1M:**
  - per-event neighbor sets were removed; edges are applied directly;
  - per-event linking sets are no longer held; they are computed on demand.
- **Pre-compiled regexes, no repeated JSON serialization.** Serialization
  happens once, for the selected evidence objects.
- **Measured bottleneck:** normalization (about 40% of preparation time),
  because every field goes through Python-level accessors. Feature building is
  next (about 27%). Both are linear.

## 11. Security boundaries

- Offline only. The package imports no network or model client, and a test
  scans for them. A test also runs the benchmark with sockets blocked.
- It never calls Claude, OpenAI, Gemini or any other provider. Raw telemetry
  stays local.
- The Stage 2 redaction guarantees are unchanged. Anything sent to a model
  still goes through the EvidenceContext Engine, which redacts, pseudonymizes
  and trips on secrets.
- The debug endpoint `GET /api/correlation/debug?limit=N` (1–200) is read-only
  and runs over the loaded scenario. It returns IDs, scores and breakdowns
  only, never raw event text or command lines.
- No secrets in fixtures. A test checks benchmark output with the secret
  tripwire.

## 12. Current limitations

- **No ground truth.** Quality metrics are N/A, and ML models are untrained
  outside tests. **Nothing shows that any model beats the rule baseline.**
- **Default rule weights** are hand-set starting points.
- **Cluster chaining.** Time-windowed single linkage over busy entities chains
  into large clusters at scale: one cluster held 46,100 of 50K events. That
  weakens cluster-level features there; ranking relies mostly on
  reference-detection features.
- **The hub filter is opt-in.** On this telemetry, frequency-based hubs
  suppressed the incident's own entities: busy is not the same as ubiquitous.
- **Selection is lenient.** Every detection-cited event is kept. For very
  chatty alerts, aggregation (not selection) is what bounds tokens.
- **Benchmark data** is the Stage 3 generator, whose embedded incident predates
  the canonical scenario. It exercises scale and plumbing, not scenario
  quality.
- **Peak memory** is the process-wide maximum, not per strategy.
- **Not production-ready.** Nothing here claims parity with, or superiority
  over, any commercial product.

## 13. Future integration with the canonical attack scenario

1. Load the canonical scenario events. They go through normalization unchanged,
   as dicts or `SecurityEvent`s.
2. Write `ground_truth.json` (`event_id`, `is_attack_related`, `attack_stage`,
   `critical`) from the scenario author's annotations, not from engine output.
3. Run the benchmark with `--ground-truth ground_truth.json`. Compare rules
   against the ML models on the held-out split, with **critical evidence
   recall** as the gating metric.
4. Tune `RuleWeights` and the selection threshold only against the train
   split. Add scenario-specific rules or features as separate strategies or
   feature groups.
5. Connect the Efficiency Lab's RAW / SIEM-PARTIAL / OUR ENGINE comparison
   through `CorrelationResult.summary()`, which provides `raw_events`,
   `correlated_events`, `evidence_objects`, `estimated_context_tokens`,
   `reduction_ratio` and `critical_evidence_recall`.
6. Feed `selected_event_ids` into the EvidenceContext Engine as its relevance
   input. Redaction and the model boundary stay as they are.

## 14. Canonical 50K scenario integration

Adapter: `app/soc_core/correlation_engine/canonical.py` (all dataset-specific parsing lives here; no
scenario values are hard-coded, which a test checks).

```powershell
app\.venv\Scripts\python.exe -m app.soc_core.correlation_engine.canonical   # validate + measure + cache
```

- Validates both representations: exactly 50,000 records each, unique IDs, timestamps, source types, no
  malformed JSON. The dataset files are read only, never modified.
- Generic `key=value` message parsing maps both RAW and SIEM records onto one generic event shape.
- **Baseline signals** stand in for detections, because the dataset carries no alerts. They are generic
  heuristics, applied identically to both representations, and **are not ground truth**:
  external (non-RFC1918) source address, failed-logon burst (≥5 in 10 min from one source), success after
  a burst, and rare event shape (≤2 occurrences).
- Measured (2026-09-19):

  | Representation | As delivered (est. tokens, never sent) | Engine output | Engine latency |
  |---|---:|---|---:|
  | Raw | 4,130,453 | 50,000 → 123 relevant → 22 objects → ~2,355 tokens | ~1.9 s |
  | SIEM | 5,204,426 | 50,000 → 123 relevant → 22 objects → ~2,384 tokens | ~2.0 s |

- **EvidenceContext:** built by the existing Stage 2 engine from the selected events only (1 incident,
  25 objects, ~9.5K tokens, usernames pseudonymized).
- **Console:** the `canonical-50k` scenario runs the existing incident, AI and response path on the
  selected evidence. Only the redacted EvidenceContext can reach a model; a test asserts this.
- **API:** `GET /api/efficiency/canonical`. The Lab's Summary tab shows a "CANONICAL 50K SCENARIO" panel.
- **Ground truth: NOT YET PROVIDED.** Precision, recall, F1 and critical evidence recall stay N/A.
  Coverage of later attack stages by the baseline signals is therefore **unmeasured**.
