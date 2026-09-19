# SOC Simulation — How It Works

A runnable, offline AI-assisted SOC pipeline. No network, no API key, no
database, no SIEM, no container. Everything external sits behind a Mock
provider.

```bash
python -m app.soc_core.demo                  # full attack chain
python -m app.soc_core.demo --scenario A     # benign baseline (no alerts)
python -m app.soc_core.demo --scenario H     # prompt injection in log data
python -m app.soc_core.demo --list-scenarios
python -m app.soc_core.demo --json           # machine-readable output

python -m unittest discover -s tests         # 357 tests
```

---

## 1. Architecture

One sentence: **deterministic code decides what is detected and what is
executed; the AI only explains.**

```
  EVIDENCE PATH (authoritative)          INTERPRETATION PATH (advisory)
  ───────────────────────────            ──────────────────────────────
  events → detections → alerts
         → correlation → incident ─┬──▶ risk score (transparent, additive)
                                   │
                                   └──▶ AI analyst → validated analysis
                                                   → proposed actions
                                                   → policy gate → DRY RUN
```

Delete the AI and the incident, its alerts, its timeline and its risk score are
identical. That separation is the whole design, and it is what makes the AI's
failure modes — hallucination, manipulation, downtime — survivable rather than
catastrophic.

**Layout** (see [architecture/SOC_DATA_FLOW.md](../architecture/SOC_DATA_FLOW.md)
for the module map and diagrams):

```
app/soc_core/
  events.py       schema, validation, flat accessors
  mitre.py        pinned ATT&CK subset + ID validation
  detections.py   8 deterministic rules + engine
  correlation.py  union-find grouping → Incident
  risk.py         explainable additive scoring
  scenarios.py    labelled A–H subsets of the dataset
  demo.py         the pipeline, wired
  providers/      siem.py · ai_analyst.py · response.py
```

---

## 2. Event flow

1. **Ingest** — `MockSIEMProvider.query_events()` reads the synthetic dataset
   through a bounded `EventQuery` (structured filters, enforced `limit`). The
   query is structured rather than a raw query string on purpose: a free-form
   query language fed from user or model input is an injection surface.
2. **Normalize & validate** — `parse_event()` enforces required fields, enum
   membership, tz-aware timestamps and length caps. Invalid records raise
   `EventValidationError`; a bad record **fails the batch** rather than being
   silently dropped, so a poisoned record cannot vanish unnoticed.
3. **Screen** — `screen_for_injection()` runs over *every* ingested event, not
   only those that end up in an incident. Findings are reported and never
   stripped: an injection attempt is evidence.
4. **Detect → correlate → score → triage → propose**, as below.

The stored event shape is nested (`host`/`user`/`details`) because that is how
log sources present data. Flat read-only accessors (`event.process`,
`event.command_line`, `event.source_ip`, `event.domain`) give detection rules a
readable view without duplicating state.

---

## 3. Detection flow

Eight rules across three explainable layers. **No AI decides whether a rule
fired.**

| Rule ID | Detects | Technique | Severity | Confidence |
|---|---|---|---|---|
| `SOC-AUTH-001` | Password spraying (distinct accounts, one source) | T1110.003 | high | high |
| `SOC-AUTH-002` | MFA fatigue / push bombing | T1621 | high | medium |
| `SOC-EXEC-001` | Suspicious PowerShell flags | T1059.001 | high | medium |
| `SOC-EXEC-002` | Encoded PowerShell | T1059.001, T1027.010 | high | high |
| `SOC-EXEC-003` | Suspicious parent→child lineage | T1204.002, T1218.011 | high | medium |
| `SOC-DNS-001` | High-entropy DNS label | T1568.002 | medium | **low** |
| `SOC-CRED-001` | LSASS access / credential dumping | T1003.001 | critical | high |
| `SOC-NET-001` | Repeated outbound to one external host | T1071.001 | high | medium |

Design decisions worth knowing:

- **Spraying counts distinct usernames**, not attempts. Many attempts against
  one account is brute force; few attempts against many accounts is spraying.
  MFA denials are explicitly excluded so `SOC-AUTH-001` and `SOC-AUTH-002`
  stay disjoint and each alert means one thing.
- **`SOC-CRED-001` fires even when the EDR blocked the attempt.** A blocked
  attempt still proves intent and an active foothold.
- **`SOC-DNS-001` is low confidence and says so.** Entropy flags legitimate CDN
  hostnames too. A rule that overstates itself trains analysts to ignore it.
- **The encoded payload is never decoded or executed** — only its presence and
  length are recorded.
- **A broken rule cannot silence the others**: `DetectionEngine.run()` isolates
  per-rule exceptions and returns them alongside the alerts.

Every alert carries `evidence_event_ids`. `DetectionResult.__post_init__`
rejects an alert with no evidence, and rejects any ATT&CK ID absent from the
pinned catalog — so a rule cannot cite a technique that does not exist.

Portable [Sigma rules](../security/detection_rules/) mirror five of these for
sharing and eventual SIEM conversion; the README there is honest about the
three that have no Sigma equivalent and why.

---

## 4. Correlation

`CorrelationEngine` runs union-find over alerts. Two alerts link when they
share an entity (host, user, source IP, destination IP) **and** their evidence
falls within the time window (default 4h).

The demo's full chain — spray → MFA fatigue → successful auth → encoded
PowerShell → rundll32 → persistence → DNS → C2 → LSASS — becomes **one**
critical incident with a 14-event timeline.

Guards against a mega-incident: generic shared infrastructure (the IdP, the
cloud control plane) never links alerts; the time window bounds growth;
technique-only correlation is off by default.

An `Incident` carries id, title, severity, timeline, hosts, users, source IPs,
alerts, evidence event IDs and ATT&CK techniques, plus a derived
`attack_stage` — the furthest kill-chain tactic reached, computed
deterministically from the tactic ordering.

`summarize_event()` deliberately **withholds** command lines and DNS names from
timeline strings. Timelines get rendered in UIs and passed around; keeping them
to structured fields avoids carrying an injection payload into a component that
never screened for it.

---

## 5. AI analysis

`AIAnalyst` is the interface; `MockAIAnalyst` is the only implementation.
It returns summary, severity assessment, evidence, likely attack stage, ATT&CK
mappings, recommended actions, confidence, uncertainty, and analyst questions.

Two properties matter more than the output quality:

**Validation lives in the base class.** `AIAnalyst.analyze()` runs
`validate_analysis()` on whatever `_analyze()` produced. A future integration
overrides `_analyze()` only, so it *cannot* skip validation. Checks:

| Check | Catches |
|---|---|
| Cited `event_id`s exist in the incident | Fabricated evidence |
| Technique IDs exist in the pinned catalog | Hallucinated ATT&CK |
| No past-tense action claims (negation-aware) | "I have isolated the host" |
| `proposed_only` is true | Implied authority |
| Tier ≥ T2 ⇒ `requires_human_approval` | Gate bypass |
| Confidence in {low, medium, high} | Malformed output |

The negation handling matters: *"No response action has been taken"* is the
statement we **want**, so flagging it would train implementations to stop
saying the true thing.

**The mock is structurally injection-immune.** It composes from templates and
never interprets log text as language, so there is nothing for an injected
instruction to steer. That is a clean baseline for demonstrating the difference
between "the prompt told it not to" and "it cannot". A real model would not
have this property — which is precisely why the controls *downstream* of it are
the ones that count.

Confidence is derived from corroboration (distinct rules, high-confidence
detections), not from model self-belief.

---

## 6. Response automation

`MockResponseProvider` records what *would* happen and changes nothing. Seven
conceptual actions: `isolate_host`, `disable_account`, `block_ip`,
`block_domain`, `collect_artifact`, `create_ticket`, `notify_analyst`.

```
T0 read-only          automatic
T1 reversible, small  automatic, audited, rate-limited
T2 disruptive         human approval required
T3 destructive/wide   human approval required
```

Gates, all enforced in the base class so no implementation can bypass them:
closed action enum · non-empty target · protected-asset list · target must
appear in the incident's evidence · tier ≥ T2 needs an approver · blast-radius
cap · everything audited including refusals · **dry run by default**.

`requests_from_analysis()` is the boundary where model prose stops being text
and must become a known action. Anything unmappable is dropped, not improvised
— so a successful prompt injection yields, at worst, a rejected suggestion.
Approval is **never** read from model output; a human supplies it or the action
is refused.

In the default demo run, every disruptive action is refused (protected asset or
missing approver) and **zero actions execute**.

---

## 7. Human-in-the-loop model

| Decision | Who |
|---|---|
| Is this an alert? | Deterministic rules |
| Do these alerts belong together? | Deterministic correlation |
| How risky is it? | Transparent additive scoring |
| What might it mean? | **AI (advisory)** |
| Is the AI right? | **Human analyst** |
| Should we act? | **Human analyst** |
| May a disruptive action run? | **Human approver (T2+)** |
| Did an action actually happen? | Orchestrator audit log — never model text |

Guards against automation bias: evidence-first output, AI text explicitly
labelled with its model, mandatory citations, uncertainty never empty, analyst
questions surfaced, low-confidence rules named, and the risk score presented
with its full factor breakdown so it can be argued with.

The AI never auto-closes anything. There is no code path from model output to
execution.

---

## 8. How Splunk could fit later

`SplunkProvider` exists as a documented placeholder implementing `SIEMProvider`;
constructing it raises `NotImplementedError` rather than silently pretending.

To implement: bearer token from `SPLUNK_TOKEN` in the environment; HTTPS with
cert verification and an explicit timeout; translate `EventQuery` into SPL with
values **quoted and escaped** — never f-string a user- or model-supplied value
into SPL; always bound with `earliest`/`latest` and `head <limit>`, since an
unbounded search is a self-inflicted DoS; map results into the normalized
schema and run them through `parse_event()` so SIEM data gets the same
validation as everything else. `create_case()` maps to an ES notable event.

Nothing in `detections.py`, `correlation.py` or `risk.py` changes.

---

## 9. How Wazuh could fit later

`WazuhProvider` is the same shape of placeholder. Wazuh is the **strongest
candidate for an offline demo** because it is open source and self-hostable — a
judge can actually run it.

To implement: API user/password from the environment exchanged for a short-lived
JWT (refresh on 401, never log it); query the Wazuh Indexer (OpenSearch) DSL
against `wazuh-alerts-*` with an explicit time range and `size` limit; map
`rule.level` (0–15) onto our severity vocabulary **once**, in one documented
place. Wazuh has no native case object, so `create_case()` should route to the
configured ticketing system and say so plainly rather than pretending the
capability exists.

`get_alerts()` returns Wazuh's own detections — these stay distinguishable from
ours so provenance is never ambiguous.

---

## 10. How Ollama could fit later

`OllamaAnalyst` is a placeholder implementing `AIAnalyst`. Three reasons it is
attractive for this track:

1. **Zero data egress** — trust boundary TB-3 disappears. If the scenario
   involves real or regulated log data, local inference may be the only
   defensible choice.
2. **Offline demo resilience** — conference wifi fails; the demo still runs.
3. **No cost** — and no cost-exhaustion vector.

To implement: endpoint from `OLLAMA_HOST` (default `http://localhost:11434`),
bound to localhost — an exposed endpoint is an open inference server. Build the
prompt from [prompts/SOC_ANALYST_PROMPT.md](../prompts/SOC_ANALYST_PROMPT.md):
event data goes inside the untrusted delimiters and nowhere else, and any
occurrence of the delimiter **in the data** must be escaped first (see
`evt-0024`, which attempts exactly that smuggling). Pass
`screen_for_injection()` findings in as metadata so the model is told what was
flagged. `temperature=0`, capped `num_predict`, explicit timeout. Parse the
reply as strict JSON into `AIAnalysis`; on failure retry once, then fall back
to `MockAIAnalyst` and mark the degradation — never ship unparsed model text
onward.

**A local model is not inherently injection-resistant.** Every control in
`validate_analysis()` still applies, which is why the base class runs it
regardless of implementation.

A sensible hybrid: local model filters volume, hosted model handles escalated
incidents after redaction.

---

## 11. Test coverage

357 tests, no network, no pytest required:

```bash
python -m unittest discover -s tests -v
```

| File | Covers |
|---|---|
| `test_security_events.py` | Event validation, parsing, untrusted-text extraction |
| `test_detections.py` | All 8 rules, engine behavior, benign false-positive control |
| `test_correlation_and_risk.py` | Correlation, incidents, risk scoring, ATT&CK mapping |
| `test_providers.py` | SIEM/AI/response interfaces, injection resistance, dry-run guarantees |
| `test_sigma_rules.py` | Sigma metadata, ATT&CK tag validity, Python↔Sigma agreement |
| `test_pipeline.py` | End-to-end demo, scenarios, synthetic-data safety |
| `test_cloud.py` | Cloud events, 11 cloud rules, correlation, risk, ATT&CK, CloudTrail injection, cloud dry-run, cloud demo |

Notable assertions: benign activity produces **zero** alerts; nothing executes
in a full run; a rogue analyst implementation is caught by base-class
validation; zero-width Unicode injection is detected; the dataset contains only
RFC 5737 addresses and RFC 2606 domains.

---

## 12. Cloud telemetry (AWS)

The same core now represents AWS control-plane telemetry. **Nothing connects to
AWS**: it's a synthetic, CloudTrail-shaped dataset through the existing
interfaces.

```bash
python -m app.soc_core.demo --profile cloud              # 37 events, 3 incidents
python -m app.soc_core.demo --profile cloud --scenario K   # full attack chain
```

Walkthrough: [CLOUD_DEMO_SCENARIO.md](CLOUD_DEMO_SCENARIO.md) ·
diagram: [architecture/CLOUD_SOC_ARCHITECTURE.mmd](../architecture/CLOUD_SOC_ARCHITECTURE.mmd) ·
threats: [SOC_THREAT_MODEL.md §14](../security/SOC_THREAT_MODEL.md) ·
coverage: [AWS_SOC_CHECKLIST.md](../security/AWS_SOC_CHECKLIST.md)

### What was extended, and what wasn't

| Layer | Change | Not changed |
|---|---|---|
| Event model | New `cloud` category + accessors (`cloud_event_name`, `principal_arn`, `session_issuer_arn`, `access_key_id`, `request_parameters`, …). `host` optional for cloud-native events | VPC Flow Logs reuse `network`; GuardDuty reuses `alert`. `VALID_CATEGORIES` kept as the endpoint vocabulary; validation uses `ALL_CATEGORIES` |
| Detection | 11 rules in `cloud_detections.py`; `all_rules()` = endpoint + cloud on **one** `DetectionEngine` | `default_rules()` still returns the 8 endpoint rules |
| Correlation | Cloud entities: `principal:`, `role:` (session issuer ↔ AssumeRole target), `key:`, `res:`; AWS-service callers and non-IP source addresses excluded | Same union-find engine; account ID deliberately **not** an entity |
| Risk | `impair_defenses` (T1562.*) and `privileged_identity` (Root) factors | Neither can trigger on endpoint data; the endpoint score is still 98 |
| AI analyst | Cloud playbook emitting **structured** `response_action` + `target`; manual tasks marked `response_action: None`; cloud uncertainty and questions | Endpoint recommendations unchanged |
| Validation | `response_action` must be a real enum and its tier must equal policy tier | All existing checks |
| Response | 6 cloud actions (all T2/T3); `CLOUD_ACTIONS` refused in the base class whenever `dry_run=False`; `record_rejection()`; cloud protected identities | Dry-run default; existing gates |
| Demo | `--profile cloud`; a SIMULATED analyst decision table | `--profile endpoint` (default) output is **byte-identical** to before |

### From AWS to this pipeline (future, not built)

```
AWS account(s)
  CloudTrail ─────────┐ (management + S3 data events)
  VPC Flow Logs ──────┼──► S3 log-archive bucket (separate account, Object Lock)
  GuardDuty ──► EventBridge ──┐
                      │       │
                      ▼       ▼
          ┌───────────────────────────────────────┐
          │ Splunk: Splunk Add-on for AWS          │  pulls S3 via SQS notifications;
          │   sourcetypes aws:cloudtrail,          │  GuardDuty via EventBridge ->
          │   aws:cloudwatchlogs:vpcflow           │  Firehose -> HEC
          │ Wazuh:  aws-s3 wodle                   │  reads the same buckets;
          │   (cloudtrail, vpcflow, guardduty)     │  decoded into wazuh-alerts-*
          └───────────────────┬───────────────────┘
                              │ SplunkProvider / WazuhProvider.query_events()
                              ▼
          normalize_<vendor>(raw) -> our schema dict      <- the missing piece
                              ▼
          parse_event()  ->  detections  ->  correlation  ->  risk  ->  AI  ->  human  ->  response
```

What each provider must do when implemented:

- **Map, then validate.** A `normalize_cloudtrail()` translates
  `userIdentity.type` → `identity_type`, `sourceIPAddress` → `source_ip`,
  `requestParameters` → `request_parameters`,
  `userIdentity.sessionContext.sessionIssuer.arn` → `session_issuer_arn`,
  `additionalEventData.MFAUsed` → `mfa_authenticated`, and so on. The output then goes through
  `parse_event()`. SIEM data gets no validation shortcut.
- **Bound every query** by time and count; never build SPL or query DSL by
  concatenating event-derived values.
- **Preserve provenance.** GuardDuty findings stay `alert` events with
  `vendor: aws-guardduty`, so vendor verdicts never look like our own
  detections.
- **Pull from the log-archive account**, not the workload account. A reader
  in the compromised account sees only what the attacker left.

### Why cloud response is stricter than endpoint response

Isolating one laptop affects one person. Revoking a key, detaching a policy or
rewriting a security group can stop production or lock responders out of the
account. And the attacker chooses which identities appear in the evidence. So:

1. **Every cloud action is T2 or T3.** A human approves each one.
2. **Dry-run only in this build**, enforced in `ResponseProvider._refusal_reason()`
   ahead of the approval check. Approval can't unlock it.
3. **Targets must appear in the incident evidence** (`Incident.entity_values`).
4. **Protected identities** (`root`, `break-glass-admin`,
   `OrganizationAccountAccessRole`) are never actioned.
5. **Rejections are audited** (`record_rejection`), and the model never supplies
   `approved_by`.
6. **The AI pipeline holds no cloud credentials at all.** A future responder
   role is separate, MFA-gated and scoped to the allow-list. Every call it makes
   should carry the incident ID and approver as tags, so CloudTrail
   independently records who authorized it.

### Replacing the synthetic AWS layer with real telemetry

| If the problem statement provides… | Do this |
|---|---|
| Raw CloudTrail JSON (files or S3 export) | Write `normalize_cloudtrail()`; load through `MockSIEMProvider(events=...)`. No SIEM needed |
| A Splunk instance with AWS data | Implement `SplunkProvider.query_events()` + the same normalizer |
| A Wazuh instance with the aws-s3 wodle | Implement `WazuhProvider` + normalizer from Wazuh's decoded fields |
| GuardDuty / Security Hub findings | Map to `alert` events with `vendor: aws-guardduty`; extend `GUARDDUTY_TECHNIQUES` only for types with a clean meaning |
| A real account to act on | Keep `CLOUD_ACTIONS` dry-run until the checklist's "before any cloud action runs for real" list is complete |

In every case update `SENSITIVE_BUCKETS`, `SENSITIVE_PORTS`, the internal
address prefixes and the protected identities first. They're tuned to the
synthetic data.
