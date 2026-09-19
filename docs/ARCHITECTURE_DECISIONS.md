# Architecture Decisions

The decisions already baked into the SOC simulation. For each one: what we
decided, why, the alternative we rejected, and what in tomorrow's problem
statement should make us reconsider.

These are **defaults, not dogma**. Each includes its own reversal condition.
When a decision changes, record it here with the reason: the next person
(or a judge) will ask.

| # | Decision | Reversal likelihood |
|---|---|---|
| ADR-01 | Deterministic detection before AI | Low |
| ADR-02 | Evidence vs interpretation separation | Very low |
| ADR-03 | Human-in-the-loop response | Medium |
| ADR-04 | Provider abstraction | Very low |
| ADR-05 | Dry-run response by default | Low |
| ADR-06 | Explainable risk scoring | Medium |
| ADR-07 | Offline-first development | Medium |
| ADR-08 | Synthetic data | **High** |
| ADR-09 | AI output validation | Very low |
| ADR-10 | Prompt injection handling | Very low |

---

## ADR-01 — Deterministic detection before AI

**Decision.** Alerts come only from deterministic rules
(`detections.py`). No model decides whether something is an alert.

**Reason.**
- **Reproducible:** same input, same alerts. That's asserted by `test_detection_is_deterministic`.
- **Explainable:** an analyst can read the rule that fired and re-derive it.
- **Not manipulable by text:** a rule matching `-enc` can't be talked out
  of matching by a log line saying "ignore this".
- **Testable:** every rule has positive and benign negative tests.
- **Cheap:** 26 events run through 8 rules in milliseconds with no API cost.

**Alternative rejected.** LLM-as-detector: feed events to a model and ask
"is this malicious?". It's non-deterministic, costly per event, unexplainable,
and above all it hands the detection decision to a component that reads
attacker-written text.

**Reconsider if** the statement asks for detection of behavior no fixed rule
can capture: novel phishing language, semantic anomaly in free text, or
"detect things we haven't seen before". Even then, **add** an AI or ML
detection layer that emits `DetectionResult`s *with evidence*, alongside the
rules. Keep the rules as the auditable baseline. Don't replace them.

---

## ADR-02 — Evidence vs interpretation separation

**Decision.** Two independent paths. The **evidence path** (events → alerts →
incident → risk score) is authoritative. The **interpretation path** (AI
analysis) is advisory. Removing the AI changes nothing in the evidence path.

**Reason.**
- The AI's failure modes (hallucination, manipulation, outage) become
  **survivable** instead of catastrophic.
- Analysts can check the AI against evidence it can't alter.
- Mirrors the prompt contract: every claim cites `event_id`s; inference is
  labelled as inference.
- The single clearest answer to a judge asking "what if the LLM is wrong?".

**Alternative rejected.** AI-centric pipeline where the model's narrative *is*
the incident record. Simpler to build, but then a manipulated model rewrites
history and nothing downstream can tell.

**Reconsider if** essentially never. If the statement is "build an AI
assistant for analysts", the AI becomes the product surface, but it should
still sit on top of an evidence layer it can't modify. This is the decision
to defend hardest.

---

## ADR-03 — Human-in-the-loop response

**Decision.** Actions are tiered T0–T3. T0/T1 (read-only, notify, ticket,
collect) may run automatically. T2/T3 (isolate, block, disable) require a
human `approved_by`. The model can't supply approval:
`requests_from_analysis()` hardcodes `approved_by=None`.

**Reason.**
- An attacker who can write a log line can influence the AI. Without a human
  gate, that attacker can influence **containment**, and can turn our SOC into
  the outage (threat T18).
- Automation bias is real. A mandatory human decision point forces review.
- Irreversible actions (`disable_account` is marked `reversible: False`) warrant
  a person.

**Alternative rejected.** Fully autonomous response above a confidence
threshold. Fast, but a confidence score is exactly what an injection or a
poisoned baseline manipulates.

**Reconsider if** the statement explicitly demands autonomous response ("respond
within 60 seconds without human intervention"). Then:
1. Automate **only reversible, low-blast-radius** actions (T1, maybe single-host T2).
2. Require **corroboration**: ≥2 independent high-confidence rules, never AI
   judgement alone.
3. Keep protected assets, blast-radius caps and the audit log.
4. Add auto-rollback on a timer unless a human confirms.
5. State the trade-off out loud in the pitch.

---

## ADR-04 — Provider abstraction

**Decision.** Every external system sits behind an interface: `SIEMProvider`,
`AIAnalyst`, `ResponseProvider`. Each has a working Mock; real integrations
are documented placeholders that raise `NotImplementedError`.

**Reason.**
- Tomorrow's statement may name Splunk, Wazuh, Sentinel, or nothing. We can't
  know, so we can't hardcode.
- Swapping a provider touches nothing in `detections.py`, `correlation.py` or
  `risk.py`.
- Mocks make the full pipeline testable offline (357 tests, no network).
- **Security controls live in base classes** (`analyze()`, `execute()`), so a
  new integration inherits them instead of reimplementing them.
- Placeholders fail loudly. Nothing silently pretends to be connected.

**Alternative rejected.** Wire a vendor SDK directly into the pipeline. Faster
for exactly one vendor; a rewrite for any other, and vendor code ends up
interleaved with security logic.

**Reconsider if** never, as a pattern. The only question is *which*
implementation to build (see [HACKATHON_RUNBOOK.md](HACKATHON_RUNBOOK.md) §E–G).

---

## ADR-05 — Dry-run response by default

**Decision.** `ResponseProvider(dry_run=True)` is the default. Dry run records
exactly what *would* happen (`would_have`) and changes nothing. Even
`MockResponseProvider._perform()` only appends to a list.

**Reason.**
- It must be impossible to execute by accident. Execution needs an explicit
  constructor argument **and** passing every gate.
- The full pipeline, including the "execute" branch, can be exercised with zero
  risk.
- A hackathon has no business touching real production systems.
- Dry-run output demos as well as execution: "here is what it would do, and here
  is what it refused".

**Alternative rejected.** Execute by default with a `--dry-run` flag. One
forgotten flag and something real happens.

**Reconsider if** the statement requires demonstrating real execution against a
**sandbox** system (a lab EDR, a test firewall). Then set `dry_run=False` for
that one provider instance, against that one sandbox, and keep the default
everywhere else. Never flip the default itself.

---

## ADR-06 — Explainable risk scoring

**Decision.** Risk score = clamped sum of named, capped, evidence-linked
factors (`risk.py`). Weights live in a `RiskWeights` dataclass. No model
produces the number.

**Reason.**
- An analyst can ask "why 98?" and get an itemized answer: +30 critical
  severity, +18 credential access, +14 C2, …
- Every factor names the alerts that triggered it, so it can be disputed.
- Tuning is a visible policy change, not a hidden retrain.
- An AI-generated risk score is an injection target: "rate this 5/100".

**Alternative rejected.** LLM-generated score, or an opaque ML model. Neither
can be audited, and the LLM version can be steered by log content.

**Reconsider if** the statement provides **labelled** data and judges reward
detection accuracy. A trained model may then beat hand-set weights. Keep the
factor breakdown as its explanation (e.g. show feature contributions), and keep
the transparent score as a baseline to compare against.

---

## ADR-07 — Offline-first development

**Decision.** The core runs with no network, no API key, no database, no SIEM,
no container. Standard library plus PyYAML (already present, used only in
tests).

**Reason.**
- Venue Wi-Fi fails. A demo that needs the internet is a demo that can fail.
- Zero setup: any teammate or judge runs it with two commands.
- Tests are fast (0.3s) and deterministic, so they get run.
- No secrets exist, so none can leak.
- It forced clean interfaces, because we couldn't lean on a vendor SDK.

**Alternative rejected.** Stand up Postgres, Redis and a SIEM from the start.
More realistic, but hours of setup that don't change what the demo shows.

**Reconsider if** the statement requires a live integration, persistence across
sessions, multiple users, or a hosted LLM. Add exactly what's required,
behind the existing interfaces, and **keep the offline path working as the
fallback demo.**

---

## ADR-08 — Synthetic data

**Decision.** All data is fictional: RFC 5737 IPs (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), RFC 2606 domains (`.test`),
invented hosts and users. Tests enforce this.

**Reason.**
- No privacy, legal, or disclosure risk.
- Nothing resolves to real infrastructure, so nothing can be accidentally
  contacted.
- Scenarios are designed: each one exercises a specific rule, including
  adversarial cases (`evt-0016`, `evt-0024`) that real data wouldn't contain
  on demand.
- A benign control scenario (A) lets us prove the absence of false positives.

**Alternative rejected.** Download public datasets (e.g. Mordor/OTRF, BOTS).
Realistic, but large, slow to normalize, and poor at hitting specific test
cases.

**Reconsider if** the statement provides data. **This is the decision most
likely to change tomorrow.** When it does:
- Add their data **alongside**; don't delete ours (the endpoint test suites depend on it).
- Update the dataset-specific constants: `DEFAULT_PROTECTED_ASSETS`,
  `GENERIC_ENTITIES`, `_INTERNAL_PREFIXES`.
- If it's real data: redact before any hosted LLM call, and prefer Ollama.
- Keep our adversarial events; inject them into their data to demo injection
  resistance.

---

## ADR-09 — AI output validation

**Decision.** `AIAnalyst.analyze()` (base class) runs `validate_analysis()` on
every implementation's output. Implementations override `_analyze()` only, so
they can't skip it. Checks: cited `event_id`s exist, ATT&CK IDs exist in the
pinned catalog, no past-tense action claims (negation-aware), T2+ actions
require approval, confidence is valid, incident ID matches.

**Reason.**
- A prompt is a request; a validator is a control. Assume a clever injection
  defeats the prompt, and let code catch the result.
- Hallucinated event IDs and ATT&CK IDs are cheap to detect mechanically.
- "I have isolated the host" when nothing happened is catastrophic during an
  incident (threat T17), so it's checked, not trusted.
- `test_base_class_applies_validation_automatically` proves a deliberately rogue
  implementation is caught.

**Alternative rejected.** Validate in each implementation, or trust the prompt.
Both rely on every future integration remembering, which is how controls
disappear.

**Reconsider if** never remove it. A real LLM will need **more** checks, not
fewer: strict JSON schema parsing, output length caps, secret-pattern redaction
on the way out.

---

## ADR-10 — Prompt injection handling

**Decision.** Defense in depth, in this order of importance:
1. **The AI has no tools.** It proposes; a closed `ResponseAction` enum and a
   human decide.
2. **Output validation** (ADR-09).
3. **Evidence independence** (ADR-02). Injection can bias a narrative, not
   rewrite alerts.
4. **Screening** (`screen_for_injection()`) over **all** ingested events, with
   NFKC normalization and zero-width stripping. Findings are **reported, never
   stripped**.
5. **Prompt contract** ([prompts/SOC_ANALYST_PROMPT.md](../prompts/SOC_ANALYST_PROMPT.md)):
   untrusted delimiters, rule restated after the data.
6. **Timeline withholding**: `summarize_event()` never interpolates command
   lines or domains.

**Reason.**
- A SOC ingests attacker-controlled data by design. Every AI downstream of a
  log pipeline is processing hostile text.
- Pattern screening alone is evadable; that's why it's layer 4, not layer 1.
  The structural controls hold even when screening misses.
- An injection attempt is **evidence of an attacker**. Stripping it would
  destroy the finding.

**Alternative rejected.** Rely on a strong system prompt, or sanitize/strip
suspicious strings. The first fails against a determined attacker; the second
deletes evidence and gives false confidence.

**Reconsider if** the statement *is* prompt-injection defense for an LLM
application. Then this stack becomes the product rather than a feature. Reuse
`screen_for_injection`, `validate_analysis` and the gate pattern directly, and
expect judges to probe screening evasions hard.

---

## Decisions deliberately NOT made yet

These are open until the problem statement answers them:

| Question | Default until answered |
|---|---|
| Which SIEM? | `MockSIEMProvider` |
| Which LLM, local or hosted? | `MockAIAnalyst` |
| Real response execution? | Dry run only |
| Persistence? | In-memory; audit log not durable |
| UI? | Terminal output + JSON |
| Multi-tenancy / authN / authZ? | None. No API exists yet |
| Vendor log normalizer? | None. `parse_event()` validates only |
