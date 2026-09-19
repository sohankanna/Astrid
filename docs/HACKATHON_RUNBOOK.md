# Hackathon Runbook

Emergency playbook for hackathon day. Read section A the moment the problem
statement lands. Everything else is reference.

**Current baseline:** offline SOC pipeline (endpoint + AWS cloud profiles), 357 passing tests, `python -m app.soc_core.demo` works.
**Golden rule:** keep it working. Commit before every risky change.

---

## 0. Before anything else (2 minutes)

The repo has **no git commits**. If an edit breaks the baseline there is no
way back.

```bash
git add -A && git commit -m "Pre-hackathon baseline: offline SOC simulation, 357 tests"
git tag baseline
```

Then confirm the baseline still runs on the machine you will demo from:

```bash
python -m unittest discover -s tests      # expect: Ran 357 tests ... OK
python -m app.soc_core.demo               # expect: 1 critical incident, 0 executed
```

Run both **from the repo root**. `python -m app.soc_core.demo` fails from any
other directory.

---

## A. The first 15 minutes after the problem statement

| Min | Action | Output |
|---|---|---|
| 0–3 | Read the statement twice. Highlight every noun that is **data**, every verb that is an **action**, every word that is a **constraint**. | Annotated statement |
| 3–6 | Answer the 8 triage questions below. Write the answers down. | 8 one-line answers |
| 6–9 | Run the **fit test** (section B). Decide: *adapt*, *extend*, or *pivot*. | One word |
| 9–12 | Write the demo's final sentence first: "We show that ___." Everything we build serves that sentence. | Demo thesis |
| 12–15 | Split work. One person owns data ingestion, one owns detection/logic, one owns demo + slides. Nobody touches `events.py` without telling the others. | Owners assigned |

### The 8 triage questions

1. **What data do we get?** Format (JSON, CSV, EVTX, PCAP, free text)? Size? Provided, or do we generate it?
2. **Is there a SIEM requirement?** Named product, or our choice?
3. **Is an LLM required, allowed, or forbidden?** Hosted allowed? Is internet access guaranteed?
4. **Must response actions actually execute,** or is recommendation enough?
5. **Is it real or synthetic data?** (Real data changes the privacy posture.)
6. **Who is the user?** Tier-1 analyst, CISO, incident commander, developer?
7. **What is judged?** Detection accuracy, UX, novelty, security, completeness?
8. **Is there a UI requirement?** (We currently have none.)

Questions 3 and 4 change the architecture the most. If the statement is
ambiguous on either, **ask the organizers immediately**. Don't guess.

---

## B. Does the existing architecture apply?

### Fit test

| If the problem is about… | Fit | Plan |
|---|---|---|
| Triaging alerts / reducing analyst fatigue | **Direct** | Adapt: swap dataset, tune rules, strengthen AI layer |
| Detecting an attack in provided logs | **Direct** | Adapt: write normalizer + new rules |
| Correlating events into incidents | **Direct** | Adapt: tune correlation window/entities |
| Incident response automation / SOAR | **Strong** | Extend: implement one real `ResponseProvider` |
| Threat hunting from a hypothesis | **Good** | Extend: add a hunt query mode over `MockSIEMProvider` |
| Explaining alerts to non-experts | **Good** | Extend: AI layer becomes the product |
| Phishing / email analysis | **Partial** | Extend: new `email` category + rules; keep the rest |
| Malware / file analysis | **Partial** | Pivot the data layer; **sandbox required** (threat T7) |
| Anomaly detection with ML | **Partial** | Extend: add a statistical rule layer; keep deterministic rules as the baseline |
| Securing an LLM app (prompt-injection defense) | **Reuse the controls, not the pipeline** | Pivot: `screen_for_injection`, `validate_analysis`, the gate pattern |
| Network forensics from PCAP | **Weak** | Pivot: PCAP parsing is new work; keep the downstream pipeline |
| Compliance / policy checking | **Weak** | Pivot: reuse risk scoring pattern only |

**Signals to pivot rather than adapt:** the core input is not an event stream,
there is no concept of an incident, or the judged artifact is a UI we don't
have.

**Default when unsure: adapt.** A working pipeline with a new dataset beats an
elegant half-finished rewrite.

---

## C. Components to keep

Keep these unchanged unless the problem statement directly contradicts them.
They are the defensible core, and they're what judges in a security track will
probe.

| Component | Why keep |
|---|---|
| `SecurityEvent` + `parse_event()` | Schema is stable; validation is tested. Extend, don't replace |
| `DetectionEngine` + rule base classes | Adding a rule is one subclass. The engine isolates rule crashes |
| `CorrelationEngine` | Entity + time correlation is generic |
| `risk.py` | Transparent scoring is a talking point in itself. Retune `RiskWeights`, keep the model |
| `mitre.py` | Closed vocabulary = hallucination check. Add techniques, never remove the check |
| `AIAnalyst.analyze()` base-class validation | The single most important AI-security control |
| `ResponseProvider.execute()` gates | The second most important one |
| `screen_for_injection()` | Cheap, visible, demos well |
| Dry-run default | Never flip this for a demo |
| The test suite | Your regression net. Run after every change |

---

## D. Components to delete or change

| Component | Change when… | How |
|---|---|---|
| `data/sample_security_events.json` | Always, if data is provided | Keep it for tests; add new data alongside. **Don't delete**: the endpoint test suites depend on it |
| `scenarios.py` | New dataset | Add new scenario keys; leave A–H for tests |
| The 8 rules | Different attack domain | Add rules; keep existing ones unless they misfire on new data |
| `DEFAULT_PROTECTED_ASSETS` | **Any new dataset** | ⚠ It lists *synthetic* hostnames. On new data it protects nothing. See trap 1 |
| `GENERIC_ENTITIES` | Any new dataset | Same problem: hardcoded synthetic names |
| `_INTERNAL_PREFIXES` | Any real network data | ⚠ Misses `172.17–31.x`; treats `192.0.2.x` as internal. See trap 3 |
| `MockAIAnalyst` | An LLM is required | Implement `OllamaAnalyst` or `HostedLLMAnalyst`; **keep the mock as fallback** |
| `demo.py` rendering | Different audience | Change `render()` only; leave `run_pipeline()` alone |
| Empty placeholder files | Before submission | `ARCHITECTURE.md`, `DATA_FLOW.md`, `THREAT_MODEL.md`, `SECURITY_REQUIREMENTS.md`, `MVP.md`, `README.md`, `main.py` are **0 bytes**. Fill them or delete them. Empty files look unfinished |

### Known traps in the current code

Each one was confirmed by running it, so these are observed behaviors rather
than guesses. None blocks the current demo. Each one can bite on new data.

1. **Protected assets are synthetic names.** `DEFAULT_PROTECTED_ASSETS` lists
   `DC-CORP-01`, `idp.corp.test` and similar. Load real data and the protected list matches
   nothing, which silently removes a safety control. **Update it first when
   data changes.**
2. **One bad record rejects the whole batch.** `parse_events()` fails fast by
   design. With a messy provided dataset, a single `severity: "SEV3"` kills the
   run. Fix at the normalizer: map vendor values *before* `parse_event()`.
   Don't weaken validation.
3. **RFC 1918 coverage is incomplete.** `172.20.1.5` is classified as external,
   so real internal traffic will fire `SOC-NET-001`.
4. **Negated prose maps to actions.** `"Do not isolate the host yet"` becomes an
   `isolate_host` request in `requests_from_analysis()`. It's still gated by
   approval, so it's not dangerous, but it's wrong. **Fix available:** an
   action dict carrying `response_action` (an enum value) + `target` bypasses
   the keyword path entirely. The cloud playbook already uses it. Make any real
   LLM return that shape.
5. **`SOC-CRED-001` fires critical on any mention of "lsass".** A benign
   `tasklist /fi "imagename eq lsass.exe"` triggers it. Expect false positives on
   real data.
6. **Nested field lengths are unbounded.** `MAX_FIELD_LENGTH` doesn't cover
   `details.*`. A huge `command_line` passes validation. Cap it before it reaches
   a prompt.
7. **Correlation is O(n²).** Measured: 500 alerts in 0.1s, 2,000 in 1.5s, so
   ~10,000 alerts would take roughly 40s. Pre-filter to high/critical alerts if
   the dataset is large.
8. **`data/*` is gitignored.** New dataset files won't be committed unless you
   add a `!data/<file>` line to `.gitignore`.
9. **The demo proposes disabling spray *victims*.** `a.chen` and `m.okafor` only
   had failed logins, yet the mock proposes disabling them because they're in
   the incident's user list. It's refused (no approval), but a sharp judge will
   ask. See the demo script for the answer.
10. **Cloud constants are synthetic too.** `SENSITIVE_BUCKETS` in
    `cloud_detections.py` lists `corp-finance-archive` and `hr-records`. On real
    data CLOUD-S3-001 **silently never fires** until it lists the real sensitive
    buckets. The same goes for `SENSITIVE_PORTS` and the cloud protected identities.
11. **The cloud demo's approvals are simulated.** `SIMULATED_ANALYST_DECISIONS`
    stands in for a person. It's labelled in the output; say so out loud in
    the demo, or a judge will reasonably ask who "approved" the actions.

### Cloud profile quick reference

```bash
python -m app.soc_core.demo --profile cloud                  # 37 events, 3 incidents
python -m app.soc_core.demo --profile cloud --scenario K       # attack chain
python -m app.soc_core.demo --profile cloud --list-scenarios   # A-K
```

If the problem statement is AWS-centric, start from
[CLOUD_DEMO_SCENARIO.md](CLOUD_DEMO_SCENARIO.md) and
[SOC_SIMULATION.md §12](SOC_SIMULATION.md). The first real code is a
`normalize_cloudtrail()` mapping raw CloudTrail JSON onto our schema.

---

## E. Splunk vs Wazuh

**Default: neither.** If the statement doesn't name a SIEM, stay on
`MockSIEMProvider` and spend the time on detection quality. A live SIEM
integration eats hours and demos poorly when Wi-Fi fails.

| Choose **Wazuh** if… | Choose **Splunk** if… |
|---|---|
| Judges or sponsors mention open source | The statement or a sponsor names Splunk |
| You need to run it locally/offline | A hosted instance and credentials are provided |
| Endpoint/HIDS data is central | Enterprise log search / SPL is central |
| Budget is zero | You already know SPL |
| You want judges able to reproduce it | Splunk Cloud trial is available and working **before** you commit |

**Time box:** if a SIEM connection isn't returning events within **90
minutes**, abandon it. Export the SIEM's data to JSON and load it through
`MockSIEMProvider`. Say in the demo "production path is `SplunkProvider`;
interface shown here". That's an honest and common hackathon move.

---

## F. Ollama vs hosted LLM

```
Is an LLM required or clearly rewarded?
├── No  → keep MockAIAnalyst. Put the effort into detection + explanation.
└── Yes → Is the data real, sensitive, or regulated?
          ├── Yes → Ollama. No egress. Say so in the pitch.
          └── No  → Is venue internet reliable AND a key available?
                    ├── No  → Ollama.
                    └── Yes → Hosted for quality; Ollama as the fallback.
```

| | Ollama (local) | Hosted (e.g. Claude) |
|---|---|---|
| Data egress | None (TB-3 disappears) | Incident data leaves the boundary |
| Quality | Weaker reasoning, slower on a laptop | Strong |
| Demo risk | Laptop RAM/GPU, model download time | Wi-Fi, rate limits, key exposure |
| Setup | Pull the model **before** the event (GBs) | Key in env var |
| Pitch value | "Privacy-preserving, air-gap capable" | "Frontier reasoning" |

**Whatever you choose:** implement it behind `AIAnalyst`, override only
`_analyze()`, and **keep `MockAIAnalyst` as automatic fallback** on timeout or
parse failure. A demo that degrades gracefully beats one that hangs.

A local model is **not** more injection-resistant. Every validation still
applies, and the base class enforces it for you.

---

## G. Turning a mock into a real integration

The pattern is the same for all three provider types.

```
1. Subclass the interface          class WazuhProvider(SIEMProvider)
2. Remove the NotImplementedError  in __init__
3. Read credentials from env       os.environ["WAZUH_PASSWORD"]; fail fast if missing
4. Implement the abstract methods  query_events, get_event, ...
5. Normalize before returning      vendor dict → our schema dict → parse_event()
6. Keep the mock                   select provider by env var: SOC_SIEM=mock|wazuh
7. Add a test using recorded data  save one real response as a JSON fixture;
                                    test the mapping offline, never live
```

**Per-type rules:**

| Type | Override | Must NOT override | Watch for |
|---|---|---|---|
| `SIEMProvider` | all 5 methods | — | Escape query values; always bound time + limit |
| `AIAnalyst` | `_analyze()` only | `analyze()` (validation lives there) | Delimiter escaping (see `evt-0024`); strict JSON parsing; timeout |
| `ResponseProvider` | `_perform()` only | `execute()`, `_refusal_reason()` (gates live there) | Rollback path; scoped credentials |

**The normalizer is the missing piece.** `parse_event()` only *validates*
our schema. It doesn't *translate* vendor formats. Tomorrow's first real
code is almost certainly `normalize_<vendor>(raw: dict) -> dict`, run before
`parse_event()`. Put vendor-value mapping there (severity strings, action
names, field paths). That also fixes trap 2.

---

## H. MVP-first strategy

Build in this order. **Each step ends with a working demo.** Commit after each.

| Step | Deliverable | Time budget |
|---|---|---|
| 1 | Their data loads: normalizer → `parse_event()` → counts printed | 1–2 h |
| 2 | One detection rule fires on their data | 1 h |
| 3 | Demo runs end to end on their data (reuse everything else) | 30 min |
| 4 | 2–4 more rules targeting what the statement cares about | 2 h |
| 5 | The differentiator: real LLM **or** real response integration **or** UI, pick **one** | 3 h |
| 6 | Tests for everything new + security pass (section J) | 1 h |
| 7 | Freeze. Rehearse. Slides. | Last 2 h |

**Rules of engagement:**

- No step starts until the previous demo works.
- Run `python -m unittest discover -s tests` after every change. If it goes red,
  fix it before continuing.
- One differentiator done well beats three half-done.
- **Feature freeze 2 hours before submission.** After freeze: bug fixes, tests,
  slides, rehearsal only.
- If you're stuck for 30 minutes, ask a teammate. At 60 minutes, cut scope.

---

## I. Demo strategy

1. **Rehearse the real command** on the demo machine, twice.
2. **Record a backup video** of the working demo as soon as step 3 works.
   Re-record after step 5. If the live demo fails, play the video without
   apologizing.
3. **Pre-run and save output:** `python -m app.soc_core.demo --json > demo_output.json`.
   Wi-Fi and a model server can't fail on a file.
4. **Show the refusal.** The strongest moment in the demo is the system
   *declining* to isolate a domain controller. Judges remember what a system
   refused to do.
5. **Show the injection.** `--scenario H` takes 15 seconds and proves the
   security story.
6. **Never demo a live LLM call without a fallback.** Timeouts on stage are fatal.
7. **Terminal font size ≥ 18pt.** Test legibility from the back of the room.

Script: [DEMO_SCRIPT.md](DEMO_SCRIPT.md).

---

## J. Security review checklist

Run before feature freeze. Each item takes 1–5 minutes.

**Secrets**
- [ ] `git grep -nE "sk-|AKIA|ghp_|password\s*=|token\s*="` returns nothing real
- [ ] All credentials come from environment variables; `.env` is gitignored
- [ ] No key appears in logs, prompts, screenshots, or the demo recording

**AI safety**
- [ ] Every new `AIAnalyst` overrides `_analyze()` only, not `analyze()`
- [ ] Event data is inside untrusted delimiters; delimiter occurrences in data are escaped
- [ ] Model output is parsed as strict JSON; parse failure falls back to the mock
- [ ] `--scenario H` still reports both injections and changes nothing
- [ ] No code path from model output to execution without `approved_by`

**Response safety**
- [ ] `dry_run=True` is still the default
- [ ] `DEFAULT_PROTECTED_ASSETS` updated for the **real** dataset's critical hosts
- [ ] `allowed_targets` is set from incident entities
- [ ] Any real `_perform()` has a documented rollback

**Input handling**
- [ ] One malformed record in the new data doesn't crash the demo (normalizer handles it)
- [ ] Oversized fields are capped before any prompt
- [ ] No SIEM query is built by string concatenation of untrusted values
- [ ] Nothing fetches a URL taken from event data (SSRF)

**Data**
- [ ] If data is real: minimized/redacted before any hosted LLM call
- [ ] New dataset committed (check the `.gitignore` `data/*` trap)

**Tests**
- [ ] Full suite green
- [ ] Every new rule has a positive test **and** a benign negative test

---

## K. Final presentation checklist

**Content (answer each in one sentence)**
- [ ] What problem, for whom?
- [ ] What does our system do that a rule-based SIEM alone doesn't?
- [ ] What does it do that a pure LLM wrapper doesn't? (*Answer: deterministic
      evidence, validated output, gated action. This is our edge.*)
- [ ] How is it attacked, and how does it defend itself?
- [ ] What would it take to put it in production? (Be honest: redaction, durable
      audit, authN/Z, real rollback.)

**Artifacts**
- [ ] `architecture/ARCHITECTURE.mmd` rendered to an image for the slides
- [ ] Top-level `README.md` exists and says how to run it in 2 commands
- [ ] Empty placeholder files filled or deleted
- [ ] Test count on a slide ("350+ tests, fully offline")
- [ ] Backup demo video on the presenting laptop, **not** only in the cloud

**Delivery**
- [ ] Timed rehearsal completed under the limit
- [ ] Every presenter can run the demo command
- [ ] Prepared answers: *"Why not just use an LLM?"*, *"What if the LLM is
      manipulated?"*, *"Does it actually block anything?"*, *"How does it
      scale?"*
- [ ] Final commit pushed; repository link tested from a different machine
