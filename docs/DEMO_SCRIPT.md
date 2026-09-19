# Demo Script: 3 Minutes

Technical demo of the **current** implementation. Every number below is taken
from a verified run of `python -m app.soc_core.demo`. If you change the code or
data, re-run and update the numbers before presenting.

**Spoken length:** ~420 words, about 2:55 at a calm pace (~3:05 with the optional Scenario H close).
**Setup:** terminal at repo root, font ≥ 18pt, window tall enough for ~40 lines.

```bash
# Pre-flight (do this before walking on stage)
python -m unittest discover -s tests          # Ran 357 tests ... OK
python -m app.soc_core.demo > demo_full.txt   # fallback copy to scroll through
```

---

## Beat sheet

| Time | Beat | On screen |
|---|---|---|
| 0:00 | Hook | Nothing yet |
| 0:15 | 1. Ingestion | Section 1 + 1b |
| 0:40 | 2. Detection | Section 2 |
| 1:05 | 3. Correlation | Incident header + timeline |
| 1:30 | 4. Risk scoring | Risk block |
| 1:50 | 5–6. AI analysis + MITRE | ATT&CK + AI triage blocks |
| 2:20 | 7–8. Response + safety | Proposed response block |
| 2:45 | Close | Scenario H (optional) |

---

## Script

### 0:00 · Hook (15s)

> Every SOC now wants an AI analyst. But a SOC's input is the attacker's output.
> Put an LLM behind a log pipeline and you're feeding it text an adversary
> wrote. We built a SOC pipeline where that doesn't matter.

**Run:**
```bash
python -m app.soc_core.demo
```

### 0:15 · 1. Event ingestion (25s)

**Point at:** `Loaded and validated 26 events` and the category counts.

> Twenty-six synthetic events: authentication, process, DNS, network and EDR
> alerts. They come in through a SIEM provider interface. Today that's a mock;
> Splunk and Wazuh plug into the same interface. Every event is
> schema-validated, and one malformed record fails the batch loudly rather than
> being silently dropped.

**Point at:** section **1b**, `2 field(s) contain text that attempts to manipulate automated analysis`.

> Before anything else, we screen every field for text trying to instruct an
> AI. Two events do. We report them. We never delete them, because an
> injection attempt is evidence of an attacker.

### 0:40 · 2. Detection (25s)

**Point at:** the 10 alert lines.

> Detection is deterministic. No AI decides what's an alert. Eight rules,
> ten alerts: password spraying, MFA fatigue, encoded PowerShell, Word spawning
> PowerShell spawning rundll32, a high-entropy DNS lookup, beaconing, and LSASS
> credential access. Each alert cites the exact event IDs that caused it and
> states its confidence. The DNS rule honestly says *low*, because entropy is a
> heuristic.

### 1:05 · 3. Correlation (25s)

**Point at:** `inc-0001 [critical]`, then scroll through the `TIMELINE`.

> Ten alerts become one incident. We link alerts that share a host, user or IP
> within a time window. That gives one 38-minute story across three hosts and
> fourteen events: spray, MFA push-bombing, macro execution, DNS, command and
> control, credential theft. The analyst reads one incident instead of ten alerts.

### 1:30 · 4. Risk scoring (20s)

**Point at:** `Risk score 98/100 (critical)` and the `+` lines.

> Risk is 98 out of 100, and you can see exactly why. It's a sum of named factors:
> thirty for critical severity, eighteen for credential access, fourteen for
> C2. No model invented this number, so no log line can talk it down.

### 1:50 · 5–6. AI analysis and MITRE mapping (30s)

**Point at:** the `MITRE ATT&CK` list, then `AI TRIAGE`.

> Nine ATT&CK techniques, from password spraying to LSASS memory, and the
> furthest stage reached is command and control. Every technique ID is checked
> against a pinned catalog, so a hallucinated technique is rejected.
>
> Then the AI analyst interprets. It's labelled advisory. It states its
> uncertainty and asks the analyst questions. Its output is validated in code:
> cited events must exist, and it may never claim it took an action.
> **Point at:** `validation : passed`.

### 2:20 · 7–8. Response and human approval (25s)

**Point at:** the `PROPOSED RESPONSE` block, then `actions actually executed: 0`.

> Finally, response. Ten proposed actions. Three low-risk ones ran as dry runs.
> Seven were **refused**. It won't isolate the domain controller or the identity
> provider: they're protected assets. It won't isolate the compromised
> workstation or disable accounts without a named human approver. The model
> can't approve its own proposals. Actions actually executed: zero.

### 2:45 · Close (15s)

> Deterministic evidence, AI interpretation, human decisions. Replace the AI
> with a local Ollama model or a hosted LLM and every one of these controls
> still holds, because they live in the base classes, not the prompt.

**If time allows (+15s):**
```bash
python -m app.soc_core.demo --scenario H
```
> Two poisoned log lines, one telling the AI to close the incident. Flagged,
> reported, and nothing changed.

---

## Key numbers (verified)

| Item | Value |
|---|---|
| Events | 26 (auth 12, process 6, alert 3, dns 3, network 2) |
| Injection findings | 2 (`evt-0016`, `evt-0024`) |
| Rules / alerts | 8 rules, 10 alerts |
| Incidents | 1, critical |
| Timeline | 14 events, 38 min 46 s, 3 hosts, 4 users |
| ATT&CK | 9 techniques, furthest stage *Command and Control* |
| Risk | 98/100, 7 factors |
| AI confidence | high; validation passed |
| Response | 10 proposed: 3 dry run, 7 refused, **0 executed** |
| Tests | 357, offline, ~0.3 s |

---

## Likely judge questions

**"Why not just use an LLM?"**
> Because the LLM reads attacker-written text. We use it for what it's good
> at, which is explaining, and keep detection, scoring and execution in code
> it can't influence.

**"What if the LLM is manipulated?"**
> It can make a bad suggestion. It can't create or delete an alert, change
> the risk score, or execute anything. It has no tools, its output is
> validated, and disruptive actions need a human.

**"Why does it propose disabling a.chen and m.okafor? They only had failed logins."**
> Good catch. That's a real limitation of our mock analyst: it proposes actions
> for every user in the incident, including spray *targets*. It's exactly why
> T3 actions need a human. All four were refused. A real analyst would only
> reset the account that authenticated: j.rivera.
> *(Say this confidently. Owning a limitation beats being caught by it.)*

**"Does it actually block anything?"**
> Not today, by design. Dry run is the default. Real execution means
> subclassing `ResponseProvider` and implementing one method. The policy gates
> are inherited and can't be skipped.

**"How does it scale?"**
> Detection is linear. Correlation is pairwise: about 1.5 seconds for 2,000
> alerts. At SIEM scale we'd pre-filter to high-severity alerts or index by
> entity. It's fine for this demo; we wouldn't claim it's production-ready.

**"Is the data real?"**
> Synthetic, on purpose. Documentation IP ranges and reserved `.test`
> domains, enforced by tests. Nothing resolves to real infrastructure.

---

## If something goes wrong

| Failure | Recovery |
|---|---|
| Command errors | You're not at the repo root. `cd` there and re-run |
| Output scrolls too fast | Open `demo_full.txt` in the editor and scroll |
| Laptop dies | Play the backup recording; narrate over it |
| Question you can't answer | "That's outside what we built today; here's how we'd approach it…" |
