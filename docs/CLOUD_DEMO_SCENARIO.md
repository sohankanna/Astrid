# Cloud Demo Scenario: 2–3 Minutes

An **offline** AWS cloud-SOC demo on synthetic data. This isn't hypothetical:
every step below runs today with no AWS account, no credentials, and no network.

```bash
python -m app.soc_core.demo --profile cloud             # full run: 3 incidents
python -m app.soc_core.demo --profile cloud --scenario K  # attack chain only
python -m app.soc_core.demo --profile cloud --scenario J  # prompt injection only
python -m app.soc_core.demo --profile cloud --list-scenarios
```

Every number below comes from a verified run. Re-run and update the numbers if
the code or data changes.

**Spoken length:** ~440 words, about 3:00 at a calm pace.

---

## The story

A CI pipeline's long-lived access key (`ci-deploy`) leaks. From
`203.0.113.77` the attacker enumerates the account, assumes an over-trusted
`ops-admin` role, creates a backdoor user with its own key and
`AdministratorAccess`, opens SSH to the internet, **stops the organization
trail**, chains into a `data-reader` role, and pulls four files from the
finance bucket. The attacker assumed that stopping CloudTrail made them
invisible. A separate S3 data-events trail and GuardDuty kept recording.

Two decoys run alongside: a root login without MFA (a separate incident), and
a vendor's cross-account role assumption (a plausible false positive, scored
low).

---

## Script

### 1 · A CloudTrail event arrives (0:00–0:20)

**On screen:** `Loaded and validated 37 events`, then section **1b**.

> Thirty-seven synthetic AWS events: CloudTrail API calls, VPC Flow Logs and
> GuardDuty findings, through the same SIEM interface as our endpoint demo. And
> before detection even runs, two CloudTrail fields are already flagged. One is
> an IAM role *description*, the other a *User-Agent* header. Both tell an AI
> to mark the incident benign. An attacker controls both, and CloudTrail
> records both verbatim.

### 2 · Detection identifies suspicious IAM activity (0:20–0:45)

**On screen:** section **2**, 17 alerts.

> Seventeen alerts from deterministic rules; no AI decides what fired. An
> enumeration burst of six distinct APIs from outside, a role assumed from an
> external address, an access key minted *for a different user*,
> AdministratorAccess attached, SSH opened to the world, and StopLogging,
> which is critical. Self key-rotation and port 443 for a web tier are in the
> data too, and correctly stay quiet.

### 3 · Events correlate into an incident (0:45–1:05)

**On screen:** `inc-0001 [critical]` and the timeline.

> Twelve of those alerts become one incident: 21 events over 29 minutes. The
> link isn't only the IP. When a role is assumed, every later call made with
> that session names the same role as its issuer, and that's what we
> correlate on. Even VPC flow logs from the EC2 instance join the incident,
> caught by our existing *endpoint* beaconing rule, unchanged.
> The root login and the vendor are separate incidents. We don't over-merge.

### 4 · Risk score increases (1:05–1:20)

**On screen:** `Risk score 98/100 (critical)`.

> 98 out of 100, itemized. It includes a factor that exists specifically for
> this: *impair defenses*, plus 14 because someone turned off our logging. The
> root incident gets a *privileged identity* factor and scores 62. The vendor
> scores 12.

### 5–6 · AI summary and ATT&CK mapping (1:20–1:50)

**On screen:** `MITRE ATT&CK` list, then `AI TRIAGE`.

> Eight techniques, from Cloud Accounts through Additional Cloud Credentials,
> Disable or Modify Cloud Logs, to Data from Cloud Storage. Each one comes from a
> rule that earned it, and IDs are checked against a pinned catalog.
> The AI summary flags the injection in the StopLogging call and *keeps the
> severity at critical*. It also says the thing an analyst most needs to hear:
> logging was tampered with, so missing events aren't proof of nothing.

### 7 · AI recommends remediation (1:50–2:05)

**On screen:** `MANUAL TASKS`, then the start of `PROPOSED RESPONSE`.

> First recommendation: restore logging. That one is manual and never
> automated. Then: revoke the leaked key and the minted key, disable the
> backdoor user, detach the admin policies, revoke the SSH rule, snapshot then
> isolate the instance, block the indicators. Each is an enum value with a
> target that must appear in the evidence.

### 8–9 · Human approves or rejects → DRY RUN (2:05–3:00)

**On screen:** the `[dry_run]`, `[rejected]` and `[refused]` lines, then `actions actually executed: 0`.

> Every cloud action needs a human. Here a clearly labelled *simulated*
> analyst approves seven. With three low-tier actions that need no approval,
> that's ten dry runs, each showing exactly what *would* happen. They reject isolation: "snapshot first." That rejection is
> audited. One block is left pending, and without approval it's refused.
> And even with approval, cloud actions are dry-run only in this build. The
> base class refuses to execute them. Actions actually executed: zero. No AWS
> API exists anywhere in this code.

---

## Verified numbers

| Item | Value |
|---|---|
| Events | 37 (cloud 31, network 4, alert 2) |
| Injection findings | 2 (`cev-0023` role description, `cev-0026` User-Agent) |
| Alerts | 17 (11 cloud rules + SOC-NET-001) |
| Incidents | 3: critical chain / high root / medium vendor |
| Chain | 12 alerts, 10 rules, 21 events, 29 min 25 s, 8 techniques, stage *Command and Control* |
| Chain risk | 98/100 critical, 7 factors incl. `impair_defenses` |
| Root risk | 62/100 high, incl. `privileged_identity` |
| Vendor risk | 12/100 informational |
| Chain response | 12 requests: 10 dry run (7 simulated approvals + 3 low-tier: notify, snapshot, ticket), 1 rejected, 1 refused; 1 manual task |
| Executed | **0** |

---

## Likely judge questions

**"Is this connected to AWS?"**
> No, deliberately. It's a synthetic, CloudTrail-shaped dataset through the
> same SIEM interface a real Splunk or Wazuh feed would use. There's no AWS
> SDK in the project.

**"Who approved those actions?"**
> A fixed decision table labelled SIMULATED, standing in for a person so every
> approval branch can be shown offline. In production that's a named analyst,
> and the model can never supply approval itself.

**"Why not auto-revoke the leaked key? It's obviously bad."**
> Because the attacker picks what appears in the evidence. Auto-revoking every
> key in an incident is attacker-steerable denial of service. A key a
> production service depends on is one API call from an outage.

**"Why is the vendor alert scored informational?"**
> One medium-confidence rule, no corroboration. Cross-account assumption from a
> partner is normal. The analyst question it generates is the right one: *is
> that a contracted partner account?*

**"What if the attacker had stopped the data-events trail too?"**
> Then the S3 reads would be missing, and our uncertainty section already
> tells the analyst not to read absence as innocence. That's why the checklist
> says to put trails in a separate account behind an SCP.
