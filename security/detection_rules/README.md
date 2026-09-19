# Sigma Detection Rules

Vendor-neutral detection content for the SOC simulation. These rules are
**documentation and portability artifacts** — the running simulation executes
the Python rules in [app/soc_core/detections.py](../../app/soc_core/detections.py),
not this YAML. Nothing here needs a live SIEM.

## Why both a Sigma rule and a Python rule?

They serve different purposes, and the duplication is deliberate:

| | Sigma YAML (here) | Python `DetectionRule` |
|---|---|---|
| **Runs in** | A real SIEM, after conversion | Our offline simulation |
| **Purpose** | Portability, review, sharing | Execution with no dependencies |
| **Expresses** | Field predicates over one log source | Stateful logic: sliding windows, entropy, distinct-entity counts |
| **Audience** | Detection engineers, other tools | This codebase |

Sigma is excellent at "these field values, in this log source". It is weaker
at the stateful correlation several of our rules need — counting *distinct
usernames* inside a sliding window, or computing Shannon entropy of a DNS
label. Those parts live in Python and are noted in each rule's `condition`
using Sigma's aggregation syntax, which not every backend supports.

So: the YAML is the portable statement of intent; the Python is the executable
truth. When they disagree, the Python is what ran.

## Rule index

Each file carries a non-standard `internal_rule_id` field linking it to the
Python rule that implements the same logic.

| Sigma file | `internal_rule_id` | Python class | ATT&CK | Level |
|---|---|---|---|---|
| [auth_password_spray.yml](auth_password_spray.yml) | `SOC-AUTH-001` | `PasswordSprayRule` | T1110.003 | high |
| [auth_mfa_fatigue.yml](auth_mfa_fatigue.yml) | `SOC-AUTH-002` | `MFAFatigueRule` | T1621 | high |
| [proc_encoded_powershell.yml](proc_encoded_powershell.yml) | `SOC-EXEC-002` | `EncodedPowerShellRule` | T1059.001, T1027.010 | high |
| [proc_suspicious_lineage.yml](proc_suspicious_lineage.yml) | `SOC-EXEC-003` | `SuspiciousProcessLineageRule` | T1204.002, T1218.011 | high |
| [cred_lsass_access.yml](cred_lsass_access.yml) | `SOC-CRED-001` | `CredentialDumpingRule` | T1003.001 | critical |

Three Python rules have **no** Sigma equivalent here, for honest reasons:

- `SOC-EXEC-001` (suspicious PowerShell flags) — largely subsumed by the
  encoded-PowerShell rule; a separate Sigma rule would mostly duplicate it.
- `SOC-DNS-001` (high-entropy DNS label) — entropy is a computation, not a
  field predicate. Expressing it in Sigma would require a backend-specific
  function and would not be portable.
- `SOC-NET-001` (repeated outbound connections) — needs windowed aggregation
  per host/destination pair, which is backend-dependent in Sigma.

Claiming Sigma coverage we do not really have would be worse than the gap.

## Field mapping

Sigma rules are written against native log-source field names
(`TargetUserName`, `ParentImage`, `GrantedAccess`). Our normalized schema uses
different names. The mapping, if a converter is added later:

| Sigma / native | Normalized schema | Flat accessor |
|---|---|---|
| `Image`, `NewProcessName` | `process.name` | `event.process` |
| `ParentImage` | `process.parent_name` | `event.parent_process` |
| `CommandLine` | `process.command_line` | `event.command_line` |
| `TargetUserName`, `actor.alternateId` | `user.name` | `event.username` |
| `IpAddress`, `client.ip` | `auth.source_ip` | `event.source_ip` |
| `QueryName` | `dns.query_name` | `event.domain` |
| `DestinationIp` / `DestinationPort` | `network.destination_ip` / `.destination_port` | `event.destination_ip` / `.destination_port` |
| `Computer`, `host.name` | `host.hostname` | `event.hostname` |

Write this mapping **once**, in one place, when a converter is introduced.
Scattered per-rule conversions are how detection coverage silently rots.

## Validating these rules offline

`tests/test_sigma_rules.py` parses every file and asserts:

- it is valid YAML with the required Sigma keys,
- `id` is unique across the directory,
- `level` is a valid Sigma level,
- every `attack.tXXXX` tag resolves to a technique in the pinned ATT&CK
  catalog ([app/soc_core/mitre.py](../../app/soc_core/mitre.py)),
- `internal_rule_id` matches a real rule in the Python engine,
- `falsepositives` is non-empty — a rule whose author has not thought about
  false positives is not ready for an analyst queue.

No SIEM, no network, no `pysigma` dependency.

## Using these against a real SIEM later

```bash
# Not run today -- requires installing pysigma + a backend.
sigma convert -t splunk security/detection_rules/
sigma convert -t opensearch_lucene security/detection_rules/
```

Before any of these is deployed for real, each needs a tuning pass against
that environment's actual baseline. The `falsepositives` sections are starting
points, not a substitute for tuning.

## Conventions for new rules

1. `id` must be a fresh UUID; never reuse one.
2. `status: experimental` until validated against real data.
3. `falsepositives` must be populated with specific, plausible cases.
4. `level` must agree with the Python rule's `severity`.
5. Add `internal_rule_id` when a Python counterpart exists.
6. Tag with ATT&CK techniques that are actually *earned* by the logic — and
   add the technique to the pinned catalog first, or the test will fail.
7. Use only fictional/documentation data in examples (RFC 5737 addresses,
   RFC 2606 domains).
