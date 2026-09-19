"""Tests for the Evidence Context Engine and redaction.

The redaction tests plant LITERAL secrets and assert, by plain substring
search, that none reaches the serialized LLM payload. They deliberately do not
reuse the redactor's own regexes to check the result, so a broken pattern
cannot make its own test pass.
"""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.soc_core.cloud_detections import all_rules  # noqa: E402
from app.soc_core.correlation import CorrelationEngine  # noqa: E402
from app.soc_core.detections import DetectionEngine  # noqa: E402
from app.soc_core.events import load_events, parse_event  # noqa: E402
from app.soc_core.evidence_context import (  # noqa: E402
    ContextBudget,
    build_evidence_context,
    canonical_json,
    estimate_tokens,
)
from app.soc_core.providers.ai_analyst import screen_for_injection  # noqa: E402
from app.soc_core.redaction import Redactor, contains_secret  # noqa: E402
from app.soc_core.risk import score_incident  # noqa: E402

DATA = REPO_ROOT / "data"

# Fake secrets planted into events. None may appear in any payload. Each is
# assembled at runtime so no key-shaped literal sits in the source, where it
# would trip repository secret scanners (they are fake, but scanners can't know).
SECRETS = {
    "aws_key_id": "AKIA" + "QWERTYUIOPASDFGH",
    "aws_secret": "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY99",
    "password": "Hunter2-Summer!",
    "bearer": "eyQ9mZkT3pL8vN2xB7cR4sW1",
    "jwt": "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbjEyMyJ9.c2lnbmF0dXJlLXZhbHVlLXg",
    "anthropic_key": "sk-" + "ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX",
    "github_token": "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "url_password": "s3cr3tpass",
    "private_key_body": "MIIEowIBAAKCAQEAnotarealkeybutbase64",
    "session_token_field": "FwoGZXIvYXdzEBYaDHOTSESSIONTOKEN",
}


def _pipeline(paths: list[Path], rules=all_rules):
    events = [e for p in paths for e in load_events(p)]
    alerts, _ = DetectionEngine(rules()).run(events)
    incidents = CorrelationEngine().correlate(alerts, events)
    return events, incidents, screen_for_injection(events)


def _context(incident, events, findings=(), budget=ContextBudget()):
    return build_evidence_context(
        incident, all_events=events, risk=score_incident(incident), findings=findings, budget=budget
    )


def _auth(event_id: str, user: str, ip: str, seconds: int, outcome: str = "failure") -> dict:
    t = datetime(2026, 9, 17, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return {
        "event_id": event_id, "timestamp": t.isoformat(), "source": "windows_security",
        "category": "authentication", "action": "logon_failed" if outcome == "failure" else "logon_success",
        "outcome": outcome, "severity": "low", "host": {"hostname": "DC-LAB-01"},
        "user": {"name": user, "domain": "CORP"},
        "auth": {"logon_type": "network", "source_ip": ip, "failure_reason": "bad_password"},
    }


def _spray_incident(n_failures: int = 500, accounts: int = 23):
    """A synthetic burst: n failures over `accounts` accounts from one IP,
    then one success, then noise elsewhere."""
    raw = [_auth(f"x{i:05d}", f"user{i % accounts:02d}", "203.0.113.99", i % 240) for i in range(n_failures)]
    raw.append(_auth("x-success", "user07", "203.0.113.99", 250, outcome="success"))
    raw += [_auth(f"noise{i}", f"other{i}", f"192.0.2.{i % 200}", 3600 + i, "success") for i in range(40)]
    events = [parse_event(r) for r in raw]
    alerts, _ = DetectionEngine(all_rules()).run(events)
    incident = CorrelationEngine().correlate(alerts, events)[0]
    return events, incident


class TestReduction(unittest.TestCase):
    def test_burst_is_aggregated_not_repeated(self) -> None:
        events, incident = _spray_incident(500, 23)
        ctx = _context(incident, events)
        aggregates = [i for i in ctx.pack["evidence"] if i["kind"] == "aggregate"]
        self.assertEqual(len(aggregates), 1)
        burst = aggregates[0]
        self.assertEqual(burst["count"], 500)
        self.assertEqual(burst["aggregate"]["distinct_actors"], 23)
        self.assertEqual(burst["aggregate"]["type"], "authentication_failure_burst")
        self.assertLessEqual(len(burst["event_ids"]), ContextBudget().max_event_ids_per_item)
        self.assertEqual(len(ctx.evidence_to_events[burst["id"]]), 500)  # all kept server-side
        self.assertLess(burst["first_seen"], burst["last_seen"])

    def test_metrics_show_reduction(self) -> None:
        events, incident = _spray_incident(500, 23)
        m = _context(incident, events).metrics
        self.assertEqual(m["raw_events"], 541)
        self.assertGreaterEqual(m["relevant_events"], 501)
        self.assertLess(m["evidence_objects"], 10)
        self.assertGreater(m["estimated_tokens"], 0)
        self.assertEqual(m["estimated_total_tokens"], m["estimated_tokens"] + m["estimated_output_tokens"])

    def test_state_transition_survives_compression(self) -> None:
        """failure burst -> success must stay visible, even with no rule on the success."""
        events, incident = _spray_incident(500, 23)
        ctx = _context(incident, events)
        timeline = ctx.pack["timeline"]
        self.assertLess(len(timeline), ctx.metrics["relevant_events"])
        success = [t for t in timeline if "[success]" in t["summary"]]
        self.assertTrue(success, "successful logon after the spray was lost")
        self.assertTrue(success[0]["state_transition"])

    def test_contextual_event_no_rule_fired_on_is_included(self) -> None:
        events, incidents, findings = _pipeline([DATA / "sample_security_events.json"], rules=lambda: all_rules())
        ctx = _context(incidents[0], events, findings)
        all_ids = {e for ids in ctx.evidence_to_events.values() for e in ids}
        self.assertIn("evt-0006", all_ids)  # the successful logon from the spray IP
        item = next(i for i in ctx.pack["evidence"] if "evt-0006" in ctx.evidence_to_events[i["id"]])
        self.assertEqual(item["role"], "context")
        self.assertEqual(item["detections"], [])

    def test_unrelated_events_are_counted_not_sent(self) -> None:
        events, incident = _spray_incident(50, 5)
        ctx = _context(incident, events)
        self.assertEqual(ctx.pack["benign_context"]["excluded_events"], 40)
        self.assertNotIn("other1", ctx.to_json())

    def test_no_dangling_evidence_references_under_any_budget(self) -> None:
        """Every evidence ID cited anywhere in the pack must exist in the pack,
        even after budget trimming removed items (regression)."""
        events, incident = _spray_incident(2000, 200)
        for tokens in (3000, 6000, 12000):
            with self.subTest(max_input_tokens=tokens):
                pack = _context(incident, events, budget=ContextBudget(max_input_tokens=tokens)).pack
                present = {i["id"] for i in pack["evidence"]}
                cited = set()
                for section in ("entities", "detections", "mitre", "inferences"):
                    for entry in pack[section]:
                        cited.update(entry["evidence_ids"])
                cited.update(t["evidence_id"] for t in pack["timeline"])
                for rel in pack["relationships"]:
                    cited.update((rel["from"], rel["to"]))
                self.assertLessEqual(cited, present)
                self.assertLessEqual(len(pack["entities"]), ContextBudget().max_entities)

    def test_budget_trims_context_but_keeps_detection_evidence(self) -> None:
        events, incidents, findings = _pipeline([DATA / "sample_security_events.json"])
        full = _context(incidents[0], events, findings)
        tight = _context(incidents[0], events, findings, ContextBudget(max_input_tokens=6000))
        self.assertLess(tight.metrics["evidence_objects"], full.metrics["evidence_objects"])
        detection_full = {i["id"] for i in full.pack["evidence"] if i["role"] == "detection_evidence"}
        detection_tight = {i["id"] for i in tight.pack["evidence"] if i["role"] == "detection_evidence"}
        self.assertEqual(detection_full, detection_tight)


class TestStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.events, cls.incidents, cls.findings = _pipeline(
            [DATA / "sample_security_events.json", DATA / "aws_cloudtrail_samples.json"]
        )
        cls.cloud = next(i for i in cls.incidents if "CLOUD-LOG-001" in i.rule_ids)
        cls.ctx = _context(cls.cloud, cls.events, cls.findings)

    def test_schema_sections(self) -> None:
        for key in ("incident", "risk", "entities", "timeline", "detections", "mitre",
                    "relationships", "evidence", "inferences", "benign_context",
                    "response_context", "context_metrics"):
            self.assertIn(key, self.ctx.pack)

    def test_entity_extraction_types(self) -> None:
        types = {e["type"] for e in self.ctx.pack["entities"]}
        for expected in ("user", "ip", "aws_account", "access_key", "aws_role", "aws_resource", "host"):
            self.assertIn(expected, types)
        self.assertTrue(all(e["evidence_ids"] for e in self.ctx.pack["entities"]))

    def test_every_evidence_item_names_its_detections(self) -> None:
        for item in self.ctx.pack["evidence"]:
            if item["role"] == "detection_evidence":
                self.assertTrue(item["detections"], item["id"])

    def test_mitre_preserved_exactly(self) -> None:
        self.assertEqual([m["technique_id"] for m in self.ctx.pack["mitre"]], self.cloud.technique_ids)
        self.assertTrue(all(m["evidence_ids"] for m in self.ctx.pack["mitre"]))

    def test_classifications(self) -> None:
        pack = self.ctx.pack
        self.assertTrue(all(i["classification"] == "OBSERVED" for i in pack["evidence"]))
        for section in ("detections", "relationships", "mitre"):
            self.assertTrue(all(x["classification"] == "CORRELATED" for x in pack[section]), section)
        self.assertTrue(all(x["classification"] == "INFERRED" for x in pack["inferences"]))
        self.assertNotIn("AI_RECOMMENDATION", self.ctx.to_json())

    def test_ranking_is_explainable_and_additive(self) -> None:
        for item in self.ctx.pack["evidence"]:
            score = item["evidence_score"]
            self.assertEqual(score["total"], sum(score["components"].values()))
            self.assertEqual(
                set(score["components"]),
                {"detection_match", "entity_link", "temporal_relevance", "attack_stage_relevance", "severity", "rarity"},
            )
        ranks = sorted(self.ctx.pack["evidence"], key=lambda i: i["rank"])
        self.assertEqual(ranks[0]["role"], "detection_evidence")

    def test_relationships_reference_real_evidence(self) -> None:
        ids = {i["id"] for i in self.ctx.pack["evidence"]}
        for rel in self.ctx.pack["relationships"]:
            self.assertIn(rel["from"], ids)
            self.assertIn(rel["to"], ids)

    def test_serialization_is_deterministic_json(self) -> None:
        again = _context(self.cloud, self.events, self.findings)
        self.assertEqual(self.ctx.to_json(), again.to_json())
        self.assertEqual(json.loads(self.ctx.to_json())["schema"], "evidence-context/1.0")

    def test_no_raw_angle_brackets_in_payload(self) -> None:
        """No string in the pack can close the prompt's <evidence_context> tag."""
        self.assertNotIn("<", self.ctx.to_json())
        self.assertNotIn(">", self.ctx.to_json())

    def test_injection_flags_carried_as_data(self) -> None:
        flagged = [i for i in self.ctx.pack["evidence"] if i.get("injection_flagged")]
        self.assertTrue(flagged)
        self.assertIn("untrusted_text", flagged[0])


class TestTokenEstimation(unittest.TestCase):
    def test_estimator_is_deterministic(self) -> None:
        self.assertEqual(estimate_tokens(""), 0)
        self.assertEqual(estimate_tokens("a" * 35), 10)
        self.assertEqual(estimate_tokens("a" * 36), 11)

    def test_metric_matches_payload(self) -> None:
        events, incidents, findings = _pipeline([DATA / "aws_cloudtrail_samples.json"])
        ctx = _context(incidents[0], events, findings)
        # context_metrics is embedded in the pack after measuring; remeasure
        # the pack without it to check the reported number.
        pack = dict(ctx.pack)
        pack.pop("context_metrics")
        self.assertEqual(ctx.metrics["estimated_tokens"], estimate_tokens(canonical_json(pack)))


class TestRedaction(unittest.TestCase):
    def _poisoned_events(self):
        events = load_events(DATA / "sample_security_events.json")
        raw = json.loads((DATA / "sample_security_events.json").read_text(encoding="utf-8"))["events"]
        poisoned = next(r for r in raw if r["event_id"] == "evt-0008")
        poisoned = json.loads(json.dumps(poisoned))
        poisoned["process"]["command_line"] = (
            f"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A "
            f"-p {SECRETS['password']} ; $env:AWS_SECRET_ACCESS_KEY={SECRETS['aws_secret']} "
            f"; aws configure set key {SECRETS['aws_key_id']} "
            f"; curl -H 'Authorization: Bearer {SECRETS['bearer']}' https://admin:{SECRETS['url_password']}@corp.test/x "
            f"; echo {SECRETS['jwt']} {SECRETS['anthropic_key']} {SECRETS['github_token']} "
            f"-----BEGIN RSA PRIVATE KEY-----{SECRETS['private_key_body']}-----END RSA PRIVATE KEY-----"
        )
        poisoned["user"]["email"] = "j.rivera@corp.example"
        poisoned["process"]["session_token"] = SECRETS["session_token_field"]
        events = [parse_event(poisoned) if e.event_id == "evt-0008" else e for e in events]
        alerts, _ = DetectionEngine(all_rules()).run(events)
        incident = CorrelationEngine().correlate(alerts, events)[0]
        return events, incident

    def test_planted_secrets_never_reach_the_payload(self) -> None:
        """CRITICAL: a secret inside an event must not appear in the AI context."""
        events, incident = self._poisoned_events()
        self.assertIn("evt-0008", incident.event_ids)
        ctx = _context(incident, events, screen_for_injection(events))
        payload = ctx.to_json()
        for name, secret in SECRETS.items():
            with self.subTest(secret=name):
                self.assertNotIn(secret, payload)
        self.assertGreater(ctx.metrics["redacted_field_count"], 0)
        self.assertFalse(contains_secret(payload))

    def test_aws_key_id_is_pseudonymized_not_sent(self) -> None:
        events, incident = self._poisoned_events()
        ctx = _context(incident, events)
        payload = ctx.to_json()
        self.assertNotIn(SECRETS["aws_key_id"], payload)
        self.assertIn("ACCESS_KEY_", payload)
        # The real value is recoverable ONLY server-side, for response targets.
        self.assertIn(SECRETS["aws_key_id"], ctx.reverse_map.values())

    def test_identities_pseudonymized_consistently(self) -> None:
        events, incidents, findings = _pipeline([DATA / "sample_security_events.json"])
        ctx = _context(incidents[0], events, findings)
        payload = ctx.to_json()
        for real in ("j.rivera", "a.chen", "m.okafor"):
            with self.subTest(user=real):
                self.assertNotIn(real, payload)
        token = next(k for k, v in ctx.reverse_map.items() if v == "j.rivera")
        self.assertIn(token, payload)

    def test_cloud_identifiers_pseudonymized(self) -> None:
        events, incidents, findings = _pipeline([DATA / "aws_cloudtrail_samples.json"])
        for incident in incidents:
            payload = _context(incident, events, findings).to_json()
            for real in ("111122223333", "444455556666", "EXAMPLE-KEY-", "ci-deploy", "svc-backup-02"):
                with self.subTest(incident=incident.incident_id, value=real):
                    self.assertNotIn(real, payload)

    def test_reverse_map_is_not_in_the_payload(self) -> None:
        events, incidents, findings = _pipeline([DATA / "sample_security_events.json"])
        ctx = _context(incidents[0], events, findings)
        self.assertTrue(ctx.reverse_map)
        self.assertNotIn("reverse", ctx.to_json())

    def test_redactor_unit(self) -> None:
        r = Redactor()
        out = r.value("secret_access_key", SECRETS["aws_secret"])
        self.assertEqual(out, "[REDACTED_SECRET_FIELD]")
        self.assertEqual(r.pseudonym("USER", "alice"), r.pseudonym("USER", "alice"))
        self.assertNotEqual(r.pseudonym("USER", "alice"), r.pseudonym("USER", "bob"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
