"""Tests for the cloud (AWS) extension of the SOC core.

Fully offline: synthetic data only, no AWS SDK, no network, no credentials.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import re
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLOUD_DATASET = REPO_ROOT / "data" / "aws_cloudtrail_samples.json"
ENDPOINT_DATASET = REPO_ROOT / "data" / "sample_security_events.json"
sys.path.insert(0, str(REPO_ROOT / "app"))

from soc_core.cloud_detections import (  # noqa: E402
    GUARDDUTY_TECHNIQUES,
    AccessKeyCreationRule,
    CloudLoggingTamperingRule,
    ConsoleLoginWithoutMFARule,
    GuardDutyHighSeverityRule,
    IAMPrivilegeEscalationRule,
    InboundAdminPortFlowRule,
    RootAccountActivityRule,
    SecurityGroupExposureRule,
    SuspiciousS3AccessRule,
    UnusualAPIActivityRule,
    UnusualAssumeRoleRule,
    all_rules,
    arn_account,
    cloud_rules,
    is_external_source,
)
from soc_core.cloud_scenarios import CLOUD_SCENARIOS  # noqa: E402
from soc_core.correlation import CorrelationEngine, entities_for  # noqa: E402
from soc_core.demo import main, run_pipeline  # noqa: E402
from soc_core.detections import DetectionEngine, default_rules  # noqa: E402
from soc_core.events import (  # noqa: E402
    ALL_CATEGORIES,
    VALID_CATEGORIES,
    EventValidationError,
    load_events,
    parse_event,
)
from soc_core.mitre import TECHNIQUES, is_known_technique  # noqa: E402
from soc_core.providers.ai_analyst import (  # noqa: E402
    AIAnalysis,
    MockAIAnalyst,
    screen_for_injection,
    validate_analysis,
)
from soc_core.providers.response import (  # noqa: E402
    ACTION_TIERS,
    CLOUD_ACTIONS,
    MockResponseProvider,
    ResponseAction,
    ResponseRequest,
    requests_from_analysis,
)
from soc_core.risk import score_incident  # noqa: E402
from soc_core.scenarios import events_for_scenario  # noqa: E402


def load_cloud() -> list:
    return load_events(CLOUD_DATASET)


def by_id(events) -> dict:
    return {event.event_id: event for event in events}


def cloud_event(event_name: str, **cloud_overrides) -> object:
    """A minimal valid CloudTrail-style event with cloud-object overrides."""
    event_id = cloud_overrides.pop("event_id", "cev-test")
    timestamp = cloud_overrides.pop("timestamp", "2026-09-18T09:00:00Z")
    outcome = cloud_overrides.pop("outcome", "success")
    user = cloud_overrides.pop("user", "tester")
    cloud = {
        "provider": "aws",
        "account_id": "111122223333",
        "region": "us-east-1",
        "event_source": "iam.amazonaws.com",
        "event_name": event_name,
        "identity_type": "IAMUser",
        "principal_arn": f"arn:aws:iam::111122223333:user/{user}",
        "source_ip": "192.0.2.10",
        "request_parameters": {},
        "response_elements": {},
        "resources": [],
    }
    cloud.update(cloud_overrides)
    return parse_event(
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": "aws_cloudtrail",
            "category": "cloud",
            "action": event_name,
            "outcome": outcome,
            "severity": "low",
            "user": {"name": user},
            "cloud": cloud,
        }
    )


def cloud_incidents():
    events = load_cloud()
    alerts, errors = DetectionEngine(all_rules()).run(events)
    assert errors == [], errors
    return events, alerts, CorrelationEngine().correlate(alerts, events)


def chain_incident():
    _, _, incidents = cloud_incidents()
    return next(i for i in incidents if "CLOUD-LOG-001" in i.rule_ids)


# ---------------------------------------------------------------------------
# CloudTrail event validation
# ---------------------------------------------------------------------------


class TestCloudEventValidation(unittest.TestCase):
    def test_cloud_is_accepted_category(self) -> None:
        self.assertIn("cloud", ALL_CATEGORIES)

    def test_original_vocabulary_is_unchanged(self) -> None:
        """The endpoint vocabulary constant must not grow (compatibility)."""
        self.assertNotIn("cloud", VALID_CATEGORIES)

    def test_dataset_loads(self) -> None:
        self.assertEqual(len(load_cloud()), 37)

    def test_cloud_event_needs_no_host(self) -> None:
        event = cloud_event("ListUsers")
        self.assertIsNone(event.hostname)
        self.assertEqual(event.host, {})

    def test_endpoint_event_still_requires_host(self) -> None:
        """Relaxing host for cloud must not relax it for endpoint telemetry."""
        with self.assertRaises(EventValidationError):
            parse_event(
                {
                    "event_id": "e1",
                    "timestamp": "2026-09-18T09:00:00Z",
                    "source": "s",
                    "category": "process",
                    "action": "a",
                    "outcome": "success",
                    "severity": "low",
                    "process": {"name": "x.exe"},
                }
            )

    def test_cloud_category_requires_cloud_object(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(
                {
                    "event_id": "e1",
                    "timestamp": "2026-09-18T09:00:00Z",
                    "source": "aws_cloudtrail",
                    "category": "cloud",
                    "action": "ListUsers",
                    "outcome": "success",
                    "severity": "low",
                }
            )

    def test_host_must_be_object_when_present(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(
                {
                    "event_id": "e1",
                    "timestamp": "2026-09-18T09:00:00Z",
                    "source": "aws_cloudtrail",
                    "category": "cloud",
                    "action": "ListUsers",
                    "outcome": "success",
                    "severity": "low",
                    "host": "not-an-object",
                    "cloud": {"event_name": "ListUsers"},
                }
            )

    def test_cloud_accessors(self) -> None:
        event = by_id(load_cloud())["cev-0020"]
        self.assertEqual(event.cloud_event_name, "CreateAccessKey")
        self.assertEqual(event.cloud_event_source, "iam.amazonaws.com")
        self.assertEqual(event.account_id, "111122223333")
        self.assertEqual(event.identity_type, "AssumedRole")
        self.assertEqual(event.session_issuer_arn, "arn:aws:iam::111122223333:role/ops-admin")
        self.assertEqual(event.request_parameters["userName"], "svc-backup-02")
        self.assertEqual(event.response_elements["accessKeyId"], "EXAMPLE-KEY-SVC-BACKUP-02")
        self.assertEqual(event.source_ip, "203.0.113.77")
        self.assertTrue(event.is_cloud)

    def test_vpc_flow_reuses_network_category(self) -> None:
        event = by_id(load_cloud())["cev-0025"]
        self.assertEqual(event.category, "network")
        self.assertEqual(event.destination_port, 22)
        self.assertEqual(event.account_id, "111122223333")  # via aux cloud object

    def test_guardduty_reuses_alert_category(self) -> None:
        event = by_id(load_cloud())["cev-0033"]
        self.assertEqual(event.category, "alert")
        self.assertIsNone(event.hostname)  # IAM-scoped finding, no host
        self.assertEqual(event.source_ip, "203.0.113.77")

    def test_non_cloud_event_has_empty_cloud_context(self) -> None:
        event = load_events(ENDPOINT_DATASET)[0]
        self.assertEqual(event.cloud, {})
        self.assertFalse(event.is_cloud)
        self.assertIsNone(event.cloud_event_name)

    def test_both_datasets_together_cover_every_category(self) -> None:
        categories = {e.category for e in load_cloud()} | {
            e.category for e in load_events(ENDPOINT_DATASET)
        }
        self.assertEqual(categories, set(ALL_CATEGORIES))


class TestCloudDatasetSafety(unittest.TestCase):
    """Nothing in the cloud dataset may be real or credential-shaped."""

    def setUp(self) -> None:
        self.text = CLOUD_DATASET.read_text(encoding="utf-8")

    def test_only_documentation_ips(self) -> None:
        allowed = ("192.0.2.", "198.51.100.", "203.0.113.", "0.0.0.")
        for address in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", self.text):
            with self.subTest(address=address):
                self.assertTrue(address.startswith(allowed), address)

    def test_only_documentation_account_ids(self) -> None:
        found = set(re.findall(r"\b\d{12}\b", self.text))
        self.assertTrue(found)
        self.assertLessEqual(found, {"111122223333", "444455556666"})

    def test_no_real_access_key_shapes(self) -> None:
        """AKIA/ASIA + 16 chars is the real AWS key-ID format; never use it."""
        self.assertIsNone(re.search(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", self.text))

    def test_no_secret_access_keys(self) -> None:
        self.assertNotIn("secretAccessKey", self.text)
        self.assertNotIn("sessionToken", self.text)

    def test_cloud_dataset_is_not_gitignored(self) -> None:
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("!data/aws_cloudtrail_samples.json", gitignore)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestCloudHelpers(unittest.TestCase):
    def test_external_source(self) -> None:
        self.assertTrue(is_external_source("203.0.113.77"))
        self.assertFalse(is_external_source("192.0.2.10"))
        self.assertFalse(is_external_source("ec2.amazonaws.com"))
        self.assertFalse(is_external_source("AWS Internal"))
        self.assertFalse(is_external_source(None))

    def test_arn_account(self) -> None:
        self.assertEqual(arn_account("arn:aws:iam::444455556666:role/x"), "444455556666")
        self.assertIsNone(arn_account("not-an-arn"))
        self.assertIsNone(arn_account(None))


# ---------------------------------------------------------------------------
# Cloud detection rules
# ---------------------------------------------------------------------------


class TestRuleSetComposition(unittest.TestCase):
    def test_eleven_cloud_rules(self) -> None:
        self.assertEqual(len(cloud_rules()), 11)

    def test_all_rules_is_endpoint_plus_cloud_on_one_engine(self) -> None:
        self.assertEqual(len(all_rules()), len(default_rules()) + len(cloud_rules()))
        DetectionEngine(all_rules())  # raises on duplicate rule IDs

    def test_endpoint_default_rules_unchanged(self) -> None:
        self.assertEqual(len(default_rules()), 8)

    def test_cloud_rules_do_not_fire_on_endpoint_data(self) -> None:
        alerts, errors = DetectionEngine(cloud_rules()).run(load_events(ENDPOINT_DATASET))
        self.assertEqual((alerts, errors), ([], []))

    def test_benign_cloud_scenarios_produce_no_alerts(self) -> None:
        events = load_cloud()
        for key in ("A", "B"):
            with self.subTest(scenario=key):
                subset = events_for_scenario(events, key, CLOUD_SCENARIOS)
                alerts, _ = DetectionEngine(all_rules()).run(subset)
                self.assertEqual([a.rule_id for a in alerts], [])

    def test_attack_scenarios_produce_alerts(self) -> None:
        events = load_cloud()
        for key in "CDEFGHIJK":
            with self.subTest(scenario=key):
                subset = events_for_scenario(events, key, CLOUD_SCENARIOS)
                alerts, _ = DetectionEngine(all_rules()).run(subset)
                self.assertTrue(alerts, f"cloud scenario {key} produced no alerts")

    def test_every_scenario_references_real_events(self) -> None:
        known = {e.event_id for e in load_cloud()}
        for key, scenario in CLOUD_SCENARIOS.items():
            with self.subTest(scenario=key):
                self.assertLessEqual(set(scenario.event_ids), known)

    def test_every_cloud_rule_fires_on_the_dataset(self) -> None:
        alerts, _ = DetectionEngine(cloud_rules()).run(load_cloud())
        fired = {a.rule_id for a in alerts}
        self.assertEqual(fired, {r.rule_id for r in cloud_rules()})

    def test_every_alert_cites_real_events(self) -> None:
        events = load_cloud()
        known = {e.event_id for e in events}
        alerts, _ = DetectionEngine(all_rules()).run(events)
        for alert in alerts:
            self.assertLessEqual(set(alert.evidence_event_ids), known)


class TestRootAndConsoleRules(unittest.TestCase):
    def test_root_activity_fires(self) -> None:
        event = cloud_event("ListBuckets", identity_type="Root")
        self.assertIsNotNone(RootAccountActivityRule().matches(event))

    def test_iam_user_is_not_root(self) -> None:
        self.assertIsNone(RootAccountActivityRule().matches(cloud_event("ListBuckets")))

    def test_console_login_without_mfa(self) -> None:
        event = cloud_event("ConsoleLogin", mfa_authenticated=False)
        self.assertIsNotNone(ConsoleLoginWithoutMFARule().matches(event))

    def test_console_login_with_mfa_ignored(self) -> None:
        event = cloud_event("ConsoleLogin", mfa_authenticated=True)
        self.assertIsNone(ConsoleLoginWithoutMFARule().matches(event))

    def test_unknown_mfa_is_not_treated_as_false(self) -> None:
        self.assertIsNone(ConsoleLoginWithoutMFARule().matches(cloud_event("ConsoleLogin")))

    def test_failed_console_login_ignored(self) -> None:
        event = cloud_event("ConsoleLogin", mfa_authenticated=False, outcome="failure")
        self.assertIsNone(ConsoleLoginWithoutMFARule().matches(event))


class TestUnusualAssumeRole(unittest.TestCase):
    def _assume(self, **overrides):
        params = {"roleArn": overrides.pop("role", "arn:aws:iam::111122223333:role/r")}
        return cloud_event("AssumeRole", request_parameters=params, **overrides)

    def test_internal_same_account_is_quiet(self) -> None:
        self.assertIsNone(UnusualAssumeRoleRule().matches(self._assume()))

    def test_external_source(self) -> None:
        matched = UnusualAssumeRoleRule().matches(self._assume(source_ip="203.0.113.9"))
        self.assertIn("external-source", matched["reasons"])

    def test_role_chaining(self) -> None:
        matched = UnusualAssumeRoleRule().matches(
            self._assume(
                identity_type="AssumedRole",
                principal_arn="arn:aws:sts::111122223333:assumed-role/a/s",
            )
        )
        self.assertIn("role-chaining", matched["reasons"])

    def test_cross_account(self) -> None:
        matched = UnusualAssumeRoleRule().matches(
            self._assume(principal_arn="arn:aws:iam::444455556666:user/v")
        )
        self.assertIn("cross-account", matched["reasons"])

    def test_aws_service_is_ignored(self) -> None:
        event = self._assume(identity_type="AWSService", source_ip="203.0.113.9")
        self.assertIsNone(UnusualAssumeRoleRule().matches(event))

    def test_dataset_hits(self) -> None:
        alerts = UnusualAssumeRoleRule().evaluate(load_cloud())
        self.assertEqual(
            sorted(eid for a in alerts for eid in a.evidence_event_ids),
            ["cev-0018", "cev-0027", "cev-0035"],
        )


class TestIAMPrivilegeEscalation(unittest.TestCase):
    rule = IAMPrivilegeEscalationRule()

    def test_attach_administrator_access(self) -> None:
        event = cloud_event(
            "AttachUserPolicy",
            request_parameters={
                "userName": "u",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        )
        self.assertIsNotNone(self.rule.matches(event))

    def test_attach_non_admin_policy_is_quiet(self) -> None:
        event = cloud_event(
            "AttachUserPolicy",
            request_parameters={
                "userName": "u",
                "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            },
        )
        self.assertIsNone(self.rule.matches(event))

    def test_inline_wildcard_policy(self) -> None:
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        event = cloud_event("PutRolePolicy", request_parameters={"roleName": "r", "policyDocument": doc})
        self.assertIsNotNone(self.rule.matches(event))

    def test_inline_policy_as_json_string(self) -> None:
        doc = json.dumps({"Statement": {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}})
        event = cloud_event("PutUserPolicy", request_parameters={"userName": "u", "policyDocument": doc})
        self.assertIsNotNone(self.rule.matches(event))

    def test_inline_scoped_policy_is_quiet(self) -> None:
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
        event = cloud_event("PutUserPolicy", request_parameters={"userName": "u", "policyDocument": doc})
        self.assertIsNone(self.rule.matches(event))

    def test_deny_statement_is_quiet(self) -> None:
        doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        event = cloud_event("PutUserPolicy", request_parameters={"userName": "u", "policyDocument": doc})
        self.assertIsNone(self.rule.matches(event))

    def test_unparsable_policy_fails_toward_visibility(self) -> None:
        event = cloud_event(
            "PutUserPolicy", request_parameters={"userName": "u", "policyDocument": "{not json"}
        )
        matched = self.rule.matches(event)
        self.assertIsNotNone(matched)
        self.assertIn("could not be parsed", matched["policy"])

    def test_policy_version_only_counts_when_default(self) -> None:
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        not_default = cloud_event("CreatePolicyVersion", request_parameters={"policyDocument": doc})
        default = cloud_event(
            "CreatePolicyVersion", request_parameters={"policyDocument": doc, "setAsDefault": True}
        )
        self.assertIsNone(self.rule.matches(not_default))
        self.assertIsNotNone(self.rule.matches(default))

    def test_failed_escalation_is_quiet(self) -> None:
        event = cloud_event(
            "AttachUserPolicy",
            outcome="failure",
            request_parameters={"userName": "u", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        )
        self.assertIsNone(self.rule.matches(event))


class TestAccessKeyCreation(unittest.TestCase):
    def test_key_for_another_user(self) -> None:
        event = cloud_event("CreateAccessKey", request_parameters={"userName": "someone-else"})
        self.assertIsNotNone(AccessKeyCreationRule().matches(event))

    def test_self_rotation_is_quiet(self) -> None:
        """Routine rotation must not alert, or analysts learn to ignore the rule."""
        self.assertIsNone(AccessKeyCreationRule().matches(cloud_event("CreateAccessKey")))

    def test_root_key_always_fires(self) -> None:
        event = cloud_event("CreateAccessKey", identity_type="Root", user="root")
        self.assertEqual(AccessKeyCreationRule().matches(event)["by_root"], "true")


class TestSecurityGroupExposure(unittest.TestCase):
    rule = SecurityGroupExposureRule()

    def _sg(self, **permission):
        return cloud_event(
            "AuthorizeSecurityGroupIngress",
            event_source="ec2.amazonaws.com",
            request_parameters={"groupId": "sg-x", "ipPermissions": [permission]},
        )

    def test_ssh_open_to_world(self) -> None:
        matched = self.rule.matches(self._sg(ipProtocol="tcp", fromPort=22, toPort=22, cidrIp="0.0.0.0/0"))
        self.assertEqual(matched["exposed_ports"], "22")
        self.assertEqual(matched["cidr"], "0.0.0.0/0")

    def test_https_open_to_world_is_quiet(self) -> None:
        self.assertIsNone(self.rule.matches(self._sg(ipProtocol="tcp", fromPort=443, toPort=443, cidrIp="0.0.0.0/0")))

    def test_all_protocols_open(self) -> None:
        matched = self.rule.matches(self._sg(ipProtocol="-1", cidrIp="0.0.0.0/0"))
        self.assertEqual(matched["exposed_ports"], "ALL")

    def test_ipv6_open(self) -> None:
        matched = self.rule.matches(self._sg(ipProtocol="tcp", fromPort=3389, toPort=3389, cidrIpv6="::/0"))
        self.assertEqual(matched["cidr"], "::/0")

    def test_port_range_covering_database(self) -> None:
        matched = self.rule.matches(self._sg(ipProtocol="tcp", fromPort=3000, toPort=6000, cidrIp="0.0.0.0/0"))
        self.assertIn("3306", matched["exposed_ports"])
        self.assertIn("5432", matched["exposed_ports"])

    def test_restricted_cidr_is_quiet(self) -> None:
        self.assertIsNone(self.rule.matches(self._sg(ipProtocol="tcp", fromPort=22, toPort=22, cidrIp="192.0.2.0/24")))

    def test_inbound_flow_to_admin_port(self) -> None:
        alerts = InboundAdminPortFlowRule().evaluate(load_cloud())
        self.assertEqual([a.evidence_event_ids for a in alerts], [("cev-0025",)])
        self.assertEqual(alerts[0].technique_ids, ())  # deliberately unmapped


class TestLoggingTampering(unittest.TestCase):
    rule = CloudLoggingTamperingRule()

    def test_stop_logging_is_critical(self) -> None:
        results = self.rule.evaluate([cloud_event("StopLogging", event_source="cloudtrail.amazonaws.com")])
        self.assertEqual(results[0].severity, "critical")
        self.assertEqual(results[0].technique_ids, ("T1562.008",))

    def test_delete_flow_logs_is_critical(self) -> None:
        results = self.rule.evaluate([cloud_event("DeleteFlowLogs", event_source="ec2.amazonaws.com")])
        self.assertEqual(results[0].severity, "critical")

    def test_update_trail_is_medium(self) -> None:
        """Narrowing a trail is also routine admin; do not cry wolf."""
        results = self.rule.evaluate([cloud_event("UpdateTrail", event_source="cloudtrail.amazonaws.com")])
        self.assertEqual(results[0].severity, "medium")

    def test_failed_attempt_still_fires(self) -> None:
        event = cloud_event("StopLogging", event_source="cloudtrail.amazonaws.com", outcome="failure")
        results = self.rule.evaluate([event])
        self.assertEqual(results[0].matched_fields["outcome"], "failure")

    def test_describe_trails_is_quiet(self) -> None:
        self.assertEqual(self.rule.evaluate([cloud_event("DescribeTrails")]), [])


class TestS3AndAPIRules(unittest.TestCase):
    def test_bulk_sensitive_read_fires(self) -> None:
        alerts = SuspiciousS3AccessRule().evaluate(load_cloud())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0].evidence_event_ids), 4)

    def test_normal_bucket_reads_are_quiet(self) -> None:
        subset = events_for_scenario(load_cloud(), "B", CLOUD_SCENARIOS)
        self.assertEqual(SuspiciousS3AccessRule().evaluate(subset), [])

    def test_enumeration_burst_counts_distinct_apis(self) -> None:
        alerts = UnusualAPIActivityRule().evaluate(load_cloud())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].matched_fields["count"], "6")

    def test_repeating_one_api_is_not_enumeration(self) -> None:
        events = [
            cloud_event("DescribeInstances", event_id=f"c{i}", source_ip="203.0.113.9",
                        timestamp=f"2026-09-18T09:00:0{i}Z")
            for i in range(8)
        ]
        self.assertEqual(UnusualAPIActivityRule().evaluate(events), [])


class TestGuardDutyRule(unittest.TestCase):
    def _finding(self, finding_type: str, score: float):
        return parse_event(
            {
                "event_id": "gd-1",
                "timestamp": "2026-09-18T09:00:00Z",
                "source": "aws_guardduty",
                "category": "alert",
                "action": "guardduty_finding",
                "outcome": "unknown",
                "severity": "high",
                "alert": {"rule_id": finding_type, "vendor": "aws-guardduty", "gd_severity": score},
                "cloud": {"provider": "aws", "account_id": "111122223333"},
            }
        )

    def test_high_finding_with_known_mapping(self) -> None:
        results = GuardDutyHighSeverityRule().evaluate(
            [self._finding("Exfiltration:S3/AnomalousBehavior", 8.0)]
        )
        self.assertEqual(results[0].technique_ids, ("T1530",))
        self.assertEqual(results[0].severity, "high")

    def test_critical_band(self) -> None:
        results = GuardDutyHighSeverityRule().evaluate(
            [self._finding("Exfiltration:S3/AnomalousBehavior", 9.5)]
        )
        self.assertEqual(results[0].severity, "critical")

    def test_unknown_type_gets_no_invented_mapping(self) -> None:
        results = GuardDutyHighSeverityRule().evaluate([self._finding("Backdoor:EC2/Novel", 8.0)])
        self.assertEqual(results[0].technique_ids, ())

    def test_low_finding_is_quiet(self) -> None:
        self.assertEqual(
            GuardDutyHighSeverityRule().evaluate([self._finding("Recon:EC2/PortProbeUnprotectedPort", 2.0)]),
            [],
        )


# ---------------------------------------------------------------------------
# MITRE mapping
# ---------------------------------------------------------------------------


class TestCloudMitreMapping(unittest.TestCase):
    def test_every_cloud_rule_technique_is_pinned(self) -> None:
        for rule in cloud_rules():
            for technique_id in rule.technique_ids:
                with self.subTest(rule=rule.rule_id, technique=technique_id):
                    self.assertTrue(is_known_technique(technique_id))

    def test_every_guardduty_mapping_is_pinned(self) -> None:
        for finding, techniques in GUARDDUTY_TECHNIQUES.items():
            for technique_id in techniques:
                with self.subTest(finding=finding):
                    self.assertTrue(is_known_technique(technique_id))

    def test_expected_rule_mappings(self) -> None:
        expected = {
            "CLOUD-IAM-002": ("T1098.003",),
            "CLOUD-IAM-003": ("T1098.001",),
            "CLOUD-NET-001": ("T1562.007",),
            "CLOUD-LOG-001": ("T1562.008",),
            "CLOUD-S3-001": ("T1530",),
            "CLOUD-API-001": ("T1580",),
        }
        rules = {rule.rule_id: rule for rule in cloud_rules()}
        for rule_id, techniques in expected.items():
            with self.subTest(rule=rule_id):
                self.assertEqual(rules[rule_id].technique_ids, techniques)

    def test_cloud_tactics(self) -> None:
        self.assertEqual(TECHNIQUES["T1562.008"].tactic, "Defense Evasion")
        self.assertEqual(TECHNIQUES["T1098.001"].tactic, "Persistence")
        self.assertEqual(TECHNIQUES["T1580"].tactic, "Discovery")

    def test_chain_covers_expected_techniques(self) -> None:
        techniques = set(chain_incident().technique_ids)
        self.assertLessEqual(
            {"T1078.004", "T1580", "T1098.001", "T1098.003", "T1562.007", "T1562.008", "T1530"},
            techniques,
        )


# ---------------------------------------------------------------------------
# Cloud incident correlation
# ---------------------------------------------------------------------------


class TestCloudCorrelation(unittest.TestCase):
    def test_three_separate_incidents(self) -> None:
        """Chain, root misuse, and vendor role assumption stay separate."""
        _, _, incidents = cloud_incidents()
        self.assertEqual(len(incidents), 3)

    def test_chain_links_identity_network_and_data_stages(self) -> None:
        rules = set(chain_incident().rule_ids)
        self.assertLessEqual(
            {
                "CLOUD-API-001", "CLOUD-IAM-001", "CLOUD-IAM-003", "CLOUD-IAM-002",
                "CLOUD-NET-001", "CLOUD-NET-002", "CLOUD-LOG-001", "CLOUD-S3-001",
                "CLOUD-GD-001", "SOC-NET-001",
            },
            rules,
        )

    def test_chain_is_critical(self) -> None:
        self.assertEqual(chain_incident().severity, "critical")

    def test_root_incident_is_separate(self) -> None:
        _, _, incidents = cloud_incidents()
        root = next(i for i in incidents if "CLOUD-ROOT-001" in i.rule_ids)
        self.assertNotIn("CLOUD-LOG-001", root.rule_ids)
        self.assertEqual(root.users, ["root"])

    def test_account_id_is_not_a_correlation_entity(self) -> None:
        """Every event shares the account; linking on it would merge everything."""
        entities = entities_for(load_cloud())
        self.assertFalse(any("111122223333" == e.split(":", 1)[1] for e in entities))

    def test_aws_service_callers_do_not_become_entities(self) -> None:
        event = by_id(load_cloud())["cev-0004"]
        entities = entities_for([event])
        self.assertNotIn("user:ec2.amazonaws.com", entities)
        self.assertNotIn("ip:ec2.amazonaws.com", entities)

    def test_assumed_session_links_to_its_role_without_shared_ip(self) -> None:
        """AssumeRole target role == later session's issuer, whatever the IP."""
        events = by_id(load_cloud())
        assume = entities_for([events["cev-0018"]])
        later = replace(events["cev-0024"], details={**events["cev-0024"].details, "source_ip": "198.51.100.99"})
        self.assertIn("role:arn:aws:iam::111122223333:role/ops-admin", assume & entities_for([later]))

    def test_minted_key_links_to_its_creation(self) -> None:
        entities = entities_for([by_id(load_cloud())["cev-0020"]])
        self.assertIn("key:EXAMPLE-KEY-SVC-BACKUP-02", entities)

    def test_entity_values_expose_response_targets(self) -> None:
        values = set(chain_incident().entity_values)
        for target in ("EXAMPLE-KEY-CI-DEPLOY-01", "svc-backup-02", "sg-0example0001",
                       "i-0a1b2c3d4e5f00001", "203.0.113.77"):
            with self.subTest(target=target):
                self.assertIn(target, values)

    def test_hostless_incident_is_titled_by_account(self) -> None:
        _, _, incidents = cloud_incidents()
        root = next(i for i in incidents if "CLOUD-ROOT-001" in i.rule_ids)
        self.assertIn("AWS account 111122223333", root.title)
        self.assertNotIn("0 hosts", root.title)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


class TestCloudRisk(unittest.TestCase):
    def test_chain_scores_critical_with_impair_defenses(self) -> None:
        assessment = score_incident(chain_incident())
        self.assertEqual(assessment.band, "critical")
        self.assertIn("impair_defenses", {f.name for f in assessment.factors})

    def test_root_incident_gets_privileged_identity_factor(self) -> None:
        _, _, incidents = cloud_incidents()
        root = next(i for i in incidents if "CLOUD-ROOT-001" in i.rule_ids)
        names = {f.name for f in score_incident(root).factors}
        self.assertIn("privileged_identity", names)

    def test_endpoint_incident_does_not_get_cloud_factors(self) -> None:
        output = run_pipeline(ENDPOINT_DATASET)
        _, risk, _, _ = output.results[0]
        names = {f.name for f in risk.factors}
        self.assertFalse(names & {"impair_defenses", "privileged_identity"})
        self.assertEqual(risk.score, 98)


# ---------------------------------------------------------------------------
# Prompt injection through cloud telemetry
# ---------------------------------------------------------------------------


class TestCloudPromptInjection(unittest.TestCase):
    def test_both_cloud_payloads_are_flagged(self) -> None:
        flagged = {(f.event_id, f.field_path) for f in screen_for_injection(load_cloud())}
        self.assertIn(("cev-0023", "details.request_parameters.description"), flagged)
        self.assertIn(("cev-0026", "details.user_agent"), flagged)

    def test_payloads_are_preserved(self) -> None:
        events = by_id(load_cloud())
        self.assertIn("SYSTEM NOTICE", events["cev-0026"].user_agent)

    def test_injection_does_not_lower_severity_or_close_the_incident(self) -> None:
        incident = chain_incident()
        analysis = MockAIAnalyst().analyze(incident)
        self.assertTrue(analysis.injection_attempt_detected)
        self.assertEqual(analysis.severity_assessment, "critical")
        self.assertEqual(analysis.validation_warnings, ())
        actions = " ".join(a["action"].lower() for a in analysis.recommended_actions)
        self.assertNotIn("close", actions)
        self.assertNotIn("no remediation", actions)


# ---------------------------------------------------------------------------
# Cloud analysis and response (dry run)
# ---------------------------------------------------------------------------


class TestCloudAnalysis(unittest.TestCase):
    def test_cloud_recommendations_are_structured(self) -> None:
        analysis = MockAIAnalyst().analyze(chain_incident())
        structured = [a for a in analysis.recommended_actions if a.get("response_action")]
        self.assertTrue(structured)
        for action in structured:
            with self.subTest(action=action["response_action"]):
                self.assertEqual(action["tier"], ACTION_TIERS[ResponseAction(action["response_action"])])

    def test_restore_logging_is_manual(self) -> None:
        analysis = MockAIAnalyst().analyze(chain_incident())
        manual = [a for a in analysis.recommended_actions if "response_action" in a and a["response_action"] is None]
        self.assertTrue(any("restore logging" in a["action"].lower() for a in manual))

    def test_validation_catches_tier_mislabel(self) -> None:
        incident = chain_incident()
        analysis = AIAnalysis(
            incident_id=incident.incident_id, summary="s", severity_assessment="high",
            evidence=(), likely_attack_stage=None, technique_ids=(),
            recommended_actions=(
                {"action": "x", "response_action": "disable_iam_user", "target": "u",
                 "tier": "T1", "requires_human_approval": False},
            ),
            confidence="high", uncertainty=(), analyst_questions=(),
        )
        self.assertTrue(any("policy tier" in w for w in validate_analysis(analysis, incident)))

    def test_validation_flags_unknown_response_action(self) -> None:
        incident = chain_incident()
        analysis = AIAnalysis(
            incident_id=incident.incident_id, summary="s", severity_assessment="high",
            evidence=(), likely_attack_stage=None, technique_ids=(),
            recommended_actions=({"action": "x", "response_action": "delete_account", "target": "u", "tier": "T1"},),
            confidence="high", uncertainty=(), analyst_questions=(),
        )
        self.assertTrue(any("unknown response_action" in w for w in validate_analysis(analysis, incident)))


class TestCloudResponseDryRun(unittest.TestCase):
    def _request(self, action=ResponseAction.REVOKE_ACCESS_KEY, target="EXAMPLE-KEY-X", approved_by=None):
        return ResponseRequest(action=action, target=target, reason="t", incident_id="inc-1", approved_by=approved_by)

    def test_every_cloud_action_needs_a_human(self) -> None:
        for action in CLOUD_ACTIONS:
            with self.subTest(action=action.value):
                self.assertIn(ACTION_TIERS[action], {"T2", "T3"})

    def test_cloud_action_refused_when_not_dry_run_even_if_approved(self) -> None:
        """No code path may execute a cloud action in this build."""
        provider = MockResponseProvider(dry_run=False)
        for action in CLOUD_ACTIONS:
            with self.subTest(action=action.value):
                result = provider.execute(self._request(action=action, approved_by="human@corp.test"))
                self.assertEqual(result.status, "refused")
                self.assertIn("dry-run only", result.detail)
        self.assertEqual(provider.performed, [])

    def test_approved_cloud_action_is_dry_run(self) -> None:
        result = MockResponseProvider().execute(self._request(approved_by="human@corp.test"))
        self.assertEqual(result.status, "dry_run")
        self.assertFalse(result.executed)
        self.assertIn("WOULD revoke_access_key", result.would_have)

    def test_unapproved_cloud_action_is_refused(self) -> None:
        result = MockResponseProvider().execute(self._request())
        self.assertEqual(result.status, "refused")

    def test_rejection_is_audited(self) -> None:
        provider = MockResponseProvider()
        result = provider.record_rejection(self._request(), reviewer="human", reason="not yet")
        self.assertEqual(result.status, "rejected")
        self.assertIn(result, provider.audit_log)
        self.assertFalse(result.executed)

    def test_rejection_requires_a_reviewer(self) -> None:
        with self.assertRaises(ValueError):
            MockResponseProvider().record_rejection(self._request(), reviewer=" ", reason="x")

    def test_root_is_protected(self) -> None:
        result = MockResponseProvider().execute(
            self._request(action=ResponseAction.DISABLE_IAM_USER, target="root", approved_by="human")
        )
        self.assertIn("protected asset", result.detail)

    def test_structured_mapper(self) -> None:
        requests = requests_from_analysis(
            [{"action": "anything", "response_action": "revoke_access_key", "target": "K1"}], "inc-1"
        )
        self.assertEqual((requests[0].action, requests[0].target), (ResponseAction.REVOKE_ACCESS_KEY, "K1"))
        self.assertIsNone(requests[0].approved_by)

    def test_structured_mapper_drops_manual_and_unknown(self) -> None:
        requests = requests_from_analysis(
            [
                {"action": "MANUAL: restore logging", "response_action": None, "target": "trail"},
                {"action": "x", "response_action": "delete_everything", "target": "t"},
                {"action": "x", "response_action": "revoke_access_key", "target": ""},
            ],
            "inc-1",
        )
        self.assertEqual(requests, [])

    def test_structured_mapper_avoids_negation_trap(self) -> None:
        """Prose 'do not isolate' must not become an isolate request."""
        requests = requests_from_analysis(
            [{"action": "Do not isolate the host yet", "response_action": "notify_analyst", "target": "inc-1"}],
            "inc-1",
        )
        self.assertEqual([r.action for r in requests], [ResponseAction.NOTIFY_ANALYST])

    def test_target_outside_evidence_refused(self) -> None:
        provider = MockResponseProvider(allowed_targets=["EXAMPLE-KEY-A"])
        result = provider.execute(self._request(target="EXAMPLE-KEY-B", approved_by="human"))
        self.assertIn("does not appear in the incident", result.detail)


# ---------------------------------------------------------------------------
# End-to-end cloud demo
# ---------------------------------------------------------------------------


class TestCloudDemo(unittest.TestCase):
    def setUp(self) -> None:
        self.output = run_pipeline(profile="cloud")

    def test_runs_offline_with_three_incidents(self) -> None:
        self.assertEqual(self.output.profile, "cloud")
        self.assertEqual(len(self.output.events), 37)
        self.assertEqual(len(self.output.results), 3)

    def test_nothing_executes(self) -> None:
        for _, _, _, responses in self.output.results:
            self.assertEqual([r for r in responses if r.executed], [])

    def test_every_approval_branch_is_shown(self) -> None:
        incident, _, _, responses = self.output.results[0]
        self.assertIn("CLOUD-LOG-001", incident.rule_ids)
        statuses = {r.status for r in responses}
        self.assertEqual(statuses, {"dry_run", "rejected", "refused"})

    def test_simulated_approvals_are_labelled(self) -> None:
        _, _, _, responses = self.output.results[0]
        approvers = {r.request.approved_by for r in responses if r.request.approved_by}
        self.assertTrue(approvers)
        self.assertTrue(all("SIMULATED" in a for a in approvers))

    def test_analysis_passes_validation(self) -> None:
        for _, _, analysis, _ in self.output.results:
            self.assertEqual(analysis.validation_warnings, ())

    def test_cli_cloud_profile(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["--profile", "cloud", "--scenario", "K"]), 0)
        text = buffer.getvalue()
        self.assertIn("cloud profile", text)
        self.assertIn("actions actually executed: 0", text)

    def test_cli_cloud_json(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main(["--profile", "cloud", "--json"])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["profile"], "cloud")
        self.assertEqual(len(payload["incidents"]), 3)

    def test_cli_rejects_scenario_from_wrong_profile(self) -> None:
        """K exists only in the cloud registry."""
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--scenario", "K"])

    def test_default_profile_is_still_endpoint(self) -> None:
        output = run_pipeline(ENDPOINT_DATASET)
        self.assertEqual(output.profile, "endpoint")
        self.assertEqual(len(output.events), 26)


if __name__ == "__main__":
    unittest.main(verbosity=2)
