"""Tests for the SOC console API.

Two layers:
* `SocService` tests run under any interpreter (no FastAPI needed).
* HTTP tests need FastAPI + httpx (installed in app/.venv) and are skipped
  cleanly when those aren't importable, so the core suite still runs under
  the system Python.

Run with the venv to include the HTTP layer:
    app/.venv/Scripts/python.exe -m unittest discover -s tests -v
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.api.service import (  # noqa: E402
    MAX_FIELD_PREVIEW,
    OPERATOR_ID,
    ConflictError,
    NotFoundError,
    ProviderUnavailableError,
    SocService,
    _clean_text,
)

HAVE_HTTP = bool(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"))


class _FailingAnalyst:
    """Simulates an AI provider outage."""

    def analyze(self, incident):  # noqa: ARG002 - interface shape
        raise RuntimeError("model endpoint timed out")


def _incident_with(service: SocService, rule_id: str) -> str:
    return next(i["incident_id"] for i in service.list_incidents()
                if rule_id in service.incident_detail(i["incident_id"])["correlated"]["rule_ids"])


# ---------------------------------------------------------------------------
# Service layer
# ---------------------------------------------------------------------------


class TestScenarios(unittest.TestCase):
    def setUp(self) -> None:
        self.soc = SocService()

    def test_default_is_hybrid_with_real_engine_output(self) -> None:
        metrics = self.soc.metrics()
        self.assertEqual(metrics["scenario"]["scenario_id"], "hybrid-full")
        self.assertEqual(
            (metrics["events_ingested"], metrics["alerts"], metrics["active_incidents"]),
            (63, 27, 4),
        )

    def test_hybrid_preserves_existing_scenario_semantics(self) -> None:
        """Combining datasets must not change any incident's severity or risk."""
        hybrid = sorted((i["severity"], i["risk_score"]) for i in self.soc.list_incidents())
        separate: list[tuple[str, int]] = []
        for scenario_id in ("endpoint-full", "cloud-full"):
            self.soc.run_scenario(scenario_id)
            separate += [(i["severity"], i["risk_score"]) for i in self.soc.list_incidents()]
        self.assertEqual(hybrid, sorted(separate))

    def test_catalog_derives_from_existing_registries(self) -> None:
        scenarios = self.soc.list_scenarios()
        self.assertEqual(len(scenarios), 3 + 8 + 11 + 1)  # + canonical 50K
        groups = {s["group"] for s in scenarios}
        self.assertEqual(
            groups,
            {"Hybrid Attack", "Endpoint Attack", "Cloud Attack", "Benign Activity", "Prompt Injection Attempt",
             "Canonical Benchmark"},
        )
        self.assertEqual(sum(1 for s in scenarios if s["active"]), 1)

    def test_every_scenario_runs_without_rule_errors(self) -> None:
        for scenario in self.soc.list_scenarios():
            with self.subTest(scenario=scenario["scenario_id"]):
                self.soc.run_scenario(scenario["scenario_id"])
                self.assertEqual(self.soc.health()["rule_errors"], [])

    def test_benign_scenarios_produce_no_incidents(self) -> None:
        for scenario_id in ("endpoint-a", "cloud-a", "cloud-b"):
            with self.subTest(scenario=scenario_id):
                self.assertEqual(self.soc.run_scenario(scenario_id)["active_incidents"], 0)

    def test_unknown_scenario(self) -> None:
        with self.assertRaises(NotFoundError):
            self.soc.run_scenario("does-not-exist")

    def test_running_a_scenario_resets_investigation_state(self) -> None:
        incident_id = self.soc.list_incidents()[0]["incident_id"]
        self.soc.analyze(incident_id)
        self.soc.run_scenario("hybrid-full")
        self.assertEqual(self.soc.metrics()["ai_investigations"], 0)


class TestIncidentViews(unittest.TestCase):
    def setUp(self) -> None:
        self.soc = SocService()
        self.cloud_id = _incident_with(self.soc, "CLOUD-LOG-001")

    def test_unknown_incident(self) -> None:
        with self.assertRaises(NotFoundError):
            self.soc.incident_detail("inc-9999")

    def test_attack_chain_is_chronological_and_evidence_backed(self) -> None:
        detail = self.soc.incident_detail(self.cloud_id)
        chain = detail["attack_chain"]
        self.assertTrue(chain)
        times = [node["first_seen"] for node in chain]
        self.assertEqual(times, sorted(times))
        incident_alerts = {a["alert_id"] for a in detail["correlated"]["alerts"]}
        for node in chain:
            self.assertLessEqual(set(node["alert_ids"]), incident_alerts)

    def test_mitre_entries_explain_every_technique(self) -> None:
        detail = self.soc.incident_detail(self.cloud_id)
        self.assertEqual(
            [m["technique_id"] for m in detail["mitre"]], detail["incident"]["technique_ids"]
        )
        for entry in detail["mitre"]:
            self.assertTrue(entry["detected_by"], entry["technique_id"])
            self.assertTrue(entry["event_ids"], entry["technique_id"])

    def test_timeline_covers_incident_events_in_order(self) -> None:
        detail = self.soc.incident_detail(self.cloud_id)
        timeline = detail["timeline"]
        self.assertEqual(len(timeline), detail["incident"]["event_count"])
        self.assertEqual([e["timestamp"] for e in timeline], sorted(e["timestamp"] for e in timeline))
        self.assertTrue(all(e["rules"] for e in timeline), "every timeline event must cite a rule")

    def test_injection_is_surfaced_on_the_incident(self) -> None:
        detail = self.soc.incident_detail(self.cloud_id)
        self.assertTrue(detail["incident"]["injection_detected"])
        flagged = [e for e in detail["timeline"] if e["injection_flags"]]
        self.assertTrue(flagged)

    def test_untrusted_fields_are_bounded(self) -> None:
        for event in self.soc.list_events(1000):
            for value in event["untrusted_fields"].values():
                self.assertLessEqual(len(value), MAX_FIELD_PREVIEW)

    def test_screening_lists_all_findings_with_owners(self) -> None:
        findings = self.soc.screening()
        self.assertEqual(len(findings), 4)
        self.assertTrue(any(f["incident_id"] is None for f in findings))  # no rule fired
        self.assertTrue(any(f["incident_id"] == self.cloud_id for f in findings))

    def test_event_limit_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            self.soc.list_events(0)
        with self.assertRaises(ValueError):
            self.soc.list_events(5000)

    def test_alerts_point_at_their_incident(self) -> None:
        alerts = self.soc.list_alerts()
        self.assertEqual(len(alerts), 27)
        self.assertTrue(all(a["incident_id"] for a in alerts))


class TestAnalystWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.soc = SocService()
        self.cloud_id = _incident_with(self.soc, "CLOUD-LOG-001")
        self.endpoint_id = _incident_with(self.soc, "SOC-CRED-001")

    def test_ai_investigation(self) -> None:
        # Stage 2 API shape: {provider, investigation, context_metrics}.
        analysis = self.soc.analyze(self.cloud_id)["investigation"]
        self.assertEqual(analysis["validation_warnings"], [])
        self.assertTrue(analysis["injection_attempt_detected"])
        self.assertEqual(self.soc.metrics()["ai_investigations"], 1)
        self.assertEqual(self.soc.incident_detail(self.cloud_id)["incident"]["status"], "INVESTIGATING")

    def test_ai_provider_unavailable(self) -> None:
        soc = SocService(analyst=_FailingAnalyst())  # type: ignore[arg-type]
        incident_id = soc.list_incidents()[0]["incident_id"]
        with self.assertRaises(ProviderUnavailableError):
            soc.analyze(incident_id)
        self.assertIsNone(soc.incident_detail(incident_id)["analysis"])

    def test_plan_requires_analysis(self) -> None:
        with self.assertRaises(ConflictError):
            self.soc.response_plan(self.cloud_id)

    def test_plan_is_server_owned_and_idempotent(self) -> None:
        self.soc.analyze(self.cloud_id)
        first = self.soc.response_plan(self.cloud_id)
        second = self.soc.response_plan(self.cloud_id)
        self.assertEqual(first, second)
        self.assertTrue(all(a["action_id"].startswith("act-") for a in first["actions"]))
        self.assertTrue(first["manual_tasks"])

    def test_approve_produces_dry_run_only(self) -> None:
        self.soc.analyze(self.cloud_id)
        plan = self.soc.response_plan(self.cloud_id)
        pending = next(a for a in plan["actions"] if a["status"] == "PENDING_APPROVAL")
        result = self.soc.decide(self.cloud_id, pending["action_id"], "approve")
        self.assertEqual(result["action"]["status"], "DRY_RUN_COMPLETE")
        self.assertFalse(result["action"]["executed"])
        self.assertEqual(result["action"]["decided_by"], OPERATOR_ID)

    def test_policy_rejection_for_protected_asset(self) -> None:
        self.soc.analyze(self.endpoint_id)
        plan = self.soc.response_plan(self.endpoint_id)
        dc = next(a for a in plan["actions"] if a["target"] == "DC-CORP-01")
        result = self.soc.decide(self.endpoint_id, dc["action_id"], "approve")
        self.assertEqual(result["action"]["status"], "BLOCKED_BY_POLICY")
        self.assertIn("protected asset", result["action"]["outcome_detail"])

    def test_reject_is_audited(self) -> None:
        self.soc.analyze(self.cloud_id)
        plan = self.soc.response_plan(self.cloud_id)
        action_id = plan["actions"][1]["action_id"]
        result = self.soc.decide(self.cloud_id, action_id, "reject", "not yet")
        self.assertEqual(result["action"]["status"], "REJECTED")
        audit = self.soc.state.providers[self.cloud_id].audit_log
        self.assertEqual(audit[-1].status, "rejected")

    def test_cannot_decide_twice(self) -> None:
        self.soc.analyze(self.cloud_id)
        action_id = self.soc.response_plan(self.cloud_id)["actions"][0]["action_id"]
        self.soc.decide(self.cloud_id, action_id, "approve")
        with self.assertRaises(ConflictError):
            self.soc.decide(self.cloud_id, action_id, "reject")

    def test_unknown_action_and_bad_decision(self) -> None:
        self.soc.analyze(self.cloud_id)
        self.soc.response_plan(self.cloud_id)
        with self.assertRaises(NotFoundError):
            self.soc.decide(self.cloud_id, "act-99", "approve")
        with self.assertRaises(ValueError):
            self.soc.decide(self.cloud_id, "act-01", "execute")

    def test_approving_everything_executes_nothing(self) -> None:
        """The core guarantee: even blanket approval changes no system."""
        for incident in self.soc.list_incidents():
            incident_id = incident["incident_id"]
            self.soc.analyze(incident_id)
            for action in self.soc.response_plan(incident_id)["actions"]:
                self.soc.decide(incident_id, action["action_id"], "approve")
        metrics = self.soc.metrics()
        self.assertEqual(metrics["responses"]["executed"], 0)
        self.assertEqual(metrics["responses"]["pending"], 0)
        self.assertGreater(metrics["responses"]["blocked"], 0)

    def test_reason_text_is_sanitized(self) -> None:
        self.assertEqual(_clean_text("ok\x00\x1b[31m done"), "ok[31m done")
        self.assertEqual(len(_clean_text("x" * 5000) or ""), 500)
        self.assertIsNone(_clean_text("   "))


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


@unittest.skipUnless(HAVE_HTTP, "FastAPI/httpx not installed in this interpreter (use app/.venv)")
class TestHttpApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import logging
        import warnings

        from fastapi.testclient import TestClient

        from app.api.main import create_app

        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("soc.api").setLevel(logging.CRITICAL)
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        cls.TestClient = TestClient
        cls.create_app = staticmethod(create_app)

    def setUp(self) -> None:
        self.soc = SocService()
        self.client = self.TestClient(self.create_app(self.soc), raise_server_exceptions=False)
        self.cloud_id = _incident_with(self.soc, "CLOUD-LOG-001")
        self.endpoint_id = _incident_with(self.soc, "SOC-CRED-001")

    def test_health(self) -> None:
        body = self.client.get("/api/health").json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["response_engine"]["mode"], "DRY RUN")

    def test_metrics(self) -> None:
        body = self.client.get("/api/metrics").json()
        self.assertEqual(body["active_incidents"], 4)
        self.assertEqual(sum(body["alert_severity"].values()), body["alerts"])

    def test_incidents_and_detail(self) -> None:
        incidents = self.client.get("/api/incidents").json()
        self.assertEqual(len(incidents), 4)
        detail = self.client.get(f"/api/incidents/{self.cloud_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("attack_chain", detail.json())

    def test_invalid_incident(self) -> None:
        self.assertEqual(self.client.get("/api/incidents/inc-9999").status_code, 404)
        self.assertEqual(self.client.get("/api/incidents/not-an-id").status_code, 422)

    def test_alerts_events_screening(self) -> None:
        self.assertEqual(len(self.client.get("/api/alerts").json()), 27)
        self.assertEqual(len(self.client.get("/api/events?limit=10").json()), 10)
        self.assertEqual(self.client.get("/api/events?limit=0").status_code, 422)
        self.assertEqual(len(self.client.get("/api/screening").json()), 4)

    def test_scenarios(self) -> None:
        self.assertEqual(len(self.client.get("/api/scenarios").json()), 23)
        run = self.client.post("/api/scenarios/cloud-k/run")
        self.assertEqual(run.status_code, 200)
        self.assertEqual(run.json()["scenario"]["scenario_id"], "cloud-k")

    def test_invalid_scenario(self) -> None:
        self.assertEqual(self.client.post("/api/scenarios/nope/run").status_code, 404)
        self.assertEqual(self.client.post("/api/scenarios/BAD_ID/run").status_code, 422)

    def test_investigation_and_approval_flow(self) -> None:
        self.assertEqual(self.client.post(f"/api/incidents/{self.cloud_id}/response-plan").status_code, 409)
        self.assertEqual(self.client.post(f"/api/incidents/{self.cloud_id}/analyze").status_code, 200)
        plan = self.client.post(f"/api/incidents/{self.cloud_id}/response-plan").json()
        action_id = next(a["action_id"] for a in plan["actions"] if a["status"] == "PENDING_APPROVAL")
        decided = self.client.post(
            f"/api/incidents/{self.cloud_id}/approve-response",
            json={"action_id": action_id, "decision": "approve"},
        )
        self.assertEqual(decided.status_code, 200)
        self.assertEqual(decided.json()["action"]["status"], "DRY_RUN_COMPLETE")
        again = self.client.post(
            f"/api/incidents/{self.cloud_id}/approve-response",
            json={"action_id": action_id, "decision": "approve"},
        )
        self.assertEqual(again.status_code, 409)

    def test_policy_rejection_over_http(self) -> None:
        self.client.post(f"/api/incidents/{self.endpoint_id}/analyze")
        plan = self.client.post(f"/api/incidents/{self.endpoint_id}/response-plan").json()
        dc = next(a for a in plan["actions"] if a["target"] == "DC-CORP-01")
        body = self.client.post(
            f"/api/incidents/{self.endpoint_id}/approve-response",
            json={"action_id": dc["action_id"], "decision": "approve"},
        ).json()
        self.assertEqual(body["action"]["status"], "BLOCKED_BY_POLICY")

    def test_client_cannot_name_action_target_or_approver(self) -> None:
        """Arbitrary response actions are impossible: extra fields are rejected."""
        self.client.post(f"/api/incidents/{self.cloud_id}/analyze")
        self.client.post(f"/api/incidents/{self.cloud_id}/response-plan")
        url = f"/api/incidents/{self.cloud_id}/approve-response"
        for body in (
            {"action_id": "act-02", "decision": "approve", "target": "root"},
            {"action_id": "act-02", "decision": "approve", "approved_by": "ceo"},
            {"action_id": "act-02", "decision": "approve", "action": "disable_iam_user"},
            {"action_id": "act-02", "decision": "execute"},
            {"action_id": "../../etc", "decision": "approve"},
            {"action_id": "act-02", "decision": "reject", "reason": "x" * 501},
        ):
            with self.subTest(body=list(body)):
                response = self.client.post(url, json=body)
                self.assertEqual(response.status_code, 422)
                self.assertNotIn("Traceback", response.text)

    def test_ai_provider_outage_is_graceful(self) -> None:
        client = self.TestClient(
            self.create_app(SocService(analyst=_FailingAnalyst())),  # type: ignore[arg-type]
            raise_server_exceptions=False,
        )
        response = client.post("/api/incidents/inc-0001/analyze")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Deterministic evidence is unaffected", response.json()["error"])
        self.assertNotIn("timed out", response.text)  # internal detail not leaked

    def test_unexpected_errors_do_not_leak_internals(self) -> None:
        class Broken(SocService):
            def list_incidents(self):  # type: ignore[override]
                raise RuntimeError("secret internal detail")

        client = self.TestClient(self.create_app(Broken()), raise_server_exceptions=False)
        response = client.get("/api/incidents")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("secret internal detail", response.text)
        self.assertNotIn("Traceback", response.text)

    def test_cors_allows_only_the_console_origin(self) -> None:
        ok = self.client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(ok.headers.get("access-control-allow-origin"), "http://localhost:5173")
        evil = self.client.get("/api/health", headers={"Origin": "http://evil.example"})
        self.assertIsNone(evil.headers.get("access-control-allow-origin"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
