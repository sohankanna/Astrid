"""Tests for the Claude investigator, provider selection and fallback.

No network: a fake client stands in for `anthropic.Anthropic()` and returns
objects shaped like the SDK's Message (content blocks, stop_reason, usage).
It records every request, so the tests can assert exactly what would leave
the process.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.api.service import ProviderUnavailableError, SocService  # noqa: E402
from app.soc_core.evidence_context import build_evidence_context  # noqa: E402
from app.soc_core.providers.ai_analyst import MockAIAnalyst  # noqa: E402
from app.soc_core.providers.claude_ai import (  # noqa: E402
    DEFAULT_MODEL,
    OUTPUT_SCHEMA,
    SYSTEM_PROMPT,
    AIProviderError,
    ClaudeAnalyst,
)
from app.soc_core.providers.selection import configured_provider  # noqa: E402

FAKE_KEY = "sk-" + "ant-api03-THIS-IS-A-FAKE-TEST-KEY-000"  # assembled: keeps scanners quiet


class FakeClient:
    """Minimal stand-in for anthropic.Anthropic: client.beta.messages.create."""

    def __init__(self, *, text: str | None = None, stop_reason: str = "end_turn", error: Exception | None = None):
        self.requests: list[dict] = []
        self._text, self._stop, self._error = text, stop_reason, error
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        if self._error:
            raise self._error
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=self._text)] if self._text is not None else [],
            stop_reason=self._stop,
            usage=SimpleNamespace(input_tokens=6123, output_tokens=1480),
            model=DEFAULT_MODEL,
        )


def _service() -> SocService:
    return SocService(analyst=MockAIAnalyst())


def _cloud(soc: SocService):
    incident = next(i for i in soc.state.incidents.values() if "CLOUD-LOG-001" in i.rule_ids)
    return incident, soc._context(incident.incident_id)


def _answer(context, **overrides) -> str:
    """A schema-valid model answer that cites real evidence from `context`."""
    evidence = context.pack["evidence"]
    log_item = next(i for i in evidence if "CLOUD-LOG-001" in i["detections"])
    key_entity = next(e for e in context.pack["entities"] if e["type"] == "access_key")
    technique = context.pack["mitre"][0]["technique_id"]
    body = {
        "summary": "A compromised identity stopped CloudTrail logging.",
        "attack_assessment": "Consistent with defense evasion before data access.",
        "severity_opinion": "critical",
        "likely_attack_stage": "Collection",
        "timeline_interpretation": [{"time": log_item["first_seen"], "interpretation": "Logging stopped.",
                                     "evidence_ids": [log_item["id"]]}],
        "affected_assets": [{"asset": "org-trail", "role": "audit trail", "evidence_ids": [log_item["id"]]}],
        "compromised_identities": [{"identity": key_entity["value"], "status": "likely",
                                    "evidence_ids": key_entity["evidence_ids"][:1]}],
        "mitre_interpretation": [{"technique_id": technique, "interpretation": "Mapped by the engine.",
                                  "evidence_ids": [log_item["id"]]}],
        "evidence_citations": [
            {"claim": "CloudTrail logging was stopped.", "classification": "OBSERVED",
             "evidence_ids": [log_item["id"]]},
            {"claim": "The attacker likely wanted to hide later activity.", "classification": "INFERRED",
             "evidence_ids": [log_item["id"]]},
            {"claim": "Revoke the key used in the chain.", "classification": "AI_RECOMMENDATION",
             "evidence_ids": []},
        ],
        "impact_assessment": "Audit gap during sensitive data access.",
        "uncertainties": ["Whether another trail recorded the gap."],
        "recommended_investigation_steps": ["Check the data-events trail for the gap window."],
        "recommended_response_actions": [
            {"action": f"Revoke {key_entity['value']}", "response_action": "revoke_access_key",
             "target": key_entity["value"], "rationale": "Key used by the attacker.",
             "evidence_ids": key_entity["evidence_ids"][:1]},
            {"action": "Restore logging on the trail", "response_action": "none", "target": "org-trail",
             "rationale": "Visibility first.", "evidence_ids": [log_item["id"]]},
        ],
        "injection_attempt_observed": True,
        "confidence": "high",
    }
    body.update(overrides)
    return json.dumps(body)


class TestClaudeRequest(unittest.TestCase):
    def setUp(self) -> None:
        self.soc = _service()
        self.incident, self.context = _cloud(self.soc)

    def test_sends_only_system_prompt_and_redacted_context(self) -> None:
        client = FakeClient(text=_answer(self.context))
        ClaudeAnalyst(client=client).analyze(self.incident, self.context)
        request = client.requests[0]
        self.assertEqual(request["model"], DEFAULT_MODEL)
        self.assertEqual(request["system"], SYSTEM_PROMPT)
        self.assertEqual(len(request["messages"]), 1)
        content = request["messages"][0]["content"]
        self.assertIn(self.context.to_json(), content)
        # Raw telemetry and real identifiers never leave the process.
        for forbidden in ("111122223333", "EXAMPLE-KEY-", "ci-deploy", '"raw"', "reverse_map"):
            self.assertNotIn(forbidden, json.dumps(request))

    def test_structured_output_and_refusal_fallback_requested(self) -> None:
        client = FakeClient(text=_answer(self.context))
        ClaudeAnalyst(client=client).analyze(self.incident, self.context)
        request = client.requests[0]
        self.assertEqual(request["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(request["output_config"]["format"]["schema"], OUTPUT_SCHEMA)
        self.assertEqual(request["fallbacks"], "default")
        self.assertEqual(request["betas"], ["server-side-fallback-2026-07-01"])

    def test_outbound_tripwire_blocks_leaked_secret(self) -> None:
        self.context.pack["evidence"][0]["fields"]["note"] = "password=Hunter2-Summer!"
        client = FakeClient(text=_answer(self.context))
        with self.assertRaises(AIProviderError) as ctx:
            ClaudeAnalyst(client=client).analyze(self.incident, self.context)
        self.assertIn("tripwire", str(ctx.exception))
        self.assertEqual(client.requests, [], "nothing may be sent")

    def test_raw_incident_without_context_is_refused(self) -> None:
        client = FakeClient(text="{}")
        with self.assertRaises(AIProviderError):
            ClaudeAnalyst(client=client).analyze(self.incident)
        self.assertEqual(client.requests, [])


class TestClaudeResponseHandling(unittest.TestCase):
    def setUp(self) -> None:
        self.soc = _service()
        self.incident, self.context = _cloud(self.soc)

    def _analyze(self, text: str, **kw):
        return ClaudeAnalyst(client=FakeClient(text=text, **kw)).analyze(self.incident, self.context)

    def test_valid_response_maps_to_validated_analysis(self) -> None:
        analysis = self._analyze(_answer(self.context))
        self.assertEqual(analysis.validation_warnings, ())
        self.assertTrue(analysis.model.startswith("claude:"))
        self.assertEqual(analysis.severity_assessment, self.incident.severity)  # engine is authoritative
        self.assertTrue(all(c["supported"] for c in analysis.citations))
        self.assertTrue(analysis.citations[0]["event_ids"])  # evidence ID -> real events
        self.assertTrue(analysis.injection_attempt_detected)

    def test_pseudonymous_target_resolved_server_side(self) -> None:
        analysis = self._analyze(_answer(self.context))
        revoke = next(a for a in analysis.recommended_actions if a["response_action"] == "revoke_access_key")
        self.assertTrue(revoke["target"].startswith("EXAMPLE-"))  # real key ID, resolved locally
        self.assertEqual(revoke["tier"], "T2")                   # policy tier, not model's
        self.assertTrue(revoke["requires_human_approval"])
        manual = next(a for a in analysis.recommended_actions if a["response_action"] is None)
        self.assertEqual(manual["tier"], "T1")

    def test_usage_is_measured(self) -> None:
        analyst = ClaudeAnalyst(client=FakeClient(text=_answer(self.context)))
        analyst.analyze(self.incident, self.context)
        self.assertEqual(analyst.last_usage["input_tokens"], 6123)
        self.assertEqual(analyst.last_usage["output_tokens"], 1480)

    def test_malformed_json(self) -> None:
        with self.assertRaises(AIProviderError):
            self._analyze("this is not json")

    def test_missing_fields(self) -> None:
        with self.assertRaises(AIProviderError):
            self._analyze(json.dumps({"summary": "x"}))

    def test_refusal(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            self._analyze(_answer(self.context), stop_reason="refusal")
        self.assertIn("refusal", str(ctx.exception))

    def test_truncated_output(self) -> None:
        with self.assertRaises(AIProviderError):
            self._analyze(_answer(self.context), stop_reason="max_tokens")

    def test_unsupported_claim_is_flagged_not_presented_as_fact(self) -> None:
        text = _answer(self.context, evidence_citations=[
            {"claim": "The attacker also compromised the domain controller.",
             "classification": "OBSERVED", "evidence_ids": ["E99"]},
        ])
        analysis = self._analyze(text)
        citation = analysis.citations[0]
        self.assertFalse(citation["supported"])
        self.assertEqual(citation["invalid_evidence_ids"], ["E99"])
        self.assertTrue(any("unsupported claim" in w for w in analysis.validation_warnings))

    def test_invented_technique_is_flagged(self) -> None:
        """An ID outside the pinned ATT&CK catalog is a hallucination."""
        text = _answer(self.context, mitre_interpretation=[
            {"technique_id": "T1486", "interpretation": "ransomware", "evidence_ids": []}])
        analysis = self._analyze(text)
        self.assertTrue(any("hallucination" in w for w in analysis.validation_warnings))

    def test_real_but_unmapped_technique_is_flagged(self) -> None:
        """A real technique the engine did not map for THIS incident is still rejected."""
        self.assertNotIn("T1003.001", self.incident.technique_ids)
        text = _answer(self.context, mitre_interpretation=[
            {"technique_id": "T1003.001", "interpretation": "LSASS", "evidence_ids": []}])
        analysis = self._analyze(text)
        self.assertTrue(any("not mapped by the deterministic engine" in w for w in analysis.validation_warnings))

    def test_action_claim_is_flagged(self) -> None:
        analysis = self._analyze(_answer(self.context, summary="I have disabled the compromised key."))
        self.assertTrue(any("claims an action" in w for w in analysis.validation_warnings))

    def test_errors_never_contain_the_api_key(self) -> None:
        boom = RuntimeError(f"upstream said: bad key {FAKE_KEY}")
        with self.assertRaises(AIProviderError) as ctx, self.assertLogs("soc", level="DEBUG") as logs:
            import logging

            logging.getLogger("soc").debug("probe")
            ClaudeAnalyst(client=FakeClient(error=boom)).analyze(self.incident, self.context)
        self.assertNotIn(FAKE_KEY, str(ctx.exception))
        self.assertNotIn(FAKE_KEY, "\n".join(logs.output))


class TestSelectionAndFallback(unittest.TestCase):
    def test_default_is_mock(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SOC_AI_PROVIDER", None)
            self.assertEqual(configured_provider().effective, "mock")

    def test_unknown_provider_falls_back_to_mock_with_note(self) -> None:
        with mock.patch.dict(os.environ, {"SOC_AI_PROVIDER": "gpt"}):
            config = configured_provider()
        self.assertEqual(config.effective, "mock")
        self.assertIn("unknown", config.note)

    def test_claude_without_credentials_falls_back_visibly(self) -> None:
        env = {"SOC_AI_PROVIDER": "claude", "ANTHROPIC_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": ""}
        with mock.patch.dict(os.environ, env):
            soc = SocService()
            incident_id = next(iter(soc.state.incidents))
            result = soc.analyze(incident_id)
        self.assertEqual(result["provider"]["requested"], "claude")
        self.assertEqual(result["provider"]["used"], "mock")
        self.assertFalse(result["provider"]["live_model"])
        # Either reason is correct depending on the interpreter: without the
        # SDK installed the provider reports that first; with it, missing
        # credentials. What matters is a visible, specific reason.
        reason = result["provider"]["fallback_reason"]
        self.assertTrue("credentials" in reason or "SDK not installed" in reason, reason)
        self.assertTrue(result["investigation"]["summary"])
        self.assertIn("estimated_tokens", result["context_metrics"])

    def test_claude_success_through_service(self) -> None:
        soc = SocService(analyst=MockAIAnalyst())
        incident, context = _cloud(soc)
        soc.analyst = ClaudeAnalyst(client=FakeClient(text=_answer(context)))
        soc.fallback_analyst = MockAIAnalyst()
        result = soc.analyze(incident.incident_id)
        self.assertEqual(result["provider"]["used"], "claude")
        self.assertTrue(result["provider"]["live_model"])
        self.assertEqual(result["provider"]["usage"]["input_tokens"], 6123)
        # The response plan built from Claude's actions is still policy-gated.
        plan = soc.response_plan(incident.incident_id)
        revoke = next(a for a in plan["actions"] if a["action"] == "revoke_access_key")
        self.assertEqual(revoke["status"], "PENDING_APPROVAL")
        self.assertTrue(revoke["target"].startswith("EXAMPLE-"))

    def test_claude_failure_falls_back_to_mock(self) -> None:
        soc = SocService(analyst=MockAIAnalyst())
        incident, _ = _cloud(soc)
        soc.analyst = ClaudeAnalyst(client=FakeClient(text="not json"))
        soc.fallback_analyst = MockAIAnalyst()
        result = soc.analyze(incident.incident_id)
        self.assertEqual(result["provider"]["used"], "mock")
        self.assertIn("malformed", result["provider"]["fallback_reason"])

    def test_no_fallback_configured_is_503(self) -> None:
        soc = SocService(analyst=ClaudeAnalyst(client=FakeClient(text="not json")))
        with self.assertRaises(ProviderUnavailableError):
            soc.analyze(next(iter(soc.state.incidents)))

    def test_mock_citations_are_evidence_backed(self) -> None:
        soc = _service()
        result = soc.analyze(next(iter(soc.state.incidents)))
        citations = result["investigation"]["citations"]
        self.assertTrue(citations)
        self.assertTrue(all(c["supported"] and c["evidence_ids"] and c["event_ids"] for c in citations))

    def test_context_endpoint_payload_is_redacted(self) -> None:
        soc = _service()
        for incident_id in soc.state.incidents:
            payload = json.dumps(soc.context_pack(incident_id)["pack"])
            for real in ("j.rivera", "111122223333", "EXAMPLE-KEY-"):
                self.assertNotIn(real, payload)

    def test_health_reports_provider_without_secrets(self) -> None:
        with mock.patch.dict(os.environ, {"SOC_AI_PROVIDER": "claude", "ANTHROPIC_API_KEY": FAKE_KEY}):
            soc = SocService()
            health = soc.health()
        self.assertEqual(health["ai_analyst"]["name"], "claude")
        self.assertEqual(health["ai_analyst"]["fallback"], "MockAIAnalyst")
        self.assertTrue(health["ai_analyst"]["config"]["claude_credentials_configured"])
        self.assertNotIn(FAKE_KEY, json.dumps(health))


if __name__ == "__main__":
    unittest.main(verbosity=2)
