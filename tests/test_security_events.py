"""Tests for parsing and validating the sample security-event dataset.

Written against the standard-library `unittest` runner so the suite runs with no
extra dependencies installed:

    python -m unittest discover -s tests -v

`unittest.TestCase` classes are also collected natively by pytest, so the same
file works unchanged once pytest is added to the project.
"""

from __future__ import annotations

import json
import sys
import unittest
from datetime import timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = REPO_ROOT / "data" / "sample_security_events.json"

# The reusable SOC modules live under app/; make them importable without
# requiring the project to be pip-installed.
sys.path.insert(0, str(REPO_ROOT / "app"))

from soc_core.events import (  # noqa: E402  (import needs the path set above)
    MAX_FIELD_LENGTH,
    REQUIRED_DETAIL_BY_CATEGORY,
    SCHEMA_VERSION,
    VALID_CATEGORIES,
    VALID_OUTCOMES,
    VALID_SEVERITIES,
    EventValidationError,
    SecurityEvent,
    iter_untrusted_text,
    load_events,
    parse_event,
    parse_events,
    parse_timestamp,
)


def _valid_event(**overrides: object) -> dict:
    """A minimal valid event, with optional field overrides."""
    event = {
        "event_id": "evt-test-0001",
        "timestamp": "2026-09-17T08:00:00Z",
        "source": "unit_test",
        "category": "authentication",
        "action": "logon_success",
        "outcome": "success",
        "severity": "low",
        "host": {"hostname": "TEST-HOST-01", "ip": "192.0.2.1"},
        "user": {"name": "test.user", "domain": "CORP"},
        "auth": {"logon_type": "network", "source_ip": "192.0.2.1"},
        "raw": "EventID=4624 Account=CORP\\test.user",
    }
    event.update(overrides)
    return event


class TestDatasetFile(unittest.TestCase):
    """The shipped sample dataset must stay loadable and well formed."""

    def test_dataset_file_exists(self) -> None:
        self.assertTrue(
            DATASET_PATH.is_file(), f"sample dataset missing at {DATASET_PATH}"
        )

    def test_dataset_is_valid_json_object(self) -> None:
        payload = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertIsInstance(payload["events"], list)

    def test_dataset_loads_and_validates(self) -> None:
        events = load_events(DATASET_PATH)
        self.assertGreater(len(events), 0)
        for event in events:
            self.assertIsInstance(event, SecurityEvent)

    def test_event_ids_are_unique(self) -> None:
        events = load_events(DATASET_PATH)
        ids = [event.event_id for event in events]
        self.assertEqual(len(ids), len(set(ids)), "duplicate event_id in dataset")

    def test_timestamps_are_utc_aware(self) -> None:
        for event in load_events(DATASET_PATH):
            self.assertIsNotNone(event.timestamp.tzinfo)
            self.assertEqual(event.timestamp.utcoffset(), timezone.utc.utcoffset(None))

    def test_every_category_carries_its_detail_object(self) -> None:
        for event in load_events(DATASET_PATH):
            self.assertIn(event.category, VALID_CATEGORIES)
            self.assertTrue(
                event.details,
                f"{event.event_id} ({event.category}) has an empty "
                f"{REQUIRED_DETAIL_BY_CATEGORY[event.category]} object",
            )

    def test_dataset_covers_all_event_categories(self) -> None:
        """The foundation is only useful if each pipeline path has an example."""
        categories = {event.category for event in load_events(DATASET_PATH)}
        self.assertEqual(categories, set(VALID_CATEGORIES))

    def test_enumerated_fields_are_within_vocabulary(self) -> None:
        for event in load_events(DATASET_PATH):
            self.assertIn(event.severity, VALID_SEVERITIES)
            self.assertIn(event.outcome, VALID_OUTCOMES)


class TestParseTimestamp(unittest.TestCase):
    def test_parses_zulu_suffix(self) -> None:
        parsed = parse_timestamp("2026-09-17T08:00:00Z")
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_converts_offset_to_utc(self) -> None:
        parsed = parse_timestamp("2026-09-17T10:00:00+02:00")
        self.assertEqual(parsed.hour, 8)

    def test_rejects_naive_timestamp(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_timestamp("2026-09-17T08:00:00")

    def test_rejects_garbage(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_timestamp("not-a-timestamp")

    def test_rejects_non_string(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_timestamp(1758096000)  # type: ignore[arg-type]


class TestParseEventRejectsBadInput(unittest.TestCase):
    """Validation is a security control: malformed input must fail loudly."""

    def test_accepts_minimal_valid_event(self) -> None:
        event = parse_event(_valid_event())
        self.assertEqual(event.event_id, "evt-test-0001")
        self.assertEqual(event.details["logon_type"], "network")

    def test_rejects_non_object(self) -> None:
        for bad in ("a string", 42, None, ["list"]):
            with self.subTest(value=bad), self.assertRaises(EventValidationError):
                parse_event(bad)

    def test_rejects_missing_required_field(self) -> None:
        for field_name in (
            "event_id",
            "timestamp",
            "source",
            "category",
            "action",
            "outcome",
            "severity",
            "host",
        ):
            event = _valid_event()
            del event[field_name]
            with self.subTest(missing=field_name):
                with self.assertRaises(EventValidationError) as ctx:
                    parse_event(event)
                self.assertIn(field_name, str(ctx.exception))

    def test_rejects_unknown_category(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(_valid_event(category="telepathy"))

    def test_rejects_unknown_severity(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(_valid_event(severity="apocalyptic"))

    def test_rejects_unknown_outcome(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(_valid_event(outcome="maybe"))

    def test_rejects_empty_string_field(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(_valid_event(action="   "))

    def test_rejects_host_without_hostname(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(_valid_event(host={"ip": "192.0.2.1"}))

    def test_rejects_category_without_matching_detail_object(self) -> None:
        event = _valid_event(category="process")
        # 'auth' is present but a process event must carry 'process'.
        with self.assertRaises(EventValidationError) as ctx:
            parse_event(event)
        self.assertIn("process", str(ctx.exception))

    def test_rejects_oversized_field(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(_valid_event(action="A" * (MAX_FIELD_LENGTH + 1)))

    def test_rejects_oversized_raw(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_event(_valid_event(raw="B" * (MAX_FIELD_LENGTH + 1)))

    def test_error_reports_event_id_when_available(self) -> None:
        with self.assertRaises(EventValidationError) as ctx:
            parse_event(_valid_event(severity="apocalyptic"))
        self.assertEqual(ctx.exception.event_id, "evt-test-0001")


class TestParseEvents(unittest.TestCase):
    def test_parses_batch(self) -> None:
        batch = [_valid_event(), _valid_event(event_id="evt-test-0002")]
        self.assertEqual(len(parse_events(batch)), 2)

    def test_rejects_duplicate_ids(self) -> None:
        batch = [_valid_event(), _valid_event()]
        with self.assertRaises(EventValidationError):
            parse_events(batch)

    def test_rejects_non_list(self) -> None:
        with self.assertRaises(EventValidationError):
            parse_events({"event_id": "evt-test-0001"})

    def test_one_bad_event_fails_the_batch(self) -> None:
        """No silent dropping: a poisoned record must not vanish unnoticed."""
        batch = [_valid_event(), _valid_event(event_id="evt-test-0002", severity="x")]
        with self.assertRaises(EventValidationError):
            parse_events(batch)


class TestLoadEvents(unittest.TestCase):
    def test_rejects_missing_file(self) -> None:
        with self.assertRaises(EventValidationError):
            load_events(REPO_ROOT / "data" / "does_not_exist.json")

    def test_rejects_invalid_json(self, ) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{ not json", encoding="utf-8")
            with self.assertRaises(EventValidationError):
                load_events(bad)

    def test_rejects_unsupported_schema_version(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / "wrong.json"
            wrong.write_text(
                json.dumps({"schema_version": "99.0.0", "events": []}),
                encoding="utf-8",
            )
            with self.assertRaises(EventValidationError):
                load_events(wrong)


class TestUntrustedTextExtraction(unittest.TestCase):
    """Injection screening depends on seeing every attacker-controlled string."""

    def test_yields_nested_strings(self) -> None:
        event = parse_event(_valid_event())
        paths = {path for path, _ in iter_untrusted_text(event)}
        self.assertIn("host.hostname", paths)
        self.assertIn("details.logon_type", paths)
        self.assertIn("raw", paths)

    def test_walks_into_lists(self) -> None:
        event = parse_event(
            _valid_event(
                category="dns",
                auth=None,
                dns={"query_name": "a.test", "resolved_ips": ["198.51.100.1"]},
            )
        )
        values = dict(iter_untrusted_text(event))
        self.assertEqual(values["details.resolved_ips[0]"], "198.51.100.1")

    def test_finds_prompt_injection_payload_in_dataset(self) -> None:
        """evt-0016 carries a deliberate injection string; it must be reachable.

        The parser must accept the event (it is structurally valid) while the
        payload stays visible to a screening step. Content is never trusted.
        """
        events = load_events(DATASET_PATH)
        carriers = [
            event.event_id
            for event in events
            for _, text in iter_untrusted_text(event)
            if "IGNORE ALL PREVIOUS INSTRUCTIONS" in text.upper()
        ]
        self.assertIn("evt-0016", carriers)


class TestNoteworthyFilter(unittest.TestCase):
    def test_high_and_critical_are_noteworthy(self) -> None:
        for severity in ("high", "critical"):
            with self.subTest(severity=severity):
                self.assertTrue(parse_event(_valid_event(severity=severity)).is_noteworthy)

    def test_low_severities_are_not_noteworthy(self) -> None:
        for severity in ("informational", "low", "medium"):
            with self.subTest(severity=severity):
                self.assertFalse(
                    parse_event(_valid_event(severity=severity)).is_noteworthy
                )

    def test_dataset_contains_noteworthy_events(self) -> None:
        events = load_events(DATASET_PATH)
        self.assertTrue(any(event.is_noteworthy for event in events))


if __name__ == "__main__":
    unittest.main(verbosity=2)
