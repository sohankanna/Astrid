"""Sigma rule metadata validation.

Runs entirely offline: no SIEM, no `pysigma`, no network. It validates the
YAML's structure and its agreement with the Python detection engine, not its
behavior against real logs.

PyYAML is present in this environment. If it ever is not, the suite skips
rather than failing, so a missing optional dependency cannot look like a
detection regression.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "security" / "detection_rules"
sys.path.insert(0, str(REPO_ROOT / "app"))

from soc_core.detections import default_rules  # noqa: E402
from soc_core.mitre import is_known_technique  # noqa: E402

try:
    import yaml

    HAVE_YAML = True
except ImportError:  # pragma: no cover - environment dependent
    HAVE_YAML = False

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
REQUIRED_KEYS = {"title", "id", "status", "description", "logsource", "detection", "level"}


def rule_files() -> list[Path]:
    return sorted(RULES_DIR.glob("*.yml"))


def load_rule(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@unittest.skipUnless(HAVE_YAML, "PyYAML not available")
class TestSigmaRuleMetadata(unittest.TestCase):
    def test_rules_directory_exists(self) -> None:
        self.assertTrue(RULES_DIR.is_dir())

    def test_has_expected_rule_count(self) -> None:
        self.assertGreaterEqual(len(rule_files()), 3)
        self.assertLessEqual(len(rule_files()), 5)

    def test_each_rule_is_valid_yaml_mapping(self) -> None:
        for path in rule_files():
            with self.subTest(rule=path.name):
                self.assertIsInstance(load_rule(path), dict)

    def test_required_keys_present(self) -> None:
        for path in rule_files():
            with self.subTest(rule=path.name):
                missing = REQUIRED_KEYS - set(load_rule(path))
                self.assertFalse(missing, f"{path.name} missing {missing}")

    def test_ids_are_unique(self) -> None:
        ids = [load_rule(path)["id"] for path in rule_files()]
        self.assertEqual(len(ids), len(set(ids)), "duplicate Sigma rule id")

    def test_levels_are_valid(self) -> None:
        for path in rule_files():
            with self.subTest(rule=path.name):
                self.assertIn(load_rule(path)["level"], VALID_LEVELS)

    def test_statuses_are_valid(self) -> None:
        for path in rule_files():
            with self.subTest(rule=path.name):
                self.assertIn(load_rule(path)["status"], VALID_STATUSES)

    def test_detection_has_a_condition(self) -> None:
        for path in rule_files():
            with self.subTest(rule=path.name):
                self.assertIn("condition", load_rule(path)["detection"])

    def test_falsepositives_are_documented(self) -> None:
        """A rule with no considered false positives is not analyst-ready."""
        for path in rule_files():
            with self.subTest(rule=path.name):
                false_positives = load_rule(path).get("falsepositives")
                self.assertTrue(
                    false_positives, f"{path.name} documents no false positives"
                )

    def test_attack_tags_resolve_to_pinned_catalog(self) -> None:
        """A tag naming a technique we do not model is a silent coverage gap."""
        for path in rule_files():
            rule = load_rule(path)
            for tag in rule.get("tags", []):
                if not tag.startswith("attack.t"):
                    continue
                technique_id = tag.split(".", 1)[1].upper()
                with self.subTest(rule=path.name, tag=tag):
                    self.assertTrue(
                        is_known_technique(technique_id),
                        f"{path.name}: {technique_id} not in the pinned ATT&CK catalog",
                    )

    def test_internal_rule_ids_match_python_engine(self) -> None:
        engine_ids = {rule.rule_id for rule in default_rules()}
        for path in rule_files():
            rule = load_rule(path)
            internal_id = rule.get("internal_rule_id")
            with self.subTest(rule=path.name):
                self.assertIsNotNone(internal_id, f"{path.name} has no internal_rule_id")
                self.assertIn(
                    internal_id,
                    engine_ids,
                    f"{path.name} references unknown Python rule {internal_id}",
                )

    def test_sigma_level_matches_python_severity(self) -> None:
        """Divergent severities would mean the two definitions have drifted."""
        by_id = {rule.rule_id: rule for rule in default_rules()}
        for path in rule_files():
            rule = load_rule(path)
            python_rule = by_id.get(rule.get("internal_rule_id"))
            if python_rule is None:
                continue
            with self.subTest(rule=path.name):
                self.assertEqual(
                    rule["level"],
                    python_rule.severity,
                    f"{path.name}: Sigma level {rule['level']} != Python severity "
                    f"{python_rule.severity}",
                )

    def test_python_rules_reference_existing_sigma_files(self) -> None:
        """A `sigma_rule` pointer to a missing file is a broken cross-reference."""
        existing = {path.name for path in rule_files()}
        for rule in default_rules():
            if rule.sigma_rule is None:
                continue
            with self.subTest(rule=rule.rule_id):
                if rule.sigma_rule in existing:
                    continue
                # Documented gaps are allowed, but only for the rules the
                # README explains -- entropy and windowed aggregation.
                self.assertIn(
                    rule.rule_id,
                    {"SOC-EXEC-001", "SOC-DNS-001", "SOC-NET-001"},
                    f"{rule.rule_id} points at missing Sigma file {rule.sigma_rule}",
                )

    def test_readme_exists_and_indexes_every_rule(self) -> None:
        readme = RULES_DIR / "README.md"
        self.assertTrue(readme.is_file())
        text = readme.read_text(encoding="utf-8")
        for path in rule_files():
            with self.subTest(rule=path.name):
                self.assertIn(path.name, text, f"{path.name} not indexed in README")

    def test_rules_use_documentation_addresses_only(self) -> None:
        """Nothing in the repo may reference real infrastructure."""
        import re

        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        allowed_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.", "0.0.0.", "127.0.0.")
        for path in rule_files():
            text = path.read_text(encoding="utf-8")
            for address in ip_pattern.findall(text):
                with self.subTest(rule=path.name, address=address):
                    self.assertTrue(
                        address.startswith(allowed_prefixes),
                        f"{path.name} contains non-documentation IP {address}",
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
