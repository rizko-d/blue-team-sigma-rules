"""
Detection-as-Code test harness — validates Sigma rules against TP/TN log fixtures.

Each fixture is a JSON file containing:
  - rule_id: the UUID of the Sigma rule to test
  - expected: true (should fire) or false (should not fire)
  - log: the log event fields
  - title: human-readable description
"""
import json
import os
import yaml
import pytest
from pathlib import Path

from test_harness.matcher import evaluate_rule_against_log

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def discover_fixtures():
    """Return list of (fixture_path, rule_path) tuples."""
    fixtures = []
    for root, dirs, files in os.walk(FIXTURES_DIR):
        for f in sorted(files):
            if f.endswith(".json"):
                fp = os.path.join(root, f)
                fixtures.append(fp)
    return fixtures


def build_rule_index():
    """Build UUID -> rule dict lookup."""
    index = {}
    for root, dirs, files in os.walk(RULES_DIR):
        for f in files:
            if not f.endswith((".yml", ".yaml")):
                continue
            with open(os.path.join(root, f)) as fh:
                rule = yaml.safe_load(fh)
            uid = rule.get("id")
            if uid:
                index[uid] = rule
    return index


RULE_INDEX = build_rule_index()
ALL_FIXTURES = discover_fixtures()


@pytest.mark.detection
@pytest.mark.parametrize("fixture_path", ALL_FIXTURES)
def test_rule_against_fixture(fixture_path):
    with open(fixture_path) as f:
        fixture = json.load(f)

    rule_id = fixture.get("rule_id")
    expected = fixture.get("expected")
    log = fixture.get("log", {})
    title = fixture.get("title", fixture_path)

    rule = RULE_INDEX.get(rule_id)
    assert rule is not None, f"Rule not found: {rule_id} (fixture: {fixture_path})"

    result = evaluate_rule_against_log(rule, log)

    status = "FIRED" if result else "SILENT"
    expect_str = "should FIRE" if expected else "should be SILENT"
    msg = f"{title}: rule={status} {expect_str}"

    assert result == expected, msg
