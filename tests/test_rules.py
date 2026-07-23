"""
Unit tests for Sigma Rules Pack.
Validates syntax, required fields, MITRE tag coverage, and rule structure.
"""

import os
import re
import yaml
import pytest

RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules')

def discover_rules():
    """Find all Sigma rule YAML files."""
    rules = []
    for root, dirs, files in os.walk(RULES_DIR):
        for f in files:
            if f.endswith(('.yml', '.yaml')):
                rules.append(os.path.join(root, f))
    return rules

ALL_RULES = discover_rules()


class TestRuleSyntax:
    """Validate YAML syntax for every rule."""
    
    @pytest.mark.parametrize('rule_path', ALL_RULES)
    def test_valid_yaml(self, rule_path):
        with open(rule_path) as f:
            yaml.safe_load(f)
    
    @pytest.mark.parametrize('rule_path', ALL_RULES)
    def test_required_fields(self, rule_path):
        required = ['title', 'id', 'status', 'description', 'logsource', 'detection', 'level']
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        for field in required:
            assert field in rule, f"Missing required field: {field}"
    
    @pytest.mark.parametrize('rule_path', ALL_RULES)
    def test_valid_id(self, rule_path):
        uuid_re = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        assert uuid_re.match(rule['id']), f"Invalid UUID: {rule['id']}"
    
    @pytest.mark.parametrize('rule_path', ALL_RULES)
    def test_valid_level(self, rule_path):
        valid_levels = {'informational', 'low', 'medium', 'high', 'critical'}
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        assert rule['level'] in valid_levels, f"Invalid level: {rule['level']}"
    
    @pytest.mark.parametrize('rule_path', ALL_RULES)
    def test_has_detection_condition(self, rule_path):
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        assert 'condition' in rule['detection'], "Missing detection condition"
    
    @pytest.mark.parametrize('rule_path', ALL_RULES)
    def test_has_mitre_tags(self, rule_path):
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        has_attack = any(tag.startswith('attack.') for tag in rule.get('tags', []))
        assert has_attack, "Missing MITRE ATT&CK tags"
    
    @pytest.mark.parametrize('rule_path', ALL_RULES)
    def test_logsource_valid(self, rule_path):
        valid_products = {'windows', 'linux', 'macos', 'office365', 'azure', 'aws', 'gcp', 'kubernetes'}
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        product = rule['logsource'].get('product', '')
        assert product in valid_products, f"Unknown product: {product}"


class TestTacticCoverage:
    """Ensure coverage across all MITRE tactics."""
    
    EXPECTED_TACTICS = {
        'attack.initial-access',
        'attack.execution',
        'attack.persistence',
        'attack.privilege-escalation',
        'attack.defense-evasion',
        'attack.credential-access',
        'attack.discovery',
        'attack.lateral-movement',
        'attack.collection',
        'attack.command-and-control',
        'attack.exfiltration',
        'attack.impact',
    }
    
    def test_tactic_coverage(self):
        covered = set()
        for rule_path in ALL_RULES:
            with open(rule_path) as f:
                rule = yaml.safe_load(f)
            for tag in rule.get('tags', []):
                if tag in self.EXPECTED_TACTICS:
                    covered.add(tag)
        
        missing = self.EXPECTED_TACTICS - covered
        assert not missing, f"Missing tactic coverage: {missing}"
    
    def test_minimum_rule_count(self):
        assert len(ALL_RULES) >= 20, f"Expected >=20 rules, got {len(ALL_RULES)}"
