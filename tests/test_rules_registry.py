"""O3 spec 5.2, 5.3, 7 and claim E2: the registry area holds three gate rules that no engine entry point evaluates,
the rule-id grammar names SW-REG and SW-ORG, and 1.2.0 carries its versions."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest
from conftest import CONFIG_FIXTURES, FIXTURES, config_documents, load_skill_fixture

from spellwarden_scan import RULES_VERSION, RuleSet, __version__, evaluate_probe, scan_agent_config, scan_skill_package
from spellwarden_scan.model import ProbeResult
from spellwarden_scan.orgrules import PATTERN_KEYS, PATTERN_PREDICATES, PROBE_PREDICATES, SPEC_KEYS
from spellwarden_scan.packs import PREDICATE_SINCE, org_rule_min_version
from spellwarden_scan.rules import AREAS, RULE_ID_RE, make_rule
from spellwarden_scan.rules import registry

BASELINE = RuleSet.baseline()
REG_IDS = ("SW-REG-001", "SW-REG-002", "SW-REG-003")


def test_baseline_has_41_rules_three_in_area_registry_severity_high():
    assert len(BASELINE) == 41
    rules = BASELINE.by_area("registry")
    assert tuple(rule.id for rule in rules) == REG_IDS
    assert {rule.severity_default for rule in rules} == {"high"}
    assert AREAS == ("skill", "mcp", "config", "registry")
    assert not [rule for rule in rules if rule.targets or rule.malicious_indicator]


def test_registry_rules_have_the_spec_titles_and_tags():
    table = {rule.id: (rule.title, rule.owasp_agentic + rule.owasp_mcp, rule.nist) for rule in registry.RULES}
    assert table == {
        "SW-REG-001": ("Skill package not admitted in the organisation's private registry", ("ASI04",), ("SR-3",)),
        "SW-REG-002": ("MCP server not admitted in the organisation's private registry", ("MCP10",), ("SR-3",)),
        "SW-REG-003": ("Agent content the private registry cannot judge", ("ASI04",), ("SR-3",)),
    }


def test_registry_rules_detect_nothing():
    for rule in registry.RULES:
        assert tuple(rule.detect(object())) == ()


def test_no_engine_entry_point_emits_an_sw_reg_id_on_any_fixture():
    emitted: set[str] = set()
    for directory in sorted((FIXTURES / "skills").glob("*/*")) if (FIXTURES / "skills").is_dir() else []:
        files, _expected = load_skill_fixture(directory.parent.name, directory.name)
        emitted |= {f.rule_id for f in scan_skill_package(files, BASELINE).findings}
    for path in sorted((FIXTURES / "probes").rglob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "probe" in document:
            emitted |= {f.rule_id for f in evaluate_probe(ProbeResult.from_dict(document["probe"]), BASELINE).findings}
    for directory in sorted(CONFIG_FIXTURES.glob("*/*")):
        files = {p.relative_to(directory).as_posix(): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
        emitted |= {f.rule_id for f in scan_agent_config(config_documents(files), BASELINE).findings}
    assert emitted and not {rule_id for rule_id in emitted if rule_id.startswith("SW-REG-")}


def test_rule_id_re_accepts_reg_and_org_and_refuses_xyz():
    assert RULE_ID_RE.pattern == r"^SW-(SKL|MCP|CFG|REG|ORG)-[0-9]{3}$"
    for good in ("SW-REG-001", "SW-ORG-123", "SW-SKL-007"):
        assert RULE_ID_RE.match(good)
    for bad in ("SW-XYZ-001", "SW-REG-01", "SW-REG-0001", "sw-reg-001"):
        assert RULE_ID_RE.match(bad) is None, bad


def test_make_rule_still_refuses_sw_org():
    with pytest.raises(ValueError):
        make_rule("SW-ORG-001", "x", "high", "registry", owasp=(), nist=(), detect=lambda _: ())
    make_rule("SW-REG-009", "x", "high", "registry", owasp=(), nist=(), detect=lambda _: ())


def test_versions_are_1_3_0_and_2026_10_3():
    assert (__version__, RULES_VERSION) == ("1.3.0", "2026.10.3")
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    assert tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"] == __version__


def test_predicate_since_covers_every_orgrules_name():
    names = set(PROBE_PREDICATES) | set(PATTERN_PREDICATES) | set(SPEC_KEYS) | set(PATTERN_KEYS)
    assert set(PREDICATE_SINCE) >= names
    assert set(PREDICATE_SINCE.values()) == {"1.1.0"}


def test_org_rule_min_version_is_1_1_0_for_every_valid_fixture():
    paths = sorted((FIXTURES / "orgrules" / "valid").glob("*.json"))
    assert paths
    for path in paths:
        assert org_rule_min_version(json.loads(path.read_text(encoding="utf-8"))) == "1.1.0", path.name


def test_org_rule_min_version_is_the_maximum_over_the_names_a_spec_uses(monkeypatch):
    spec = json.loads((FIXTURES / "orgrules" / "valid" / "probe-auth.json").read_text(encoding="utf-8"))
    monkeypatch.setitem(PREDICATE_SINCE, "auth_mode_in", "1.3.0")
    assert org_rule_min_version(spec) == "1.3.0"
    monkeypatch.setitem(PREDICATE_SINCE, "severity", "1.10.0")
    assert org_rule_min_version(spec) == "1.10.0"  # numeric, not lexical
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", org_rule_min_version({}))
