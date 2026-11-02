"""Invariant 4 of rule growth: a batch only adds. The nine rules of 1.8.0 fire on no existing skill fixture, probe
fixture, sample server, config fixture or the 1.0.0 golden repository, so everything recorded before them reads the same."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from conftest import _RUNNER_VARIABLES, CONFIG_FIXTURES, PROBE_FIXTURES, config_documents, load_probe_fixture
from golden_record import entries

from spellwarden_scan import scan_agent_config
from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import RuleSet

ROOT = Path(__file__).resolve().parents[1]
BASELINE = RuleSet.baseline()

RULES_OF_1_7_1 = frozenset({
    "SW-A2A-001", "SW-A2A-002", "SW-A2A-003", "SW-A2A-004", "SW-A2A-005", "SW-A2A-006", "SW-A2A-007", "SW-A2A-008",
    "SW-A2A-009", "SW-A2A-010", "SW-A2A-011", "SW-A2A-012", "SW-A2A-013", "SW-A2A-014", "SW-A2A-015", "SW-A2A-016",
    "SW-A2A-017", "SW-A2A-018", "SW-A2A-019",
    "SW-CFG-001", "SW-CFG-002", "SW-CFG-003", "SW-CFG-004", "SW-CFG-005", "SW-CFG-006", "SW-CFG-007", "SW-CFG-008",
    "SW-CFG-009", "SW-CFG-010",
    "SW-MCP-001", "SW-MCP-002", "SW-MCP-003", "SW-MCP-004", "SW-MCP-005", "SW-MCP-006", "SW-MCP-007", "SW-MCP-008",
    "SW-MCP-009", "SW-MCP-010", "SW-MCP-011",
    "SW-REG-001", "SW-REG-002", "SW-REG-003",
    "SW-SKL-001", "SW-SKL-002", "SW-SKL-003", "SW-SKL-004", "SW-SKL-005", "SW-SKL-006", "SW-SKL-007", "SW-SKL-008",
    "SW-SKL-009", "SW-SKL-010", "SW-SKL-011", "SW-SKL-012", "SW-SKL-013", "SW-SKL-014", "SW-SKL-015", "SW-SKL-019",
    "SW-SKL-031",
})
NEW_IDS = frozenset(rule.id for rule in BASELINE) - RULES_OF_1_7_1


def test_the_batch_is_exactly_the_nine_new_ids():
    assert len(RULES_OF_1_7_1) == 60
    assert RULES_OF_1_7_1 <= {rule.id for rule in BASELINE}
    assert NEW_IDS == {f"SW-SKL-{n:03d}" for n in range(32, 38)} | {f"SW-CFG-{n:03d}" for n in range(12, 15)}


def test_no_existing_skill_or_probe_fixture_holds_a_finding_of_a_new_rule():
    rows = entries(exclude_rules=NEW_IDS)
    assert rows and not [row for row in rows if row["rule_id"] in NEW_IDS]


def test_no_existing_config_fixture_yields_a_finding_of_a_new_rule():
    directories = [d for d in sorted(CONFIG_FIXTURES.glob("*/*")) if d.parent.name not in NEW_IDS and d.is_dir()]
    assert any(d.parent.name == "plugins-settings" for d in directories)
    for directory in directories:
        files = {p.relative_to(directory).as_posix(): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
        found = {f.rule_id for f in scan_agent_config(config_documents(files), BASELINE).findings}
        assert not found & NEW_IDS, (directory.relative_to(CONFIG_FIXTURES).as_posix(), sorted(found & NEW_IDS))


def test_no_sample_server_yields_a_finding_of_a_new_rule():
    samples = sorted((PROBE_FIXTURES / "samples").glob("*.json"))
    assert len(samples) >= 14
    for path in samples:
        probe, _expected = load_probe_fixture(f"samples/{path.stem}")
        found = {f.rule_id for f in evaluate_probe(probe, BASELINE).findings}
        assert not found & NEW_IDS, (path.name, sorted(found & NEW_IDS))


@pytest.fixture(scope="module")
def golden_sarif(tmp_path_factory):
    spec = importlib.util.spec_from_file_location("record_1_0_0", ROOT / "tests" / "golden" / "record_1_0_0.py")
    record = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(record)
    base = tmp_path_factory.mktemp("isolation")
    out = base / "out"
    out.mkdir()
    with pytest.MonkeyPatch.context() as patch:  # a module-scoped fixture runs before the autouse one that clears these
        for name in _RUNNER_VARIABLES:
            patch.delenv(name, raising=False)
        record.scan(record.build_repo(base / "repo"), out)
    return json.loads((out / "report.sarif").read_text(encoding="utf-8"))


def test_the_sarif_of_the_1_0_0_golden_repository_holds_no_result_of_a_new_rule(golden_sarif):
    results = golden_sarif["runs"][0]["results"]
    assert results and not [r for r in results if r["ruleId"] in NEW_IDS]
