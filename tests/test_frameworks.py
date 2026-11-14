"""Phase 3 batch 1 spec 9.1, 9.2, 11.3 and claims T-50, T-51 (engine half): every rule carries MITRE ATLAS ids or an explicit "no
technique" entry and the OWASP Agentic Skills Top 10 ids the landing page already published; every id exists in the pinned ATLAS
release; the data files, their string constants and the generated documentation say the same."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from frameworks_expected import EXPECTED

from spellwarden_scan import compile_org_rule, frameworks
from spellwarden_scan.frameworks import _data
from spellwarden_scan.rules import ALLOWED_NIST, ALLOWED_OWASP, RuleSet, make_rule

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "spellwarden_scan" / "frameworks"
SCRIPT = ROOT / "scripts" / "frameworks" / "build_atlas_scope.py"
RULES = RuleSet.baseline()


def _text(name: str) -> str:
    return (PACKAGE / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _script():
    spec = importlib.util.spec_from_file_location("build_atlas_scope", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_string_constants_are_the_json_files():
    # the engine reads no files (tests/test_pure.py), so each JSON file of the package is also a constant of `_data.py`
    assert _data.ATLAS_TECHNIQUES_JSON == _text("atlas_techniques.json")
    assert _data.ATLAS_SCOPE_JSON == _text("atlas_scope.json")
    assert _data.FRAMEWORKS_JSON == _text("frameworks.json")


def test_the_pinned_atlas_release_is_2026_10():
    assert (frameworks.ATLAS_VERSION, frameworks.ATLAS_FORMAT_VERSION, frameworks.ATLAS_MODIFIED) == ("2026.10", "6.1.0", "2026-10-28")
    assert len(frameworks.ATLAS_TECHNIQUES) == 221
    assert frameworks.ATLAS_TECHNIQUES["AML.T0051.001"] == "LLM Prompt Injection: Indirect"
    assert frameworks.ATLAS_TECHNIQUES["AML.T0010.005"] == "Supply Chain Compromise: AI Agent Tool"
    assert frameworks.ATLAS_TECHNIQUES["AML.T0053"] == "AI Agent Tool Invocation"
    assert frameworks.FRAMEWORKS["atlas"].version == frameworks.ATLAS_VERSION


def test_the_agentic_skills_top_10_is_labelled_an_incubator_project_under_public_review():
    ast = frameworks.FRAMEWORKS["owasp_ast"]
    assert (frameworks.AST_VERSION, frameworks.AST_STATUS) == ("1.0 (2026 edition)", "incubator project under public review")
    assert (ast.version, ast.status) == (frameworks.AST_VERSION, frameworks.AST_STATUS)
    assert [item.id for item in ast.items] == [f"AST{number:02d}" for number in range(1, 11)]
    assert ast.items[0].name == "Malicious Skills" and ast.items[9].name == "Cross-Platform Reuse"
    assert frameworks.FRAMEWORKS["atlas"].status is None and frameworks.FRAMEWORKS["nist"].status is None


def test_the_frameworks_list_every_identifier_a_rule_may_use():
    listed = {key: {item.id for item in framework.items} for key, framework in frameworks.FRAMEWORKS.items()}
    assert list(frameworks.FRAMEWORKS) == ["owasp_agentic", "owasp_mcp", "nist", "atlas", "owasp_ast"]
    assert {identifier for identifier in ALLOWED_OWASP if identifier.startswith("ASI")} <= listed["owasp_agentic"]
    assert {identifier for identifier in ALLOWED_OWASP if identifier.startswith("MCP")} <= listed["owasp_mcp"]
    assert set(ALLOWED_NIST) <= listed["nist"]
    assert len(listed["owasp_agentic"]) == len(listed["owasp_mcp"]) == 10
    assert all(framework.url.startswith("https://") and framework.name and framework.version for framework in frameworks.FRAMEWORKS.values())


def test_every_rule_has_atlas_ids_or_a_no_technique_entry_never_both_never_neither():
    assert len(RULES) == 65
    without = {rule.id for rule in RULES if not rule.atlas}
    assert without == set(frameworks.NO_ATLAS)
    assert all(frameworks.NO_ATLAS[rule_id].strip() for rule_id in without)
    assert len(without) == 21


def test_every_id_exists_in_the_pinned_release_and_every_ast_id_is_ast01_to_ast10():
    for rule in RULES:
        assert all(identifier in frameworks.ATLAS_TECHNIQUES for identifier in rule.atlas), rule.id
        assert all(identifier in frameworks.AST_IDS for identifier in rule.owasp_ast), rule.id
        assert len(set(rule.atlas)) == len(rule.atlas) and len(set(rule.owasp_ast)) == len(rule.owasp_ast), rule.id


def test_the_rules_carry_exactly_the_reviewed_tags():
    assert set(EXPECTED) == {rule.id for rule in RULES}
    for rule in RULES:
        assert (rule.atlas, rule.owasp_ast) == EXPECTED[rule.id], rule.id


def test_the_ast_column_is_the_mapping_the_landing_page_published():
    """Spec 9.2: carried over row for row from the public AST page, so that page does not change when the tags arrive."""
    by_ast: dict[str, set[str]] = {}
    for rule in RULES:
        for identifier in rule.owasp_ast:
            by_ast.setdefault(identifier, set()).add(rule.id)
    assert by_ast == {
        "AST01": {"SW-SKL-004", "SW-SKL-008", "SW-SKL-032"},
        "AST02": {"SW-SKL-007", "SW-SKL-009", "SW-SKL-010", "SW-SKL-037", "SW-CFG-003", "SW-CFG-009"},
        "AST03": {"SW-SKL-036", "SW-SKL-003", "SW-SKL-005"},
        "AST04": {"SW-SKL-015", "SW-SKL-031"},
        "AST05": {"SW-SKL-001", "SW-SKL-002", "SW-SKL-019"},
        "AST07": {"SW-SKL-009", "SW-SKL-037", "SW-CFG-003", "SW-CFG-009"},
        "AST09": {"SW-REG-001", "SW-REG-002", "SW-REG-003"},
    }


def test_the_scope_list_holds_every_agent_technique_and_every_id_a_rule_uses():
    scope = json.loads(_text("atlas_scope.json"))
    ids = scope["ids"]
    used = {identifier for rule in RULES for identifier in rule.atlas}
    assert scope["release"] == frameworks.ATLAS_VERSION and ids == sorted(set(ids))
    assert used <= set(ids) and set(ids) <= set(frameworks.ATLAS_TECHNIQUES)
    assert all("Agent" in frameworks.ATLAS_TECHNIQUES[i] for i in set(ids) - used)
    assert [item.id for item in frameworks.FRAMEWORKS["atlas"].items] == ids


@pytest.mark.skipif(not SCRIPT.exists(), reason="the builder script is not in an sdist")
def test_the_scope_file_the_data_module_and_the_documentation_are_what_the_script_writes():
    module = _script()
    document = json.loads(_text("atlas_techniques.json"))
    assert module.scope_text(document, module.used_ids()) == _text("atlas_scope.json")
    assert module.data_text() == (PACKAGE / "_data.py").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert module.docs_text() == (ROOT / "docs" / "frameworks.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert module.run_check() == 0


def test_make_rule_needs_atlas_and_checks_the_ids():
    def build(**more):
        return make_rule("SW-CFG-999", "t", "low", "config", owasp=(), nist=(), detect=lambda _: iter(()), **more)

    with pytest.raises(TypeError):
        build()
    assert build(atlas=()).atlas == () and build(atlas=()).owasp_ast == ()
    with pytest.raises(ValueError, match="AML.T9999"):
        build(atlas=("AML.T9999",))
    with pytest.raises(ValueError, match="AST11"):
        build(atlas=(), owasp_ast=("AST11",))
    rule = build(atlas=("AML.T0053",), owasp_ast=("AST03",))
    assert (rule.atlas, rule.owasp_ast) == (("AML.T0053",), ("AST03",))
    assert rule.to_dict()["atlas"] == ["AML.T0053"] and rule.to_dict()["owasp_ast"] == ["AST03"]


def test_an_organisation_rule_carries_no_atlas_or_ast_id():
    rule = compile_org_rule({"id": "SW-ORG-001", "title": "Org pattern", "severity": "high", "area": "skill",
                             "detection": {"kind": "pattern", "pattern": "needle"}})
    assert (rule.atlas, rule.owasp_ast) == ((), ())
    assert rule.to_dict()["atlas"] == [] and rule.to_dict()["owasp_ast"] == []
