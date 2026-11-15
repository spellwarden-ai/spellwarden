"""1.15.0: the ToolHive export (claim T-12 of phase 3 batch 2b spec, T-16 for its coverage). The authorization file has the shape
ToolHive v0.65.0 documents, and Cedar's reference implementation (`cedarpy`, a test dependency) evaluates its policies for
`call_tool` requests built as ToolHive builds them: a `Tool` entity whose `name` attribute is the tool's name. ToolHive itself
runs the export in the release workflow's `gateway-exports` job (T-13)."""
from __future__ import annotations

import dataclasses
import hashlib
import json

import cedarpy
import pytest
from gateway_support import corpus, destructive_rule

from spellwarden_scan import baseline_pack
from spellwarden_scan.exports import CANNOT_ENFORCE, EXPORT_TARGETS, README_NAME, TARGET_NAMES, VENDOR_LINE, build, coverage
from spellwarden_scan.exports import toolhive as T
from spellwarden_scan.exports.hooks import MCP_VERBS
from spellwarden_scan.packs import ENFORCEMENT_IDS

BUILT = "2026-12-01T10:00:00Z"


def export(doc=None) -> dict[str, bytes]:
    return build(doc or baseline_pack(), "toolhive", built_at=BUILT)


def without(rule_id: str):
    doc = baseline_pack()
    return dataclasses.replace(doc, rules=tuple((rid, False if rid == rule_id else on) for rid, on in doc.rules))


def authz(doc=None) -> dict:
    return json.loads(export(doc)[T.AUTHZ_PATH])


def decision(policies: list[str], action: str, tool: str) -> str:
    entity_type = {"call_tool": "Tool", "get_prompt": "Prompt", "read_resource": "Resource"}[action]
    request = {"principal": 'Client::"agent"', "action": f'Action::"{action}"', "resource": f'{entity_type}::{json.dumps(tool)}',
               "context": {}}
    entities = [{"uid": {"type": entity_type, "id": tool}, "attrs": {"name": tool}, "parents": []}]
    result = cedarpy.is_authorized(request, "\n".join(policies), entities)
    assert result.diagnostics.errors == [], result.diagnostics.errors
    return "deny" if result.decision == cedarpy.Decision.Deny else "allow"


destructive = destructive_rule()


# --- the file ------------------------------------------------------------------------------------------------------------

def test_the_target_is_registered_with_its_name():
    assert "toolhive" in EXPORT_TARGETS and TARGET_NAMES["toolhive"] == "ToolHive"
    assert (T.GATEWAY, T.GATEWAY_VERSION) == ("ToolHive", "v0.65.0")


def test_the_export_has_three_files_and_sums_that_match():
    files = export()
    assert set(files) == {T.AUTHZ_PATH, README_NAME, T.SUMS_NAME}
    lines = files[T.SUMS_NAME].decode("ascii").splitlines()
    assert lines == [f"{hashlib.sha256(files[path]).hexdigest()}  {path}" for path in sorted((T.AUTHZ_PATH, README_NAME))]


def test_the_file_has_the_documented_shape():
    document = authz()
    assert set(document) == {"version", "type", "cedar"}
    assert (document["version"], document["type"]) == ("1.0", "cedarv1")
    assert set(document["cedar"]) == {"policies", "entities_json"} and document["cedar"]["entities_json"] == "[]"
    policies = document["cedar"]["policies"]
    assert policies[0] == T.ALLOW_REST and len(policies) == 1 + len(MCP_VERBS)
    assert [p.split('"')[1] for p in policies[1:]] == [f"SW-GW-006:{verb}" for verb in MCP_VERBS]
    assert all(len(policy.encode("utf-8")) < T.MAX_POLICY_BYTES for policy in policies)
    cedarpy.format_policies("\n".join(policies))  # parses


def test_the_export_is_deterministic_and_ascii():
    assert export() == export()
    for content in export().values():
        content.decode("ascii")


# --- T-12: Cedar evaluates it --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("spelling", [str.lower, str.capitalize, str.upper], ids=["lower", "Capitalised", "UPPER"])
def test_every_name_mcp_verb_denies_is_denied_and_every_other_allowed(spelling):
    policies = authz()["cedar"]["policies"]
    for name in corpus(spelling):
        expected = "deny" if destructive(name) else "allow"
        assert decision(policies, "call_tool", name) == expected, name


def test_a_mixed_case_spelling_is_the_stated_limit():
    policies = authz()["cedar"]["policies"]
    assert destructive("dElete_row") and decision(policies, "call_tool", "dElete_row") == "allow"
    assert "dElete_row is not" in export()[README_NAME].decode("ascii")


def test_prompts_and_resources_pass():
    policies = authz()["cedar"]["policies"]
    assert decision(policies, "get_prompt", "delete_everything") == "allow"
    assert decision(policies, "read_resource", "delete_order") == "allow"


def test_with_sw_gw_006_off_only_the_permit_remains():
    doc = without("SW-GW-006")
    assert authz(doc)["cedar"]["policies"] == [T.ALLOW_REST]
    assert decision([T.ALLOW_REST], "call_tool", "delete_order") == "allow"
    readme = export(doc)[README_NAME].decode("ascii")
    assert "Nothing is enforced" in readme and "SW-GW-006" in readme.split("## Not included")[1]


# --- coverage and the README (T-16) --------------------------------------------------------------------------------------

def test_coverage_of_the_baseline():
    enforced, cannot, not_included = coverage(baseline_pack(), "toolhive")
    assert enforced == ["SW-GW-006 (denied: the gateway cannot ask a person)"]
    assert [rule_id for rule_id, _ in cannot] == [i for i in ENFORCEMENT_IDS if i != "SW-GW-006"]
    assert not_included == []
    assert CANNOT_ENFORCE[("SW-GW-004", "toolhive")] == "the authorization file decides on requests, not on tool results"


def test_the_readme_names_the_version_the_install_and_ends_with_the_tagged_guide():
    readme = export()[README_NAME].decode("ascii")
    assert "ToolHive v0.65.0" in readme and "thv run --authz-config" in readme and VENDOR_LINE in readme
    assert "copy the forbid policies of this file" in readme
    assert readme.rstrip("\n").splitlines()[-1] == f"Guide: {T.GUIDE}"
    assert T.GUIDE == ("https://spellwarden.ai/docs/export-toolhive?utm_source=export&utm_medium=toolhive"
                       "&utm_campaign=policy-export")
    assert "!" not in readme and "\u2014" not in readme and "\u2013" not in readme


@pytest.mark.parametrize("name", ['Pack "quoted"', "Line\u2028break? no: unicode été", "<script>x</script>"])
def test_pack_names_reach_only_the_readme_through_comment_safe(name):
    doc = dataclasses.replace(baseline_pack(), name=name)
    files = export(doc)
    assert files[T.AUTHZ_PATH] == export()[T.AUTHZ_PATH]
    files[README_NAME].decode("ascii")
