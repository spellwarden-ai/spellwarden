"""SW-MCP-013: a tool takes a command line to run as an argument (P6-9 spec 8.3, claims 9 to 14). The module's `detect` is called
directly; tests/test_p6_9_registered.py reads the registered rule through `evaluate_probe`."""
from __future__ import annotations

import ast
import inspect

import pytest

from spellwarden_scan import ProbeResult, RuleSet, evaluate_probe
from spellwarden_scan.model import PromptInfo, ResourceInfo, ToolInfo
from spellwarden_scan.rules import growth_mcp_013
from spellwarden_scan.rules.growth_mcp_013 import (
    ATLAS, MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, _PER_SERVER, detect,
)


def schema(parameter: str = "command", **prop) -> dict:
    return {"type": "object", "properties": {parameter: {"type": "string", **prop}}, "required": [parameter]}


def tool(name: str = "run_command", text: str = "Runs a command.", parameter: str = "command", **prop) -> ToolInfo:
    """A tool with the description `text`; `prop` (for example `description=`) goes to the parameter's own schema."""
    return ToolInfo(name, text, {}, schema(parameter, **prop))


def probe(*tools: ToolInfo, **more) -> ProbeResult:
    return ProbeResult(endpoint="https://mcp.example/mcp", reachable=True, tools=tuple(tools), tools_source="probe", **more)


def at(findings) -> list[str]:
    return [finding.location.path for finding in findings]


def test_module_constants():
    assert (RULE_ID, TITLE, SEVERITY) == ("SW-MCP-013", "Tool takes a command line to run as an argument", "medium")
    assert OWASP == ("MCP05", "ASI05") and NIST == ("SI-10",) and ATLAS == ("AML.T0053",) and MALICIOUS is False
    assert _PER_SERVER == 25


def test_module_imports_no_rule_module():
    tree = ast.parse(inspect.getsource(growth_mcp_013))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not {"spellwarden_scan.rules.mcp", "spellwarden_scan.rules.skill", "spellwarden_scan.rules.config"} & imported


# --- claim 9: it fires once per tool --------------------------------------------------------------------------------------

@pytest.mark.parametrize("parameter", ("command", "cmd", "commandLine", "shell_command", "bash", "command-line", "PowerShellCommand", "shell"))
def test_each_command_parameter_spelling_fires(parameter):
    findings = list(detect(probe(tool(parameter=parameter))))
    assert at(findings) == ["tool:run_command"]
    first = findings[0]
    assert (first.rule_id, first.severity, first.title, first.malicious_indicator) == (RULE_ID, "medium", TITLE, False)
    assert first.location.line is None and len(first.fingerprint) == 64


def test_an_execution_word_may_stand_in_the_name_the_description_or_the_property():
    assert at(detect(probe(tool("bash", "Does things.")))) == ["tool:bash"]
    assert at(detect(probe(tool("exec_remote", "Does things.")))) == ["tool:exec_remote"]
    assert at(detect(probe(tool("helper", "Starts a subprocess for you.")))) == ["tool:helper"]
    assert at(detect(probe(tool("helper", "Does things.", description="The command line to execute.")))) == ["tool:helper"]
    assert at(detect(probe(tool("helper", "Accepts a shell command-line string.")))) == ["tool:helper"]
    assert at(detect(probe(tool("helper", "Sends text to the operating system.")))) == ["tool:helper"]
    assert at(detect(probe(tool("runCommand", "Does things.")))) == ["tool:runCommand"]


def test_a_type_list_that_holds_string_counts():
    assert at(detect(probe(ToolInfo("run", "", {}, {"properties": {"command": {"type": ["string", "null"]}}})))) == ["tool:run"]


def test_the_evidence_names_the_tool_the_parameter_and_the_word_never_the_description():
    secret = "SECRET-DESCRIPTION-WORDS"
    (finding,) = detect(probe(tool("run_command", f"Runs a command. {secret}")))
    assert finding.evidence == "run_command: parameter command takes a command line (run)"
    assert secret not in finding.evidence


def test_the_fingerprint_follows_the_tool_and_the_parameter_not_the_description():
    first = next(detect(probe(tool("run_command", "Runs a command."))))
    second = next(detect(probe(tool("run_command", "Runs any command you give it."))))
    third = next(detect(probe(tool("run_command", "Runs a command.", parameter="cmd"))))
    assert first.fingerprint == second.fingerprint != third.fingerprint


def test_invisible_characters_do_not_hide_the_execution_word():
    assert at(detect(probe(tool("helper", "Ru​ns a command.")))) == ["tool:helper"]


# --- claim 10: quiet ------------------------------------------------------------------------------------------------------

def test_an_enum_or_a_const_makes_the_parameter_a_choice():
    assert list(detect(probe(tool(enum=["status", "version"])))) == []
    assert list(detect(probe(tool(const="status")))) == []


def test_a_parameter_that_is_not_a_string_is_quiet():
    for kind in ("integer", "boolean", "array", "object"):
        assert list(detect(probe(ToolInfo("run", "Runs it.", {}, {"properties": {"command": {"type": kind}}})))) == []
    assert list(detect(probe(ToolInfo("run", "Runs it.", {}, {"properties": {"command": {}}})))) == []


def test_without_an_execution_word_it_is_quiet():
    assert list(detect(probe(tool("slash", "Sends a slash instruction to the bot.")))) == []


@pytest.mark.parametrize("parameter", ("commands", "command_id", "commandName", "subcommand", "args", "script"))
def test_other_parameter_names_are_quiet(parameter):
    assert list(detect(probe(tool(parameter=parameter)))) == []


def test_a_tool_without_a_schema_or_with_odd_schemas_is_quiet():
    assert list(detect(probe(ToolInfo("run_command", "Runs a command.")))) == []
    for odd in ({}, {"properties": []}, {"properties": {"command": "string"}}, {"properties": {5: {"type": "string"}}}):
        assert list(detect(probe(ToolInfo("run_command", "Runs a command.", {}, odd)))) == []


def test_nested_objects_are_not_read():
    nested = {"properties": {"options": {"type": "object", "properties": {"command": {"type": "string"}}}}}
    assert list(detect(probe(ToolInfo("run_command", "Runs a command.", {}, nested)))) == []


# --- claim 11: a claim of the server never silences it ------------------------------------------------------------------------

def test_a_servers_own_claim_does_not_silence_the_rule():
    claimed = ToolInfo("run_command", "Runs only allowed commands, sandboxed.", {"readOnlyHint": True, "destructiveHint": False}, schema())
    assert at(detect(probe(claimed))) == ["tool:run_command"]
    assert at(detect(probe(ToolInfo("run_command", "Runs only allowed commands.", {}, schema())))) == ["tool:run_command"]


# --- claim 12: a dropped schema -----------------------------------------------------------------------------------------------

def test_a_tool_whose_schema_the_prober_dropped_yields_nothing_and_the_cut_stays_reported():
    from spellwarden_cli.probe import MAX_SCHEMA_BYTES, _tool_cut, _tool_of

    raw = {"name": "run_command", "description": "Runs a command.",
           "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "description": "x" * (MAX_SCHEMA_BYTES + 1)}}}}
    recorded = _tool_of(raw)
    assert recorded.input_schema is None and _tool_cut(raw) is True  # the prober's own notice stays what reports the cut
    cut = probe(recorded, lists_cut=("tools",))
    assert list(detect(cut)) == [] and cut.lists_cut == ("tools",)
    assert [f for f in evaluate_probe(cut, RuleSet.baseline()).findings if f.rule_id == RULE_ID] == []


# --- claim 13: the cap ----------------------------------------------------------------------------------------------------------

def test_a_probe_yields_at_most_25_findings_and_the_last_counts_the_rest():
    tools = [tool(f"run_{number}") for number in range(40)]
    findings = list(detect(probe(*tools)))
    assert len(findings) == 25 and at(findings)[0] == "tool:run_0" and at(findings)[-1] == "tool:run_24"
    assert findings[-1].evidence.endswith(" and 15 more tools") and not findings[0].evidence.endswith("more tools")
    assert len(list(detect(probe(*tools[:25])))) == 25 and "more tools" not in next(iter(list(detect(probe(*tools[:25])))[-1:])).evidence


# --- claim 14: tools only -----------------------------------------------------------------------------------------------------

def test_no_prompt_resource_template_or_instruction_text_is_read():
    words = "Runs a command line in a shell."
    quiet = probe(ToolInfo("helper", "Does things.", {}, schema()), instructions=words, instructions_truncated=False,
                  prompts=(PromptInfo("run_command", None, words),), resources=(ResourceInfo("file:///a", "shell", None, words),))
    assert list(detect(quiet)) == []


def test_the_module_does_not_use_probe_texts():
    assert "probe_texts" not in inspect.getsource(growth_mcp_013)
