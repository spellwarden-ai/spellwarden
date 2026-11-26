"""SW-MCP-013: a tool takes a command line to run as an argument.

Read over the tools a probe recorded (`ProbeResult.tools`), from each tool's name, description and input schema (`ToolInfo.
input_schema`, a JSON object the prober keeps up to 16 KiB). A tool fires, once and at `tool:<name>`, when

* a property of its input schema is a command parameter: its name, lower-cased with `_` and `-` removed, is `command`, `cmd`,
  `commandline`, `shellcommand`, `bashcommand`, `powershellcommand`, `shell` or `bash`; its `type` is `"string"` (or a list that
  holds `"string"`); and it has neither `enum` nor `const`; and
* an execution word stands as a whole word in the tool's name, in its description or in the property's own description: `run`,
  `runs`, `execute`, `executes`, `exec`, `shell`, `terminal`, `bash`, `powershell`, `cmd`, `subprocess`, `spawn`, `command
  line`, `command-line`, `operating system` or `os command`.

The schema is read at its top level only: a nested object, `anyOf` and an array are not read. A tool without a recorded schema,
which includes one whose schema the prober dropped for size (the probe result already names `tools` in `lists_cut`, and that
notice stays the report of it), is not judged and says nothing. A claim of the server (`readOnlyHint`, "sandboxed", "only
allowed commands") never silences the rule: it is a remote claim. No prompt, resource, template or instruction text is read.
A probe yields at most `_PER_SERVER` findings; the evidence of the last one counts the tools after it. The evidence names the
tool, the parameter and the word, never the description. The module is registered by the rule set, not here."""
from __future__ import annotations

import re
from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.model import Finding, Location, ProbeResult, ToolInfo
from spellwarden_scan.normalise import visible
from spellwarden_scan.probe import text_of

RULE_ID = "SW-MCP-013"
TITLE = "Tool takes a command line to run as an argument"
SEVERITY = "medium"
OWASP = ("MCP05", "ASI05")
NIST = ("SI-10",)
ATLAS = ("AML.T0053",)
MALICIOUS = False

_PER_SERVER = 25
_PARAMETERS = frozenset({"command", "cmd", "commandline", "shellcommand", "bashcommand", "powershellcommand", "shell", "bash"})
_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_EXECUTION = frozenset({"run", "runs", "execute", "executes", "exec", "shell", "terminal", "bash", "powershell", "cmd", "subprocess",
                        "spawn"})
_EXECUTION_TEXT = re.compile(
    r"\b(?:runs?|executes?|exec|shell|terminal|bash|powershell|cmd|subprocess|spawn|command[ -]line|operating system|os command)\b",
    re.IGNORECASE)


def _is_string(value: object) -> bool:
    return value == "string" or (isinstance(value, list) and "string" in value)


def _parameters(schema: dict | None) -> Iterator[tuple[str, dict]]:
    """`(name, property)` of each command parameter of the schema's top level."""
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return
    for name, prop in properties.items():
        if not isinstance(name, str) or not isinstance(prop, dict):
            continue
        if name.lower().replace("_", "").replace("-", "") not in _PARAMETERS:
            continue
        if _is_string(prop.get("type")) and "enum" not in prop and "const" not in prop:
            yield name, prop


def _execution_word(tool: ToolInfo, prop: dict) -> str | None:
    """The first execution word of the tool's name, its description or the property's description, or None."""
    for word in _WORDS.findall(tool.name):
        if word.lower() in _EXECUTION:
            return word.lower()
    for text in (text_of(tool.description), text_of(prop.get("description"))):
        found = _EXECUTION_TEXT.search(" ".join(visible(text).split()))
        if found is not None:
            return found.group(0).lower()
    return None


def _matches(probe: ProbeResult) -> Iterator[tuple[ToolInfo, str, str]]:
    for tool in probe.tools:
        for name, prop in _parameters(tool.input_schema):
            word = _execution_word(tool, prop)
            if word is not None:
                yield tool, name, word
                break


def detect(probe: ProbeResult) -> Iterator[Finding]:
    found = list(_matches(probe))
    for index, (tool, parameter, word) in enumerate(found[:_PER_SERVER]):
        shown = f"{tool.name}: parameter {parameter} takes a command line ({word})"
        if index == _PER_SERVER - 1 and len(found) > _PER_SERVER:
            shown += f" and {len(found) - _PER_SERVER} more tools"
        location = f"tool:{tool.name}"
        yield Finding(RULE_ID, SEVERITY, TITLE, Location(location, None), bounded_evidence(shown),
                      fingerprint(RULE_ID, location, parameter), MALICIOUS)
