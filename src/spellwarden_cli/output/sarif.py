"""SARIF 2.1.0 (spec 6.9): one run, every rule of the set, one result per finding with the engine's fingerprint;
accepted findings carry an external suppression. No timestamps, and an invocation only after a failed workstation upload
(phase 3 batch 2c spec 11.2, F1), with no time in it: the file is byte-deterministic."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import quote

from spellwarden_scan import Rule, lint

from spellwarden_cli import escape, instruction_files
from spellwarden_cli.output.upload import upload_path
from spellwarden_cli.report import Report, ReportFinding

SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/spellwarden-ai/spellwarden"
HELP_URI = "https://github.com/spellwarden-ai/spellwarden#the-rules"
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_WORD = re.compile(r"[A-Za-z0-9]+")
# Phase 3 batch 2c spec 11.2 (F1): a report holding one of these errors names every error of the run in the invocation.
UPLOAD_ERRORS = ("workstation_upload_failed", "workstation_upload_too_large")


def _name(rule: Rule) -> str:
    """SARIF's `name` is an identifier: the title in PascalCase (`RemoteScriptPipedToAShell`)."""
    return "".join(word[:1].upper() + word[1:] for word in _WORD.findall(rule.title))


def _rule(rule: Rule) -> dict:
    return {
        "id": rule.id,
        "name": _name(rule),
        "shortDescription": {"text": rule.title},
        "helpUri": HELP_URI,
        "defaultConfiguration": {"level": LEVEL[rule.severity_default]},
        "properties": {"tags": ["security", *rule.owasp_agentic, *rule.owasp_mcp, *rule.nist, *rule.atlas, *rule.owasp_ast],
                       "security-severity": SECURITY_SEVERITY[rule.severity_default]},
    }


def _result(report: Report, item: ReportFinding, index: dict[str, int], instructions: dict[str, dict],
            clients_of: dict[str, list[str]] | None = None) -> dict:
    finding = item.finding
    text = f"{finding.title}: {finding.evidence}" if finding.evidence else finding.title
    physical: dict = {"artifactLocation": {"uri": quote(upload_path(report, finding.location.path), safe="/")}}
    if finding.location.line:
        physical["region"] = {"startLine": finding.location.line}
    location: dict = {"physicalLocation": physical}
    rule = report.rules.get(finding.rule_id)
    # a finding of a probed MCP server and one of a remote A2A agent name the resource they are about (O4 spec 6.10)
    if rule is not None and (rule.area == "mcp" or (rule.area == "a2a" and item.item.startswith("a2a-agent:"))):
        location["logicalLocations"] = [{"fullyQualifiedName": escape.message(item.item), "kind": "resource"}]
    result: dict = {
        "ruleId": finding.rule_id,
        "level": LEVEL[finding.severity],
        "message": {"text": escape.message(text)},
        "locations": [location],
        "partialFingerprints": {"spellwarden/v1": finding.fingerprint},
    }
    if finding.rule_id in index:
        result["ruleIndex"] = index[finding.rule_id]
    if item.item in instructions:  # a finding of an instruction file says which format it is and when the agent applies it
        result["properties"] = {"instructions": instructions[item.item]}
    if clients_of is not None:  # `scan --user` (phase 3 batch 2a spec 11.3): the clients whose configuration holds the item
        result.setdefault("properties", {})["clients"] = clients_of.get(item.item, [])
    if item.suppressed:
        reason = (item.baseline or {}).get("reason", "")
        result["suppressions"] = [{"kind": "external", "justification": escape.message(reason)}]
    return result


def _invocation(report: Report) -> dict:
    """The run did not complete: one tool execution notification per error, its code as the descriptor id."""
    return {"executionSuccessful": False,
            "toolExecutionNotifications": [{"descriptor": {"id": error.code}, "level": "error",
                                            "message": {"text": escape.message(error.message)}} for error in report.errors]}


LINT_HELP_URI = ("https://spellwarden.ai/docs/activation-checks?utm_source=scanner&utm_medium=cli"
                 "&utm_campaign=description-lint")


def _lint_rule(note_id: str) -> dict:
    """The descriptor of a description lint check (Phase 4 batch B spec 11.4): level `note`, no security severity."""
    title = lint.TITLES[note_id]
    return {"id": note_id, "name": "".join(word[:1].upper() + word[1:] for word in _WORD.findall(title)),
            "shortDescription": {"text": title}, "helpUri": LINT_HELP_URI, "defaultConfiguration": {"level": "note"},
            "properties": {"tags": ["description-lint"]}}


def _lint_results(report: Report, first_index: int) -> list[dict]:
    """One SARIF result of level `note` per lint note, on the skill's SKILL.md, with a fingerprint of the check, the skill and
    the other skill. Never a finding: no `security-severity`."""
    results = []
    for entry in report.lint or ():
        skill_file = "SKILL.md" if entry.skill == "." else f"{entry.skill}/SKILL.md"
        for note in entry.notes:
            digest = hashlib.sha256(f"{note.id}\n{entry.skill}\n{note.other_path or ''}".encode()).hexdigest()
            results.append({
                "ruleId": note.id, "ruleIndex": first_index + lint.LINT_IDS.index(note.id), "level": "note",
                "message": {"text": escape.message(note.message)},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": quote(upload_path(report, skill_file), safe="/")}}}],
                "partialFingerprints": {"spellwarden/v1": digest},
                "properties": {"description_lint": True},
            })
    return results


def render(report: Report) -> str:
    rules = list(report.rules)
    index = {rule.id: position for position, rule in enumerate(rules)}
    scopes = instruction_files.scopes(report.items)
    instructions = {entry.path: {"format": entry.format, "scope": escape.message(scopes[entry.path])}
                    for entry in report.items if entry.kind == "instructions"}
    clients_of = {entry.path: list(entry.clients) for entry in report.items} if report.clients is not None else None
    document = {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Spellwarden", "semanticVersion": report.scanner_version,
                                "informationUri": INFORMATION_URI, "rules": [_rule(rule) for rule in rules]}},
            "results": [_result(report, item, index, instructions, clients_of) for item in report.findings],
        }],
    }
    run = document["runs"][0]
    if any(entry.notes for entry in report.lint or ()):  # absent otherwise, so a report without notes is unchanged
        run["tool"]["driver"]["rules"].extend(_lint_rule(note_id) for note_id in lint.LINT_IDS)
        run["results"].extend(_lint_results(report, len(rules)))
    if any(error.code in UPLOAD_ERRORS for error in report.errors):  # absent otherwise, so every other SARIF file is unchanged
        document["runs"][0]["invocations"] = [_invocation(report)]
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
