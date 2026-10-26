"""SARIF 2.1.0 (spec 6.9): one run, every rule of the set, one result per finding with the engine's fingerprint;
accepted findings carry an external suppression. No timestamps, no invocations: the file is byte-deterministic."""
from __future__ import annotations

import json
import re
from urllib.parse import quote

from spellwarden_scan import Rule

from spellwarden_cli import escape
from spellwarden_cli.output.upload import upload_path
from spellwarden_cli.report import Report, ReportFinding

SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/spellwarden-ai/spellwarden"
HELP_URI = "https://github.com/spellwarden-ai/spellwarden#the-rules"
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_WORD = re.compile(r"[A-Za-z0-9]+")


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
        "properties": {"tags": ["security", *rule.owasp_agentic, *rule.owasp_mcp, *rule.nist],
                       "security-severity": SECURITY_SEVERITY[rule.severity_default]},
    }


def _result(report: Report, item: ReportFinding, index: dict[str, int]) -> dict:
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
    if item.suppressed:
        reason = (item.baseline or {}).get("reason", "")
        result["suppressions"] = [{"kind": "external", "justification": escape.message(reason)}]
    return result


def render(report: Report) -> str:
    rules = list(report.rules)
    index = {rule.id: position for position, rule in enumerate(rules)}
    document = {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Spellwarden", "semanticVersion": report.scanner_version,
                                "informationUri": INFORMATION_URI, "rules": [_rule(rule) for rule in rules]}},
            "results": [_result(report, item, index) for item in report.findings],
        }],
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
