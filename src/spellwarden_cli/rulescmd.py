"""`spellwarden rules` (spec 6.2): the baseline rule table as text, JSON or Markdown. The README's table is the
Markdown form, byte for byte (`tests/test_readme_rules.py`). With `--preset NAME` (1.18.0) each rule shows its severity under
that preset, or `off` (`presets.severity_of`): the text form in place of the severity, the Markdown form as a column after the
default, the JSON form as `preset`; `--preset balanced` prints each rule's own severity."""
from __future__ import annotations

import argparse
import json
import sys

from spellwarden_scan import Rule, RuleSet
from spellwarden_scan.rules import AREAS

from spellwarden_cli import presets
from spellwarden_cli.output import write_stdout

MALICIOUS_SUFFIX = " (malicious indicator)"


def _ordered(rules: RuleSet) -> list[Rule]:
    return [rule for area in AREAS for rule in rules.by_area(area)]


def _title(rule: Rule) -> str:
    if rule.malicious_indicator and not rule.title.endswith(MALICIOUS_SUFFIX):
        return rule.title + MALICIOUS_SUFFIX
    return rule.title


def _severity(rule: Rule, preset: str | None) -> str:
    return rule.severity_default if preset is None else presets.severity_of(rule, preset)


def rules_markdown(rules: RuleSet) -> str:
    lines = ["| Id | Title | Severity | OWASP | NIST | ATLAS | AST |", "|---|---|---|---|---|---|---|"]
    for rule in _ordered(rules):
        owasp = ", ".join(rule.owasp_agentic + rule.owasp_mcp)
        lines.append(f"| {rule.id} | {_title(rule)} | {rule.severity_default} | {owasp} | {', '.join(rule.nist)} | "
                     f"{', '.join(rule.atlas)} | {', '.join(rule.owasp_ast)} |")
    return "\n".join(lines) + "\n"


def rules_preset_markdown(rules: RuleSet, preset: str) -> str:
    lines = [f"| Id | Title | Default | {preset} |", "|---|---|---|---|"]
    for rule in _ordered(rules):
        lines.append(f"| {rule.id} | {_title(rule)} | {rule.severity_default} | {presets.severity_of(rule, preset)} |")
    return "\n".join(lines) + "\n"


def rules_text(rules: RuleSet, preset: str | None = None) -> str:
    return "".join(f"{rule.id}  {_severity(rule, preset):<8}  {_title(rule)}\n" for rule in _ordered(rules))


def rules_json(rules: RuleSet, preset: str | None = None) -> str:
    entries = []
    for rule in _ordered(rules):
        entry = rule.to_dict()
        if preset is not None:
            entry["preset"] = {"name": preset, "severity": presets.severity_of(rule, preset)}
        entries.append(entry)
    return json.dumps(entries, indent=2, sort_keys=True) + "\n"


_RENDER = {"text": rules_text, "json": rules_json, "markdown": rules_markdown}


def add_parser(commands_: argparse._SubParsersAction) -> None:
    parser = commands_.add_parser("rules", help="Print the rules this scanner applies.")
    parser.add_argument("--format", choices=sorted(_RENDER), default="text")
    parser.add_argument("--preset", choices=presets.PRESETS, default=None,
                        help="each rule's severity under this preset (off: its findings are not listed)")
    parser.set_defaults(handler=cmd_rules)


def cmd_rules(args: argparse.Namespace) -> int:
    rules = RuleSet.baseline()
    preset = getattr(args, "preset", None)
    if preset is None:
        text = _RENDER[args.format](rules)
    elif args.format == "markdown":
        text = rules_preset_markdown(rules, preset)
    elif args.format == "json":
        text = rules_json(rules, preset)
    else:
        text = rules_text(rules, preset)
    write_stdout(text, sys.stdout)
    return 0
