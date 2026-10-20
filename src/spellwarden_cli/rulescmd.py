"""`spellwarden rules` (spec 6.2): the baseline rule table as text, JSON or Markdown. The README's table is the
Markdown form, byte for byte (`tests/test_readme_rules.py`)."""
from __future__ import annotations

import argparse
import json
import sys

from spellwarden_scan import Rule, RuleSet
from spellwarden_scan.rules import AREAS

MALICIOUS_SUFFIX = " (malicious indicator)"


def _ordered(rules: RuleSet) -> list[Rule]:
    return [rule for area in AREAS for rule in rules.by_area(area)]


def _title(rule: Rule) -> str:
    if rule.malicious_indicator and not rule.title.endswith(MALICIOUS_SUFFIX):
        return rule.title + MALICIOUS_SUFFIX
    return rule.title


def rules_markdown(rules: RuleSet) -> str:
    lines = ["| Id | Title | Severity | OWASP | NIST |", "|---|---|---|---|---|"]
    for rule in _ordered(rules):
        owasp = ", ".join(rule.owasp_agentic + rule.owasp_mcp)
        lines.append(f"| {rule.id} | {_title(rule)} | {rule.severity_default} | {owasp} | {', '.join(rule.nist)} |")
    return "\n".join(lines) + "\n"


def rules_text(rules: RuleSet) -> str:
    return "".join(f"{rule.id}  {rule.severity_default:<8}  {_title(rule)}\n" for rule in _ordered(rules))


def rules_json(rules: RuleSet) -> str:
    return json.dumps([rule.to_dict() for rule in _ordered(rules)], indent=2, sort_keys=True) + "\n"


_RENDER = {"text": rules_text, "json": rules_json, "markdown": rules_markdown}


def add_parser(commands_: argparse._SubParsersAction) -> None:
    parser = commands_.add_parser("rules", help="Print the rules this scanner applies.")
    parser.add_argument("--format", choices=sorted(_RENDER), default="text")
    parser.set_defaults(handler=cmd_rules)


def cmd_rules(args: argparse.Namespace) -> int:
    from spellwarden_cli.main import write_stdout  # main imports this module

    write_stdout(_RENDER[args.format](RuleSet.baseline()), sys.stdout)
    return 0
