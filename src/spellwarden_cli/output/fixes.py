"""1.21.0 (P6-15 spec 6.5, 6.6, 4.5): what the "How to fix" sections of the text and Markdown reports list. One entry per
baseline rule among the findings given, in rule id order, with its fix sentence, its tagged page and the distinct setting lines
of those findings (at most five per rule, the rows of `rules.fix_lines.SOURCES`). Also whether one of them is an organisation
rule's finding, which gets the one line `ORG_LINE`, since an organisation's policy pack holds no fix text."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from spellwarden_scan.model import FixLines

from spellwarden_cli.report import Report, ReportFinding, rule_fix, rule_url

ORG_LINE = ("Organisation rules (SW-ORG-) come from your organisation's policy pack, which holds no fix text: ask the people who "
            "manage it.")


@dataclass(frozen=True)
class RuleFix:
    rule_id: str
    sentence: str
    url: str
    lines: tuple[FixLines, ...]


def rule_fixes(report: Report, rows: Sequence[ReportFinding]) -> tuple[tuple[RuleFix, ...], bool]:
    """The entries for `rows` and whether one of them is an organisation rule's finding. A finding of a rule the set lacks, or of
    a rule without a fix sentence, adds nothing."""
    lines: dict[str, set[FixLines]] = {}
    organisation = False
    for row in rows:
        rule_id = row.finding.rule_id
        if rule_id.startswith("SW-ORG-"):
            organisation = True
            continue
        if rule_fix(report.rules.get(rule_id)) is None:
            continue
        found = lines.setdefault(rule_id, set())
        if row.finding.fix_lines is not None:
            found.add(row.finding.fix_lines)
    entries = []
    for rule_id in sorted(lines):
        rule = report.rules.get(rule_id)
        entries.append(RuleFix(rule_id, rule_fix(rule) or "", rule_url(rule) or "",
                               tuple(sorted(lines[rule_id], key=lambda fix: (fix.where, fix.text)))))
    return tuple(entries), organisation


__all__ = ["ORG_LINE", "RuleFix", "rule_fixes"]
