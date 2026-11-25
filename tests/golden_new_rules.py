"""The three rules of 1.25.0 (SW-SKL-038, SW-MCP-013, SW-CFG-015) sit in the middle of the SARIF rule table, so a report written
by this scanner holds three descriptors that a report recorded by an older release does not, and every `ruleIndex` after the first
of them is higher by the number of new descriptors before it. `without_new_rules` takes the descriptors out and renumbers
`ruleIndex` through the reduced table, so that the golden tests of the older releases go on proving every other byte of their
reports unchanged. The reports of the other formats name no rule table and come back as the very same text."""
from __future__ import annotations

import json

NEW_RULE_IDS = ("SW-SKL-038", "SW-MCP-013", "SW-CFG-015")


def without_new_rules(name: str, text: str) -> str:
    """`text`, the report `name` (a golden recorder's file name), without the descriptors of `NEW_RULE_IDS`; SARIF only."""
    if name != "report.sarif":
        return text
    document = json.loads(text)
    for run in document.get("runs", []):
        table = run["tool"]["driver"]["rules"]
        kept = [rule for rule in table if rule["id"] not in NEW_RULE_IDS]
        if len(kept) == len(table):
            continue
        renumbered = {old: kept.index(rule) for old, rule in enumerate(table) if rule["id"] not in NEW_RULE_IDS}
        for result in run.get("results", []):
            if "ruleIndex" in result:
                result["ruleIndex"] = renumbered[result["ruleIndex"]]
        run["tool"]["driver"]["rules"] = kept
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


__all__ = ["NEW_RULE_IDS", "without_new_rules"]
