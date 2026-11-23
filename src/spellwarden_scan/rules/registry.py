"""The three registry gate rules (O3 spec 5.2). They have no detector: the connected command evaluates them against
the organisation's private registry (spec 6.6), and no engine entry point ever emits them (claim E2). They exist in the
baseline so that `spellwarden rules`, SARIF and the hosted finding views know their ids, titles and tags."""
from __future__ import annotations

from spellwarden_scan.rules import Rule, make_rule


def _no_detector(_subject: object) -> tuple:
    return ()


RULES: tuple[Rule, ...] = (
    make_rule("SW-REG-001", "Skill package not admitted in the organisation's private registry", "high", "registry",
              owasp=("ASI04",), nist=("SR-3",), atlas=("AML.T0010.005",), owasp_ast=("AST09",), detect=_no_detector,
              fix="Request the skill's admission to your organisation's private registry with the link in the report, or take the skill out of the change."),
    make_rule("SW-REG-002", "MCP server not admitted in the organisation's private registry", "high", "registry",
              owasp=("MCP09",), nist=("SR-3",), atlas=("AML.T0010.005",), owasp_ast=("AST09",), detect=_no_detector,
              fix="Request the MCP server's admission to your organisation's private registry with the link in the report, or take the server out of the change."),
    make_rule("SW-REG-003", "Agent content the private registry cannot judge", "high", "registry",
              owasp=("ASI04",), nist=("SR-3",), atlas=("AML.T0010.005",), owasp_ast=("AST09",), detect=_no_detector,
              fix="Make the item identifiable, for example by pinning every package to an exact version and writing the launch out in full, then request its admission."),
)
