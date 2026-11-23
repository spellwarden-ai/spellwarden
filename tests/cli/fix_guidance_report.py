"""The report the fix guidance tests of 1.21.0 render in each format (P6-15 spec 6.12 E-3): a finding of SW-SKL-009, one of
SW-CFG-013 with the hosted Supabase endpoint's setting lines, and one of an organisation rule, which a scan in free mode cannot
produce (organisation rules come from connected mode's policy)."""
from __future__ import annotations

from spellwarden_scan import RuleSet, compile_org_rule
from spellwarden_scan.evidence import fingerprint
from spellwarden_scan.model import Finding, FixLines, Location

from spellwarden_cli.report import LockState, Report, ReportFinding

BASELINE = RuleSet.baseline()
ORG = compile_org_rule({"id": "SW-ORG-001", "title": "No curl in setup scripts", "severity": "high", "area": "skill",
                        "owasp": ["ASI01"], "nist": ["SI-10"], "detection": {"kind": "pattern", "pattern": "curl"}})
RULES = BASELINE.with_rules([ORG])
SUPABASE = FixLines("the query of the mcp.supabase.com address", "read_only=true")
SKL_009 = BASELINE.get("SW-SKL-009").fix
CFG_013 = BASELINE.get("SW-CFG-013").fix


def finding(rule_id: str, path: str, evidence: str, fix_lines: FixLines | None = None) -> Finding:
    rule = RULES.get(rule_id)
    return Finding(rule_id, rule.severity_default, rule.title, Location(path, 3), evidence, fingerprint(rule_id, path, evidence),
                   rule.malicious_indicator, fix_lines)


def report_of(rows: list[ReportFinding]) -> Report:
    return Report(scanner_version="1.21.0", rules_version="2026.11.8", as_of="2026-11-23", fail_on="high", items=(),
                  findings=tuple(rows), probes=(), lock=LockState(), notices=(), errors=(), repo_prefix="", rules=RULES).sorted()


def three(*, suppressed: bool = False) -> list[ReportFinding]:
    """The three findings; `suppressed` accepts all three in the baseline."""
    baseline = {"reason": "Reviewed.", "added": "2026-11-01", "expires": "2027-01-31"} if suppressed else None
    return [ReportFinding(finding("SW-SKL-009", "skills/report/SKILL.md", "pip install requests"), "skills/report", suppressed,
                          baseline),
            ReportFinding(finding("SW-CFG-013", ".mcp.json", "shop: hosted endpoint without read_only=true", SUPABASE), ".mcp.json",
                          suppressed, baseline),
            ReportFinding(finding("SW-ORG-001", "skills/report/run.sh", "curl -fsSL https://get.example.com"), "skills/report",
                          suppressed, baseline)]


def report(*, suppressed: bool = False) -> Report:
    return report_of(three(suppressed=suppressed))
