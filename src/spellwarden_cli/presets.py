"""Presets (1.18.0): `--preset strict|balanced|low-noise`, the setting `preset` and the variable `SPELLWARDEN_PRESET`. `ROWS` is
the one statement of what each preset does to each rule: the README's "Presets" table (`table_markdown`), `spellwarden rules
--preset` (`severity_of`) and the tests are generated from it or checked against it, so changing a row is a change of `ROWS` and
of the golden files under tests/golden/1.18.0/presets and nothing else.

`balanced` is every rule's own severity. Without a preset, or with `balanced`, `apply` returns the report it was given: no
notice, no key and no field is added, so every output is the one a scan without presets writes. `strict` and `low-noise` change
only the scanner's own rules (`SW-SKL-`, `SW-MCP-`, `SW-CFG-`, `SW-A2A-`), never an organisation rule (`SW-ORG-`) or a finding of
the registry gate (`SW-REG-`). `run.scan` calls `apply` last: after the baseline, which matches by fingerprint, so a preset never
changes what it accepts, and after the connected upload, which so carries every finding at its rule's own severity. `apply` never
touches the errors, so an incomplete scan stays exit 2, and never lowers or turns off a critical or high finding or a malicious
indicator, whatever a row says. A finding it turns off is counted in the report's `preset` block and in its notice, never
silently dropped (README "Limits": an output cap)."""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from types import MappingProxyType

from spellwarden_scan import SEVERITY_RANK, Finding, Rule, RuleSet

from spellwarden_cli.report import Notice, Report, ReportFinding

STRICT, BALANCED, LOW_NOISE = "strict", "balanced", "low-noise"
PRESETS = (STRICT, BALANCED, LOW_NOISE)
OFF = "off"
SOURCES = ("flag", "environment", "file")
NOTICE_CODE = "preset"
CONFIG_PATH = ".spellwarden/config.yml"  # as settings.CONFIG_PATH (settings imports this module, so it is not imported here)
GUIDE_URL = "https://spellwarden.ai/docs/presets?utm_source=scanner&utm_medium=cli&utm_campaign=presets"
PRESET_PREFIXES = ("SW-SKL-", "SW-MCP-", "SW-CFG-", "SW-A2A-")  # the scanner's own rules: the only ones a preset changes
_LOWERABLE = ("medium", "low")


@dataclass(frozen=True)
class Row:
    """One rule of the table: its severity under `strict` and under `low-noise` (a severity, or `off`), and why."""
    rule_id: str
    strict: str
    low_noise: str
    why: str


ROWS: tuple[Row, ...] = (
    Row("SW-A2A-001", "medium", "low", "format conformance, no attack path"),
    Row("SW-A2A-002", "medium", "off", "protocol age only"),
    Row("SW-A2A-003", "medium", "off", "protocol age only"),
    Row("SW-A2A-004", "high", "high", "high: never lowered"),
    Row("SW-A2A-005", "high", "high", "high: never lowered"),
    Row("SW-A2A-006", "high", "medium", "authentication weakness: strict raises; low-noise keeps a real risk at medium"),
    Row("SW-A2A-007", "high", "medium", "authentication: as above"),
    Row("SW-A2A-008", "high", "medium", "credential exposure: as above"),
    Row("SW-A2A-009", "medium", "off", "least-privilege hygiene, low"),
    Row("SW-A2A-010", "high", "high", "high: never lowered"),
    Row("SW-A2A-011", "high", "high", "high: never lowered"),
    Row("SW-A2A-012", "medium", "off", "most cards are unsigned; hygiene"),
    Row("SW-A2A-013", "high", "medium", "trust of the signature: strict raises"),
    Row("SW-A2A-014", "high", "high", "high: never lowered"),
    Row("SW-A2A-015", "critical", "critical", "critical: never lowered"),
    Row("SW-A2A-016", "high", "medium", "possible card substitution: strict raises"),
    Row("SW-A2A-017", "high", "medium", "unverifiable signature: strict raises"),
    Row("SW-A2A-018", "high", "high", "high: never lowered"),
    Row("SW-A2A-019", "high", "high", "high: never lowered"),
    Row("SW-CFG-001", "high", "high", "high: never lowered"),
    Row("SW-CFG-002", "critical", "critical", "critical"),
    Row("SW-CFG-003", "high", "low", "`npx -y package` style launches are the common way configurations are written; strict "
        "treats an unpinned launch as supply-chain risk"),
    Row("SW-CFG-004", "high", "medium", "a hidden destination: strict raises; not common in benign configurations"),
    Row("SW-CFG-005", "high", "high", "high"),
    Row("SW-CFG-006", "critical", "critical", "malicious indicator"),
    Row("SW-CFG-007", "critical", "critical", "malicious indicator"),
    Row("SW-CFG-008", "high", "high", "high"),
    Row("SW-CFG-009", "high", "medium", "supply chain: strict raises"),
    Row("SW-CFG-010", "high", "high", "high"),
    Row("SW-CFG-012", "high", "high", "high"),
    Row("SW-CFG-013", "high", "high", "high"),
    Row("SW-CFG-015", "high", "high", "measured at high on its whole frame: never lowered"),
    Row("SW-MCP-001", "high", "high", "high: never lowered, although it fires on 16,546 census hosts, most of them public "
        "read-only servers by design; the largest remaining source of MCP noise"),
    Row("SW-MCP-002", "high", "medium", "authentication: strict raises"),
    Row("SW-MCP-003", "medium", "low", "protocol migration; 5,366 census hosts (63% of OAuth servers)"),
    Row("SW-MCP-004", "medium", "low", "protocol migration"),
    Row("SW-MCP-005", "low", "off", "protocol age; 13,897 census hosts"),
    Row("SW-MCP-006", "medium", "off", "protocol migration; 1,708 hosts"),
    Row("SW-MCP-007", "medium", "off", "protocol migration; 13,852 hosts"),
    Row("SW-MCP-008", "medium", "off", "protocol migration; 715 hosts"),
    Row("SW-MCP-009", "high", "high", "high"),
    Row("SW-MCP-010", "high", "medium", "token audience and issuer checks: strict raises"),
    Row("SW-MCP-011", "high", "high", "precision tuned on its own record (87 holdout false alarms in 1.12.0); a preset does not "
        "override it"),
    Row("SW-MCP-012", "high", "high", "high"),
    Row("SW-MCP-013", "high", "medium", "a command primitive the user may intend (a shell server): strict raises"),
    Row("SW-REG-001", "high", "high", "the organisation's policy: no preset touches it"),
    Row("SW-REG-002", "high", "high", "as above"),
    Row("SW-REG-003", "high", "high", "as above"),
    Row("SW-SKL-001", "high", "high", "high"),
    Row("SW-SKL-002", "high", "high", "high"),
    Row("SW-SKL-003", "high", "high", "high"),
    Row("SW-SKL-004", "critical", "critical", "malicious indicator"),
    Row("SW-SKL-005", "high", "high", "high"),
    Row("SW-SKL-006", "high", "low", "common in benign operations skills (`rm -rf build/`); strict treats it as a direct risk"),
    Row("SW-SKL-007", "high", "high", "high"),
    Row("SW-SKL-008", "critical", "critical", "malicious indicator"),
    Row("SW-SKL-009", "high", "low", "unpinned installs are the analyzer's most common benign category; strict treats them as "
        "supply-chain risk"),
    Row("SW-SKL-010", "high", "medium", "an unreadable file: strict raises; kept at medium because a binary cannot be judged"),
    Row("SW-SKL-011", "critical", "critical", "critical"),
    Row("SW-SKL-012", "high", "low", "many benign cloud skills name `~/.aws/credentials` to explain setup; strict treats it as "
        "an exfiltration path"),
    Row("SW-SKL-013", "high", "medium", "a hidden destination: strict raises"),
    Row("SW-SKL-014", "high", "medium", "obfuscation: strict raises"),
    Row("SW-SKL-015", "medium", "off", "metadata only"),
    Row("SW-SKL-019", "high", "low", "common in research and documentation skills; strict treats it as an injection path"),
    Row("SW-SKL-031", "medium", "off", "metadata only"),
    Row("SW-SKL-032", "critical", "critical", "malicious indicator"),
    Row("SW-SKL-036", "high", "low", "many benign skills pre-approve `Bash`; strict treats unscoped execution as a direct risk"),
    Row("SW-SKL-037", "high", "low", "the same pattern as SW-SKL-009 for executables; strict raises"),
    Row("SW-SKL-038", "high", "medium", "a standing instruction that outlives the session: strict raises"),
)
_BY_ID = {row.rule_id: row for row in ROWS}


def severity_of(rule: Rule, name: str) -> str:
    """The severity `rule` has under the preset `name`, or `off`. Under `balanced`, and for a rule without a row (one a later
    release adds before it adds the row), the rule's own severity."""
    if name not in PRESETS:
        raise ValueError(f"unknown preset {name!r}")
    row = _BY_ID.get(rule.id)
    if name == BALANCED or row is None:
        return rule.severity_default
    return row.strict if name == STRICT else row.low_noise


@cache
def changes(name: str) -> Mapping[str, str]:
    """The rules whose severity the preset `name` changes, each with the severity (or `off`) it gives them: the scanner's own
    rules only, and only where the row differs from the rule's own severity. Empty for `balanced`."""
    found = {}
    for rule in RuleSet.baseline():
        target = severity_of(rule, name)
        if rule.id.startswith(PRESET_PREFIXES) and target != rule.severity_default:
            found[rule.id] = target
    return MappingProxyType(found)


def _may_lower(finding: Finding) -> bool:
    """A preset lowers or turns off a medium or low finding only, and never a malicious indicator."""
    return finding.severity in _LOWERABLE and not finding.malicious_indicator


def _moved(row: ReportFinding, severity: str) -> ReportFinding:
    return dataclasses.replace(row, finding=dataclasses.replace(row.finding, severity=severity),
                               preset_from=row.finding.severity)


def apply(report: Report, name: str | None, *, source: str = "flag", origin: str = "--preset") -> Report:
    """`report` under the preset `name`: each finding of a rule `changes(name)` names takes the preset's severity, with
    `preset_from` set to the severity it had, or is left out and counted; then the block `preset` and the notice. A target that
    would lower a high, critical or malicious-indicator finding, or raise nothing, leaves the finding as it is. None or
    `balanced` returns `report` itself. `source` is where the preset was set (`SOURCES`), `origin` how the notice names that
    place (`origin_of`)."""
    if name is None or name == BALANCED:
        return report
    if name not in PRESETS:
        raise ValueError(f"unknown preset {name!r}")
    if source not in SOURCES:
        raise ValueError(f"unknown preset source {source!r}")
    targets = changes(name)
    kept: list[ReportFinding] = []
    lowered = raised = off = 0
    off_rules: set[str] = set()
    for row in report.findings:
        finding = row.finding
        target = targets.get(finding.rule_id)
        if target is None or not finding.rule_id.startswith(PRESET_PREFIXES):
            kept.append(row)
        elif target == OFF:
            if _may_lower(finding):
                off += 1
                off_rules.add(finding.rule_id)
            else:
                kept.append(row)
        elif SEVERITY_RANK[target] < SEVERITY_RANK[finding.severity]:
            raised += 1
            kept.append(_moved(row, target))
        elif SEVERITY_RANK[target] > SEVERITY_RANK[finding.severity] and _may_lower(finding):
            lowered += 1
            kept.append(_moved(row, target))
        else:
            kept.append(row)
    block = {"name": name, "source": source, "changed": lowered + raised, "off": off}
    upload = (report.connected or {}).get("upload")
    uploaded = isinstance(upload, dict) and upload.get("status") == "uploaded"  # skipped or failed: nothing to say of an upload
    text = notice_message(name, origin, off=off, off_rules=len(off_rules), lowered=lowered, raised=raised,
                          connected=uploaded)
    return dataclasses.replace(report, findings=tuple(kept), preset=block,
                               notices=(*report.notices, Notice(NOTICE_CODE, "", text))).sorted()


def _counted(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def notice_message(name: str, origin: str, *, off: int, off_rules: int, lowered: int, raised: int, connected: bool) -> str:
    """The notice `preset`, in every output: what the preset did, that the organisation's parts are applied as they are, when
    a connected run uploaded its results (`connected`) what the upload carries, and the guide."""
    parts = []
    if off:
        parts.append(f"{_counted(off, 'finding', 'findings')} of {_counted(off_rules, 'rule', 'rules')} "
                     f"{'is' if off == 1 else 'are'} not listed")
    for count, verb in ((lowered, "lowered"), (raised, "raised")):
        if count:
            parts.append(f"{_counted(count, 'finding', 'findings')} {'was' if count == 1 else 'were'} {verb}")
    what = " and ".join(parts) if parts else "no finding was changed"
    upload = " The upload to your organisation carries every finding at the rule's own severity." if connected else ""
    return (f"Preset {name} (from {origin}): {what}. The organisation's rules, its registry gate and the baseline file are "
            f"applied as they are.{upload} See {GUIDE_URL}")


def notice_of(report: Report) -> Notice | None:
    """The report's notice `preset`; None without a preset or with `balanced`."""
    return next((notice for notice in report.notices if notice.code == NOTICE_CODE), None)


def change_words(preset_from: str, severity: str, name: str) -> str:
    """How a finding's severity moved, in the words every output uses: `raised from medium by the strict preset`."""
    verb = "raised" if SEVERITY_RANK[severity] < SEVERITY_RANK[preset_from] else "lowered"
    return f"{verb} from {preset_from} by the {name} preset"


def origin_of(source: str, config: str | None) -> str:
    """How the notice names where the preset was set: `--preset`, `SPELLWARDEN_PRESET`, `.spellwarden/config.yml`, or `the
    --config file` (never the path the operator typed: a report holds no absolute path)."""
    if source == "flag":
        return "--preset"
    if source == "environment":
        return "SPELLWARDEN_PRESET"
    return CONFIG_PATH if config is None else "the --config file"


def table_markdown(rules: RuleSet) -> str:
    """The README's table of every row: the rule, its title and default from `rules`, its severity under each preset, why."""
    lines = ["| Rule | Title | Default | strict | low-noise | Why |", "|---|---|---|---|---|---|"]
    for row in ROWS:
        rule = rules.get(row.rule_id)
        lines.append(f"| `{row.rule_id}` | {rule.title} | {rule.severity_default} | {row.strict} | {row.low_noise} "
                     f"| {row.why} |")
    return "\n".join(lines) + "\n"


__all__ = ["BALANCED", "GUIDE_URL", "LOW_NOISE", "NOTICE_CODE", "OFF", "PRESETS", "PRESET_PREFIXES", "ROWS", "SOURCES",
           "STRICT", "Row", "apply", "change_words", "changes", "notice_message", "notice_of", "origin_of", "severity_of",
           "table_markdown"]
