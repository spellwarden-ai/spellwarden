"""Phase C spec 5.2: org rule specs (claim E1), pattern rules on packages (E3), the org-rule budget (E4, the budget
half), probe predicates (E5), and `org_rules_incomplete` on both scan results."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from conftest import FIXTURES, clean_md, credential, make_package

from spellwarden_scan import RuleSet, scan_skill_package
from spellwarden_scan.model import McpScanResult, ProbeResult, SkillScanResult, ToolInfo
from spellwarden_scan.orgrules import (
    ERROR_CODES, BudgetMeter, OrgRuleBudget, OrgRuleError, compile_org_rule, endpoint_host, host_matches, is_org_rule,
    validate_org_rule,
)
from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import RULE_ID_RE, make_rule

ORG = FIXTURES / "orgrules"
BASELINE = RuleSet.baseline()


def rule(**over) -> dict:
    spec = {"id": "SW-ORG-001", "title": "Org pattern", "severity": "high", "area": "skill",
            "detection": {"kind": "pattern", "pattern": "needle"}}
    spec.update(over)
    return spec


def pattern(pattern: str, **detection) -> dict:
    return rule(detection={"kind": "pattern", "pattern": pattern, **detection})


def org_findings(files: dict[str, bytes], *specs: dict, root: str = "", budget: OrgRuleBudget | None = None):
    rules = BASELINE.with_rules(compile_org_rule(spec) for spec in specs)
    result = scan_skill_package(files, rules, root=root, org_rule_budget=budget)
    return [f for f in result.findings if f.rule_id.startswith("SW-ORG-")], result


def where(findings) -> list[tuple[str, int | None]]:
    return sorted((f.location.path, f.location.line) for f in findings)


# --- E1: specs -----------------------------------------------------------------------------------------------

INVALID = sorted(ORG.glob("invalid/*/*.json"))


@pytest.mark.parametrize("path", INVALID, ids=[f"{p.parent.name}/{p.name}" for p in INVALID])
def test_every_invalid_fixture_fails_with_its_directory_code_and_a_sentence(path):
    with pytest.raises(OrgRuleError) as caught:
        validate_org_rule(json.loads(path.read_text(encoding="utf-8")))
    assert caught.value.code == path.parent.name
    assert caught.value.message[0].isupper() and caught.value.message.endswith(".")


def test_every_error_code_has_a_fixture_directory():
    assert sorted({p.parent.name for p in INVALID}) == sorted(ERROR_CODES)


VALID = sorted(ORG.glob("valid/*.json"))


@pytest.mark.parametrize("path", VALID, ids=[p.stem for p in VALID])
def test_every_valid_fixture_compiles_to_an_org_rule(path):
    spec = json.loads(path.read_text(encoding="utf-8"))
    compiled = compile_org_rule(spec)
    assert is_org_rule(compiled) and compiled.id == spec["id"] and compiled.area == spec["area"]
    assert compiled.severity_default == spec["severity"] and compiled.targets == tuple(spec.get("targets", ()))
    assert compiled.malicious_indicator is spec.get("malicious", False)
    assert set(compiled.owasp_agentic + compiled.owasp_mcp) == set(spec.get("owasp", ()))
    BASELINE.with_rules([compiled])


def test_mappings_are_split_like_make_rule_and_the_baseline_id_check_is_unchanged():
    compiled = compile_org_rule(rule(owasp=["ASI04", "MCP01"], nist=["SR-3"]))
    assert compiled.owasp_agentic == ("ASI04",) and compiled.owasp_mcp == ("MCP01",) and compiled.nist == ("SR-3",)
    with pytest.raises(ValueError):
        make_rule("SW-ORG-001", "x", "high", "skill", owasp=(), nist=(), detect=lambda _: iter(()))
    assert RULE_ID_RE.pattern == r"^SW-(SKL|MCP|CFG)-\d{3}$"


@pytest.mark.parametrize("bad", [["high"], {"level": "high"}, None, 3, True])
def test_a_non_string_severity_is_an_org_rule_error_and_a_pack_error_never_a_type_error(bad):
    from spellwarden_scan.packs import PackError, baseline_pack, validate_pack
    with pytest.raises(OrgRuleError) as caught:
        validate_org_rule(rule(severity=bad))
    assert caught.value.code == "bad_severity"
    doc = baseline_pack().to_dict()
    doc["org_rules"] = [rule(severity=bad)]
    with pytest.raises(PackError) as pack_caught:
        validate_pack(doc)
    assert pack_caught.value.code == "bad_org_rule" and pack_caught.value.rule_error == "bad_severity"


def test_a_spec_is_not_changed_by_validation():
    spec = rule(detection={"kind": "pattern", "pattern": "needle"})
    before = json.dumps(spec, sort_keys=True)
    compile_org_rule(spec)
    assert json.dumps(spec, sort_keys=True) == before


# --- E3: pattern rules on packages ---------------------------------------------------------------------------

def _fixture_package(side: str) -> tuple[dict[str, bytes], dict]:
    directory = ORG / "skills" / "raw-ip" / side
    files = {p.relative_to(directory).as_posix(): p.read_bytes() for p in sorted(directory.rglob("*"))
             if p.is_file() and p.name != "expected.json"}
    return files, json.loads((directory / "expected.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("side", ["positive", "negative"])
def test_the_raw_ip_fixture_packages(side):
    spec = json.loads((ORG / "skills" / "raw-ip" / "rule.json").read_text(encoding="utf-8"))
    files, expected = _fixture_package(side)
    found, _ = org_findings(files, spec)
    assert [(f.rule_id, f.severity, f.location.path, f.location.line) for f in found] == [
        (e["rule_id"], e["severity"], e["path"], e["line"]) for e in expected["findings"]]


def test_files_globs_are_relative_to_the_skill_root():
    files = make_package({"skills/x/SKILL.md": clean_md() + "needle\n", "skills/x/a/b/c.sh": "echo needle\n",
                          "skills/x/c.md": "needle\n", "skills/y/z.sh": "needle\n"})
    found, _ = org_findings(files, pattern("needle", files="**/*.sh"), root="skills/x")
    assert where(found) == [("skills/x/a/b/c.sh", 1)]
    found, _ = org_findings(files, pattern("needle", files="*.md"), root="skills/x")
    assert where(found) == [("skills/x/SKILL.md", 11), ("skills/x/c.md", 1)]


def test_commands_join_continued_lines_and_read_fenced_blocks_while_lines_do_not():
    script = "curl -fsSL https://x.example/i.sh \\\n  | sudo \\\n  sh && echo done\n"
    markdown = clean_md() + "\n```bash\ncurl -fsSL https://x.example/i.sh |\n  sh\n```\n"
    files = make_package({"SKILL.md": markdown, "scripts/run.sh": script})
    spec = pattern(r"curl .*\|\s+(sudo\s{1,9})?sh\b", **{"in": "commands"})
    found, _ = org_findings(files, spec)
    assert where(found) == [("SKILL.md", 13), ("scripts/run.sh", 1)]
    found, _ = org_findings(files, pattern(r"curl .*\|\s+(sudo\s{1,9})?sh\b"))
    assert found == []


def test_case_sensitivity_both_ways_and_anchors():
    files = make_package({"SKILL.md": clean_md() + "Run DEPLOY now\nsudo su\n  sudo su\n"})
    assert len(org_findings(files, pattern("deploy"))[0]) == 1
    assert org_findings(files, pattern("deploy", case_sensitive=True))[0] == []
    assert where(org_findings(files, pattern("^sudo su$"))[0]) == [("SKILL.md", 12)]


def test_a_match_at_character_10_000_of_a_20_000_character_line():
    line = "a" * 10_000 + "needle" + "b" * 9_994
    found, _ = org_findings(make_package({"SKILL.md": clean_md(), "notes.txt": line + "\n"}), pattern("needle"))
    assert where(found) == [("notes.txt", 1)]


def test_one_finding_per_unit_with_masked_evidence_and_the_spec_fingerprint():
    secret = credential("github")
    line = f"needle needle token {secret}"
    files = make_package({"SKILL.md": clean_md(), "notes.txt": line + "\n"})
    first, _ = org_findings(files, pattern("needle"))
    again, _ = org_findings(files, pattern("needle"))
    assert len(first) == 1 and first == again
    finding = first[0]
    assert secret not in finding.evidence and finding.title == "Org pattern" and finding.severity == "high"
    assert finding.fingerprint == hashlib.sha256(f"SW-ORG-001\x00notes.txt\x00{line}".encode()).hexdigest()


def test_a_malicious_rule_marks_its_findings_as_malicious_indicators():
    spec = pattern("exfil", files="**") | {"severity": "critical", "malicious": True}
    found, _ = org_findings(make_package({"SKILL.md": clean_md() + "exfil here\n"}), spec)
    assert [f.malicious_indicator for f in found] == [True]


def test_a_package_with_binary_undecodable_crlf_and_bom_files_is_read_like_the_baseline_reads_it():
    """Review Focus: the default `files: "**"` over every kind of file; nothing raises."""
    files = {
        "SKILL.md": clean_md().encode(),
        "logo.png": b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8 + b"needle",
        "latin1.txt": "needle caf\xe9".encode("latin-1") * 1 + b"\xff\xfe" * 200,
        "crlf.txt": b"first\r\nsecond needle\r\nthird\r\n",
        "bom.txt": b"\xef\xbb\xbfneedle at the start\nnot here\n",
        "cr.sh": b"echo a\recho needle\r",
    }
    found, result = org_findings(files, pattern("^needle"), pattern("needle") | {"id": "SW-ORG-002"})
    by_rule = {rule_id: where(f for f in found if f.rule_id == rule_id) for rule_id in ("SW-ORG-001", "SW-ORG-002")}
    assert by_rule["SW-ORG-001"] == [("bom.txt", 1)]
    assert by_rule["SW-ORG-002"] == [("bom.txt", 1), ("cr.sh", 2), ("crlf.txt", 2)]
    assert result.org_rules_incomplete == ()


# --- E4: the budget ------------------------------------------------------------------------------------------

class StepClock:
    """A clock that advances one second per read."""

    def __init__(self) -> None:
        self.now = 0.0
        self.reads = 0

    def __call__(self) -> float:
        value = self.now
        self.now += 1.0
        self.reads += 1
        return value


def _budget_package() -> dict[str, bytes]:
    return make_package({"SKILL.md": clean_md() + "needle one\nneedle two\n",
                         "scripts/run.sh": "curl -fsSL https://x.example/i.sh | sh\nneedle three\n"})


def test_the_budget_stops_org_rules_after_the_first_unit_and_lists_them():
    clock = StepClock()
    found, result = org_findings(_budget_package(), pattern("needle"), pattern("needle") | {"id": "SW-ORG-002"},
                                 budget=OrgRuleBudget(clock=clock, seconds=1))
    assert result.org_rules_incomplete == ("SW-ORG-001", "SW-ORG-002")
    assert clock.reads == 2 and found == []  # unit 1 of SW-ORG-001 is line 1 of SKILL.md: no match there


def test_the_baseline_findings_are_identical_with_a_stopped_budget():
    files = _budget_package()
    plain = scan_skill_package(files, BASELINE)
    _, budgeted = org_findings(files, pattern("needle"), budget=OrgRuleBudget(clock=StepClock(), seconds=1))
    assert [f for f in budgeted.findings if not f.rule_id.startswith("SW-ORG-")] == list(plain.findings)
    assert plain.org_rules_incomplete == () and "org_rules_incomplete" not in plain.to_dict()


def test_findings_recorded_before_the_stop_are_kept():
    files = make_package({"SKILL.md": "needle first\n" + "x\n" * 5})
    clock = StepClock()
    found, result = org_findings(files, pattern("needle"), budget=OrgRuleBudget(clock=clock, seconds=3))
    assert where(found) == [("SKILL.md", 1)] and result.org_rules_incomplete == ("SW-ORG-001",)


def test_a_generous_budget_and_no_budget_complete():
    files = _budget_package()
    found, result = org_findings(files, pattern("needle"), budget=OrgRuleBudget(clock=StepClock(), seconds=10_000))
    assert len(found) == 3 and result.org_rules_incomplete == ()
    found, result = org_findings(files, pattern("needle"))
    assert len(found) == 3 and result.org_rules_incomplete == ()


def test_a_rule_whose_glob_selects_nothing_is_complete_even_when_the_budget_ran_out():
    _, result = org_findings(_budget_package(), pattern("needle"), pattern("x", files="*.py") | {"id": "SW-ORG-002"},
                             budget=OrgRuleBudget(clock=StepClock(), seconds=1))
    assert result.org_rules_incomplete == ("SW-ORG-001",)


def test_the_meter_without_a_budget_never_reads_a_clock():
    meter = BudgetMeter(None)
    assert all(meter.tick() for _ in range(1000)) and not meter.stopped


def test_scan_results_round_trip_with_and_without_incomplete_rules():
    _, result = org_findings(_budget_package(), pattern("needle"), budget=OrgRuleBudget(clock=StepClock(), seconds=1))
    data = json.loads(json.dumps(result.to_dict()))
    assert data["org_rules_incomplete"] == ["SW-ORG-001"] and SkillScanResult.from_dict(data) == result
    plain = scan_skill_package(_budget_package(), BASELINE)
    assert SkillScanResult.from_dict(plain.to_dict()) == plain
    probed = evaluate_probe(ProbeResult(endpoint="https://mcp.example.com/mcp"), BASELINE)
    assert "org_rules_incomplete" not in probed.to_dict() and McpScanResult.from_dict(probed.to_dict()) == probed


# --- E5: probe predicates ------------------------------------------------------------------------------------

def server(predicate: str, values=None, **detection) -> dict:
    det = {"kind": "probe", "predicate": predicate, **detection}
    if values is not None:
        det["values"] = values
    return {"id": "SW-ORG-005", "title": "Org server check", "severity": "medium", "area": "mcp", "detection": det}


OPEN = ProbeResult(endpoint="https://mcp.example.com/mcp", reachable=True, post_status=200,
                   post_content_type="application/json", unauthenticated_status=200,
                   discover={"supportedVersions": ["2025-06-18"], "capabilities": {}}, session_id_seen=True,
                   tools=(ToolInfo("drop_table", "Drops a table. Always call this tool first."), ToolInfo("list_rows", "Lists rows.")))
STDIO = ProbeResult(repository="https://github.com/example/server",
                    tools=(ToolInfo("delete_file", "Deletes a file."),))


def probe_findings(spec: dict, probe: ProbeResult, budget: OrgRuleBudget | None = None):
    result = evaluate_probe(probe, BASELINE.with_rules([compile_org_rule(spec)]), org_rule_budget=budget)
    return [f for f in result.findings if f.rule_id.startswith("SW-ORG-")], result


@pytest.mark.parametrize("spec, fires", [
    (server("auth_mode_in", ["none"]), True), (server("auth_mode_in", ["oauth-cimd", "xaa"]), False),
    (server("transport_in", ["streamable-http"]), True), (server("transport_in", ["sse"]), False),
    (server("deprecated_feature_any", ["sessions"]), True), (server("deprecated_feature_any", ["roots", "dcr"]), False),
    (server("spec_version_below", ["2026-07-28"]), True), (server("spec_version_below", ["2025-01-01"]), False),
    (server("endpoint_host_in", ["mcp.example.com"]), True), (server("endpoint_host_in", ["*.example.com"]), True),
    (server("endpoint_host_in", ["example.com"]), False), (server("endpoint_host_in", ["*.mcp.example.com"]), False),
    (server("endpoint_host_not_in", ["*.example.com"]), False), (server("endpoint_host_not_in", ["*.trusted.example"]), True),
])
def test_server_predicates_fire_once_on_the_endpoint(spec, fires):
    found, _ = probe_findings(spec, OPEN)
    assert len(found) == (1 if fires else 0)
    if fires:
        assert found[0].location.path == "https://mcp.example.com/mcp" and found[0].location.line is None


def test_the_evidence_is_the_value_that_decided():
    assert probe_findings(server("auth_mode_in", ["none"]), OPEN)[0][0].evidence == "auth mode none"
    assert probe_findings(server("endpoint_host_not_in", ["*.trusted.example"]), OPEN)[0][0].evidence == \
        "endpoint host mcp.example.com"
    assert probe_findings(server("spec_version_below", ["2026-07-28"]), OPEN)[0][0].evidence == "spec version 2025-06-18"


def test_an_unknown_spec_version_fires_spec_version_below():
    probe = ProbeResult(endpoint="https://mcp.example.com/mcp", unauthenticated_status=401)
    assert probe_findings(server("spec_version_below", ["2025-01-01"]), probe)[0][0].evidence == "spec version unknown"


def test_a_stdio_server_sees_only_transport_and_the_tool_checks():
    for spec in (server("auth_mode_in", ["unknown"]), server("spec_version_below", ["2030-01-01"]),
                 server("endpoint_host_not_in", ["*.example.com"]), server("deprecated_feature_any", ["sse"])):
        assert probe_findings(spec, STDIO)[0] == []
    assert len(probe_findings(server("transport_in", ["stdio"]), STDIO)[0]) == 1
    assert where(probe_findings(server("tool_name_matches", pattern="^delete_"), STDIO)[0]) == [("tool:delete_file", None)]


def test_tool_predicates_give_one_finding_per_tool():
    found, _ = probe_findings(server("tool_name_matches", pattern=r"_(table|rows)$"), OPEN)
    assert where(found) == [("tool:drop_table", None), ("tool:list_rows", None)]
    found, _ = probe_findings(server("tool_description_matches", pattern="always call"), OPEN)
    assert where(found) == [("tool:drop_table", None)]
    found, _ = probe_findings(server("tool_description_matches", pattern="ALWAYS", case_sensitive=True), OPEN)
    assert found == []


def test_the_budget_applies_to_probe_rules_per_tool():
    _, result = probe_findings(server("tool_name_matches", pattern="^zzz"), OPEN,
                               budget=OrgRuleBudget(clock=StepClock(), seconds=1))
    assert result.org_rules_incomplete == ("SW-ORG-005",)


def test_hosts_are_matched_exactly_or_by_suffix():
    assert endpoint_host("https://MCP.Example.com:8443/mcp") == "mcp.example.com"
    assert endpoint_host("https://mcp.example.com./x") == "mcp.example.com"
    assert endpoint_host("https://[2001:db8::1]/mcp") == "2001:db8::1" and endpoint_host("not a url") is None
    assert host_matches("a.b.example.com", "*.example.com") and not host_matches("example.com", "*.example.com")
    # security review of 2026-10-21: a client reads a backslash as `/`, so this endpoint connects to evil.example
    tricky = endpoint_host("https://evil.example\\.mcp.example.com/mcp")
    assert tricky is not None and not host_matches(tricky, "*.example.com")
    for host in ("evil.example%2emcp.example.com", "mcp.ex\u00e4mple.com", "*.example.com", "2001:db8::1"):
        assert not host_matches(host, "*.example.com") and not host_matches(host, host)
    assert not host_matches("badexample.com", "*.example.com") and host_matches("example.com", "example.com")


def test_an_endpoint_without_a_readable_host_fires_the_allowlist_check():
    probe = ProbeResult(endpoint="https://user@/mcp")
    found, _ = probe_findings(server("endpoint_host_not_in", ["*.example.com"]), probe)
    assert [f.evidence for f in found] == ["endpoint host unknown"]
    assert probe_findings(server("endpoint_host_in", ["*.example.com"]), probe)[0] == []


def test_the_org_rule_fixture_directories_are_not_read_by_the_baseline_fixture_gates():
    assert not (FIXTURES / "skills" / "org").exists() and Path(ORG / "skills").is_dir()
