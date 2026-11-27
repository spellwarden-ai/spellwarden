"""1.18.0 presets: the table of `spellwarden_cli.presets` (one row per baseline rule, and the rules every row keeps), `apply` (every
row, and what a preset never changes: organisation rules, the registry gate, a high or critical finding, a malicious indicator,
the baseline's acceptances, the errors), the notice and the JSON report's `preset` block, the settings (flag over environment
over file, unknown values refused) and the two schemas."""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
from conftest import cyclonedx_problems, write_tree
from jsonschema import Draft202012Validator

from spellwarden_scan import RULES_VERSION, SEVERITY_RANK, Finding, Location, RuleSet, __version__
from spellwarden_scan.evidence import fingerprint

from spellwarden_cli import presets
from spellwarden_cli.output import FORMATS
from spellwarden_cli.report import LockState, Notice, Report, ReportFinding, to_json_dict
from spellwarden_cli.settings import Flags, SettingsError, load_settings

RULES = RuleSet.baseline()
SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
CONFIG = ".spellwarden/config.yml"
TAIL = ("The organisation's rules, its registry gate and the baseline file are applied as they are. "
        f"See {presets.GUIDE_URL}")


def finding(rule_id: str, severity: str | None = None, path: str = "skills/demo/scripts/run.sh", line: int | None = 2, *,
            malicious: bool | None = None) -> Finding:
    rule = RULES.get(rule_id)
    evidence = f"evidence of {rule_id} in {path}"
    return Finding(rule_id, severity or (rule.severity_default if rule else "medium"),
                   rule.title if rule else "Mentions the staging bastion", Location(path, line), evidence,
                   fingerprint(rule_id, path, evidence),
                   (rule.malicious_indicator if rule else False) if malicious is None else malicious)


def report_of(findings, *, errors=(), fail_on: str = "high", connected: dict | None = None,
              accepted: frozenset[str] = frozenset()) -> Report:
    rows = tuple(ReportFinding(f, f.location.path.rsplit("/", 1)[0], f.fingerprint in accepted,
                               {"reason": "Reviewed.", "added": "2026-11-01", "expires": "2027-01-31"}
                               if f.fingerprint in accepted else None) for f in findings)
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of="2026-11-17", fail_on=fail_on, items=(),
                  findings=rows, probes=(), lock=LockState(), notices=(), errors=tuple(errors), repo_prefix="", rules=RULES,
                  connected=connected).sorted()


def applied(findings, name: str, *, source: str = "flag", origin: str = "--preset", **more) -> Report:
    return presets.apply(report_of(findings, **more), name, source=source, origin=origin)


def message(report: Report) -> str:
    notice = presets.notice_of(report)
    assert notice is not None
    return notice.message


# --- the table --------------------------------------------------------------------------------------------------------

def test_every_baseline_rule_has_exactly_one_row():
    ids = [row.rule_id for row in presets.ROWS]
    assert ids == sorted(ids) and len(ids) == len(set(ids))
    assert set(ids) == {rule.id for rule in RULES}  # a rule a release adds without a row fails here (E-12)


def test_every_row_holds_valid_values_and_keeps_the_rules_of_the_table():
    for row in presets.ROWS:
        rule = RULES.get(row.rule_id)
        default = SEVERITY_RANK[rule.severity_default]
        assert row.strict in SEVERITY_RANK and SEVERITY_RANK[row.strict] <= default, row  # strict raises or keeps, never off
        assert row.low_noise in (*SEVERITY_RANK, presets.OFF), row
        if row.low_noise != presets.OFF:
            assert SEVERITY_RANK[row.low_noise] >= default, row  # low-noise lowers or keeps
        if rule.severity_default in ("critical", "high") or rule.malicious_indicator or rule.id.startswith("SW-REG-"):
            assert row.low_noise == rule.severity_default, row
        if rule.id.startswith("SW-REG-"):
            assert row.strict == rule.severity_default, row
        assert row.why and "|" not in row.why, row


def test_severity_of_reads_the_row_and_balanced_is_every_rules_own_severity():
    for row in presets.ROWS:
        rule = RULES.get(row.rule_id)
        assert presets.severity_of(rule, presets.STRICT) == row.strict
        assert presets.severity_of(rule, presets.LOW_NOISE) == row.low_noise
        assert presets.severity_of(rule, presets.BALANCED) == rule.severity_default
    assert dict(presets.changes(presets.BALANCED)) == {}


def test_a_rule_without_a_row_is_balanced_in_every_preset():
    rule = dataclasses.replace(RULES.get("SW-SKL-009"), id="SW-SKL-099")
    assert {name: presets.severity_of(rule, name) for name in presets.PRESETS} == dict.fromkeys(presets.PRESETS, "medium")


def test_an_unknown_preset_name_is_refused():
    with pytest.raises(ValueError):
        presets.severity_of(RULES.get("SW-SKL-009"), "loud")
    with pytest.raises(ValueError):
        presets.apply(report_of([]), "loud")


def test_changes_name_only_the_scanners_own_rules_whose_row_differs():
    for name in (presets.STRICT, presets.LOW_NOISE):
        for rule_id, target in presets.changes(name).items():
            assert rule_id.startswith(presets.PRESET_PREFIXES) and target != RULES.get(rule_id).severity_default


def test_the_markdown_table_lists_every_row():
    lines = presets.table_markdown(RULES).splitlines()
    assert lines[:2] == ["| Rule | Title | Default | strict | low-noise | Why |", "|---|---|---|---|---|---|"]
    assert len(lines) == 2 + len(presets.ROWS)
    first = presets.ROWS[0]
    rule = RULES.get(first.rule_id)
    assert lines[2] == (f"| `{first.rule_id}` | {rule.title} | {rule.severity_default} | {first.strict} | {first.low_noise} "
                        f"| {first.why} |")
    assert lines[2].startswith("| `SW-A2A-001` | Agent card does not follow A2A 1.0 | medium | ")


# --- apply ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", [presets.STRICT, presets.LOW_NOISE])
def test_apply_gives_each_rule_exactly_the_severity_of_its_row(name):
    rules = [rule for rule in RULES if rule.id.startswith(presets.PRESET_PREFIXES)]
    after = presets.apply(report_of([finding(rule.id) for rule in rules]), name)
    by_rule = {row.finding.rule_id: row for row in after.findings}
    for rule in rules:
        target = presets.severity_of(rule, name)
        if target == presets.OFF:
            assert rule.id not in by_rule, rule.id
        elif target == rule.severity_default:
            assert (by_rule[rule.id].finding.severity, by_rule[rule.id].preset_from) == (target, None), rule.id
        else:
            assert (by_rule[rule.id].finding.severity, by_rule[rule.id].preset_from) == (target, rule.severity_default), rule.id


@pytest.mark.parametrize("name", presets.PRESETS)
def test_organisation_rules_and_the_registry_gate_are_never_changed(name):
    before = report_of([finding("SW-ORG-010", "medium"), finding("SW-ORG-011", "low", path="skills/demo/SKILL.md"),
                        finding("SW-REG-001", path="skills/demo"), finding("SW-REG-003", path="skills/other")])
    assert presets.apply(before, name).findings == before.findings


def test_a_high_or_critical_finding_and_a_malicious_indicator_are_never_lowered():
    findings = [finding("SW-SKL-009", "high"),  # a medium rule's finding graded high
                finding("SW-SKL-031", "medium", path="skills/demo/SKILL.md", malicious=True),
                finding("SW-SKL-006", "critical", path="skills/demo/scripts/clean.sh")]
    after = applied(findings, presets.LOW_NOISE)
    assert after.findings == report_of(findings).findings
    assert message(after) == "Preset low-noise (from --preset): no finding was changed. " + TAIL
    raised = applied([finding("SW-SKL-009", "critical")], presets.STRICT)  # strict never lowers either
    assert [row.finding.severity for row in raised.findings] == ["critical"]


def test_errors_stay_and_an_incomplete_scan_stays_exit_2():
    error = Notice("duplicate_key", ".mcp.json", "the key a is repeated")
    for name in (presets.STRICT, presets.LOW_NOISE):
        after = applied([finding("SW-SKL-031", path="skills/demo/SKILL.md")], name, errors=[error])
        assert after.errors == (error,) and after.exit_code() == 2


@pytest.mark.usefixtures("example_rows")
def test_the_baselines_acceptance_is_kept_by_fingerprint():
    accepted = finding("SW-SKL-009")
    after = applied([accepted], presets.STRICT, accepted=frozenset({accepted.fingerprint}))
    (row,) = after.findings
    assert row.suppressed and row.baseline["reason"] == "Reviewed."
    assert (row.finding.severity, row.preset_from, row.finding.fingerprint) == ("high", "medium", accepted.fingerprint)
    assert after.exit_code() == 0


@pytest.mark.parametrize("name", [None, presets.BALANCED])
def test_no_preset_and_balanced_return_the_report_itself(name):
    before = report_of([finding("SW-SKL-009"), finding("SW-SKL-031", path="skills/demo/SKILL.md")])
    assert presets.apply(before, name) is before
    document = to_json_dict(before)
    assert "preset" not in document and all("preset_from" not in entry for entry in document["findings"])


@pytest.mark.usefixtures("example_rows")
def test_the_exit_code_follows_the_presets_severities():
    medium = [finding("SW-SKL-009")]
    assert report_of(medium).exit_code() == 0 and applied(medium, presets.STRICT).exit_code() == 1
    assert report_of(medium, fail_on="medium").exit_code() == 1
    assert applied(medium, presets.LOW_NOISE, fail_on="medium").exit_code() == 0


# --- the notice and the block -----------------------------------------------------------------------------------------

@pytest.mark.usefixtures("example_rows")
def test_the_notice_and_the_block_count_what_low_noise_did():
    findings = [finding("SW-SKL-031", path="a/SKILL.md", line=1), finding("SW-SKL-031", path="b/SKILL.md", line=1),
                finding("SW-SKL-015", path="c/SKILL.md", line=1), finding("SW-SKL-009", path="a/run.sh"),
                finding("SW-SKL-009", path="b/run.sh"), finding("SW-SKL-006", path="c/run.sh")]
    after = applied(findings, presets.LOW_NOISE, source="file", origin=CONFIG)
    assert after.preset == {"name": "low-noise", "source": "file", "changed": 3, "off": 3}
    assert message(after) == ("Preset low-noise (from .spellwarden/config.yml): 3 findings of 2 rules are not listed and 3 "
                              "findings were lowered. " + TAIL)
    assert [row.finding.rule_id for row in after.findings] == ["SW-SKL-006", "SW-SKL-009", "SW-SKL-009"]
    document = to_json_dict(after)
    assert document["preset"] == after.preset and [entry["code"] for entry in document["notices"]] == ["preset"]
    assert all(entry["preset_from"] == "medium" and entry["severity"] == "low" for entry in document["findings"])


@pytest.mark.usefixtures("example_rows")
def test_the_notice_in_the_singular_for_strict_and_for_no_change():
    one = applied([finding("SW-SKL-031", path="a/SKILL.md", line=1), finding("SW-SKL-009")], presets.LOW_NOISE,
                  source="environment", origin="SPELLWARDEN_PRESET")
    assert message(one) == ("Preset low-noise (from SPELLWARDEN_PRESET): 1 finding of 1 rule is not listed and 1 finding was "
                            "lowered. " + TAIL)
    raised = applied([finding("SW-SKL-009"), finding("SW-SKL-006", path="c/run.sh")], presets.STRICT)
    assert message(raised) == "Preset strict (from --preset): 2 findings were raised. " + TAIL
    assert raised.preset == {"name": "strict", "source": "flag", "changed": 2, "off": 0}
    unchanged = applied([finding("SW-SKL-001", path="a/SKILL.md")], presets.LOW_NOISE)
    assert message(unchanged) == "Preset low-noise (from --preset): no finding was changed. " + TAIL


@pytest.mark.usefixtures("example_rows")
def test_in_connected_mode_the_notice_says_what_the_upload_carries():
    uploaded = {"credential": "oidc", "upload": {"status": "uploaded", "attested": True}}
    after = applied([finding("SW-SKL-009")], presets.STRICT, connected=uploaded)
    assert message(after) == ("Preset strict (from --preset): 1 finding was raised. The organisation's rules, its registry gate "
                              "and the baseline file are applied as they are. The upload to your organisation carries every "
                              f"finding at the rule's own severity. See {presets.GUIDE_URL}")


@pytest.mark.usefixtures("example_rows")
@pytest.mark.parametrize("upload", [{"status": "skipped", "reason": "disabled"}, {"status": "skipped", "reason": "local"},
                                    {"status": "skipped", "reason": "branch"}, {"status": "failed", "error": "http_503"},
                                    None])
def test_without_an_upload_the_notice_says_nothing_about_one(upload):
    connected = {"credential": "key"} if upload is None else {"credential": "key", "upload": upload}
    after = applied([finding("SW-SKL-009")], presets.STRICT, connected=connected)
    assert message(after) == "Preset strict (from --preset): 1 finding was raised. " + TAIL
    assert "upload" not in message(after)


def test_change_words_and_origins():
    assert presets.change_words("medium", "high", "strict") == "raised from medium by the strict preset"
    assert presets.change_words("medium", "low", "low-noise") == "lowered from medium by the low-noise preset"
    assert presets.origin_of("flag", None) == "--preset"
    assert presets.origin_of("environment", "x.yml") == "SPELLWARDEN_PRESET"
    assert presets.origin_of("file", None) == CONFIG
    assert presets.origin_of("file", "/home/someone/operator.yml") == "the --config file"


# --- the settings (E-13) ----------------------------------------------------------------------------------------------

def _load(tmp_path, text=None, *, flags=None, env=None, config=None):
    if text is not None:
        write_tree(tmp_path, {CONFIG: text})
    return load_settings(str(tmp_path), config=config, flags=flags or Flags(), env=env or {})


def test_no_preset_by_default(tmp_path):
    settings = _load(tmp_path)
    assert (settings.preset, settings.preset_source, settings.preset_origin) == (None, None, None)


def test_flag_over_environment_over_file(tmp_path):
    write_tree(tmp_path, {CONFIG: "version: 1\npreset: low-noise\n"})
    file_only = _load(tmp_path)
    assert (file_only.preset, file_only.preset_source, file_only.preset_origin) == ("low-noise", "file", CONFIG)
    env = _load(tmp_path, env={"SPELLWARDEN_PRESET": "strict"})
    assert (env.preset, env.preset_source, env.preset_origin) == ("strict", "environment", "SPELLWARDEN_PRESET")
    flag = _load(tmp_path, flags=Flags(preset="balanced"), env={"SPELLWARDEN_PRESET": "strict"})
    assert (flag.preset, flag.preset_source, flag.preset_origin) == ("balanced", "flag", "--preset")
    assert _load(tmp_path, env={"SPELLWARDEN_PRESET": "  "}).preset == "low-noise"  # empty: not set


def test_a_config_file_is_named_without_its_path(tmp_path):
    chosen = tmp_path / "operator.yml"
    chosen.write_text("version: 1\npreset: strict\n", encoding="utf-8")
    settings = _load(tmp_path, config=str(chosen))
    assert (settings.preset, settings.preset_source, settings.preset_origin) == ("strict", "file", "the --config file")


@pytest.mark.parametrize("text", ["version: 1\npreset: loud\n", "version: 1\npreset: true\n", "version: 1\npreset: [strict]\n"])
def test_an_unknown_preset_in_the_file_is_settings_invalid(tmp_path, text):
    with pytest.raises(SettingsError) as caught:
        _load(tmp_path, text)
    assert "`preset` must be one of strict, balanced, low-noise" in str(caught.value) and CONFIG in str(caught.value)


def test_an_unknown_preset_in_the_environment_or_the_flags_is_refused(tmp_path):
    with pytest.raises(SettingsError, match="SPELLWARDEN_PRESET: 'loud' is not one of strict, balanced, low-noise"):
        _load(tmp_path, env={"SPELLWARDEN_PRESET": "loud"})
    with pytest.raises(SettingsError, match="--preset"):
        _load(tmp_path, flags=Flags(preset="loud"))


# --- the schemas (E-16) -----------------------------------------------------------------------------------------------

def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def test_the_settings_schema_takes_the_three_presets_and_refuses_any_other():
    validator = _validator("settings")
    assert validator.schema["properties"]["preset"]["enum"] == list(presets.PRESETS)
    for name in presets.PRESETS:
        validator.validate({"version": 1, "preset": name})
    assert not validator.is_valid({"version": 1, "preset": "loud"})


def test_the_report_schema_takes_a_report_with_and_without_a_preset():
    validator = _validator("report")
    plain = report_of([finding("SW-SKL-009")])
    validator.validate(to_json_dict(plain))
    validator.validate(to_json_dict(presets.apply(plain, presets.STRICT, source="environment", origin="SPELLWARDEN_PRESET")))
    bad = to_json_dict(presets.apply(plain, presets.STRICT))
    bad["preset"]["name"] = "balanced"
    assert not validator.is_valid(bad)


def test_reports_written_by_earlier_releases_still_validate():
    golden = Path(__file__).resolve().parents[1] / "golden"
    for path in (golden / "1.13.0" / "out" / "report.json", golden / "1.0.0" / "out" / "report.json"):
        _validator("report").validate(json.loads(path.read_text(encoding="utf-8")))


# --- every output (Task 2) --------------------------------------------------------------------------------------------

def strict_report(*, connected: dict | None = None) -> Report:
    return applied([finding("SW-SKL-009", path="skills/demo/scripts/setup.sh"),
                    finding("SW-SKL-031", path="skills/demo/SKILL.md", line=1)], presets.STRICT, connected=connected)


def off_report() -> Report:
    """low-noise turns the one finding off: nothing is left to list."""
    return applied([finding("SW-SKL-031", path="skills/demo/SKILL.md", line=1)], presets.LOW_NOISE, source="environment",
                   origin="SPELLWARDEN_PRESET")


def _sarif_validator():
    vendored = Path(__file__).resolve().parents[1] / "schemas" / "sarif-schema-2.1.0.json"  # tests/schemas, as test_outputs.py
    schema = json.loads(vendored.read_bytes().replace(b"\r\n", b"\n"))
    return jsonschema.validators.validator_for(schema)(schema)


@pytest.mark.usefixtures("example_rows")
def test_the_text_report_prints_the_notice_and_how_a_finding_moved():
    out = FORMATS["text"](strict_report())
    assert f"notice preset : {message(strict_report())}" in out
    assert ("  high SW-SKL-009 skills/demo/scripts/setup.sh:2 Unpinned dependency install "
            "(raised from medium by the strict preset)") in out
    assert ("  medium SW-SKL-031 skills/demo/SKILL.md:1 Missing license and version metadata "
            "(raised from low by the strict preset)") in out


@pytest.mark.usefixtures("example_rows")
def test_the_markdown_report_says_it_under_the_verdict_and_in_the_severity_cell():
    out = FORMATS["markdown"](strict_report())
    body = message(strict_report()).removesuffix(f" See {presets.GUIDE_URL}")
    assert f"**Preset:** {body} [How presets work]({presets.GUIDE_URL})" in out
    assert ("| high (raised from medium by the strict preset) | [SW-SKL-009](https://spellwarden.ai/docs/rules/sw-skl-009"
            "?utm_source=scanner&utm_medium=cli&utm_campaign=rule-docs) |") in out
    assert out.index("**Preset:**") < out.index("| Severity | Rule |")
    assert "(from SPELLWARDEN\\_PRESET)" in FORMATS["markdown"](off_report())


@pytest.mark.usefixtures("example_rows")
def test_sarif_carries_the_block_and_preset_from():
    document = json.loads(FORMATS["sarif"](strict_report()))
    _sarif_validator().validate(document)
    run = document["runs"][0]
    assert run["properties"] == {"preset": {"name": "strict", "source": "flag", "changed": 2, "off": 0}}
    result = next(entry for entry in run["results"] if entry["ruleId"] == "SW-SKL-009")
    assert result["level"] == "error" and result["properties"] == {"preset_from": "medium"}
    plain = json.loads(FORMATS["sarif"](report_of([finding("SW-SKL-009")])))
    assert "properties" not in plain["runs"][0] and all("properties" not in entry for entry in plain["runs"][0]["results"])


@pytest.mark.usefixtures("example_rows")
def test_code_quality_puts_the_notice_in_the_first_entry_or_an_entry_of_its_own():
    issues = json.loads(FORMATS["gitlab-codequality"](strict_report()))
    assert issues[0]["description"].endswith("\n" + message(strict_report()))
    assert all("\n" not in issue["description"] for issue in issues[1:])
    described = next(issue["description"] for issue in issues if issue["check_name"] == "SW-SKL-009")
    assert "(raised from medium by the strict preset)" in described
    (only,) = json.loads(FORMATS["gitlab-codequality"](off_report()))
    assert only == {"description": message(off_report()), "check_name": "spellwarden-preset",
                    "fingerprint": hashlib.sha256(b"spellwarden-preset\nlow-noise").hexdigest(), "severity": "info",
                    "location": {"path": "", "lines": {"begin": 1}}}
    assert json.loads(FORMATS["gitlab-codequality"](report_of([]))) == []


@pytest.mark.usefixtures("example_rows")
def test_cyclonedx_carries_the_preset_properties():
    document = json.loads(FORMATS["cyclonedx"](strict_report()))
    assert cyclonedx_problems(document) == []
    metadata = {(entry["name"], entry["value"]) for entry in document["metadata"]["properties"]}
    assert {("spellwarden:preset", "strict"), ("spellwarden:preset_source", "flag"), ("spellwarden:preset_changed", "2"),
            ("spellwarden:preset_off", "0")} <= metadata
    vulnerability = next(entry for entry in document["vulnerabilities"] if entry["id"] == "SW-SKL-009")
    assert vulnerability["ratings"][0]["severity"] == "high"
    assert {"name": "spellwarden:preset_from", "value": "medium"} in vulnerability["properties"]
    plain = json.loads(FORMATS["cyclonedx"](report_of([finding("SW-SKL-009")])))
    assert not any(entry["name"].startswith("spellwarden:preset") for entry in plain["metadata"]["properties"])


@pytest.mark.usefixtures("example_rows")
@pytest.mark.parametrize("fmt", ["text", "markdown", "json", "gitlab-codequality"])
def test_every_output_counts_the_finding_low_noise_turned_off(fmt):
    assert "1 finding of 1 rule is not listed" in FORMATS[fmt](off_report())


@pytest.mark.usefixtures("example_rows")
def test_sarif_and_cyclonedx_count_it_too():
    assert json.loads(FORMATS["sarif"](off_report()))["runs"][0]["properties"]["preset"]["off"] == 1
    properties = json.loads(FORMATS["cyclonedx"](off_report()))["metadata"]["properties"]
    assert {"name": "spellwarden:preset_off", "value": "1"} in properties


@pytest.mark.parametrize("fmt", ["text", "markdown", "sarif", "gitlab-codequality", "cyclonedx"])
def test_without_a_preset_no_output_changes(fmt):
    plain = report_of([finding("SW-SKL-009"), finding("SW-SKL-031", path="skills/demo/SKILL.md", line=1)])
    assert FORMATS[fmt](presets.apply(plain, presets.BALANCED)) == FORMATS[fmt](plain)
    assert "preset" not in FORMATS[fmt](plain).lower()


# --- spellwarden rules --preset ---------------------------------------------------------------------------------------

@pytest.mark.usefixtures("example_rows")
def test_rules_prints_each_rule_under_a_preset(run_cli):
    code, out, _ = run_cli(["rules", "--preset", "low-noise"])
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == len(RULES)
    by_id = {line.split()[0]: line for line in lines}
    for rule in RULES:
        assert by_id[rule.id].split()[1] == presets.severity_of(rule, "low-noise"), rule.id
    assert by_id["SW-SKL-031"] == f"SW-SKL-031  {'off':<8}  Missing license and version metadata"
    assert run_cli(["rules", "--preset", "balanced"])[1] == run_cli(["rules"])[1]


@pytest.mark.usefixtures("example_rows")
def test_rules_json_and_markdown_name_the_preset(run_cli):
    code, out, _ = run_cli(["rules", "--preset", "strict", "--format", "json"])
    entries = json.loads(out)
    assert code == 0 and len(entries) == len(RULES)
    assert all(entry["preset"] == {"name": "strict", "severity": presets.severity_of(RULES.get(entry["id"]), "strict")}
               for entry in entries)
    code, out, _ = run_cli(["rules", "--preset", "strict", "--format", "markdown"])
    assert code == 0 and out.splitlines()[:2] == ["| Id | Title | Default | strict |", "|---|---|---|---|"]
    assert "| SW-SKL-009 | Unpinned dependency install | medium | high |" in out
    assert run_cli(["rules", "--preset", "loud"])[0] == 2
