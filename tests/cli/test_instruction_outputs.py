"""Phase 3 batch 1 spec 10.4 and claim T-47 (outputs): the findings of an instruction file are reported in text, JSON, SARIF,
Markdown and Code Quality, each with when the agent applies the file; a report without an instruction file is as it was."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from instruction_fixture import FILES, INJECTION, PLAIN

SARIF_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "sarif-schema-2.1.0.json"
SCOPES = {
    "AGENTS.md": "Applied: always",
    "docs/CLAUDE.md": "Applied: always",
    ".claude/CLAUDE.md": "Applied: always",
    "pkg/GEMINI.md": "Applied: always",
    ".github/copilot-instructions.md": "Applied: always",
    ".cursor/rules/style.mdc": "Applied to files matching: src/**, tests/**",
    "app/.cursor/rules/sub/api.mdc": "Applied to files matching: *.ts",
    ".cursorrules": "Applied: always",
    ".windsurf/rules/team.md": "Applied: always",
    "svc/.devin/rules/deploy.md": "Applied when the agent judges it relevant: Deploy steps",
    ".windsurfrules": "Applied: always",
}


def run(run_cli, repo, fmt: str, *more: str):
    code, out, err = run_cli(["scan", str(repo), "--format", fmt, "--no-telemetry", "--as-of", "2026-11-14", *more])
    assert err == ""
    return code, out


def test_the_text_report_puts_the_scope_under_each_finding_and_counts_the_files(make_repo, tmp_path, run_cli):
    code, out = run(run_cli, make_repo(tmp_path / "repo", {**PLAIN, **FILES}), "text")
    lines = out.splitlines()
    assert code == 1
    for path, scope in SCOPES.items():
        at = lines.index(path)
        assert lines[at + 1].startswith("  high SW-SKL-001 ") and lines[at + 2] == f"    {scope}", path
    assert "instruction files: 11 scanned" in lines
    assert lines.index("instruction files: 11 scanned") == len(lines) - 2  # just above the summary line
    other = lines.index("skills/setup") if "skills/setup" in lines else None
    assert other is None or not lines[other + 2].startswith("    Applied")  # a finding of a skill has no scope line


def test_a_report_without_instruction_files_has_neither_scope_lines_nor_the_count(make_repo, tmp_path, run_cli):
    _code, out = run(run_cli, make_repo(tmp_path / "repo", PLAIN), "text")
    assert "Applied" not in out and "instruction files" not in out
    _code, markdown = run(run_cli, tmp_path / "repo", "markdown")
    assert "Instruction files" not in markdown and "Applied" not in markdown
    _code, sarif = run(run_cli, tmp_path / "repo", "sarif")
    assert '"instructions": {' not in sarif and '"properties": {"instructions"' not in sarif


def test_the_markdown_report_lists_the_scope_of_each_file_with_an_open_finding(make_repo, tmp_path, run_cli):
    code, out = run(run_cli, make_repo(tmp_path / "repo", {**PLAIN, **FILES}), "markdown")
    assert code == 1 and "**Instruction files:** 11 files scanned." in out
    section = out[out.index("**Instruction files:**"):]
    assert "- `.cursor/rules/style.mdc`: Applied to files matching: src/\\*\\*, tests/\\*\\*" in section
    assert "- `svc/.devin/rules/deploy.md`: Applied when the agent judges it relevant: Deploy steps" in section
    assert "- `AGENTS.md`: Applied: always" in section
    assert out.index("| Severity | Rule |") < out.index("**Instruction files:**")


def test_the_markdown_report_with_one_clean_file_counts_it_and_lists_no_scope(make_repo, tmp_path, run_cli):
    _code, out = run(run_cli, make_repo(tmp_path / "repo", {**PLAIN, "AGENTS.md": "# Agents\n\nBe kind.\n"}), "markdown")
    assert "**Instruction files:** 1 file scanned." in out and "Applied" not in out


def test_sarif_results_of_an_instruction_file_carry_its_format_and_scope(make_repo, tmp_path, run_cli):
    _code, out = run(run_cli, make_repo(tmp_path / "repo", {**PLAIN, **FILES}), "sarif")
    document = json.loads(out)
    schema = json.loads(SARIF_SCHEMA.read_bytes().replace(b"\r\n", b"\n"))
    jsonschema.validators.validator_for(schema)(schema).validate(document)
    results = document["runs"][0]["results"]
    mine = {result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: result for result in results
            if result["ruleId"] == "SW-SKL-001"}
    assert sorted(mine) == sorted(SCOPES)
    assert mine[".cursor/rules/style.mdc"]["properties"] == {"instructions": {"format": "cursor-mdc",
                                                                              "scope": "Applied to files matching: src/**, tests/**"}}
    assert mine["AGENTS.md"]["properties"] == {"instructions": {"format": "agents-md", "scope": "Applied: always"}}
    assert all(result["properties"]["instructions"]["scope"] == SCOPES[uri] for uri, result in mine.items())
    assert all("properties" not in result for result in results if result["ruleId"] != "SW-SKL-001")


def test_a_scope_that_holds_hostile_text_is_escaped_in_every_format(make_repo, tmp_path, run_cli):
    hostile = "---\ndescription: a\\x1b[31m<script>@channel\ttab\n---\n" + INJECTION
    repo = make_repo(tmp_path / "repo", {".cursor/rules/x.mdc": hostile.replace("\\x1b", "\x1b")})
    _code, text = run(run_cli, repo, "text")
    assert "\x1b" not in text and "\\x1b" in text and "Applied when the agent judges it relevant: a" in text
    _code, markdown = run(run_cli, repo, "markdown")
    assert "\x1b" not in markdown and "<script>" not in markdown
    _code, sarif = run(run_cli, repo, "sarif")
    assert "\x1b" not in sarif  # the JSON encoder writes it as \\u001b, inert wherever the file is shown


def test_code_quality_has_one_issue_per_finding_of_an_instruction_file_and_no_new_field(make_repo, tmp_path, run_cli):
    _code, out = run(run_cli, make_repo(tmp_path / "repo", {**PLAIN, **FILES}), "gitlab-codequality")
    issues = [issue for issue in json.loads(out) if issue["check_name"] == "SW-SKL-001"]
    assert sorted(issue["location"]["path"] for issue in issues) == sorted(SCOPES)
    assert all(set(issue) == {"description", "check_name", "fingerprint", "severity", "location"} for issue in issues)


def test_the_json_report_has_the_items_and_no_scope(make_repo, tmp_path, run_cli):
    _code, out = run(run_cli, make_repo(tmp_path / "repo", {**PLAIN, **FILES}), "json")
    report = json.loads(out)
    assert report["schema"] == 1 and "Applied" not in out
