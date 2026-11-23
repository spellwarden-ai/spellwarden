"""Engine 1.20.0 (claims C28, C56): the README says what 1.20.0 reads, what it reads but does not judge, what `--follow-links` does,
what it never follows and what stays unjudged while it is off, the new limits, and what the hook's file filter covers."""
from __future__ import annotations

from pathlib import Path

from spellwarden_cli import instruction_files

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
# Every path pattern of spec 7.1 and 7.3, as the README writes it
PATHS = (".codex/config.toml", ".codex/hooks.json", ".gemini/settings.json", ".cursor/hooks.json", ".windsurf/hooks.json",
         ".devin/mcp_config.json", ".devin/mcp_config.local.json", ".devin/hooks.v1.json", ".devin/config.json",
         ".devin/config.local.json", ".github/hooks/", ".github/copilot/settings.json", ".github/copilot/settings.local.json",
         ".github/mcp.json", ".claude/rules/", "CLAUDE.local.md", "AGENTS.override.md", "AGENTS.local.md", "AGENT.md",
         ".windsurf/rules/", ".devin/rules/", ".windsurf/global_rules.md", ".devin/global_rules.md", ".github/instructions/",
         ".claude/commands/", ".claude/agents/", ".claude/output-styles/", ".cursor/agents/", ".codex/agents/", ".gemini/agents/",
         ".devin/agents/", ".agents/agents/", ".github/agents/")


def section(heading: str) -> str:
    start = README.index(heading)
    end = README.find("\n### ", start + len(heading))
    return " ".join(README[start:end if end != -1 else len(README)].split())


def test_what_a_scan_reads_names_every_new_path_and_what_is_read_but_not_judged():
    text = section("### What a scan reads")
    for path in PATHS:
        assert f"`{path}" in text, path
    for needle in ("Read but not judged", "`type` `prompt`", "`http`", "`agent` and `mcp_tool`", "`developer_instructions`",
                   "`notify` is not a hook in a project file", "`tools.discoveryCommand`", "`context.fileName`",
                   "`permissions` is not judged", "`permissionMode`", "`mcp-servers`, `hooks` and `handoffs`", "`auth` values",
                   "`SW-SKL-036`", "`--follow-links` follows a linked directory in an instruction folder"):
        assert needle in text, needle


def test_instruction_files_say_what_follow_links_does_and_what_stays_unjudged_without_it():
    text = section("### Instruction files")
    for format in instruction_files.FORMATS:
        assert f"`{format}`" in text, format
    for needle in ("is not followed by default", "the rule files reached only through it are not judged",
                   "the scan can pass", "`symlink_skipped`", "`--follow-links`", "A link is followed one level",
                   "the error `unsafe_path`", "Never followed, with or without the argument",
                   "a link whose target is outside the scan root", "a linked folder above an instruction folder",
                   "a link to a directory inside a skill or a local plugin directory",
                   "Give `spellwarden lock`, `lock --check`, `scan --locked` and the `baseline` commands the same `--follow-links`",
                   "`scan --user` follows a link to a directory inside the home already and refuses `--follow-links`",
                   "carry the plugin's name", "has not been measured", "`.github/prompts/*.prompt.md`"):
        assert needle in text, needle


def test_the_commands_limits_lock_baseline_and_workstation_sections_name_the_argument_and_the_limits():
    assert "[--follow-links]" in README and "spellwarden lock [PATH] [--check | --probe] [--follow-links]" in README
    limits = section("### Limits")
    assert "at most 50 linked directories in instruction folders per scan root" in limits
    assert "200 plugin directories" in limits
    assert "`--follow-links`" in section("### The lock file") and "`--follow-links`" in section("### The baseline file")
    workstation = section("### Scanning a workstation")
    for needle in ("`SW-CFG-012` and `SW-CFG-013` also judge the MCP servers of Codex's `config.toml` and Gemini CLI's "
                   "`settings.json`", "`scan --user` takes no baseline", "`--follow-links` is a usage error with `--user`"):
        assert needle in workstation, needle
    exit_codes = section("### Exit codes")
    assert "50 linked directories in instruction folders" in exit_codes


def test_the_hook_section_names_the_new_folders_and_the_argument():
    text = section("### Pre-commit hook")
    for needle in ("`.gemini`", "`.devin`", "`.windsurf`", "`.agents`", "`.github/hooks`", "`.github/instructions`",
                   "`.github/agents`", "`.github/copilot`", "args: [--follow-links]",
                   "a change inside the directory a followed link names (`shared-rules/`), is not matched by the file filter"):
        assert needle in text, needle
