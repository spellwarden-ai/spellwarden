"""Phase 3 batch 1 spec 10.2 to 10.4: which paths are instruction files, how the front matter of a rule file is read (a line parser,
not YAML), and how a file's scope is put in words."""
from __future__ import annotations

import pytest

from spellwarden_cli import instruction_files as instructions
from spellwarden_cli.instruction_files import front_matter_of, instruction_scope


@pytest.mark.parametrize("path, expected", [
    ("AGENTS.md", "agents-md"), ("docs/AGENTS.md", "agents-md"), ("a/b/c/AGENTS.md", "agents-md"),
    ("CLAUDE.md", "claude-md"), (".claude/CLAUDE.md", "claude-md"), ("docs/CLAUDE.md", "claude-md"),
    ("GEMINI.md", "gemini-md"), ("services/api/GEMINI.md", "gemini-md"),
    (".github/copilot-instructions.md", "copilot-instructions"),
    (".cursor/rules/style.mdc", "cursor-mdc"), ("app/.cursor/rules/style.mdc", "cursor-mdc"),
    (".cursor/rules/sub/deep/api.mdc", "cursor-mdc"), ("app/.cursor/rules/sub/api.mdc", "cursor-mdc"),
    (".cursorrules", "cursorrules"),
    (".windsurf/rules/team.md", "windsurf-rules"), (".devin/rules/team.md", "windsurf-rules"),
    ("svc/.windsurf/rules/team.md", "windsurf-rules"), ("svc/.devin/rules/deploy.md", "windsurf-rules"),
    (".windsurfrules", "windsurf-rules"),
    # Engine 1.20.0 (scan selection, 7.3)
    (".claude/rules/a.md", "claude-rule"), (".claude/rules/team/deep/a.md", "claude-rule"), ("pkg/.claude/rules/a.md", "claude-rule"),
    ("CLAUDE.local.md", "claude-md"), ("docs/CLAUDE.local.md", "claude-md"),
    ("AGENTS.override.md", "agents-md"), ("AGENTS.local.md", "agents-md"), ("AGENT.md", "agents-md"), ("docs/AGENT.md", "agents-md"),
    (".windsurf/rules/sub/team.md", "windsurf-rules"), (".devin/rules/a/b/c.md", "windsurf-rules"),
    (".windsurf/global_rules.md", "windsurf-rules"), ("svc/.devin/global_rules.md", "windsurf-rules"),
    (".github/instructions/python.instructions.md", "github-instructions"),
    (".github/instructions/sub/x.instructions.md", "github-instructions"),
    (".claude/commands/deploy.md", "claude-command"), (".claude/commands/ops/restart.md", "claude-command"),
    (".claude/agents/reviewer.md", "claude-agent"), ("pkg/.claude/agents/team/x.md", "claude-agent"),
    (".claude/output-styles/terse.md", "claude-output-style"),
    (".cursor/agents/planner.md", "cursor-agent"), (".codex/agents/helper.md", "codex-agent"),
    (".gemini/agents/researcher.md", "gemini-agent"),
    (".devin/agents/triage.md", "devin-agent"), (".agents/agents/x.md", "devin-agent"),
    (".devin/agents/a/AGENT.md", "devin-agent"), (".agents/agents/support/AGENT.md", "devin-agent"),
    (".github/agents/review.agent.md", "github-agent"), (".github/agents/team/x.md", "github-agent"),
])
def test_the_paths_of_the_table_are_instruction_files(path, expected):
    assert instructions.format_of(path) == expected
    assert expected in instructions.REPOSITORY_FORMATS


@pytest.mark.parametrize("path", [
    "README.md", "AGENTS.mdx", ".github/copilot-instructions.md.bak", "docs/.github/copilot-instructions.md",
    "sub/.cursorrules", "sub/.windsurfrules", ".cursor/rules/old.md", ".cursor/rules/style.mdc.bak", ".cursor/style.mdc",
    "rules/style.mdc", ".windsurf/rules/team.txt", ".devin/team.md", ".gemini/GEMINI.txt", "AGENTS.md/x", "a/CLAUDE.md/b.md",
    ".windsurf/rules.md",
    # Engine 1.20.0 (scan selection, 7.3, 7.13): still not read
    ".github/prompts/release.prompt.md", ".codex/agents/helper.toml", ".gemini/commands/x.toml", ".cursor/commands/x.md",
    ".windsurf/workflows/w.md", ".claude/output-styles/sub/x.md", ".cursor/agents/sub/x.md", ".devin/agents/a/notes.md",
    ".github/instructions/notes.md", ".claude/rules.md", "rules/x.md", ".gemini/notes.md", ".claude/workflows/x.js",
])
def test_everything_else_is_not_an_instruction_file(path):
    assert instructions.format_of(path) is None


def fm(text: str, format: str = "cursor-mdc"):
    return front_matter_of(format, text.encode("utf-8"))


def test_a_cursor_rule_front_matter_is_read():
    assert fm("---\ndescription: Style rules\nglobs: src/**, tests/**\nalwaysApply: false\n---\nBody\n") == (
        {"description": "Style rules", "globs": ["src/**", "tests/**"], "always_apply": False, "trigger": None}, True)
    assert fm("---\nalwaysApply: true\n---\n")[0] == {"description": None, "globs": None, "always_apply": True, "trigger": None}


def test_globs_that_yaml_refuses_are_read():
    assert fm("---\nglobs: *.ts\n---\n")[0]["globs"] == ["*.ts"]
    assert fm("---\nglobs: *.ts,**/*.tsx\n---\n")[0]["globs"] == ["*.ts", "**/*.tsx"]


def test_globs_may_be_a_bracketed_list_a_quoted_list_or_dash_lines():
    assert fm("---\nglobs: [src/**, \"tests/**\"]\n---\n")[0]["globs"] == ["src/**", "tests/**"]
    assert fm("---\nglobs: ['*.py', '*.pyi']\n---\n")[0]["globs"] == ["*.py", "*.pyi"]
    assert fm("---\nglobs:\n  - src/**\n  - \"docs/*.md\"\ndescription: After the list\n---\n")[0] == {
        "description": "After the list", "globs": ["src/**", "docs/*.md"], "always_apply": None, "trigger": None}
    assert fm("---\nglobs: []\n---\n")[0]["globs"] == []


def test_a_windsurf_or_devin_rule_reads_trigger_globs_and_description_only():
    text = "---\ntrigger: glob\nglobs: **/*.go\ndescription: Go rules\nalwaysApply: true\n---\n"
    assert fm(text, "windsurf-rules") == ({"description": "Go rules", "globs": ["**/*.go"], "always_apply": None, "trigger": "glob"}, True)
    assert fm("---\ntrigger: always_on\n---\n", "windsurf-rules")[0]["trigger"] == "always_on"
    cursor = fm("---\ntrigger: always_on\ndescription: d\n---\n")[0]  # Cursor does not read `trigger`
    assert cursor["trigger"] is None and cursor["description"] == "d"


def test_the_kept_values_are_cut_and_unknown_keys_are_ignored():
    many = "\n".join(f"  - g{n}" for n in range(25))
    result = fm(f"---\ndescription: {'d' * 400}\nowner: someone\nglobs:\n{many}\n---\n")[0]
    assert len(result["description"]) == 300 and result["globs"] == [f"g{n}" for n in range(20)]
    assert fm(f"---\nglobs: {'g' * 300}, short\n---\n")[0]["globs"] == ["g" * 200, "short"]
    assert fm(f"---\ntrigger: {'t' * 80}\n---\n", "windsurf-rules")[0]["trigger"] == "t" * 32


def test_always_apply_is_a_boolean_or_nothing():
    for text, expected in (("TRUE", True), ("False", False), ("yes", None), ("1", None), ("", None)):
        assert fm(f"---\nalwaysApply: {text}\n---\n")[0]["always_apply"] is expected, text


def test_no_front_matter_is_not_an_error_and_a_block_that_never_closes_is():
    assert fm("# Just a rule\n\nBody\n") == (None, True)
    assert fm("") == (None, True)
    assert fm("---\ndescription: never closed\nBody continues\n") == (None, False)
    assert fm("---\nglobs: [src/**\n---\n") == (None, False)
    padded = "---\ndescription: d\n" + "# filler\n" * 600 + "---\n"  # the closing line is past 4 KiB
    assert len(padded) > 4096 and fm(padded) == (None, False)
    within = "---\ndescription: d\n" + "# filler\n" * 100 + "---\n"
    assert fm(within)[1] is True and fm(within)[0]["description"] == "d"


def test_crlf_and_a_byte_order_mark_do_not_hide_the_front_matter():
    assert fm("---\r\nglobs: *.ts\r\n---\r\nBody\r\n")[0]["globs"] == ["*.ts"]
    assert front_matter_of("cursor-mdc", b"\xef\xbb\xbf---\ndescription: d\n---\n")[0]["description"] == "d"
    assert front_matter_of("cursor-mdc", b"---\ndescription: \xff\xfe broken\n---\n")[1] is True  # invalid UTF-8 is replaced, not refused


def test_the_other_formats_have_no_front_matter_to_read():
    for format in ("agents-md", "claude-md", "gemini-md", "copilot-instructions", "cursorrules"):
        assert fm("---\ndescription: x\n---\n", format) == (None, True), format


@pytest.mark.parametrize("format, path, front_matter, expected", [
    ("agents-md", "AGENTS.md", None, "Applied: always"),
    ("claude-md", ".claude/CLAUDE.md", None, "Applied: always"),
    ("gemini-md", "GEMINI.md", None, "Applied: always"),
    ("copilot-instructions", ".github/copilot-instructions.md", None, "Applied: always"),
    ("cursorrules", ".cursorrules", None, "Applied: always"),
    ("windsurf-rules", ".windsurfrules", None, "Applied: always"),
    ("cursor-mdc", ".cursor/rules/a.mdc", {"description": None, "globs": None, "always_apply": True, "trigger": None}, "Applied: always"),
    ("cursor-mdc", ".cursor/rules/a.mdc", {"description": "d", "globs": ["src/**", "tests/**"], "always_apply": False, "trigger": None},
     "Applied to files matching: src/**, tests/**"),
    ("cursor-mdc", ".cursor/rules/a.mdc", {"description": "Use for API work", "globs": None, "always_apply": False, "trigger": None},
     "Applied when the agent judges it relevant: Use for API work"),
    ("cursor-mdc", ".cursor/rules/a.mdc", {"description": None, "globs": [], "always_apply": None, "trigger": None}, "Applied when asked for"),
    ("cursor-mdc", ".cursor/rules/a.mdc", None, "Applied when asked for"),
    ("windsurf-rules", ".windsurf/rules/a.md", {"description": None, "globs": None, "always_apply": None, "trigger": "always_on"},
     "Applied: always"),
    ("windsurf-rules", ".windsurf/rules/a.md", {"description": None, "globs": ["*.go"], "always_apply": None, "trigger": "glob"},
     "Applied to files matching: *.go"),
    ("windsurf-rules", ".devin/rules/a.md", {"description": "Deploy steps", "globs": None, "always_apply": None, "trigger": "model_decision"},
     "Applied when the agent judges it relevant: Deploy steps"),
    ("windsurf-rules", ".devin/rules/a.md", {"description": "x", "globs": ["*.go"], "always_apply": None, "trigger": "manual"},
     "Applied when asked for"),
    ("windsurf-rules", ".windsurf/rules/a.md", None, "Applied when asked for"),
    ("windsurf-rules", ".windsurf/rules/a.md", {"description": None, "globs": None, "always_apply": None, "trigger": "model_decision"},
     "Applied when the agent judges it relevant"),
])
def test_the_scope_in_words(format, path, front_matter, expected):
    assert instruction_scope(format, path, front_matter) == expected


def test_scopes_covers_the_instruction_items_only():
    class Item:
        def __init__(self, kind, path, format=None, front_matter=None):
            self.kind, self.path, self.format, self.front_matter = kind, path, format, front_matter

    items = [Item("skill", "skills/a"), Item("instructions", "AGENTS.md", "agents-md"),
             Item("instructions", ".cursor/rules/a.mdc", "cursor-mdc", None)]
    assert instructions.scopes(items) == {"AGENTS.md": "Applied: always", ".cursor/rules/a.mdc": "Applied when asked for"}


@pytest.mark.parametrize(("path", "expected"), [
    ("claude.md", "claude-md"), ("Agents.MD", "agents-md"), ("docs/gemini.md", "gemini-md"),
    (".GITHUB/Copilot-Instructions.md", "copilot-instructions"), (".CursorRules", "cursorrules"), (".WindsurfRules", "windsurf-rules"),
    (".Cursor/Rules/style.MDC", "cursor-mdc"), ("app/.cursor/RULES/sub/a.mdc", "cursor-mdc"),
    (".Windsurf/rules/team.MD", "windsurf-rules"), (".DEVIN/Rules/deploy.md", "windsurf-rules"),
])
def test_a_path_in_another_case_is_the_same_instruction_file(path, expected):
    """macOS and Windows open `CLAUDE.md` when the repository holds `claude.md`: the scanner must read what the agent loads."""
    assert instructions.format_of(path) == expected


@pytest.mark.parametrize(("path", "first"), [
    ("AGENTS.md", True), ("claude.md", True), (".github/copilot-instructions.md", True), (".cursorrules", True),
    (".windsurfrules", True), (".cursor/rules/a/b/c.mdc", True), (".Windsurf/rules/t.md", True), (".devin/rules/d.md", True),
    ("app/AGENTS.md", False), ("app/.cursor/rules/x.mdc", False), ("svc/.windsurf/rules/t.md", False),
    (".github/d1/AGENTS.md", False), (".cursor/rules/AGENTS.md", False), (".windsurf/rules/x/CLAUDE.md", False),
    (".devin/rules/GEMINI.md", False), ("README.md", False),
])
def test_the_places_an_agent_reads_at_the_root_come_first(path, first):
    assert instructions.loaded_first(path) is first


def test_the_precedence_of_a_path_with_two_rules():
    """Engine 1.20.0 (7.4, D12): Devin's `<name>/AGENT.md` first, then names, then the scan-root files, then folders in order."""
    assert instructions.format_of(".devin/agents/a/AGENT.md") == "devin-agent"
    assert instructions.format_of(".claude/agents/AGENTS.md") == "agents-md"
    assert instructions.format_of(".cursor/rules/AGENTS.md") == "agents-md"
    assert instructions.format_of("docs/AGENT.md") == "agents-md"
    assert instructions.format_of(".claude/rules/x/.claude/commands/y.md") == "claude-rule"
    assert instructions.format_of(".windsurf/rules/global_rules.md") == "windsurf-rules"


@pytest.mark.parametrize("path, first", [
    ("AGENTS.md", True), ("CLAUDE.local.md", True), ("AGENTS.override.md", True), ("docs/AGENT.md", False),
    (".claude/commands/x.md", True), (".claude/commands/a/b.md", True), ("pkg/.claude/commands/x.md", False),
    (".claude/rules/x.md", True), (".claude/agents/x.md", True), (".claude/output-styles/x.md", True),
    (".cursor/agents/x.md", True), (".codex/agents/x.md", True), (".gemini/agents/x.md", True), (".devin/agents/x.md", True),
    (".agents/agents/s/AGENT.md", True), (".github/instructions/x.instructions.md", True), (".github/agents/x.md", True),
    (".windsurf/global_rules.md", True), ("svc/.windsurf/global_rules.md", False), (".windsurf/rules/a/b.md", True),
    ("svc/.devin/rules/x.md", False), ("README.md", False),
])
def test_the_root_agent_folders_are_loaded_first(path, first):
    assert instructions.loaded_first(path) is first


def test_apply_to_is_read_as_globs_and_a_block_description_of_a_new_format_is_none():
    assert fm('---\napplyTo: "**/*.ts,**/*.tsx"\ndescription: TypeScript\n---\n', "github-instructions")[0] == {
        "description": "TypeScript", "globs": ["**/*.ts", "**/*.tsx"], "always_apply": None, "trigger": None}
    assert fm("---\napplyTo:\n  - src/**\n  - '*.py'\n---\n", "github-instructions")[0]["globs"] == ["src/**", "*.py"]
    assert fm("---\napplyTo: [a/**, b/**]\n---\n", "github-instructions")[0]["globs"] == ["a/**", "b/**"]
    for block in ("|", ">", "|-", ">+", "|2"):
        assert fm(f"---\ndescription: {block}\n  Reviews code.\n---\n", "claude-agent")[0]["description"] is None, block
    assert fm("---\ndescription: Reviews code.\nmodel: opus\ntools: Read\n---\n", "claude-agent")[0] == {
        "description": "Reviews code.", "globs": None, "always_apply": None, "trigger": None}
    assert fm("---\ndescription: |\n---\n", "cursor-mdc")[0]["description"] == "|"  # an existing format parses as on 1.19.0
    assert fm('---\nglobs: "*.ts"\n---\n')[0]["globs"] == ["*.ts"]  # Cursor's globs are not changed


@pytest.mark.parametrize("format, path, text, expected", [
    ("claude-output-style", ".claude/output-styles/t.md", "---\ndescription: Short\n---\n", "Applied when asked for"),
    ("codex-prompt", "~/.codex/prompts/r.md", "---\ndescription: Release\n---\n", "Applied when asked for"),
    ("claude-command", ".claude/commands/d.md", "---\ndescription: Deploys\n---\n",
     "Applied when the agent judges it relevant: Deploys"),
    ("claude-command", ".claude/commands/d.md", "No front matter\n", "Applied when asked for"),
    ("claude-agent", ".claude/agents/r.md", "---\ndescription: Reviews\n---\n", "Applied when the agent judges it relevant: Reviews"),
    ("cursor-agent", ".cursor/agents/p.md", "x\n", "Applied when asked for"),
    ("devin-agent", ".devin/agents/a/AGENT.md", "---\ndescription: Triages\n---\n",
     "Applied when the agent judges it relevant: Triages"),
    ("github-instructions", ".github/instructions/p.instructions.md", '---\napplyTo: "**/*.py"\n---\n',
     "Applied to files matching: **/*.py"),
    ("github-instructions", ".github/instructions/p.instructions.md", "---\ndescription: Python\n---\n",
     "Applied when the agent judges it relevant: Python"),
    ("github-instructions", ".github/instructions/p.instructions.md", "x\n", "Applied when asked for"),
    ("github-agent", ".github/agents/a.agent.md", "x\n", "Applied when asked for"),
    ("windsurf-rules", ".windsurf/global_rules.md", "x\n", "Applied: always"),
    ("windsurf-rules", "svc/.devin/global_rules.md", "x\n", "Applied: always"),
    ("windsurf-rules", ".windsurf/rules/global_rules.md", "x\n", "Applied when asked for"),
    ("copilot-instructions", "~/.copilot/copilot-instructions.md", "x\n", "Applied: always"),
    ("agents-md", "AGENTS.override.md", "x\n", "Applied: always"),
    ("claude-rule", ".claude/rules/a.md", "x\n", "Applied: always"),
])
def test_the_scope_words_of_each_format(format, path, text, expected):
    front_matter, _ = front_matter_of(format, text.encode("utf-8"))
    assert instruction_scope(format, path, front_matter) == expected


def test_the_schemas_list_the_formats_and_every_format_is_short():
    import json
    from pathlib import Path

    schemas = Path(__file__).resolve().parents[2] / "schemas"
    report = json.loads((schemas / "report.schema.json").read_text(encoding="utf-8"))
    lock = json.loads((schemas / "lock.schema.json").read_text(encoding="utf-8"))
    assert report["$defs"]["item"]["properties"]["format"]["enum"] == list(instructions.FORMATS)
    (locked,) = [entry for entry in lock["$defs"]["item"]["oneOf"]
                 if entry["properties"]["kind"].get("const") == "instructions"]
    assert locked["properties"]["format"]["enum"] == list(instructions.REPOSITORY_FORMATS)
    assert set(instructions.REPOSITORY_FORMATS) == set(instructions.FORMATS) - set(instructions.USER_ONLY_FORMATS)
    assert len(instructions.FORMATS) == 21 and len(set(instructions.FORMATS)) == 21
    assert all(len(format) <= 24 for format in instructions.FORMATS)


@pytest.mark.parametrize("format", [f for f in instructions.FORMATS if f not in ("agents-md", "claude-md", "gemini-md",
                                                                                  "copilot-instructions", "cursorrules",
                                                                                  "codex-agents-md")])
def test_every_front_matter_has_the_four_uploaded_fields_only(format):
    text = b"---\ndescription: d\nglobs: a\npaths: b\napplyTo: c\nalwaysApply: true\ntrigger: manual\nhooks: x\n---\n"
    front_matter, readable = front_matter_of(format, text)
    assert readable and set(front_matter) == {"description", "globs", "always_apply", "trigger"}


@pytest.mark.parametrize("path, holds", [
    (".claude/rules/shared", True), (".claude/rules/team/shared", True), ("pkg/.claude/commands/ops", True),
    (".cursor/rules/shared", True), (".github/instructions/shared", True), (".devin/agents/reviewer", True),
    (".claude/rules", True), (".cursor/rules", True), (".github/agents", True), (".windsurf/rules/claude", True),
    (".claude/output-styles/more", False), (".cursor/agents/more", False), (".claude", False), (".github", False),
    ("docs/shared", False), (".devin/agents/reviewer/notes.txt", False),
])
def test_a_directory_holds_instructions_when_a_folder_rule_could_name_a_file_in_it(path, holds):
    """Engine 1.20.0 (spec 7.20.2, D39): the names that match anywhere (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`) say nothing."""
    assert instructions.holds_instructions(path) is holds


def test_linked_directories_in_the_root_agent_folders_come_first_and_at_most_50_are_followed():
    assert instructions.MAX_LINKED_DIRECTORIES == 50
    assert instructions.linked_first(".claude/rules/shared") and instructions.linked_first(".cursor/rules")
    assert not instructions.linked_first("pkg/.claude/commands/ops")
    assert not instructions.linked_first("docs/shared")
