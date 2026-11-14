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
])
def test_the_paths_of_the_table_are_instruction_files(path, expected):
    assert instructions.format_of(path) == expected
    assert expected in instructions.FORMATS


@pytest.mark.parametrize("path", [
    "README.md", "agents.md", "Agents.md", "claude.md", "gemini.md", "AGENT.md", "AGENTS.local.md", "CLAUDE.local.md", "AGENTS.mdx",
    ".github/instructions/python.instructions.md", ".github/copilot-instructions.md.bak", "docs/.github/copilot-instructions.md",
    "sub/.cursorrules", "sub/.windsurfrules", ".cursor/rules/old.md", ".cursor/rules/style.mdc.bak", ".cursor/style.mdc",
    "rules/style.mdc", ".windsurf/rules/sub/team.md", ".windsurf/rules/team.txt", ".windsurf/global_rules.md", ".devin/team.md",
    ".gemini/GEMINI.txt", "AGENTS.md/x", "a/CLAUDE.md/b.md", ".windsurf/rules.md",
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
