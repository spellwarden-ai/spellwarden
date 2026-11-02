"""SW-SKL-036: frontmatter pre-approves an unscoped shell or interpreter.
The rule is not registered yet, so the tests call the module's `detect` directly."""
from __future__ import annotations

import time

import pytest
from conftest import GENERATED, SKILL_FIXTURES, _read_dir, make_package

from spellwarden_scan.package import Package
from spellwarden_scan.rules.growth_skl_036 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

NEW_IDS = frozenset({f"SW-SKL-{n:03d}" for n in range(32, 38)})


def skill(front: str, body: str = "\n# demo-skill\n\nRead the task, then act.\n") -> str:
    """A SKILL.md whose frontmatter is `front` (line 1 is `---`, `name:` is line 2, `front` starts on line 4)."""
    return f"---\nname: demo-skill\ndescription: A demo skill for the tests.\n{front}\n---\n{body}"


def run(front: str = "", *, body: str | None = None, **extra: str):
    text = skill(front) if body is None else skill(front, body)
    return list(detect(Package.build(make_package({"SKILL.md": text, **extra}))))


def at(findings) -> list[tuple[str, int]]:
    return [(f.location.path, f.location.line) for f in findings]


def test_module_constants():
    assert RULE_ID == "SW-SKL-036"
    assert TITLE == "Frontmatter pre-approves an unscoped shell or interpreter"
    assert SEVERITY == "medium"
    assert OWASP == ("ASI02", "ASI03")
    assert NIST == ("AC-6", "CM-7")
    assert MALICIOUS is False


# --- positives --------------------------------------------------------------------------------

def test_one_line_value_fires_at_the_key_line():
    findings = run("allowed-tools: Read, Bash, Edit")
    assert at(findings) == [("SKILL.md", 4)]
    first = findings[0]
    assert first.rule_id == RULE_ID
    assert first.severity == "medium"
    assert first.title == TITLE
    assert first.malicious_indicator is False
    assert "Bash" in first.evidence
    assert len(first.evidence) <= 300
    assert len(first.fingerprint) == 64


def test_space_separated_value_fires():
    assert at(run("allowed-tools: Read Bash Edit")) == [("SKILL.md", 4)]


def test_list_form_fires_at_the_item_line():
    front = "allowed-tools:\n  - Read\n  - Bash\n  - Edit"
    assert at(run(front)) == [("SKILL.md", 6)]


def test_flow_list_fires_at_the_key_line():
    assert at(run("allowed-tools: [Read, Bash, Edit]")) == [("SKILL.md", 4)]


@pytest.mark.parametrize("entry", ["Bash(python3:*)", "Bash(python:*)", "Bash(node:*)", "Bash(npx:*)", "Bash(uvx:*)",
                                   "Bash(bash:*)", "Bash(sh:*)", "Bash(pwsh:*)", "Bash(pip:*)", "Bash(eval:*)",
                                   "Bash(source:*)", "Bash(python3)", "Bash(*)", "Bash(:*)", "bash", "Shell",
                                   "PowerShell", "BASH(PYTHON3:*)", "PowerShell(pwsh:*)"])
def test_unscoped_or_interpreter_entries_fire(entry):
    assert at(run(f"allowed-tools: Read, {entry}")) == [("SKILL.md", 4)], entry


def test_each_offending_list_item_is_reported_at_its_own_line():
    front = "allowed-tools:\n  - Bash\n  - Read\n  - Bash(node:*)"
    assert at(run(front)) == [("SKILL.md", 5), ("SKILL.md", 7)]


def test_fingerprint_follows_the_entry_not_the_line():
    first = run("allowed-tools: Read, Bash")[0]
    moved = run("version: 1.0.0\nallowed-tools: Read, Bash")[0]
    other = run("allowed-tools: Read, Shell")[0]
    assert first.fingerprint == moved.fingerprint
    assert first.fingerprint != other.fingerprint


def test_command_file_inside_the_package_fires_with_its_path():
    command = "---\ndescription: Do the thing\nallowed-tools: Bash\n---\n\nDo the thing.\n"
    findings = run("allowed-tools: Read", **{"commands/x.md": command})
    assert at(findings) == [("commands/x.md", 3)]


def test_command_file_with_a_list_fires_at_the_item():
    command = "---\ndescription: Do the thing\nallowed-tools:\n  - Read\n  - Bash(sh:*)\n---\n\nDo the thing.\n"
    assert at(run("", **{"commands/x.md": command})) == [("commands/x.md", 5)]


def test_quoted_entries_fire():
    assert at(run('allowed-tools: "Read, Bash"')) == [("SKILL.md", 4)]


def test_crlf_frontmatter_reports_the_same_lines():
    text = skill("allowed-tools:\n  - Read\n  - Bash").replace("\n", "\r\n")
    findings = list(detect(Package.build(make_package({"SKILL.md": text}))))
    assert at(findings) == [("SKILL.md", 6)]


# --- near misses ------------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "Read, Bash(gh pr view:*)",
    "Read Grep Bash(gh pr view:*) Bash(gh pr diff:*)",
    "Bash(mytool deploy:*), Read",
    "Bash(python3 -m pytest:*)",
    "Bash(node scripts/build.js:*)",
    "Bash(git status)",
    "Read, Grep, Glob, Edit, Write",
    "WebFetch(domain:docs.example.com)",
    "mcp__server__bash_tool",
    "Bashful, Shellfish",
])
def test_scoped_or_non_shell_values_are_quiet(value):
    assert run(f"allowed-tools: {value}") == []


def test_read_only_list_is_quiet():
    assert run("allowed-tools:\n  - Read\n  - Grep\n  - Glob") == []


def test_example_in_a_fenced_block_of_a_guide_is_quiet():
    guide = "# Guide\n\n```yaml\n---\nname: example\nallowed-tools: Read, Bash, Edit\n---\n```\n"
    assert run("", **{"references/guide.md": guide}) == []


def test_example_after_leading_prose_is_quiet():
    guide = "# Guide\n\nUse this in your frontmatter:\n\n---\nallowed-tools: Bash\n---\n"
    assert run("", **{"references/guide.md": guide}) == []


def test_allowed_tools_in_the_body_is_quiet():
    assert run("", body="\n# demo\n\nallowed-tools: Read, Bash\n") == []


def test_subagent_tools_list_is_quiet():
    agent = "---\nname: helper\ndescription: A helper\ntools: Read, Bash, Edit\n---\n\nHelp.\n"
    assert run("tools: Read, Bash", **{"agents/helper.md": agent}) == []


def test_nested_key_is_not_the_top_level_key():
    assert run("metadata:\n  allowed-tools: Bash") == []


def test_unparsable_or_missing_frontmatter_is_skipped():
    assert run("allowed-tools: [Bash", **{"a.md": "no frontmatter at all\n", "b.md": "---\nkey: [oops\n---\n"}) == []
    assert run("allowed-tools: Read", **{"c.md": "---\n- just\n- a list\n---\n"}) == []


def test_non_markdown_files_are_not_read():
    notes = "---\nallowed-tools: Bash\n---\n"
    assert run("allowed-tools: Read", **{"notes.txt": notes, "scripts/run.sh": notes}) == []


def test_non_string_values_are_quiet():
    assert run("allowed-tools: 5") == []
    assert run("allowed-tools:") == []
    assert run("allowed-tools:\n  - key: Bash\n  - 3") == []


# --- bounded and linear -----------------------------------------------------------------------

@pytest.mark.parametrize("token", ["Read, ", "Bash(x:*) ", "Bash(", "Bash, "])
def test_long_allowed_tools_line_is_read_in_linear_time(token):
    line = "allowed-tools: " + token * (300_000 // len(token))
    start = time.perf_counter()
    findings = run(line)
    assert time.perf_counter() - start < 1.0
    assert len(findings) <= 10


def test_escaped_entries_that_are_not_in_the_raw_text_are_read_in_linear_time():
    # YAML unescapes "\x42a\x73h" to Bash, so the raw text never contains the entry that the parser returns.
    entry = '"\\x42a\\x73h", '
    line = "allowed-tools: [" + entry * (280_000 // len(entry)) + "]"
    start = time.perf_counter()
    findings = run(line)
    assert time.perf_counter() - start < 1.0
    assert at(findings) == [("SKILL.md", 4)]


@pytest.mark.parametrize("entry", [
    "Bash(/usr/bin/python3:*)", "Bash(python3.12:*)", "Bash(env python3:*)", "Bash(env:*)", "Bash(xargs:*)",
    "Bash(python3 -c:*)", "Bash(node -e:*)", "Bash(python -m:*)", "Bash(sudo bash:*)", "Bash(PYTHONPATH=. python3:*)",
])
def test_interpreter_scopes_by_path_version_launcher_or_inline_code_fire(entry):
    assert at(run(f"allowed-tools: Read, {entry}")) == [("SKILL.md", 4)]


@pytest.mark.parametrize("entry", ["Bash(python3 scripts/report.py:*)", "Bash(env FOO=1 mytool deploy:*)", "Bash(/opt/acme/bin/acme sync:*)"])
def test_scopes_to_one_script_or_tool_stay_quiet_whatever_the_path(entry):
    assert run(f"allowed-tools: Read, {entry}") == []


def test_the_parsed_key_decides_even_when_the_text_does_not_show_it_plainly():
    # An escaped key (`allowed\x2dtools`) and a complex key (`? allowed-tools`): YAML reads `allowed-tools`, the text
    # has no plain `allowed-tools:` line. Before, such a file was skipped.
    assert at(run('"allowed\\x2dtools": Read, Bash')) == [("SKILL.md", 4)]
    assert at(run("? allowed-tools\n: Read, Bash")) == [("SKILL.md", 5)]


def test_a_list_item_after_many_escaped_entries_keeps_its_own_line():
    # Review r1:F3: the entries YAML unescapes are not searched for at all, so a later plain `- Bash` keeps its line.
    escaped = "".join(f'  - "\\x42a\\x73h({n}"\n' for n in range(12))
    front = "allowed-tools:\n" + escaped + "  - Read\n  - Bash"
    findings = run(front)
    assert ("SKILL.md", 4 + 1 + 12 + 1) in at(findings)


def test_a_bare_entry_is_not_placed_inside_an_earlier_scoped_one():
    front = "allowed-tools:\n  - Bash(gh pr view:*)\n  - Bash"
    assert at(run(front)) == [("SKILL.md", 6)]


def test_output_is_bounded():
    front = "allowed-tools:\n" + "".join(f"  - Bash({name}:*)\n" for name in ("python", "node", "deno", "bun", "ruby", "perl", "sh", "zsh")).rstrip("\n")
    findings = run(front)
    assert len(findings) == 5  # per file
    assert len(run("", **{f"commands/{n}.md": skill(front) for n in range(10)})) == 10  # per package


# --- invariant 4: no finding on any existing skill fixture ------------------------------------

def _existing_skill_packages():
    for directory in sorted(SKILL_FIXTURES.iterdir()):
        if not directory.is_dir() or directory.name in NEW_IDS:
            continue
        for side in sorted(p for p in directory.iterdir() if p.is_dir()):
            generator = GENERATED.get(f"{directory.name}/{side.name}")
            yield f"{directory.name}/{side.name}", (generator() if generator is not None else _read_dir(side))


def test_no_finding_on_any_existing_skill_fixture():
    seen = 0
    for name, files in _existing_skill_packages():
        seen += 1
        assert list(detect(Package.build(files))) == [], name
    assert seen >= 30


# --- the rule's own fixtures ------------------------------------------------------------------

def test_own_positive_fixture_fires_and_negative_stays_quiet():
    positive = list(detect(Package.build(_read_dir(SKILL_FIXTURES / RULE_ID / "positive"))))
    negative = list(detect(Package.build(_read_dir(SKILL_FIXTURES / RULE_ID / "negative"))))
    assert at(positive) == [("SKILL.md", 6), ("commands/notes.md", 5)]
    assert negative == []
