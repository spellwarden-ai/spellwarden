"""Phase C spec 5.1 and claim E2: the README's section "Org rules, packs and exports" states the pattern language's
limits exactly as `PATTERN_LIMITS` holds them, names every file each export of the baseline pack writes, and its
Python example runs as printed."""
from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

from spellwarden_scan import PATTERN_LIMITS, baseline_pack, build_export

README = Path(__file__).resolve().parents[1] / "README.md"
HEADING = "## Org rules, packs and exports\n"
LIMITS_START, LIMITS_END = "<!-- pattern-limits:start -->\n", "<!-- pattern-limits:end -->"
EXAMPLE_START, EXAMPLE_END = "<!-- orgrules-example:start -->\n", "<!-- orgrules-example:end -->"


def _section() -> str:
    text = README.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.count(HEADING) == 1
    rest = text[text.index(HEADING) + len(HEADING):]
    return rest[:rest.index("\n## ")]


def _between(text: str, start: str, end: str) -> str:
    assert text.count(start) == 1 and text.count(end) == 1
    return text[text.index(start) + len(start):text.index(end)]


def test_the_readme_limits_table_equals_pattern_limits():
    rows = re.findall(r"^\| `([a-z_]+)` \| (\d+) \| [^|\n]+ \|$", _between(_section(), LIMITS_START, LIMITS_END), re.M)
    assert {name: int(value) for name, value in rows} == dict(PATTERN_LIMITS)
    assert len(rows) == len(PATTERN_LIMITS)


def test_the_readme_names_every_file_of_every_export():
    section = _section()
    for target, mode in (("claude-code-hooks", "project"), ("claude-code-hooks", "managed"), ("kong", "project")):
        for path in build_export(baseline_pack(), target, built_at="2026-12-01T00:00:00Z", mode=mode):
            assert f"`{path}`" in section, (target, mode, path)


def test_the_readme_example_runs_and_finds_the_org_rule():
    block = _between(_section(), EXAMPLE_START, EXAMPLE_END)
    code = block.removeprefix("```python\n").removesuffix("```\n")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(compile(code, "README.md", "exec"), {"__name__": "readme_example"})  # noqa: S102 -- our own README
    lines = out.getvalue().splitlines()
    assert "['SW-ORG-001']" in lines
    assert any("'managed/spellwarden_guard.py'" in line for line in lines)


def test_the_managed_mode_states_its_verification_as_the_exports_do():
    # Spec 5.5.1: a platform is "not yet verified" in the README exactly while it is missing from
    # `exports.hooks.MANAGED_VERIFIED`, which also decides the sentence in every managed export's README (Task 6);
    # Task 8 sets the constant and the README cells in one commit after the release gate.
    from spellwarden_scan.exports import hooks

    section = _section()
    for platform in hooks.PLATFORMS:
        name, script = hooks.PLATFORM_NAMES[platform], hooks.MANAGED_SCRIPT_PATHS[platform]
        status = (r"verified on \d{1,2} [A-Z][a-z]+ 20\d\d" if platform in hooks.MANAGED_VERIFIED
                  else re.escape(f"not yet verified on {name}"))
        row = re.escape(f"| {name} | `{script}` | `{hooks.MANAGED_SETTINGS_PATHS[platform]}` | ") + status + r" \|"
        assert re.search(rf"^{row}$", section, re.M), platform


def _fenced(block: str) -> str:
    lines = block.strip("\n").split("\n")
    assert lines[0].startswith("```") and lines[-1] == "```"
    return "\n".join(lines[1:-1]) + "\n"


def test_the_readme_export_examples_are_what_the_baseline_exports():
    # review of 2026-10-21 (r0:F6, r0:F7): an example of each export and of both hook modes, kept equal to the output
    section, built = _section(), "2026-12-01T00:00:00Z"
    project = build_export(baseline_pack(), "claude-code-hooks", built_at=built, mode="project")
    managed = build_export(baseline_pack(), "claude-code-hooks", built_at=built, mode="managed")
    kong = build_export(baseline_pack(), "kong", built_at=built)
    for name, expected in (("hooks-project", project[".claude/settings.json"]),
                           ("hooks-managed", managed["managed/linux/managed-settings.json"])):
        shown = _fenced(_between(section, f"<!-- {name}-example:start -->\n", f"<!-- {name}-example:end -->"))
        assert shown == expected.decode("utf-8")
    shown = _fenced(_between(section, "<!-- kong-example:start -->\n", "<!-- kong-example:end -->"))
    assert kong["kong/spellwarden-baseline-1.0.yaml"].decode("utf-8").startswith(shown)
    assert "Do not run `deck gateway sync` with this file alone" in section
