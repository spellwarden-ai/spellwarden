"""Claim E7, the static half (Phase C spec 5.5.1): the files of the Claude Code hooks export in both modes, the
hooks object, the command strings, `SHA256SUMS`, the README's lists and the guard script's own constraints. The
guard's decisions are tested by running it, in `test_guard.py`."""
from __future__ import annotations

import ast
import hashlib
import json

import pytest
from guard_ci import BUILT_AT, vector_pack

from spellwarden_scan.exports import CANNOT_ENFORCE, VENDOR_LINE, build
from spellwarden_scan.exports import hooks
from spellwarden_scan.exports.guard_template import TEMPLATE
from spellwarden_scan.rules import patterns as P
from spellwarden_scan.rules import skill

FULL_MATCHER = "^(Bash|PowerShell|Read|Grep|Glob|mcp__.*)$"
PROJECT_FILES = {".claude/.gitignore", ".claude/hooks/spellwarden_guard.py", ".claude/settings.json", "SHA256SUMS",
                 "SPELLWARDEN-README.md"}
MANAGED_FILES = {"managed/linux/managed-settings.json", "managed/macos/managed-settings.json",
                 "managed/windows/managed-settings.json", "managed/spellwarden_guard.py", "SHA256SUMS", "SPELLWARDEN-README.md"}


def _files(mode: str, doc=None) -> dict[str, bytes]:
    return hooks.hooks_files(doc or vector_pack(), built_at=BUILT_AT, mode=mode)


def _settings(files: dict[str, bytes], path: str) -> dict:
    return json.loads(files[path].decode("ascii"))


def test_project_mode_files_and_settings():
    files = _files("project")
    assert set(files) == PROJECT_FILES
    assert files[".claude/.gitignore"] == b"spellwarden-activity.jsonl*\n"
    settings = _settings(files, ".claude/settings.json")
    assert set(settings) == {"hooks"}
    pre, post = settings["hooks"]["PreToolUse"], settings["hooks"]["PostToolUse"]
    assert pre == [{"matcher": FULL_MATCHER, "hooks": [{"type": "command", "timeout": 10,
                    "command": 'python3 -I "$CLAUDE_PROJECT_DIR"/.claude/hooks/spellwarden_guard.py pre'}]}]
    assert post == [{"matcher": "*", "hooks": [{"type": "command", "timeout": 10,
                     "command": 'python3 -I "$CLAUDE_PROJECT_DIR"/.claude/hooks/spellwarden_guard.py post'}]}]


@pytest.mark.parametrize("platform", ["linux", "macos", "windows"])
def test_managed_mode_settings_name_the_absolute_script_and_allow_managed_hooks_only(platform):
    files = _files("managed")
    assert set(files) == MANAGED_FILES
    settings = _settings(files, f"managed/{platform}/managed-settings.json")
    assert settings["allowManagedHooksOnly"] is True
    command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    path = hooks.MANAGED_SCRIPT_PATHS[platform]
    assert f'"{path}"' in command and command.endswith(" pre")
    assert path.startswith("/") or path.startswith("C:\\")
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == FULL_MATCHER
    assert settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == command[:-3] + "post"


def test_no_managed_file_names_the_project_directory():
    for path, content in _files("managed").items():
        assert b"$CLAUDE_PROJECT_DIR" not in content, path


def test_the_managed_commands_are_quoted_exactly():
    assert hooks.hook_command("managed", "linux", "pre") == 'python3 -I "/etc/claude-code/spellwarden/spellwarden_guard.py" pre'
    assert hooks.hook_command("managed", "macos", "pre") == (
        'python3 -I "/Library/Application Support/ClaudeCode/spellwarden/spellwarden_guard.py" pre')
    assert hooks.hook_command("managed", "windows", "post") == (
        'py -3 -I "C:\\Program Files\\ClaudeCode\\spellwarden\\spellwarden_guard.py" post')
    windows = _files("managed")["managed/windows/managed-settings.json"]
    assert rb'"py -3 -I \"C:\\Program Files\\ClaudeCode\\spellwarden\\spellwarden_guard.py\" pre"' in windows
    with pytest.raises(ValueError):
        hooks.hook_command("managed", "solaris", "pre")
    with pytest.raises(ValueError):
        hooks.hook_command("project", None, "during")


@pytest.mark.parametrize("mode,script", [("project", ".claude/hooks/spellwarden_guard.py"),
                                         ("managed", "managed/spellwarden_guard.py")])
def test_sha256sums_names_the_script(mode, script):
    files = _files(mode)
    digest = hashlib.sha256(files[script]).hexdigest()
    assert files["SHA256SUMS"] == f"{digest}  {script}\n".encode("ascii")


def test_only_sw_hk_002_needs_the_shell_and_file_tools_and_no_post_hook():
    settings = _settings(_files("project", vector_pack(enabled={"SW-HK-002"}, org_rules=[])), ".claude/settings.json")
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "^(Bash|PowerShell|Read|Grep|Glob)$"
    assert "PostToolUse" not in settings["hooks"]


def test_only_sw_ob_008_gives_only_the_post_hook():
    settings = _settings(_files("project", vector_pack(enabled={"SW-OB-008"}, org_rules=[])), ".claude/settings.json")
    assert list(settings["hooks"]) == ["PostToolUse"]


def test_nothing_to_enforce_gives_empty_hooks_and_says_so():
    files = _files("managed", vector_pack(enabled=set(), org_rules=[]))
    for platform in ("linux", "macos", "windows"):
        assert _settings(files, f"managed/{platform}/managed-settings.json") == {"allowManagedHooksOnly": True, "hooks": {}}
    assert "This pack enforces nothing in Claude Code." in files["SPELLWARDEN-README.md"].decode("utf-8")


def test_checks_order_deny_before_ask_and_copy_the_engine_matchers():
    checks = hooks.compile_checks(vector_pack())
    assert [(c["rule_id"], c["decision"], c["kind"]) for c in checks] == [
        ("SW-HK-001", "deny", "commands"), ("SW-HK-002", "deny", "any_path"), ("SW-ORG-001", "deny", "then"),
        ("SW-GW-006", "ask", "commands"), ("SW-GW-006", "ask", "mcp_verb"), ("SW-ORG-002", "ask", "then")]
    hk001 = checks[0]["any"]
    assert hk001[0] == {"piped": [skill._PIPED.matchers[0].source.pattern, skill._PIPED.matchers[0].sink.pattern], "i": True}
    assert len(hk001) == len(skill._PIPED.matchers)
    assert checks[1]["any"] == [{"re": P.SECRET_PATHS.pattern, "i": True}, {"re": P.MORE_SECRET_PATHS.pattern, "i": True}]
    assert checks[4]["verbs"] == ["delete", "drop", "destroy", "remove", "purge", "truncate", "terminate", "wipe", "reset", "force"]


def test_an_org_rule_without_the_hooks_target_is_not_a_check_and_is_listed_not_included():
    kong_only = dict(vector_pack().org_rules[0], targets=["kong"])
    doc = vector_pack(org_rules=[kong_only])
    assert [c["rule_id"] for c in hooks.compile_checks(doc)] == ["SW-HK-001", "SW-HK-002", "SW-GW-006", "SW-GW-006"]
    readme = _files("project", doc)["SPELLWARDEN-README.md"].decode("utf-8")
    assert "SW-ORG-001" in readme


@pytest.mark.parametrize("mode", ["project", "managed"])
def test_readme_lists_what_is_enforced_and_what_cannot_be(mode):
    readme = _files(mode)["SPELLWARDEN-README.md"].decode("utf-8")
    for rule_id in ("SW-HK-001", "SW-HK-002", "SW-GW-006", "SW-ORG-001", "SW-ORG-002"):
        assert rule_id in readme
    for rule_id in ("SW-GW-003", "SW-GW-004", "SW-EG-005", "SW-RG-007", "SW-OB-008"):
        assert rule_id in readme and CANNOT_ENFORCE[(rule_id, "claude-code-hooks")] in readme
    assert VENDOR_LINE in readme
    assert "not an audit trail" in readme
    if mode == "project":
        assert "This mode is advisory." in readme
    else:
        unverified = [hooks.PLATFORM_NAMES[name] for name in hooks.PLATFORMS if name not in hooks.MANAGED_VERIFIED]
        if unverified:  # until Task 8 sets MANAGED_VERIFIED after the release gate
            assert "The managed mode is not yet verified on " + ", ".join(unverified) + "." in readme
        else:
            assert "not yet verified" not in readme


def test_build_dispatches_the_hooks_target():
    doc = vector_pack()
    for mode in ("project", "managed"):
        assert build(doc, "claude-code-hooks", built_at=BUILT_AT, mode=mode) == _files(mode, doc)
    with pytest.raises(ValueError):
        hooks.hooks_files(doc, built_at=BUILT_AT, mode="global")


def test_the_export_is_deterministic_and_the_script_holds_no_build_time():
    first, second = _files("managed"), _files("managed")
    assert first == second
    assert BUILT_AT.encode() not in first["managed/spellwarden_guard.py"]
    other = hooks.hooks_files(vector_pack(), built_at="2027-01-01T00:00:00Z", mode="managed")
    assert other["managed/spellwarden_guard.py"] == first["managed/spellwarden_guard.py"]


def test_the_guard_is_python_3_8_and_imports_only_the_standard_library_six():
    script = hooks.guard_script(vector_pack()).decode("utf-8")
    tree = ast.parse(script, feature_version=(3, 8))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert imported == {"datetime", "json", "os", "re", "stat", "sys"}
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not [node for node in ast.walk(tree) if type(node).__name__ in ("Match", "TypeAlias")]
    for later in ("removeprefix", "removesuffix", "| None", "zoneinfo"):
        assert later not in script
    assert "'''" not in TEMPLATE
    assert all(len(line) <= 130 for line in TEMPLATE.splitlines())


def test_a_pack_name_holding_a_placeholder_stays_text():
    doc = vector_pack(name="Ops __CHECKS__ and __MODE__ \"quoted\"")
    script = hooks.guard_script(doc, mode="managed").decode("utf-8")
    namespace: dict = {}
    exec(compile(script.replace('if __name__ == "__main__":', "if False:"), "guard", "exec"), namespace)
    assert namespace["PACK_NAME"] == "Ops __CHECKS__ and __MODE__ \"quoted\""
    assert namespace["MODE"] == "managed"
    assert namespace["CHECKS"] == json.loads(json.dumps(hooks.compile_checks(doc), sort_keys=True))
