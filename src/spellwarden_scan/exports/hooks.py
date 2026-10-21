"""The `claude-code-hooks` export (spec 5.5.1): a hooks object for Claude Code's settings and the generated guard
script, in a project mode (files committed to the repository, advisory) and a managed mode (an administrator
installs the script outside every checkout and declares the hooks in Claude Code's managed settings). Pure: the
checks are compiled from the engine's own matcher objects, so the patterns a scan uses and the patterns a hook
enforces are one source (decision D5)."""
from __future__ import annotations

import hashlib
import json
import re

from spellwarden_scan import orgrules
from spellwarden_scan.exports import CANNOT_ENFORCE, EXPORT_MODES, readme_text
from spellwarden_scan.exports.guard_template import TEMPLATE
from spellwarden_scan.packs import ENFORCEMENT_RULES, PackDocument
from spellwarden_scan.rules import patterns as P
from spellwarden_scan.rules import skill

TARGET = "claude-code-hooks"
GUARD_NAME = "spellwarden_guard.py"
PROJECT_SCRIPT = ".claude/hooks/" + GUARD_NAME
MANAGED_SCRIPT = "managed/" + GUARD_NAME
PLATFORMS = ("linux", "macos", "windows")
MANAGED_SCRIPT_PATHS = {
    "linux": "/etc/claude-code/spellwarden/spellwarden_guard.py",
    "macos": "/Library/Application Support/ClaudeCode/spellwarden/spellwarden_guard.py",
    "windows": "C:\\Program Files\\ClaudeCode\\spellwarden\\spellwarden_guard.py",
}
# Where Claude Code reads a managed settings file (code.claude.com/docs/en/managed-settings, checked 2026-10-21).
MANAGED_SETTINGS_PATHS = {
    "linux": "/etc/claude-code/managed-settings.json",
    "macos": "/Library/Application Support/ClaudeCode/managed-settings.json",
    "windows": "C:\\Program Files\\ClaudeCode\\managed-settings.json",
}
# The platforms on which the managed mode passed the release gate of spec 5.5.1 (the CI job `managed-guard` and the
# owner's check with Claude Code installed). Task 8 sets it before the v1.1.0 tag; the README names the others.
MANAGED_VERIFIED: tuple[str, ...] = ("linux", "macos", "windows")
PLATFORM_NAMES = {"linux": "Linux", "macos": "macOS", "windows": "Windows"}
# SW-GW-006 for MCP tools: the `<tool>` part of `mcp__<server>__<tool>` starts with one of these or holds it as a
# `_`- or `-`-separated word.
MCP_VERBS = ("delete", "drop", "destroy", "remove", "purge", "truncate", "terminate", "wipe", "reset", "force")
# Claude Code's shell tools: Bash, and PowerShell on Windows (code.claude.com/docs/en/hooks, checked 2026-10-21).
COMMAND_TOOLS = ("Bash", "PowerShell")
PATH_TOOLS = ("Read", "Grep", "Glob")
TOOL_ORDER = ("Bash", "PowerShell", "Read", "Grep", "Glob", "mcp__*")
HOOK_TIMEOUT_SECONDS = 10
DECISION_ORDER = {"deny": 0, "ask": 1}
GITIGNORE = b"spellwarden-activity.jsonl*\n"
_FLAGS = re.IGNORECASE | re.UNICODE
_PLACEHOLDER = re.compile(r"__(PACK_NAME|PACK_VERSION|MODE|CHECKS)__")


def _matchers(item) -> list[dict]:
    """A JSON form of one engine matcher (`re.Pattern`, `Then`, `Within`, `Piped`, `AnyOf`) for the guard."""
    if isinstance(item, P.AnyOf):
        return [spec for inner in item.matchers for spec in _matchers(inner)]
    if isinstance(item, re.Pattern):
        return [{"re": item.pattern, "i": _ignore_case(item)}]
    if isinstance(item, P.Then):
        return [{"then": [part.pattern for part in item.parts], "i": _ignore_case(*item.parts)}]
    if isinstance(item, P.Piped):
        return [{"piped": [item.source.pattern, item.sink.pattern], "i": _ignore_case(item.source, item.sink)}]
    if isinstance(item, P.Within):
        return [{"within": [item.opener.pattern, item.inner.pattern, item.close], "i": _ignore_case(item.opener, item.inner)}]
    raise TypeError(f"no guard form for {type(item).__name__}")


def _ignore_case(*patterns: re.Pattern) -> bool:
    flags = {pattern.flags for pattern in patterns}
    if len(flags) != 1 or flags.pop() & ~_FLAGS:
        raise ValueError("a guard matcher needs one flag set of IGNORECASE and UNICODE only")
    return bool(patterns[0].flags & re.IGNORECASE)


def _titles() -> dict[str, str]:
    return {rule.id: rule.title for rule in ENFORCEMENT_RULES}


def compile_checks(doc: PackDocument) -> list[dict]:
    """The CHECKS of spec 5.5.1 for the enabled rules: deny checks first, then ask checks, each in rule id order
    (the guard takes the first match, so a deny is never hidden behind an ask)."""
    enabled = set(doc.enabled())
    titles = _titles()
    checks: list[dict] = []
    if "SW-HK-001" in enabled:
        checks.append({"rule_id": "SW-HK-001", "title": titles["SW-HK-001"], "decision": "deny",
                       "tools": list(COMMAND_TOOLS), "field": "command", "kind": "commands", "any": _matchers(skill._PIPED)})
    if "SW-HK-002" in enabled:
        checks.append({"rule_id": "SW-HK-002", "title": titles["SW-HK-002"], "decision": "deny",
                       "tools": list(COMMAND_TOOLS + PATH_TOOLS), "field": "path", "kind": "any_path",
                       "any": _matchers(P.SECRET_PATHS) + _matchers(P.MORE_SECRET_PATHS)})
    if "SW-GW-006" in enabled:
        checks.append({"rule_id": "SW-GW-006", "title": titles["SW-GW-006"], "decision": "ask",
                       "tools": list(COMMAND_TOOLS), "field": "command", "kind": "commands",
                       "any": _matchers(skill._DESTRUCTIVE)})
        checks.append({"rule_id": "SW-GW-006", "title": titles["SW-GW-006"], "decision": "ask",
                       "tools": ["mcp__*"], "field": "tool_name", "kind": "mcp_verb", "verbs": list(MCP_VERBS)})
    for spec in hook_org_rules(doc):
        detection = spec["detection"]
        compiled = orgrules.compile_pattern(detection["pattern"], case_sensitive=bool(detection.get("case_sensitive", False)))
        checks.append({"rule_id": spec["id"], "title": spec["title"],
                       "decision": "deny" if spec["severity"] in ("critical", "high") else "ask",
                       "tools": list(COMMAND_TOOLS), "field": "command", "kind": "then",
                       "parts": [part.pattern for part in compiled.parts], "i": not compiled.case_sensitive,
                       "anchored_end": compiled.anchored_end})
    return sorted(checks, key=lambda check: (DECISION_ORDER[check["decision"]], check["rule_id"]))


def hook_org_rules(doc: PackDocument) -> list[dict]:
    """The pack's org rules that name this target (each is a pattern rule reading `commands`, spec 5.2.1)."""
    return [spec for spec in doc.org_rules if TARGET in spec.get("targets", ())]


def hook_command(mode: str, platform: str | None, phase: str) -> str:
    """The command string of one hook. Paths are always double-quoted (two of the managed ones hold spaces)."""
    if phase not in ("pre", "post"):
        raise ValueError(f"phase {phase!r}")
    if mode == "project":
        return f'python3 -I "$CLAUDE_PROJECT_DIR"/{PROJECT_SCRIPT} {phase}'
    if mode != "managed" or platform not in PLATFORMS:
        raise ValueError(f"mode {mode!r} platform {platform!r}")
    interpreter = "py -3 -I" if platform == "windows" else "python3 -I"
    return f'{interpreter} "{MANAGED_SCRIPT_PATHS[platform]}" {phase}'


def hooks_object(doc: PackDocument, command_pre: str, command_post: str) -> dict:
    """`{"PreToolUse": [...], "PostToolUse": [...]}` with only the tools the enabled checks need; `PostToolUse`
    only with SW-OB-008 on; `{}` when there is nothing to do in Claude Code."""
    needed = {tool for check in compile_checks(doc) for tool in check["tools"]}
    names = [("mcp__.*" if tool == "mcp__*" else tool) for tool in TOOL_ORDER if tool in needed]
    hooks: dict = {}
    if names:
        hooks["PreToolUse"] = [{"matcher": "^(" + "|".join(names) + ")$",
                                "hooks": [{"type": "command", "command": command_pre, "timeout": HOOK_TIMEOUT_SECONDS}]}]
    if "SW-OB-008" in doc.enabled():
        hooks["PostToolUse"] = [{"matcher": "*",
                                 "hooks": [{"type": "command", "command": command_post, "timeout": HOOK_TIMEOUT_SECONDS}]}]
    return hooks


def guard_script(doc: PackDocument, *, mode: str = "project") -> bytes:
    """`spellwarden_guard.py`: the template with the pack's name, version, mode and CHECKS as Python literals,
    replaced in one pass (a pack name holding a placeholder's text stays text)."""
    if mode not in EXPORT_MODES:
        raise ValueError(f"mode {mode!r}")
    values = {"PACK_NAME": repr(doc.name), "PACK_VERSION": repr(doc.version), "MODE": repr(mode),
              "CHECKS": repr(json.dumps(compile_checks(doc), sort_keys=True, ensure_ascii=True))}
    return _PLACEHOLDER.sub(lambda match: values[match.group(1)], TEMPLATE).encode("utf-8")


def _json_file(value: dict) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _sha256sums(path: str, content: bytes) -> bytes:
    return f"{hashlib.sha256(content).hexdigest()}  {path}\n".encode("ascii")


def _lists(doc: PackDocument) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    """What this export enforces, which enabled rules it cannot enforce (with the reason), what is not included."""
    enabled = doc.enabled()
    org = hook_org_rules(doc)
    enforced = [rule.id for rule in ENFORCEMENT_RULES if rule.id in enabled and TARGET in rule.enforced_by]
    enforced += [spec["id"] for spec in org]
    cannot = [(rule.id, CANNOT_ENFORCE[(rule.id, TARGET)]) for rule in ENFORCEMENT_RULES
              if rule.id in enabled and TARGET not in rule.enforced_by]
    not_included = [rule_id for rule_id, on in doc.rules if not on]
    not_included += [spec["id"] for spec in doc.org_rules if spec not in org]
    return enforced, cannot, not_included


INSTALL_PROJECT = [
    "Copy the `.claude` folder of this archive into the root of the repository: `.claude/settings.json` declares the "
    "hooks and `.claude/hooks/spellwarden_guard.py` is the guard. If the repository already has a "
    "`.claude/settings.json`, add this file's `hooks` entries to it.",
    "Check the guard against `SHA256SUMS` (`sha256sum -c SHA256SUMS` from the archive's root).",
    "Commit the three files, `.claude/.gitignore` included: it keeps the local activity log out of the repository.",
    "Start a new Claude Code session in the repository; the hooks run from then on.",
]
INSTALL_MANAGED = [
    "Install `managed/spellwarden_guard.py` read-only, owned by root (Linux, macOS) or by the Administrators group "
    "(Windows) and writable by nobody else, at `/etc/claude-code/spellwarden/spellwarden_guard.py` on Linux, "
    "`/Library/Application Support/ClaudeCode/spellwarden/spellwarden_guard.py` on macOS and "
    "`C:\\Program Files\\ClaudeCode\\spellwarden\\spellwarden_guard.py` on Windows. Its folder must not be "
    "writable by users either.",
    "Verify the installed script against `SHA256SUMS`.",
    "Place the settings file of the platform where Claude Code reads managed settings: "
    "`managed/linux/managed-settings.json` as `/etc/claude-code/managed-settings.json`, "
    "`managed/macos/managed-settings.json` as `/Library/Application Support/ClaudeCode/managed-settings.json`, "
    "`managed/windows/managed-settings.json` as `C:\\Program Files\\ClaudeCode\\managed-settings.json`. If that "
    "file already holds your organisation's policy, add this file's keys to it, or place this file next to it as "
    "`managed-settings.d/50-spellwarden.json`.",
    "Restart Claude Code; `/status` names the managed settings source.",
]
LIMITS_COMMON = [
    "The hooks run only where Python 3.8 or newer is installed as `python3` (on Windows, the `py` launcher).",
    "A missing interpreter or a hook timeout lets the tool call proceed: Claude Code treats both as non-blocking "
    "unless the hook sets `onFailure` to `block` (Claude Code v2.1.295 or later), which this export does not set. "
    "An administrator who wants failures to block adds it to the managed hooks.",
    "The guard never blocks on its own failure: unreadable or unexpected hook input, including an event larger "
    "than 1 MiB, lets the tool call proceed, with one line on standard error. An agent can therefore pass every "
    "check by making one tool call larger than 1 MiB.",
    "A missing or unreadable guard script is not a guard failure: Python exits with status 2, which Claude Code "
    "reads as a block, so every matched tool call is refused until the script is restored. This also happens when "
    "the hook's path does not resolve in the shell Claude Code runs it with.",
    "Commands are matched as text. Quoting, variables, aliases or encodings can evade a check, and an org rule can "
    "miss a match longer than 512 characters that crosses a 4096-character window boundary. PowerShell commands "
    "are matched with the same patterns, which are written for POSIX shells.",
    "SW-OB-008: the guard appends one line per tool call (time, session, tool name; no tool input or output) to "
    "`spellwarden-activity.jsonl`. It is a local activity log the user can read, change or delete, not an audit "
    "trail.",
]
LIMITS_PROJECT = [
    "This mode is advisory. The project controls these files: any branch can change, replace or remove the script "
    "or the settings, so this mode helps developers who want it and enforces nothing against a developer or a "
    "checkout that does not.",
]
LIMITS_MANAGED = [
    "Managed settings protect the hook declaration; the guard script is protected only by the permissions it is "
    "installed with.",
    "On WSL, `/etc/claude-code` can be written by the user, so the managed mode is not enforced there.",
]


def _limits(mode: str, hooks: dict) -> list[str]:
    limits = list(LIMITS_PROJECT if mode == "project" else LIMITS_MANAGED)
    if mode == "managed":
        unverified = [PLATFORM_NAMES[name] for name in PLATFORMS if name not in MANAGED_VERIFIED]
        if unverified:
            limits.append("The managed mode is not yet verified on " + ", ".join(unverified) + ".")
    if not hooks:
        limits.append("This pack enforces nothing in Claude Code.")
    return limits + LIMITS_COMMON


def hooks_files(doc: PackDocument, *, built_at: str, mode: str) -> dict[str, bytes]:
    """The files of the export, by archive path (spec 5.5.1)."""
    if mode not in EXPORT_MODES:
        raise ValueError(f"mode {mode!r}")
    script = guard_script(doc, mode=mode)
    enforced, cannot, not_included = _lists(doc)
    files: dict[str, bytes] = {}
    if mode == "project":
        hooks = hooks_object(doc, hook_command("project", None, "pre"), hook_command("project", None, "post"))
        files[".claude/settings.json"] = _json_file({"hooks": hooks})
        files[PROJECT_SCRIPT] = script
        files[".claude/.gitignore"] = GITIGNORE
        files["SHA256SUMS"] = _sha256sums(PROJECT_SCRIPT, script)
        install = INSTALL_PROJECT
    else:
        hooks = {}
        for platform in PLATFORMS:
            hooks = hooks_object(doc, hook_command("managed", platform, "pre"), hook_command("managed", platform, "post"))
            files[f"managed/{platform}/managed-settings.json"] = _json_file({"allowManagedHooksOnly": True, "hooks": hooks})
        files[MANAGED_SCRIPT] = script
        files["SHA256SUMS"] = _sha256sums(MANAGED_SCRIPT, script)
        install = INSTALL_MANAGED
    files["SPELLWARDEN-README.md"] = readme_text(doc, target=TARGET, mode=mode, built_at=built_at, enforced=enforced,
                                                 cannot_enforce=cannot, not_included=not_included, install=install,
                                                 limits=_limits(mode, hooks))
    return dict(sorted(files.items()))
