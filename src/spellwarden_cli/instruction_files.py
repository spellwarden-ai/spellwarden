"""Instruction files (Phase 3 batch 1 spec 10.2 to 10.4; Engine 1.20.0: scan selection, 7.3 to 7.6): which files of a repository
are instructions to an agent, the front matter of a rule file, and how a file's scope is put in words. Pure functions of a path
and bytes; `discover.py` finds the files, `run.py` scans them and the output modules print `instruction_scope`.

Paths are scan-root paths with `/`, matched whatever their case and Unicode form (NFC, then case folding, as macOS and Windows
open names and as configuration file names match): a `claude.md` committed to a repository is what an agent on those systems
loads as `CLAUDE.md`. One path has one format; `format_of` decides in this order, first match wins (7.4):

1. `<name>/AGENT.md` directly in a `.devin/agents/` or `.agents/agents/` folder: `devin-agent`.
2. A name, at any depth: `AGENTS.md`, `AGENTS.override.md`, `AGENTS.local.md`, `AGENT.md` (`agents-md`); `CLAUDE.md`,
   `CLAUDE.local.md` (`claude-md`); `GEMINI.md` (`gemini-md`).
3. At the scan root: `.github/copilot-instructions.md` (`copilot-instructions`), `.cursorrules` (`cursorrules`),
   `.windsurfrules` (`windsurf-rules`).
4. A folder, at any depth: `.mdc` below `.cursor/rules/` (`cursor-mdc`); `.md` below `.windsurf/rules/` or `.devin/rules/`, and
   `global_rules.md` directly in a `.windsurf` or `.devin` folder (`windsurf-rules`); `.md` below `.claude/rules/`
   (`claude-rule`), `.claude/commands/` (`claude-command`), `.claude/agents/` (`claude-agent`); `.md` directly in
   `.claude/output-styles/` (`claude-output-style`), `.cursor/agents/` (`cursor-agent`), `.codex/agents/` (`codex-agent`),
   `.gemini/agents/` (`gemini-agent`), `.devin/agents/` or `.agents/agents/` (`devin-agent`); `.instructions.md` below
   `.github/instructions/` (`github-instructions`); `.md` below `.github/agents/` (`github-agent`).

Four formats exist only in `scan --user`, where the client table gives each file its format and `format_of` is not asked:
`codex-agents-md` (Codex's user `AGENTS.md`), `devin-rules` (Devin Desktop's user rules, front matter as Windsurf's),
`codex-prompt` (Codex's custom prompts) and `cursor-command` (the commands of a Cursor local plugin). A `global_rules.md` of
Windsurf or Devin in the home, or directly in a `.windsurf` or `.devin` folder, is always applied.
"""
from __future__ import annotations

import posixpath
import re

from spellwarden_scan.identity import fold_skill_name as _fold

FORMATS = ("agents-md", "claude-md", "gemini-md", "copilot-instructions", "cursor-mdc", "cursorrules", "windsurf-rules",
           "claude-rule", "codex-agents-md", "devin-rules", "claude-command", "claude-agent", "claude-output-style",
           "cursor-agent", "cursor-command", "codex-agent", "codex-prompt", "gemini-agent", "devin-agent", "github-instructions",
           "github-agent")
# The formats only `scan --user` gives; every other one is also a repository format, which the lock file's schema lists
# (Engine 1.20.0: scan selection, 7.17, D26).
USER_ONLY_FORMATS = ("codex-agents-md", "devin-rules", "codex-prompt", "cursor-command")
REPOSITORY_FORMATS = tuple(format for format in FORMATS if format not in USER_ONLY_FORMATS)
MAX_FILES = 300            # instruction files read per scan root; more is the error `instructions_limit` (exit 2)
# Engine 1.20.0 (scan selection, 7.20.4, D42): with `--follow-links`, at most this many linked directories in instruction folders
# are followed per scan root; more is the error `instructions_limit` (exit 2)
MAX_LINKED_DIRECTORIES = 50
# The names a directory is probed with (`holds_instructions`), one per file shape a folder rule names, and the formats a name
# gives anywhere, which say nothing of the folder that holds it
_PROBES = ("x.md", "x.mdc", "x.instructions.md", "AGENT.md")
_BY_NAME = ("agents-md", "claude-md", "gemini-md")
FRONT_MATTER_WINDOW = 4096  # the closing `---` must be within this many bytes of the file's start
MAX_GLOBS = 20
MAX_GLOB = 200
MAX_DESCRIPTION = 300
MAX_TRIGGER = 32
_NAMED = {"agents.md": "agents-md", "agents.override.md": "agents-md", "agents.local.md": "agents-md", "agent.md": "agents-md",
          "claude.md": "claude-md", "claude.local.md": "claude-md", "gemini.md": "gemini-md"}  # folded names
_DEVIN_AGENTS = ((".devin", "agents"), (".agents", "agents"))
# The agent folders an agent reads at the root of the repository (`loaded_first`), folded.
_ROOT_FOLDERS = (".cursor/rules/", ".windsurf/rules/", ".devin/rules/", ".claude/rules/", ".claude/commands/", ".claude/agents/",
                 ".claude/output-styles/", ".cursor/agents/", ".codex/agents/", ".gemini/agents/", ".devin/agents/",
                 ".agents/agents/", ".github/instructions/", ".github/agents/")
# The formats new in 1.20.0, whose `description` written as a YAML block (`|`, `>`) is None: the line parser reads no block value.
# Existing formats keep 1.19.0's parsing (Engine 1.20.0: scan selection, 7.5, D13).
_NEW_FORMATS = frozenset(FORMATS[FORMATS.index("claude-command"):])
_BLOCK = re.compile(r"[|>][-+0-9]*")
# The keys read from the front matter of a rule file, by format: Cursor writes `description`, `globs` and `alwaysApply`,
# Windsurf and Devin `trigger`, `globs` and `description`, Claude Code `paths` (read like `globs`), GitHub's instruction files
# `applyTo` (one string of comma-separated globs, read as `globs`) and `description`, and every command, subagent, output style
# and prompt a `description`. No other format has its front matter read; no other field is uploaded (task 6.6).
_FRONT_MATTER_KEYS = {"cursor-mdc": ("description", "globs", "alwaysApply"),
                      "windsurf-rules": ("trigger", "globs", "description"),
                      "devin-rules": ("trigger", "globs", "description"),
                      "claude-rule": ("paths",),
                      "github-instructions": ("applyTo", "description"),
                      **{format: ("description",) for format in _NEW_FORMATS if format != "github-instructions"}}

ALWAYS = "Applied: always"
ASKED = "Applied when asked for"


def format_of(path: str) -> str | None:
    """The `format` of the instruction file at the scan-root path `path`, or None when it is not one (the order of the module's
    docstring, Engine 1.20.0: scan selection, 7.4)."""
    folded = _fold(path)
    parts = folded.split("/")
    name, directories = parts[-1], parts[:-1]
    if name == "agent.md" and len(directories) >= 3 and tuple(directories[-3:-1]) in _DEVIN_AGENTS:
        return "devin-agent"
    if name in _NAMED:
        return _NAMED[name]
    if folded == ".github/copilot-instructions.md":
        return "copilot-instructions"
    if folded == ".cursorrules":
        return "cursorrules"
    if folded == ".windsurfrules":
        return "windsurf-rules"
    pairs = set(zip(directories, directories[1:], strict=False))
    last = tuple(directories[-2:])
    if name.endswith(".mdc") and (".cursor", "rules") in pairs:
        return "cursor-mdc"
    if not name.endswith(".md"):
        return None
    if (".windsurf", "rules") in pairs or (".devin", "rules") in pairs:
        return "windsurf-rules"
    if name == "global_rules.md" and directories and directories[-1] in (".windsurf", ".devin"):
        return "windsurf-rules"
    if (".claude", "rules") in pairs:
        return "claude-rule"
    if (".claude", "commands") in pairs:
        return "claude-command"
    if (".claude", "agents") in pairs:
        return "claude-agent"
    if last == (".claude", "output-styles"):
        return "claude-output-style"
    if last == (".cursor", "agents"):
        return "cursor-agent"
    if last == (".codex", "agents"):
        return "codex-agent"
    if last == (".gemini", "agents"):
        return "gemini-agent"
    if last in _DEVIN_AGENTS:
        return "devin-agent"
    if name.endswith(".instructions.md") and (".github", "instructions") in pairs:
        return "github-instructions"
    if (".github", "agents") in pairs:
        return "github-agent"
    return None


def loaded_first(path: str) -> bool:
    """Whether the instruction file at `path` is in a place an agent reads at the root of the repository: `AGENTS.md`,
    `CLAUDE.md`, `GEMINI.md` and their variants at the root, `.github/copilot-instructions.md`, `.cursorrules`, `.windsurfrules`,
    the root `global_rules.md` of `.windsurf` or `.devin`, or a file of an agent folder at the root (`_ROOT_FOLDERS`;
    Engine 1.20.0: scan selection, 7.3, D15). Past the limit these are read before any other, so nested decoys cannot push
    them out of the scan."""
    format, folded = format_of(path), _fold(path)
    if format is None:
        return False
    if format in ("agents-md", "claude-md", "gemini-md"):
        return "/" not in folded  # `.github/x/AGENTS.md` or `.cursor/rules/AGENTS.md` is a nested file, not a root place
    if format in ("copilot-instructions", "cursorrules") or "/" not in folded:
        return True  # the table holds these at the root only (`.windsurfrules` among them)
    if folded in (".windsurf/global_rules.md", ".devin/global_rules.md"):
        return True
    return folded.startswith(_ROOT_FOLDERS)


def _folder_probes(path: str) -> list[str]:
    """The probe paths below the directory `path` that a folder rule of `format_of` (steps 1 and 4) makes instruction files."""
    probes = [f"{path}/{name}" for name in _PROBES]
    return [probe for probe in probes if format_of(probe) not in (None, *_BY_NAME)]


def holds_instructions(path: str) -> bool:
    """Whether a directory at the scan-root path `path` could hold an instruction file by a folder rule (Engine 1.20.0: scan
    selection, 7.20.2, D39): below an instruction folder that is read at that depth (`.claude/rules/shared`,
    `.devin/agents/reviewer`), or the folder itself (`.claude/rules`). A folder above one (`.claude`), a folder read one level
    deep below its first level (`.claude/output-styles/more`) and any other directory are not."""
    return bool(_folder_probes(path))


def linked_first(path: str) -> bool:
    """Whether a linked instruction directory at `path` is in an agent folder at the root of the repository (`loaded_first` of a
    file its folder rule would name there): past `MAX_LINKED_DIRECTORIES` these are followed first."""
    return any(loaded_first(probe) for probe in _folder_probes(path))


def _unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _globs(value: str) -> list[str] | None:
    """The globs of `globs: value` on one line: a bracketed list or a comma-separated list; None for a bracket never closed.
    An empty value starts a list of `- item` lines (the caller reads them)."""
    if value.startswith("["):
        if not value.endswith("]"):
            return None
        value = value[1:-1]
    return [_unquote(part.strip()) for part in value.split(",") if part.strip()]


def front_matter_of(format: str, content: bytes) -> tuple[dict | None, bool]:
    """`(front matter, readable)` of a rule file (spec 10.3). It is a line parser, not YAML, because Cursor writes values YAML
    refuses (`globs: *.ts` is an alias error): between a first line `---` and the next `---` within FRONT_MATTER_WINDOW bytes,
    the lines `key: value` of the keys of the format. A value is unquoted; `globs` is a comma-separated list, a bracketed list or
    the `- item` lines that follow an empty value; at most MAX_GLOBS globs of MAX_GLOB characters and a description of
    MAX_DESCRIPTION characters are kept; `alwaysApply` is true or false. `applyTo` (1.20.0) is read as `globs`; a `description`
    of a format new in 1.20.0 that is a YAML block indicator is None. The result is None with `readable` True when the format
    has no front matter to read or the file starts with none, and None with `readable` False when it starts with `---` and the
    block never closes within the window or a bracketed list never closes."""
    keys = _FRONT_MATTER_KEYS.get(format)
    if keys is None:
        return None, True
    head = content[:FRONT_MATTER_WINDOW].decode("utf-8", errors="replace").lstrip("\ufeff")
    lines = head.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines[0].strip() != "---":
        return None, True
    end = next((index for index in range(1, len(lines)) if lines[index].strip() == "---"), None)
    if end is None:
        return None, False
    globs: list[str] | None = None
    in_list = False
    always_apply = description = trigger = None
    for line in lines[1:end]:
        stripped = line.strip()
        if in_list and globs is not None and stripped.startswith("- "):
            globs.append(_unquote(stripped[2:].strip()))
            continue
        in_list = False
        key, separator, value = stripped.partition(":")
        key, value = key.strip(), value.strip()
        if not separator or key not in keys:
            continue
        if key in ("globs", "paths", "applyTo"):
            if value == "":
                globs, in_list = [], True
                continue
            # GitHub's `applyTo` is one string of comma-separated globs: unquoted whole first, then split (7.5)
            globs = _globs(_unquote(value) if key == "applyTo" else value)
            if globs is None:
                return None, False
        elif key == "alwaysApply":
            always_apply = {"true": True, "false": False}.get(value.lower())
        elif key == "description":
            description = None if format in _NEW_FORMATS and _BLOCK.fullmatch(value) else _unquote(value)
        else:
            trigger = _unquote(value)
    return {
        "description": description[:MAX_DESCRIPTION] if description else None,
        "globs": None if globs is None else [glob[:MAX_GLOB] for glob in globs if glob][:MAX_GLOBS],
        "always_apply": always_apply,
        "trigger": trigger[:MAX_TRIGGER] if trigger else None,
    }, True


def instruction_scope(format: str, path: str, front_matter: dict | None) -> str:
    """When the agent applies the file, in words (spec 10.4), from the front matter by one rule: `Applied: always`, `Applied
    to files matching: <globs>`, `Applied when the agent judges it relevant: <description>` or `Applied when asked for`. The
    plain files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, the Copilot file, `.cursorrules`, `.windsurfrules`) are always applied;
    a rule file is applied as its front matter says, and as asked for when it says nothing. The text holds words of the file
    (globs, a description): the output modules escape it."""
    if format not in _FRONT_MATTER_KEYS or (front_matter is None and posixpath.basename(path) == ".windsurfrules"):
        return ALWAYS
    if format in ("claude-output-style", "codex-prompt"):
        return ASKED  # the user picks a style or invokes a prompt (Engine 1.20.0: scan selection, 7.6, D14)
    if format in ("windsurf-rules", "devin-rules") and _fold(posixpath.basename(path)) == "global_rules.md" and (
            path.startswith("~/") or _fold(posixpath.basename(posixpath.dirname(path))) in (".windsurf", ".devin")):
        return ALWAYS  # the global rules of Windsurf and Devin apply to every conversation, in the home and in a repository
    given = front_matter or {}
    trigger, description, globs = given.get("trigger"), given.get("description"), given.get("globs") or []
    if format == "claude-rule":
        return "Applied to files matching: " + ", ".join(globs) if globs else ALWAYS
    if given.get("always_apply") is True or trigger == "always_on":
        return ALWAYS
    if trigger == "manual":
        return ASKED
    if trigger == "model_decision":
        return _relevant(description)
    if globs:
        return "Applied to files matching: " + ", ".join(globs)
    if description:
        return _relevant(description)
    return ASKED


def _relevant(description: object) -> str:
    base = "Applied when the agent judges it relevant"
    return f"{base}: {description}" if isinstance(description, str) and description else base


def scopes(items) -> dict[str, str]:
    """`{path: instruction_scope(...)}` for the items of kind `instructions` among `items` (any object with `kind`, `path`,
    `format` and `front_matter`)."""
    return {item.path: instruction_scope(item.format, item.path, item.front_matter)
            for item in items if item.kind == "instructions"}
