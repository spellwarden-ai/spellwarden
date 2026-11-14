"""Instruction files (Phase 3 batch 1 spec 10.2 to 10.4): which files of a repository are instructions to an agent, the front
matter of a rule file, and how a file's scope is put in words. Pure functions of a path and bytes; `discover.py` finds the files,
`run.py` scans them and the output modules print `instruction_scope`.

The table of 10.2, as each tool documented its layout on 2026-11-13. Paths are scan-root paths with `/`, matched exactly as
written (no case folding); each row is a `format`:

- `agents-md`: a file named `AGENTS.md`, at any depth.
- `claude-md`: a file named `CLAUDE.md`, at any depth.
- `gemini-md`: a file named `GEMINI.md`, at any depth.
- `copilot-instructions`: `.github/copilot-instructions.md` at the scan root.
- `cursor-mdc`: a `.mdc` file under a directory `.cursor/rules/` at any depth, subfolders included.
- `cursorrules`: `.cursorrules` at the scan root.
- `windsurf-rules`: a `.md` file directly under `.windsurf/rules/` or `.devin/rules/` at any depth, and `.windsurfrules` at the
  scan root.
"""
from __future__ import annotations

import posixpath

FORMATS = ("agents-md", "claude-md", "gemini-md", "copilot-instructions", "cursor-mdc", "cursorrules", "windsurf-rules")
MAX_FILES = 200            # instruction files read per scan root; the rest are the notice `instructions_limit`
FRONT_MATTER_WINDOW = 4096  # the closing `---` must be within this many bytes of the file's start
MAX_GLOBS = 20
MAX_GLOB = 200
MAX_DESCRIPTION = 300
MAX_TRIGGER = 32
_NAMED = {"AGENTS.md": "agents-md", "CLAUDE.md": "claude-md", "GEMINI.md": "gemini-md"}
# The keys read from the front matter of a rule file, by format: Cursor writes `description`, `globs` and `alwaysApply`,
# Windsurf and Devin `trigger`, `globs` and `description`. No other format has its front matter read.
_FRONT_MATTER_KEYS = {"cursor-mdc": ("description", "globs", "alwaysApply"),
                      "windsurf-rules": ("trigger", "globs", "description")}

ALWAYS = "Applied: always"
ASKED = "Applied when asked for"


def format_of(path: str) -> str | None:
    """The `format` of the instruction file at the scan-root path `path`, or None when it is not one."""
    parts = path.split("/")
    name, directories = parts[-1], parts[:-1]
    if name in _NAMED:
        return _NAMED[name]
    if path == ".github/copilot-instructions.md":
        return "copilot-instructions"
    if path == ".cursorrules":
        return "cursorrules"
    if path == ".windsurfrules":
        return "windsurf-rules"
    if name.endswith(".mdc") and any(a == ".cursor" and b == "rules" for a, b in zip(directories, directories[1:], strict=False)):
        return "cursor-mdc"
    if name.endswith(".md") and tuple(directories[-2:]) in ((".windsurf", "rules"), (".devin", "rules")):
        return "windsurf-rules"
    return None


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
    MAX_DESCRIPTION characters are kept; `alwaysApply` is true or false. The result is None with `readable` True when the format
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
        if key == "globs":
            if value == "":
                globs, in_list = [], True
                continue
            globs = _globs(value)
            if globs is None:
                return None, False
        elif key == "alwaysApply":
            always_apply = {"true": True, "false": False}.get(value.lower())
        elif key == "description":
            description = _unquote(value)
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
    given = front_matter or {}
    trigger, description, globs = given.get("trigger"), given.get("description"), given.get("globs") or []
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
