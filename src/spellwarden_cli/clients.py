"""The client table of `spellwarden scan --user` (phase 3 batch 2a spec 11.2): for each of the seven clients, per operating
system, the files and directories in a user's home that hold its agent configuration, each with the client's own documentation
as its source and the date that source was read. One table for every operating system; the README's "Scanning a workstation"
table and its "Not read" list are generated from it byte for byte (`tests/test_readme_clients.py`).

A row is kept only while its source confirms it (spec D21): a row whose source no longer names the path moves to `NOT_READ`.
Paths are written with `/` on every system and start at a base token (`BASES`); `*` in a path matches one directory or file
name. Pure: `resolve_base` and `display` take the home, the platform and the environment as arguments."""
from __future__ import annotations

import os
import posixpath
from collections.abc import Mapping
from dataclasses import dataclass

CLIENTS = ("claude-code", "claude-desktop", "cursor", "vscode", "windsurf", "codex", "gemini-cli")
CLIENT_NAMES = {"claude-code": "Claude Code", "claude-desktop": "Claude Desktop", "cursor": "Cursor", "vscode": "VS Code",
                "windsurf": "Windsurf (Devin Desktop)", "codex": "Codex", "gemini-cli": "Gemini CLI"}
SYSTEMS = ("linux", "macos", "windows")
ALL = SYSTEMS
SYSTEM_NAMES = {"linux": "Linux", "macos": "macOS", "windows": "Windows"}
# The base tokens of 11.2, each with what it stands for when its variable is not set.
BASES = ("~", "$XDG_CONFIG_HOME", "%APPDATA%", "~/Library/Application Support", "$CLAUDE_CONFIG_DIR", "$CODEX_HOME",
         "$COPILOT_HOME")
_DEFAULTS = {"$XDG_CONFIG_HOME": ".config", "%APPDATA%": "AppData/Roaming", "~/Library/Application Support":
             "Library/Application Support", "$CLAUDE_CONFIG_DIR": ".claude", "$CODEX_HOME": ".codex", "$COPILOT_HOME": ".copilot"}
_VARIABLES = {"$XDG_CONFIG_HOME": "XDG_CONFIG_HOME", "%APPDATA%": "APPDATA", "$CLAUDE_CONFIG_DIR": "CLAUDE_CONFIG_DIR",
              "$CODEX_HOME": "CODEX_HOME", "$COPILOT_HOME": "COPILOT_HOME"}
_ONLY_ON = {"$XDG_CONFIG_HOME": ("linux",), "%APPDATA%": ("windows",), "~/Library/Application Support": ("macos",)}
# The readers of `userdocs` and `userscan`, one per file shape.
READERS = ("mcp", "windsurf-mcp", "gemini-settings", "claude-json", "settings", "hooks", "cursor-hooks", "codex-config",
           "skills", "instructions", "claude-plugins", "claude-marketplaces", "gemini-extensions")
CHECKED = "2026-11-14"


@dataclass(frozen=True)
class Row:
    id: str             # unique, `<client>/<what>`
    client: str         # one of CLIENTS
    systems: tuple[str, ...]
    base: str           # one of BASES
    paths: tuple[str, ...]  # relative to the base, `/`-separated; `*` matches one name
    reader: str         # one of READERS
    reads: str          # what the row reads, in words (the README's "Reads" column)
    source: str         # the client's own documentation
    checked: str        # the date the source was read, YYYY-MM-DD
    format: str | None = None   # the instruction format, for the reader `instructions`
    moved_by: str | None = None  # a variable that, when set, holds the file instead of the base (`.claude.json`)
    shared: bool = False  # a directory other clients read too: finding it does not show that this client is installed


_CLAUDE_DIRECTORY = "https://code.claude.com/docs/en/claude-directory"
_CLAUDE_SETTINGS = "https://code.claude.com/docs/en/settings"
_CLAUDE_PLUGINS = "https://code.claude.com/docs/en/plugins/loading"
_DESKTOP = "https://modelcontextprotocol.io/docs/develop/connect-local-servers"
_VSCODE_MCP = "https://code.visualstudio.com/docs/copilot/reference/mcp-configuration"
_VSCODE_SKILLS = "https://code.visualstudio.com/docs/copilot/customization/agent-skills"
_DEVIN_MCP = "https://docs.devin.ai/desktop/cascade/mcp"
_DEVIN_MEMORIES = "https://docs.devin.ai/desktop/cascade/memories"
_CODEX_CONFIG = "https://learn.chatgpt.com/docs/config-file/config-reference"
_CODEX_HOOKS = "https://learn.chatgpt.com/docs/hooks"
_CODEX_SKILLS = "https://learn.chatgpt.com/docs/build-skills"
_CODEX_AGENTS = "https://learn.chatgpt.com/docs/agent-configuration/agents-md"
_GEMINI_CONFIG = "https://geminicli.com/docs/reference/configuration"
_GEMINI_EXTENSIONS = "https://geminicli.com/docs/extensions/reference/"
_GEMINI_MEMORY = "https://geminicli.com/docs/cli/gemini-md/"
_GEMINI_SKILLS = "https://geminicli.com/docs/cli/skills/"

ROWS: tuple[Row, ...] = (
    Row("claude-code/state", "claude-code", ALL, "~", (".claude.json",), "claude-json",
        "MCP servers of the user scope (`mcpServers`) and of each project (`projects.<directory>.mcpServers`)",
        _CLAUDE_DIRECTORY, CHECKED, moved_by="CLAUDE_CONFIG_DIR"),
    Row("claude-code/settings", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("settings.json",), "settings",
        "hooks, permissions, `enabledPlugins`, `extraKnownMarketplaces`", _CLAUDE_SETTINGS, CHECKED),
    Row("claude-code/skills", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("skills",), "skills", "skills (`<name>/SKILL.md`)",
        _CLAUDE_DIRECTORY, CHECKED),
    Row("claude-code/memory", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("CLAUDE.md",), "instructions",
        "instruction file (`claude-md`)", _CLAUDE_DIRECTORY, CHECKED, format="claude-md"),
    Row("claude-code/rules", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("rules/*.md",), "instructions",
        "instruction files (`claude-rule`)", _CLAUDE_DIRECTORY, CHECKED, format="claude-rule"),
    Row("claude-code/plugins", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("plugins/installed_plugins.json",), "claude-plugins",
        "installed plugins, and in each plugin's directory its skills, `.mcp.json`, `hooks/hooks.json` and "
        "`.claude-plugin/plugin.json`", _CLAUDE_PLUGINS, CHECKED),
    Row("claude-code/marketplaces", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("plugins/known_marketplaces.json",),
        "claude-marketplaces", "marketplaces and their sources", _CLAUDE_PLUGINS, CHECKED),
    Row("claude-desktop/linux", "claude-desktop", ("linux",), "$XDG_CONFIG_HOME", ("Claude/claude_desktop_config.json",), "mcp",
        "MCP servers (`mcpServers`)", _DESKTOP, CHECKED),
    Row("claude-desktop/macos", "claude-desktop", ("macos",), "~/Library/Application Support",
        ("Claude/claude_desktop_config.json",), "mcp", "MCP servers (`mcpServers`)", _DESKTOP, CHECKED),
    Row("claude-desktop/windows", "claude-desktop", ("windows",), "%APPDATA%", ("Claude/claude_desktop_config.json",), "mcp",
        "MCP servers (`mcpServers`)", _DESKTOP, CHECKED),
    Row("cursor/mcp", "cursor", ALL, "~", (".cursor/mcp.json",), "mcp", "MCP servers (`mcpServers`)",
        "https://cursor.com/docs/context/mcp", CHECKED),
    Row("cursor/hooks", "cursor", ALL, "~", (".cursor/hooks.json",), "cursor-hooks", "hooks",
        "https://cursor.com/docs/agent/hooks", CHECKED),
    Row("vscode/copilot", "vscode", ALL, "$COPILOT_HOME", ("mcp-config.json",), "mcp", "MCP servers (`mcpServers`)",
        _VSCODE_MCP, CHECKED),
    Row("vscode/skills", "vscode", ALL, "$COPILOT_HOME", ("skills",), "skills", "skills (`<name>/SKILL.md`)", _VSCODE_SKILLS,
        CHECKED),
    Row("vscode/claude-skills", "vscode", ALL, "~", (".claude/skills",), "skills", "skills (`<name>/SKILL.md`)",
        _VSCODE_SKILLS, CHECKED, shared=True),
    Row("vscode/agents-skills", "vscode", ALL, "~", (".agents/skills",), "skills", "skills (`<name>/SKILL.md`)",
        _VSCODE_SKILLS, CHECKED, shared=True),
    Row("windsurf/mcp", "windsurf", ALL, "~", (".config/devin/mcp_config.json",), "windsurf-mcp",
        "MCP servers (`mcpServers`, remote ones by `serverUrl` or `url`)", _DEVIN_MCP, CHECKED),
    Row("windsurf/global-rules", "windsurf", ALL, "~", (".devin/global_rules.md",), "instructions",
        "instruction file (`devin-rules`)", _DEVIN_MEMORIES, CHECKED, format="devin-rules"),
    Row("windsurf/rules", "windsurf", ALL, "~", (".devin/rules/*.md",), "instructions", "instruction files (`devin-rules`)",
        _DEVIN_MEMORIES, CHECKED, format="devin-rules"),
    Row("windsurf/skills", "windsurf", ALL, "~", (".config/devin/skills",), "skills", "skills (`<name>/SKILL.md`)", _DEVIN_MCP,
        CHECKED),
    Row("windsurf/agents-skills", "windsurf", ALL, "~", (".agents/skills",), "skills", "skills (`<name>/SKILL.md`)",
        _DEVIN_MCP, CHECKED, shared=True),
    Row("codex/config", "codex", ALL, "$CODEX_HOME", ("config.toml",), "codex-config",
        "MCP servers (`[mcp_servers.<id>]`), hooks (`[hooks]`, `notify`), plugins (`[plugins]`), marketplaces "
        "(`[marketplaces]`)", _CODEX_CONFIG, CHECKED),
    Row("codex/hooks", "codex", ALL, "$CODEX_HOME", ("hooks.json",), "hooks", "hooks", _CODEX_HOOKS, CHECKED),
    Row("codex/skills", "codex", ALL, "~", (".agents/skills",), "skills", "skills (`<name>/SKILL.md`)", _CODEX_SKILLS, CHECKED,
        shared=True),
    Row("codex/agents", "codex", ALL, "$CODEX_HOME", ("AGENTS.md", "AGENTS.override.md"), "instructions",
        "instruction files (`codex-agents-md`)", _CODEX_AGENTS, CHECKED, format="codex-agents-md"),
    Row("gemini-cli/settings", "gemini-cli", ALL, "~", (".gemini/settings.json",), "gemini-settings",
        "MCP servers (`mcpServers`; `url` is SSE, `httpUrl` streamable HTTP), hooks", _GEMINI_CONFIG, CHECKED),
    Row("gemini-cli/extensions", "gemini-cli", ALL, "~", (".gemini/extensions",), "gemini-extensions",
        "extensions (plugins): each `<name>/gemini-extension.json` with its MCP servers, `hooks/hooks.json` and the context "
        "files it names", _GEMINI_EXTENSIONS, CHECKED),
    Row("gemini-cli/memory", "gemini-cli", ALL, "~", (".gemini/GEMINI.md",), "instructions", "instruction file (`gemini-md`)",
        _GEMINI_MEMORY, CHECKED, format="gemini-md"),
    Row("gemini-cli/skills", "gemini-cli", ALL, "~", (".gemini/skills",), "skills", "skills (`<name>/SKILL.md`)",
        _GEMINI_SKILLS, CHECKED),
    Row("gemini-cli/agents-skills", "gemini-cli", ALL, "~", (".agents/skills",), "skills", "skills (`<name>/SKILL.md`)",
        _GEMINI_SKILLS, CHECKED, shared=True),
)

# What `scan --user` does not read, with the reason (spec 11.2 and D21): the README's "Not read" list, one line each.
NOT_READ: tuple[str, ...] = (
    "Windsurf's `~/.codeium/windsurf/mcp_config.json` and `~/.codeium/windsurf/memories/global_rules.md`: the Windsurf "
    "documentation now leads to Devin Desktop's, which names `~/.config/devin/` and `~/.devin/` instead.",
    "Codex's `$CODEX_HOME/skills/`: the Codex skills guide names `~/.agents/skills/` only.",
    "VS Code's user and profile `mcp.json` files (`Code/User/mcp.json`, `Code/User/profiles/*/mcp.json`, also of VS Code "
    "Insiders): the profiles and MCP documentation name no path for the file.",
    "VS Code's user instruction files (`*.instructions.md` of the user profile): the documentation names no path.",
    "The files of installed Codex plugins: only the `[plugins]` and `[marketplaces]` entries of `config.toml` are listed.",
    "Claude Code's plugins when `CLAUDE_CODE_PLUGIN_CACHE_DIR` moves them out of `$CLAUDE_CONFIG_DIR/plugins/`, the "
    "components a plugin declares outside its standard layout, and MCP bundles (`.mcpb`, `.dxt`).",
    "Skills inside Gemini CLI extensions: the documentation names no directory for them.",
    "System-wide managed files outside the home directory (`/etc/claude-code/`, `/etc/gemini-cli/`, `C:\\ProgramData\\`), "
    "which belong to an administrator, not to the user.",
    "Cursor's user rules, which Cursor keeps in its own settings database, not in a file.",
    "Claude Code subagents, commands and output styles, and Claude Desktop extensions.",
)


def platform_of(sys_platform: str) -> str:
    """`sys.platform` as a system of the table: `darwin` is macOS, `win32` and `cygwin` Windows, every other one Linux."""
    if sys_platform == "darwin":
        return "macos"
    if sys_platform in ("win32", "cygwin"):
        return "windows"
    return "linux"


def rows_for(system: str) -> tuple[Row, ...]:
    return tuple(row for row in ROWS if system in row.systems)


def _join(base: str, relative: str) -> str:
    return os.path.join(base, *relative.split("/"))


def resolve_base(row: Row, home: str, system: str, env: Mapping[str, str]) -> str | None:
    """The absolute directory the row's paths start at, for the user whose home is `home`; None when the row's base is not
    used on `system` (11.2). `system` decides which bases apply; the paths themselves are the running system's (so a test
    reads the Windows fixture home on Linux). A variable that is set but empty or relative counts as unset."""
    if row.moved_by is not None and _absolute(env.get(row.moved_by, "")):
        return env[row.moved_by]
    if system not in _ONLY_ON.get(row.base, SYSTEMS):
        return None
    if row.base == "~":
        return home
    variable = _VARIABLES.get(row.base)
    if variable is not None and _absolute(env.get(variable, "")):
        return env[variable]
    return _join(home, _DEFAULTS[row.base])


def _absolute(value: str) -> bool:
    return bool(value) and os.path.isabs(value)


def relative_to(path: str, directory: str) -> str | None:
    """`path` relative to `directory` with `/`, "" for the directory itself, None when it is not inside it. Names compare as
    the running system compares them (`os.path.normcase`)."""
    path, directory = os.path.normpath(path), os.path.normpath(directory)
    if os.path.normcase(path) == os.path.normcase(directory):
        return ""
    prefix = directory if directory.endswith(os.sep) else directory + os.sep
    if not os.path.normcase(path).startswith(os.path.normcase(prefix)):
        return None
    return path[len(prefix):].replace(os.sep, "/")


def display(path: str, home: str, system: str, env: Mapping[str, str]) -> str | None:
    """How an absolute path is shown (11.2): `~/...` when it lies inside the home, else under the first base token whose
    directory holds it (`%APPDATA%/Claude/...`), always with `/`; None for a path under neither, which is never printed."""
    inside = relative_to(path, home)
    if inside is not None:
        return "~" if inside == "" else "~/" + inside
    for token, variable in _VARIABLES.items():
        value = env.get(variable, "")
        if system in _ONLY_ON.get(token, SYSTEMS) and _absolute(value):
            inside = relative_to(path, value)
            if inside is not None:
                return token if inside == "" else f"{token}/{inside}"
    return None


def table_markdown() -> str:
    """The README's client table: one line per row, in table order."""
    lines = ["| Client | Systems | Path | Reads | Source | Checked |", "|---|---|---|---|---|---|"]
    for row in ROWS:
        systems = "all" if row.systems == ALL else ", ".join(SYSTEM_NAMES[system] for system in row.systems)
        paths = "<br>".join(f"`{row.base}/{path}`" for path in row.paths)
        if row.moved_by is not None:
            paths += f" (`${row.moved_by}/{posixpath.basename(row.paths[0])}` when `{row.moved_by}` is set)"
        lines.append(f"| {CLIENT_NAMES[row.client]} | {systems} | {paths} | {row.reads} | <{row.source}> | {row.checked} |")
    return "\n".join(lines) + "\n"


def not_read_markdown() -> str:
    return "".join(f"- {line}\n" for line in NOT_READ)


def readme_block() -> str:
    """What sits between `<!-- clients:start -->` and `<!-- clients:end -->` in the README."""
    return f"{table_markdown()}\nNot read:\n\n{not_read_markdown()}"


__all__ = ["BASES", "CLIENTS", "CLIENT_NAMES", "NOT_READ", "READERS", "ROWS", "SYSTEMS", "Row", "display", "platform_of",
           "readme_block", "relative_to", "resolve_base", "rows_for"]
