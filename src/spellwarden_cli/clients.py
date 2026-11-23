"""The client table of `spellwarden scan --user` (phase 3 batch 2a spec 11.2): for each of the seven clients, per operating
system, the files and directories in a user's home that hold its agent configuration, each with the client's own documentation
as its source and the date that source was read. One table for every operating system; the README's "Scanning a workstation"
table and its "Not read" list are generated from it byte for byte (`tests/test_readme_clients.py`).

A row is kept only while its source confirms it (spec D21): a row whose source no longer names the path moves to `NOT_READ`.
Paths are written with `/` on every system and start at a base token (`BASES`); `*` in a path matches one directory or file
name, and a segment `**` zero or more directory names (Engine 1.20.0: scan selection, 7.10). Pure: `resolve_base` and `display`
take the home, the platform and the environment as arguments."""
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
# Engine 1.20.0 (7.9, D19): `$XDG_CONFIG_HOME` applies on macOS too (Devin Desktop's folder); the rows that used it before are
# Linux-only, so none of them moves
_ONLY_ON = {"$XDG_CONFIG_HOME": ("linux", "macos"), "%APPDATA%": ("windows",), "~/Library/Application Support": ("macos",)}
# The readers of `userdocs` and `userscan`, one per file shape.
READERS = ("mcp", "windsurf-mcp", "gemini-settings", "claude-json", "settings", "hooks", "cursor-hooks", "codex-config",
           "skills", "instructions", "claude-plugins", "claude-marketplaces", "gemini-extensions", "copilot-hooks",
           "copilot-settings", "devin-config", "codex-plugins", "copilot-plugins", "cursor-plugins")
CHECKED = "2026-11-14"
# Phase 3 batch 2c spec 11.3 (F2): the date the VS Code user `mcp.json` rows' three sources were read.
CHECKED_VSCODE_USER = "2026-11-15"
# Engine 1.20.0 (scan selection, 7.9): the date every new or changed row's source was read.
CHECKED_SELECTION = "2026-11-23"


@dataclass(frozen=True)
class Row:
    id: str             # unique, `<client>/<what>`
    client: str         # one of CLIENTS
    systems: tuple[str, ...]
    base: str           # one of BASES
    paths: tuple[str, ...]  # relative to the base, `/`-separated; `*` matches one name, `**` zero or more directories
    reader: str         # one of READERS
    reads: str          # what the row reads, in words (the README's "Reads" column)
    source: str         # the client's own documentation
    checked: str        # the date the source was read, YYYY-MM-DD
    format: str | None = None   # the instruction format, for the reader `instructions`
    moved_by: str | None = None  # a variable that, when set, holds the file instead of the base (`.claude.json`)
    shared: bool = False  # a directory other clients read too: finding it does not show that this client is installed
    # Batch 2c spec 11.3: the pages the path is derived from, when the source names the file but not where it is
    path_from: tuple[str, ...] = ()


_CLAUDE_DIRECTORY = "https://code.claude.com/docs/en/claude-directory"
_CLAUDE_SETTINGS = "https://code.claude.com/docs/en/settings"
_CLAUDE_PLUGINS = "https://code.claude.com/docs/en/plugins/loading"
_CLAUDE_PLUGIN_LAYOUT = "https://code.claude.com/docs/en/plugins/manifest-reference"
_CLAUDE_MEMORY_RULES = "https://code.claude.com/docs/en/memory#user-level-rules"
_CLAUDE_SKILLS = "https://code.claude.com/docs/en/skills"
# The skills page names `.claude/commands/` only; the settings reference names `~/.claude/commands/` (row check of 2026-11-23).
_CLAUDE_COMMANDS = "https://code.claude.com/docs/en/settings-reference"
_CLAUDE_SUBAGENTS = "https://code.claude.com/docs/en/sub-agents"
_CLAUDE_OUTPUT_STYLES = "https://code.claude.com/docs/en/output-styles"
_DESKTOP = "https://modelcontextprotocol.io/docs/develop/connect-local-servers"
_CURSOR_SKILLS = "https://cursor.com/docs/skills"
_CURSOR_SUBAGENTS = "https://cursor.com/docs/subagents"
# The reference page names the plugin layout but not the local folder; the guide names `~/.cursor/plugins/local` (row check of
# 2026-11-23), so the guide is the row's source.
_CURSOR_PLUGINS = "https://cursor.com/docs/plugins"
_VSCODE_MCP = "https://code.visualstudio.com/docs/copilot/reference/mcp-configuration"
_VSCODE_SKILLS = "https://code.visualstudio.com/docs/copilot/customization/agent-skills"
_VSCODE_INSTRUCTIONS = "https://code.visualstudio.com/docs/agents/reference/custom-instructions-reference"
_VSCODE_AGENTS = "https://code.visualstudio.com/docs/agents/reference/custom-agent-file-reference"
_VSCODE_AI_SETTINGS = "https://code.visualstudio.com/docs/agents/reference/ai-settings"
_COPILOT_CONFIG_DIR = "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference"
_COPILOT_PLUGINS = "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference"
_COPILOT_HOOKS = "https://docs.github.com/en/copilot/reference/hooks-reference"
# VS Code's MCP reference names the "user-profile `mcp.json`" without a path: the folder is the user settings folder of
# `settings.json` and its `profiles/<profile id>/` folders (batch 2c spec 11.3, F2).
_VSCODE_USER_FOLDER = ("https://code.visualstudio.com/docs/configure/settings",
                       "https://code.visualstudio.com/docs/configure/profiles")
_VSCODE_USER_MCP = ("Code/User/mcp.json", "Code/User/profiles/*/mcp.json", "Code - Insiders/User/mcp.json",
                    "Code - Insiders/User/profiles/*/mcp.json")
# Engine 1.20.0 (7.9, D20): Windsurf's pages now lead to Devin's; Devin Local "shares its agent harness with Devin CLI", so the
# CLI pages are the sources of what the Devin folder holds, and the customisations page gives the folder (D19, D23).
_DEVIN_CUSTOMIZATIONS = "https://docs.devin.ai/desktop/devin-local/customizations"
_DEVIN_RULES = "https://docs.devin.ai/cli/extensibility/rules"
_DEVIN_SKILLS = "https://docs.devin.ai/cli/extensibility/skills/overview"
_DEVIN_HOOKS = "https://docs.devin.ai/cli/extensibility/hooks/overview"
_DEVIN_SUBAGENTS = "https://docs.devin.ai/cli/subagents"
_DEVIN_READ_CONFIG = "https://docs.devin.ai/cli/reference/configuration/read-config-from"
_CODEX_CONFIG = "https://learn.chatgpt.com/docs/config-file/config-reference"
_CODEX_HOOKS = "https://learn.chatgpt.com/docs/hooks"
_CODEX_SKILLS = "https://learn.chatgpt.com/docs/build-skills"
_CODEX_AGENTS = "https://learn.chatgpt.com/docs/agent-configuration/agents-md"
_CODEX_PROMPTS = "https://learn.chatgpt.com/docs/custom-prompts"
_CODEX_PLUGINS = "https://developers.openai.com/plugins/build/plugins"
_GEMINI_CONFIG = "https://geminicli.com/docs/reference/configuration"
_GEMINI_EXTENSIONS = "https://geminicli.com/docs/extensions/reference/"
_GEMINI_MEMORY = "https://geminicli.com/docs/cli/gemini-md/"
_GEMINI_SKILLS = "https://geminicli.com/docs/cli/skills/"
_GEMINI_SUBAGENTS = "https://geminicli.com/docs/core/subagents/"
_SKILLS = "skills (`<name>/SKILL.md`)"
_WINDSURF_MCP = "MCP servers (`mcpServers`, remote ones by `serverUrl` or `url`)"


def _devin(row_id: str, paths: tuple[str, ...], reader: str, reads: str, source: str, *, format: str | None = None,
           path_from: tuple[str, ...] = (_DEVIN_CUSTOMIZATIONS,)) -> tuple[Row, Row]:
    """A file of Devin Desktop's configuration folder (Engine 1.20.0: scan selection, 7.9, D19): `$XDG_CONFIG_HOME/devin/` on
    Linux and macOS (`~/.config/devin/` when the variable is not set) and `%APPDATA%/devin/` on Windows, one row each; the
    customisations page gives the folder (`path_from`)."""
    return (Row(row_id, "windsurf", ("linux", "macos"), "$XDG_CONFIG_HOME", paths, reader, reads, source, CHECKED_SELECTION,
                format=format, path_from=path_from),
            Row(f"{row_id}-windows", "windsurf", ("windows",), "%APPDATA%", paths, reader, reads, source, CHECKED_SELECTION,
                format=format, path_from=path_from))

ROWS: tuple[Row, ...] = (
    Row("claude-code/state", "claude-code", ALL, "~", (".claude.json",), "claude-json",
        "MCP servers of the user scope (`mcpServers`) and of each project (`projects.<directory>.mcpServers`)",
        _CLAUDE_DIRECTORY, CHECKED, moved_by="CLAUDE_CONFIG_DIR"),
    Row("claude-code/settings", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("settings.json",), "settings",
        "hooks, permissions, `enabledPlugins`, `extraKnownMarketplaces`", _CLAUDE_SETTINGS, CHECKED),
    Row("claude-code/skills", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("skills",), "skills", _SKILLS, _CLAUDE_DIRECTORY,
        CHECKED),
    Row("claude-code/memory", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("CLAUDE.md",), "instructions",
        "instruction file (`claude-md`)", _CLAUDE_DIRECTORY, CHECKED, format="claude-md"),
    Row("claude-code/rules", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("rules/**/*.md",), "instructions",
        "instruction files (`claude-rule`), subfolders included", _CLAUDE_MEMORY_RULES, CHECKED_SELECTION, format="claude-rule"),
    Row("claude-code/commands", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("commands/**/*.md",), "instructions",
        "commands (`claude-command`), subfolders included", _CLAUDE_COMMANDS, CHECKED_SELECTION, format="claude-command"),
    Row("claude-code/agents", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("agents/**/*.md",), "instructions",
        "subagents (`claude-agent`), subfolders included", _CLAUDE_SUBAGENTS, CHECKED_SELECTION, format="claude-agent"),
    Row("claude-code/output-styles", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("output-styles/*.md",), "instructions",
        "output styles (`claude-output-style`)", _CLAUDE_OUTPUT_STYLES, CHECKED_SELECTION, format="claude-output-style"),
    Row("claude-code/plugins", "claude-code", ALL, "$CLAUDE_CONFIG_DIR", ("plugins/installed_plugins.json",), "claude-plugins",
        "installed plugins, and in each plugin's directory its skills, commands (`claude-command`), subagents (`claude-agent`), "
        f"`.mcp.json`, `hooks/hooks.json` and `.claude-plugin/plugin.json` (the layout of <{_CLAUDE_PLUGIN_LAYOUT}>)",
        _CLAUDE_PLUGINS, CHECKED_SELECTION),
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
    Row("cursor/skills", "cursor", ALL, "~", (".cursor/skills",), "skills", _SKILLS, _CURSOR_SKILLS, CHECKED_SELECTION),
    Row("cursor/agents-skills", "cursor", ALL, "~", (".agents/skills",), "skills", _SKILLS, _CURSOR_SKILLS, CHECKED_SELECTION,
        shared=True),
    Row("cursor/claude-skills", "cursor", ALL, "~", (".claude/skills",), "skills", _SKILLS, _CURSOR_SKILLS, CHECKED_SELECTION,
        shared=True),
    Row("cursor/codex-skills", "cursor", ALL, "~", (".codex/skills",), "skills", _SKILLS, _CURSOR_SKILLS, CHECKED_SELECTION,
        shared=True),
    Row("cursor/agents", "cursor", ALL, "~", (".cursor/agents/*.md",), "instructions", "subagents (`cursor-agent`)",
        _CURSOR_SUBAGENTS, CHECKED_SELECTION, format="cursor-agent"),
    Row("cursor/claude-agents", "cursor", ALL, "~", (".claude/agents/*.md",), "instructions", "subagents (`claude-agent`)",
        _CURSOR_SUBAGENTS, CHECKED_SELECTION, format="claude-agent", shared=True),
    Row("cursor/codex-agents", "cursor", ALL, "~", (".codex/agents/*.md",), "instructions", "subagents (`codex-agent`)",
        _CURSOR_SUBAGENTS, CHECKED_SELECTION, format="codex-agent", shared=True),
    Row("cursor/plugins", "cursor", ALL, "~", (".cursor/plugins/local/*",), "cursor-plugins",
        "local plugins: each plugin's `.cursor-plugin/plugin.json` or `plugin.json`, `mcp.json`, `hooks/hooks.json`, skills, "
        "rules (`cursor-mdc`), subagents (`cursor-agent`) and commands (`cursor-command`)", _CURSOR_PLUGINS, CHECKED_SELECTION),
    Row("vscode/copilot", "vscode", ALL, "$COPILOT_HOME", ("mcp-config.json",), "mcp", "MCP servers (`mcpServers`)",
        _VSCODE_MCP, CHECKED),
    Row("vscode/skills", "vscode", ALL, "$COPILOT_HOME", ("skills",), "skills", _SKILLS, _VSCODE_SKILLS, CHECKED),
    Row("vscode/claude-skills", "vscode", ALL, "~", (".claude/skills",), "skills", _SKILLS, _VSCODE_SKILLS, CHECKED, shared=True),
    Row("vscode/agents-skills", "vscode", ALL, "~", (".agents/skills",), "skills", _SKILLS, _VSCODE_SKILLS, CHECKED, shared=True),
    Row("vscode/instructions", "vscode", ALL, "$COPILOT_HOME", ("copilot-instructions.md",), "instructions",
        "instruction file (`copilot-instructions`)", _COPILOT_CONFIG_DIR, CHECKED_SELECTION, format="copilot-instructions"),
    Row("vscode/instruction-files", "vscode", ALL, "$COPILOT_HOME", ("instructions/**/*.instructions.md",), "instructions",
        "instruction files (`github-instructions`), subfolders included", _VSCODE_INSTRUCTIONS, CHECKED_SELECTION,
        format="github-instructions"),
    Row("vscode/agents", "vscode", ALL, "$COPILOT_HOME", ("agents/**/*.md",), "instructions",
        "custom agents (`github-agent`), subfolders included", _VSCODE_AGENTS, CHECKED_SELECTION, format="github-agent"),
    Row("vscode/hooks", "vscode", ALL, "$COPILOT_HOME", ("hooks/*.json",), "copilot-hooks",
        "hooks (each `bash`, `powershell` and `command`)", _COPILOT_HOOKS, CHECKED_SELECTION),
    Row("vscode/settings", "vscode", ALL, "$COPILOT_HOME", ("settings.json",), "copilot-settings",
        "inline hooks, `enabledPlugins`, `extraKnownMarketplaces`", _COPILOT_HOOKS, CHECKED_SELECTION),
    Row("vscode/plugins", "vscode", ALL, "$COPILOT_HOME", ("installed-plugins/*/*",), "copilot-plugins",
        "installed plugins (`_direct/<source id>` included): each plugin's manifest, `.mcp.json`, hooks, skills and custom "
        "agents (`github-agent`)", _COPILOT_PLUGINS, CHECKED_SELECTION),
    Row("vscode/claude-rules", "vscode", ALL, "~", (".claude/rules/**/*.md",), "instructions",
        "instruction files (`claude-rule`), subfolders included", _VSCODE_AI_SETTINGS, CHECKED_SELECTION, format="claude-rule",
        shared=True),
    Row("vscode/claude-memory", "vscode", ALL, "~", (".claude/CLAUDE.md",), "instructions", "instruction file (`claude-md`)",
        _VSCODE_INSTRUCTIONS, CHECKED_SELECTION, format="claude-md", shared=True),
    Row("vscode/claude-agents", "vscode", ALL, "~", (".claude/agents/**/*.md",), "instructions",
        "custom agents (`claude-agent`), subfolders included", _VSCODE_AGENTS, CHECKED_SELECTION, format="claude-agent",
        shared=True),
    Row("vscode/linux", "vscode", ("linux",), "$XDG_CONFIG_HOME", _VSCODE_USER_MCP, "mcp", "MCP servers (`servers`)",
        _VSCODE_MCP, CHECKED_VSCODE_USER, path_from=_VSCODE_USER_FOLDER),
    Row("vscode/macos", "vscode", ("macos",), "~/Library/Application Support", _VSCODE_USER_MCP, "mcp",
        "MCP servers (`servers`)", _VSCODE_MCP, CHECKED_VSCODE_USER, path_from=_VSCODE_USER_FOLDER),
    Row("vscode/windows", "vscode", ("windows",), "%APPDATA%", _VSCODE_USER_MCP, "mcp", "MCP servers (`servers`)",
        _VSCODE_MCP, CHECKED_VSCODE_USER, path_from=_VSCODE_USER_FOLDER),
    *_devin("windsurf/mcp", ("devin/mcp_config.json",), "windsurf-mcp", _WINDSURF_MCP, _DEVIN_CUSTOMIZATIONS, path_from=()),
    Row("windsurf/global-rules", "windsurf", ALL, "~", (".devin/global_rules.md",), "instructions",
        "instruction file (`devin-rules`)", _DEVIN_CUSTOMIZATIONS, CHECKED_SELECTION, format="devin-rules"),
    Row("windsurf/rules", "windsurf", ALL, "~", (".devin/rules/*.md",), "instructions", "instruction files (`devin-rules`)",
        _DEVIN_CUSTOMIZATIONS, CHECKED_SELECTION, format="devin-rules"),
    *_devin("windsurf/skills", ("devin/skills",), "skills", _SKILLS, _DEVIN_SKILLS),
    *_devin("windsurf/agents-md", ("devin/AGENTS.md", "devin/AGENT.md"), "instructions", "instruction files (`agents-md`)",
            _DEVIN_RULES, format="agents-md"),
    *_devin("windsurf/agents", ("devin/agents/*.md", "devin/agents/*/AGENT.md"), "instructions", "subagents (`devin-agent`)",
            _DEVIN_SUBAGENTS, format="devin-agent"),
    *_devin("windsurf/config", ("devin/config.json",), "devin-config", "hooks (`hooks`)", _DEVIN_HOOKS),
    Row("windsurf/agents-skills", "windsurf", ALL, "~", (".agents/skills",), "skills", _SKILLS, _DEVIN_SKILLS, CHECKED_SELECTION,
        shared=True),
    Row("windsurf/codeium-mcp", "windsurf", ALL, "~", (".codeium/windsurf/mcp_config.json",
                                                      ".codeium/windsurf-next/mcp_config.json",
                                                      ".codeium/windsurf-insiders/mcp_config.json"), "windsurf-mcp",
        _WINDSURF_MCP, _DEVIN_READ_CONFIG, CHECKED_SELECTION),
    Row("windsurf/codeium-skills", "windsurf", ALL, "~", (".codeium/windsurf/skills", ".codeium/windsurf-next/skills",
                                                         ".codeium/windsurf-insiders/skills"), "skills", _SKILLS,
        _DEVIN_SKILLS, CHECKED_SELECTION),
    Row("windsurf/codex-skills", "windsurf", ALL, "~", (".codex/skills",), "skills", _SKILLS, _DEVIN_READ_CONFIG,
        CHECKED_SELECTION, shared=True),
    Row("windsurf/copilot-skills", "windsurf", ALL, "~", (".copilot/skills",), "skills", _SKILLS, _DEVIN_READ_CONFIG,
        CHECKED_SELECTION, shared=True),
    Row("codex/config", "codex", ALL, "$CODEX_HOME", ("config.toml",), "codex-config",
        "MCP servers (`[mcp_servers.<id>]`), hooks (`[hooks]`, `notify`), plugins (`[plugins]`), marketplaces "
        "(`[marketplaces]`)", _CODEX_CONFIG, CHECKED),
    Row("codex/hooks", "codex", ALL, "$CODEX_HOME", ("hooks.json",), "hooks", "hooks", _CODEX_HOOKS, CHECKED),
    Row("codex/skills", "codex", ALL, "~", (".agents/skills",), "skills", _SKILLS, _CODEX_SKILLS, CHECKED, shared=True),
    Row("codex/agents", "codex", ALL, "$CODEX_HOME", ("AGENTS.md", "AGENTS.override.md"), "instructions",
        "instruction files (`codex-agents-md`)", _CODEX_AGENTS, CHECKED, format="codex-agents-md"),
    Row("codex/prompts", "codex", ALL, "$CODEX_HOME", ("prompts/*.md",), "instructions", "custom prompts (`codex-prompt`)",
        _CODEX_PROMPTS, CHECKED_SELECTION, format="codex-prompt"),
    Row("codex/plugins", "codex", ALL, "$CODEX_HOME", ("plugins/cache/*/*/*",), "codex-plugins",
        "installed plugins (`<marketplace>/<plugin>/<version>`): each plugin's `plugin.json` or `.codex-plugin/plugin.json`, "
        "`mcp.json` or `.mcp.json`, `hooks/hooks.json` and skills", _CODEX_PLUGINS, CHECKED_SELECTION),
    Row("gemini-cli/settings", "gemini-cli", ALL, "~", (".gemini/settings.json",), "gemini-settings",
        "MCP servers (`mcpServers`; `url` is SSE, `httpUrl` streamable HTTP), hooks", _GEMINI_CONFIG, CHECKED),
    Row("gemini-cli/extensions", "gemini-cli", ALL, "~", (".gemini/extensions",), "gemini-extensions",
        "extensions (plugins): each `<name>/gemini-extension.json` with its MCP servers, `hooks/hooks.json`, the context files "
        "it names, its skills (`skills/<name>/SKILL.md`) and subagents (`agents/*.md`, `gemini-agent`)", _GEMINI_EXTENSIONS,
        CHECKED_SELECTION),
    Row("gemini-cli/memory", "gemini-cli", ALL, "~", (".gemini/GEMINI.md",), "instructions", "instruction file (`gemini-md`)",
        _GEMINI_MEMORY, CHECKED, format="gemini-md"),
    Row("gemini-cli/skills", "gemini-cli", ALL, "~", (".gemini/skills",), "skills", _SKILLS, _GEMINI_SKILLS, CHECKED),
    Row("gemini-cli/agents-skills", "gemini-cli", ALL, "~", (".agents/skills",), "skills", _SKILLS, _GEMINI_SKILLS, CHECKED,
        shared=True),
    Row("gemini-cli/agents", "gemini-cli", ALL, "~", (".gemini/agents/*.md",), "instructions", "subagents (`gemini-agent`)",
        _GEMINI_SUBAGENTS, CHECKED_SELECTION, format="gemini-agent"),
)

# What `scan --user` does not read, with the reason (spec 11.2 and D21; Engine 1.20.0: scan selection, 7.13): the README's
# "Not read" list, one line each.
NOT_READ: tuple[str, ...] = (
    "Windsurf's `~/.codeium/windsurf/memories/global_rules.md`: only an archived page from before the rename to Devin Desktop "
    "names it.",
    "Codex's `$CODEX_HOME/skills/` as Codex's own: no OpenAI page names it any more; Cursor and Devin Desktop document loading "
    "`~/.codex/skills/`, so it is read as their directory.",
    "The `mcp.json` files of VS Code's remote and WSL servers (under `~/.vscode-server/` and `~/.vscode-server-insiders/`): "
    "the documentation names no path for them.",
    "VS Code's user instruction files, prompt files and custom agents of the user profile (the deprecated Local harness keeps "
    "them in the profile's user data): the documentation names no path. Copilot's `$COPILOT_HOME/instructions/` and "
    "`$COPILOT_HOME/agents/` are read.",
    "Claude Code's plugins when `CLAUDE_CODE_PLUGIN_CACHE_DIR` moves them out of `$CLAUDE_CONFIG_DIR/plugins/`, the "
    "components a plugin declares outside its standard layout, a plugin's `output-styles/`, `workflows/`, `monitors/` and "
    "`.lsp.json`, and MCP bundles (`.mcpb`, `.dxt`).",
    "System-wide managed files outside the home directory (`/etc/claude-code/`, `/etc/gemini-cli/`, `C:\\ProgramData\\`), "
    "which belong to an administrator, not to the user.",
    "Cursor's `~/.cursor/rules/`: one help page names it without a format, and the rules page says user rules are kept in "
    "Cursor's settings, not in files.",
    "Claude Desktop extensions: no Anthropic page names where they are installed.",
    "Windsurf's global workflows (`~/.codeium/windsurf/global_workflows/`): they run only when the user asks, and Devin Local "
    "does not support them.",
    "Files that need a parser or a rule the scanner does not have: Codex's `rules/*.rules`, `agents/*.toml` and profile files "
    "`<name>.config.toml`; Gemini CLI's `commands/**/*.toml` and `policies/*.toml`, in the home and in extensions, and "
    "`GEMINI_CLI_HOME`; Copilot's `lsp-config.json` and the folders `skillDirectories` names; Claude Code's `workflows/*.js`; "
    "and the settings keys that run commands besides `hooks` (`statusLine`, `apiKeyHelper` and others).",
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


def base_variable(row: Row, env: Mapping[str, str]) -> str | None:
    """The variable that decides where the row's base is (`resolve_base`): its `moved_by` when that is set, else the variable
    of its base token; None for a base no variable moves (`~`, `~/Library/Application Support`)."""
    if row.moved_by is not None and _absolute(env.get(row.moved_by, "")):
        return row.moved_by
    return _VARIABLES.get(row.base)


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
    directory holds it (`%APPDATA%/Claude/...`), always with `/`; None for a path under neither, which is never printed. On macOS
    `$XDG_CONFIG_HOME` is tried after the client variables, so a path below a `CLAUDE_CONFIG_DIR` inside an `XDG_CONFIG_HOME`
    outside the home is shown as on 1.19.0 (Engine 1.20.0: scan selection, 7.9)."""
    inside = relative_to(path, home)
    if inside is not None:
        return "~" if inside == "" else "~/" + inside
    tokens = list(_VARIABLES.items())
    if system == "macos":
        tokens = [pair for pair in tokens if pair[0] != "$XDG_CONFIG_HOME"] + [("$XDG_CONFIG_HOME", "XDG_CONFIG_HOME")]
    for token, variable in tokens:
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
        source = f"<{row.source}>"
        if row.path_from:
            source += " (the folder from " + " and ".join(f"<{page}>" for page in row.path_from) + ")"
        lines.append(f"| {CLIENT_NAMES[row.client]} | {systems} | {paths} | {row.reads} | {source} | {row.checked} |")
    return "\n".join(lines) + "\n"


def not_read_markdown() -> str:
    return "".join(f"- {line}\n" for line in NOT_READ)


def readme_block() -> str:
    """What sits between `<!-- clients:start -->` and `<!-- clients:end -->` in the README."""
    return f"{table_markdown()}\nNot read:\n\n{not_read_markdown()}"


__all__ = ["BASES", "CLIENTS", "CLIENT_NAMES", "NOT_READ", "READERS", "ROWS", "SYSTEMS", "Row", "base_variable", "display",
           "platform_of", "readme_block", "relative_to", "resolve_base", "rows_for"]
