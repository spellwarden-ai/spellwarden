"""The readers of the client table (phase 3 batch 2a spec 11.2): each turns the bytes of one client file into the engine's
`ConfigDocument`s, or into the plugin and marketplace entries a state file lists, so the existing rules judge a home's servers
and hooks as they judge a repository's. Pure functions of a display path and bytes; `userscan` reads the files.

Client shapes that differ from the five document kinds are mapped key by key, never by re-serialising: a Windsurf or Devin
`serverUrl` and a Gemini CLI `httpUrl` are the server's `url` (Gemini's `url` is SSE), Cursor's flat hook entries are hook
groups, and Codex's `notify` command is a hook of the event `notify`. Values are never read for secrets beyond what the
engine's parser keeps (`env`, `headers` and `args` stay in the in-memory entry for the rules, and no output prints them)."""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from spellwarden_scan._json import MAX_DOCUMENT_BYTES, Arr, Obj, Refused, load_json
from spellwarden_scan.agentconfig import MAX_DEPTH, MAX_PLUGINS, parse_document, parse_selected
from spellwarden_scan.cyclonedx import reduce_url
from spellwarden_scan.model import ConfigDocument

from spellwarden_cli import codex_toml

STATE_MAX_BYTES = 10 * 2**20  # Claude Code's `~/.claude.json` holds the client's own state and often passes 1 MiB


def _error_document(kind: str, path: str, code: str, content: bytes) -> ConfigDocument:
    return ConfigDocument(path=path, kind=kind, error=code, servers=(), hooks=(), settings=(), plugins=(), references=(),
                          truncated=False, sha256=hashlib.sha256(content).hexdigest())


def _load(content: bytes, max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """The JSONC reader of configuration documents; raises `Refused` with a document error code."""
    return load_json(content, strict=False, max_depth=MAX_DEPTH, max_bytes=max_bytes)


def _obj(entries: dict, line: int, lines: dict) -> Obj:
    made = Obj(entries)
    made.line, made.lines = line, lines
    return made


def _arr(items: list, line: int, lines: list) -> Arr:
    made = Arr(items)
    made.line, made.lines = line, lines
    return made


def _with(entry: Obj, extra: dict[str, tuple[object, int]]) -> Obj:
    """A copy of `entry` with each `key: (value, line)` of `extra` set."""
    copy = _obj(dict(entry), entry.line, dict(entry.lines))
    for key, (value, line) in extra.items():
        copy[key] = value
        copy.lines[key] = line
    return copy


def _map_servers(servers: Any, change: Callable[[Obj], Obj]) -> Any:
    if not isinstance(servers, Obj):
        return servers
    return _obj({name: change(entry) if isinstance(entry, Obj) else entry for name, entry in servers.items()}, servers.line,
                dict(servers.lines))


def _server_url(entry: Obj) -> Obj:
    """Windsurf and Devin Desktop: a remote server's address is `serverUrl` (an entry with `url` keeps it)."""
    if "url" not in entry and isinstance(entry.get("serverUrl"), str):
        return _with(entry, {"url": (entry["serverUrl"], entry.lines["serverUrl"])})
    return entry


def _gemini_server(entry: Obj) -> Obj:
    """Gemini CLI: `httpUrl` is a streamable HTTP server and wins over `url`, which is SSE (the configuration reference)."""
    if isinstance(entry.get("httpUrl"), str):
        line = entry.lines["httpUrl"]
        return _with(entry, {"url": (entry["httpUrl"], line), "type": ("http", line)})
    if isinstance(entry.get("url"), str) and "type" not in entry:
        return _with(entry, {"type": ("sse", entry.lines["url"])})
    return entry


def _cursor_events(hooks: Any) -> Any:
    """Cursor's `hooks.json`: `{"hooks": {event: [{"command": ...}]}}`, each entry a hook group of its own."""
    if not isinstance(hooks, Obj):
        return None
    events: dict = {}
    for event, entries in hooks.items():
        if not isinstance(entries, Arr):
            continue
        groups, lines = [], []
        for index, entry in enumerate(entries):
            if not isinstance(entry, Obj) or not isinstance(entry.get("command"), str):
                continue
            group = {"hooks": _arr([entry], entry.line, [entries.lines[index]])}
            group_lines = {"hooks": entries.lines[index]}
            if isinstance(entry.get("matcher"), str):
                group["matcher"], group_lines["matcher"] = entry["matcher"], entry.lines["matcher"]
            groups.append(_obj(group, entry.line, group_lines))
            lines.append(entries.lines[index])
        events[event] = _arr(groups, entries.line, lines)
    return _obj(events, hooks.line, {event: hooks.lines[event] for event in events})


def read_mcp(path: str, content: bytes) -> ConfigDocument:
    return parse_document("mcp", path, content)


def read_settings(path: str, content: bytes) -> ConfigDocument:
    return parse_document("settings", path, content)


def read_hooks(path: str, content: bytes) -> ConfigDocument:
    return parse_document("hooks", path, content)


def read_windsurf_mcp(path: str, content: bytes) -> ConfigDocument:
    return parse_selected("mcp", path, content, lambda root: ([_map_servers(root.get("mcpServers"), _server_url)], None))


def read_gemini_settings(path: str, content: bytes) -> ConfigDocument:
    return parse_selected("settings", path, content,
                          lambda root: ([_map_servers(root.get("mcpServers"), _gemini_server)], root.get("hooks")))


def read_cursor_hooks(path: str, content: bytes) -> ConfigDocument:
    return parse_selected("hooks", path, content, lambda root: ([], _cursor_events(root.get("hooks"))))


def read_claude_json(path: str, content: bytes, scope_of: Callable[[str], str]) -> list[tuple[ConfigDocument, str | None]]:
    """`~/.claude.json`: the document of the user scope (`mcpServers`), then one document per project whose
    `projects.<directory>.mcpServers` holds a server, at the path `<path>#<scope>` with `scope_of(directory)` as its scope
    (11.2). Read up to `STATE_MAX_BYTES`. Two projects that give one scope (one directory written twice) are one document
    holding the servers of both; a server name in both is `duplicate_key`, as in any document."""
    try:
        root = _load(content, STATE_MAX_BYTES)
    except Refused as refused:
        return [(_error_document("mcp", path, refused.code, content), None)]
    if not isinstance(root, Obj):
        return [(_error_document("mcp", path, "not_an_object", content), None)]
    found = [(parse_selected("mcp", path, content, lambda tree: ([tree.get("mcpServers")], None), root=root), None)]
    projects = root.get("projects")
    by_scope: dict[str, list[Obj]] = {}
    for directory, project in (projects.items() if isinstance(projects, Obj) else ()):
        servers = project.get("mcpServers") if isinstance(project, Obj) else None
        if isinstance(servers, Obj) and servers:
            by_scope.setdefault(scope_of(directory), []).append(servers)
    for scope, maps in by_scope.items():
        found.append((parse_selected("mcp", f"{path}#{scope}", content, lambda _tree, chosen=maps: (chosen, None), root=root),
                      scope))
    return found


@dataclass(frozen=True)
class Entry:
    """A plugin or marketplace a state file lists: `kind` `plugin` or `marketplace`, its item path, its name and the facts of
    `details` (a marketplace's `source`; a plugin's `marketplace` name and `install_path` as the file wrote it)."""
    kind: str
    path: str
    name: str
    facts: dict = field(default_factory=dict, hash=False)


@dataclass(frozen=True)
class Listing:
    entries: tuple[Entry, ...] = ()
    error: tuple[str, str] | None = None  # (code, message) for the file
    cut: int = 0  # entries over MAX_PLUGINS, not read


def _source_url(value: object) -> str | None:
    """A marketplace source as a reduced URL: `github` `owner/repo` is `https://github.com/owner/repo`; `git` and `url` sources
    and a bare URL string are reduced (11.4)."""
    if isinstance(value, str):
        return reduce_url(value)
    if not isinstance(value, dict):
        return None
    if value.get("source") == "github" and isinstance(value.get("repo"), str):
        return reduce_url("https://github.com/" + value["repo"])
    for key in ("url", "repo"):
        if isinstance(value.get(key), str):
            return reduce_url(value[key])
    return None


def _local_source(value: object) -> str | None:
    """The directory of a local marketplace source as the file wrote it (`{"source": "directory", "path": ...}`)."""
    if isinstance(value, dict) and value.get("source") in ("directory", "file") and isinstance(value.get("path"), str):
        return value["path"]
    return None


def read_claude_plugins(path: str, content: bytes) -> Listing:
    """`installed_plugins.json`: `{"plugins": {"<name>@<marketplace>": [{"scope", "installPath", "version"}]}}` (a bare
    record in place of the list is read too). One plugin entry per key, with the first record's install path."""
    try:
        root = _load(content)
    except Refused as refused:
        return Listing(error=(refused.code, f"cannot be read as JSON ({refused.code})"))
    plugins = root.get("plugins") if isinstance(root, Obj) else None
    if not isinstance(root, Obj) or ("plugins" in root and not isinstance(plugins, Obj)):
        # Valid JSON of another shape is unread content, never an empty listing (review r0:F4, the limits rule)
        return Listing(error=("not_an_object",
                              "the plugins state file or its \"plugins\" value is not a JSON object; not judged"))
    entries: list[Entry] = []
    keys = list(plugins) if isinstance(plugins, Obj) else []
    for key in keys[:MAX_PLUGINS]:
        name, _, marketplace = key.rpartition("@")
        records = plugins[key] if isinstance(plugins[key], Arr) else [plugins[key]]
        record = next((r for r in records if isinstance(r, Obj)), None)
        install = record.get("installPath") if record is not None else None
        entries.append(Entry("plugin", f"{path}#{key}", name or key, {
            "marketplace": marketplace or None, "install_path": install if isinstance(install, str) else None}))
    return Listing(tuple(entries), cut=max(0, len(keys) - MAX_PLUGINS))


def read_claude_marketplaces(path: str, content: bytes) -> Listing:
    """`known_marketplaces.json`: `{"<name>": {"source": {...}, "installLocation": ...}}`."""
    try:
        root = _load(content)
    except Refused as refused:
        return Listing(error=(refused.code, f"cannot be read as JSON ({refused.code})"))
    if not isinstance(root, Obj):  # review r0:F4: another shape is unread content, never an empty listing
        return Listing(error=("not_an_object", "the marketplaces state file is not a JSON object; not judged"))
    names = list(root)
    entries = []
    for name in names[:MAX_PLUGINS]:
        record = root[name]
        source = record.get("source") if isinstance(record, Obj) else None
        entries.append(Entry("marketplace", f"{path}#{name}", name,
                             {"source_url": _source_url(source), "source_path": _local_source(source)}))
    return Listing(tuple(entries), cut=max(0, len(names) - MAX_PLUGINS))


@dataclass(frozen=True)
class CodexConfig:
    document: ConfigDocument | None
    listing: Listing
    error: str | None = None  # the reason the file, or some of its entries, could not be read


def _notify_events(root: Obj) -> Any:
    """`[hooks]` with Codex's `notify` command added as one hook of the event `notify`."""
    hooks = root.get("hooks")
    notify = root.get("notify")
    if not (isinstance(notify, Arr) and notify and all(isinstance(part, str) for part in notify)):
        return hooks
    line = root.lines["notify"]
    hook = _obj({"type": "command", "command": " ".join(notify)}, line, {"type": line, "command": line})
    group = _obj({"hooks": _arr([hook], line, [line])}, line, {"hooks": line})
    events = dict(hooks) if isinstance(hooks, Obj) else {}
    lines = dict(hooks.lines) if isinstance(hooks, Obj) else {}
    events["notify"], lines["notify"] = _arr([group], line, [line]), line
    return _obj(events, hooks.line if isinstance(hooks, Obj) else line, lines)


def read_codex_config(path: str, content: bytes) -> CodexConfig:
    """`config.toml`: one settings document (`[mcp_servers.<id>]`, `[hooks]`, `notify`), and the entries of `[plugins]`
    (`"<name>@<marketplace>"`, the default `_default` left out) and `[marketplaces]` (`source`, `source_type` `git` or
    `local`); their item paths are `<path>#marketplaces.<name>` and `<path>#plugins.<key>`, so a server of the same name
    keeps its own."""
    try:
        root = codex_toml.read(content)
    except (ValueError, RecursionError) as exc:
        # RecursionError: a value nested past what the parser can follow is this one file's error, never the whole scan's
        # crash (review r0:F3)
        return CodexConfig(None, Listing(), f"is not valid UTF-8 TOML ({type(exc).__name__})")
    document = parse_selected("settings", path, content, lambda tree: ([tree.get("mcp_servers")], _notify_events(tree)),
                              root=root)
    entries: list[Entry] = []
    marketplaces = root.get("marketplaces")
    for name, record in (marketplaces.items() if isinstance(marketplaces, Obj) else ()):
        source = record.get("source") if isinstance(record, Obj) else None
        local = isinstance(record, Obj) and record.get("source_type") == "local"
        entries.append(Entry("marketplace", f"{path}#marketplaces.{name}", name, {
            "source_url": None if local else _source_url(source),
            "source_path": source if local and isinstance(source, str) else None}))
    plugins = root.get("plugins")
    for key in (plugins if isinstance(plugins, Obj) else ()):
        if key == "_default":
            continue
        name, _, marketplace = key.rpartition("@")
        entries.append(Entry("plugin", f"{path}#plugins.{key}", name or key, {"marketplace": marketplace or None}))
    # A server whose id is `marketplaces.<name>` or `plugins.<key>` has the item path of that entry: the entry is not read and
    # the file gets an error, so neither item is merged into the other or dropped without a word (review r1:F2).
    servers = root.get("mcp_servers")
    server_paths = {f"{path}#{server}" for server in servers} if isinstance(servers, Obj) else set()
    taken = [entry for entry in entries if entry.path in server_paths]
    entries = [entry for entry in entries if entry.path not in server_paths]
    kept = [entry for entry in entries if entry.kind == "marketplace"][:MAX_PLUGINS] + \
        [entry for entry in entries if entry.kind == "plugin"][:MAX_PLUGINS]
    error = None
    if taken:
        names = ", ".join(sorted(entry.path.partition("#")[2] for entry in taken))
        error = (f"the [marketplaces] or [plugins] entries {names} have the item path of a server of the same id in "
                 "[mcp_servers], so they were not read; rename the server")
    return CodexConfig(document, Listing(tuple(kept), cut=len(entries) - len(kept)), error)


@dataclass(frozen=True)
class Extension:
    document: ConfigDocument
    context_files: tuple[str, ...]  # the names `contextFileName` gives (default `GEMINI.md`), relative to the extension


def read_gemini_extension(path: str, content: bytes) -> Extension:
    """`gemini-extension.json`: its MCP servers (a plugin manifest) and the context files it names."""
    document = parse_selected("plugin", path, content, lambda root: ([root.get("mcpServers")], None))
    names: tuple[str, ...] = ("GEMINI.md",)
    try:
        root = _load(content)
    except Refused:
        return Extension(document, ())
    given = root.get("contextFileName") if isinstance(root, Obj) else None
    if isinstance(given, str):
        names = (given,)
    elif isinstance(given, Arr):
        names = tuple(name for name in given if isinstance(name, str))
    return Extension(document, names)


__all__ = ["STATE_MAX_BYTES", "CodexConfig", "Entry", "Extension", "Listing", "read_claude_json", "read_claude_marketplaces",
           "read_claude_plugins", "read_codex_config", "read_cursor_hooks", "read_gemini_extension", "read_gemini_settings",
           "read_hooks", "read_mcp", "read_settings", "read_windsurf_mcp"]
