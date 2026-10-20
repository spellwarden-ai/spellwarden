"""Agent configuration parsing (spec 5.2 and 5.6): MCP client configurations, Claude Code settings and hook files,
plugin marketplaces and plugin manifests, read from `(path, bytes)` into `ConfigDocument`s. Pure and total: a
document it cannot read becomes a `ConfigDocument` with `error` set and no entries, never an exception.

JSON is read with a small recursive-descent reader that accepts JSONC (line and block comments, trailing commas;
VS Code's `mcp.json` is JSONC), records the 1-based line of every key and array item from the token it parsed,
refuses a key repeated in one object (`duplicate_key`: agents disagree on which duplicate wins), and stops at
`MAX_DEPTH`. A value of an unexpected type inside an otherwise valid document is skipped, not fatal."""
from __future__ import annotations

import bisect
import hashlib
import ipaddress
import json
import re
from json.decoder import scanstring
from typing import Any, NamedTuple

from spellwarden_scan.model import (
    ConfigDocument, HookCommand, MarketplacePlugin, McpServerEntry, PluginSource, SettingFlag,
)
from spellwarden_scan.relpath import UnsafePath, contain

MAX_DOCUMENT_BYTES = 2**20
MAX_DEPTH = 32
MAX_SERVERS = 200
MAX_HOOKS = 500
MAX_PLUGINS = 200
DOCUMENT_ERRORS = ("too_large", "not_utf8", "not_json", "duplicate_key", "too_deep", "not_an_object", "truncated")
DOC_KINDS = ("mcp", "hooks", "settings", "marketplace", "plugin")

_LINE_END = re.compile(r"\r\n|\r|\n")
_COMMENT_END = re.compile(r"[\r\n]")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_SURROGATE = re.compile("[\ud800-\udfff]")
_LITERALS = (("true", True), ("false", False), ("null", None))
_HEX40 = re.compile(r"[0-9A-Fa-f]{40}")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#\s]*)([^?#\s]*)(\?[^#\s]*)?(#\S*)?")
_PORT = re.compile(r":[0-9]{0,5}")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class _Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Obj(dict):
    """A JSON object with the line of each key (`lines`) and of its opening brace (`line`)."""

    __slots__ = ("line", "lines")


class _Arr(list):
    """A JSON array with the line of each item (`lines`) and of its opening bracket (`line`)."""

    __slots__ = ("line", "lines")


class _Reader:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.ends = [match.start() for match in _LINE_END.finditer(text)]

    def line(self, pos: int) -> int:
        return bisect.bisect_left(self.ends, pos) + 1

    def skip(self) -> None:
        text, pos, size = self.text, self.pos, len(self.text)
        while pos < size:
            char = text[pos]
            if char in " \t\r\n":
                pos += 1
            elif text.startswith("//", pos):
                end = _COMMENT_END.search(text, pos)
                pos = size if end is None else end.start()
            elif text.startswith("/*", pos):
                end = text.find("*/", pos + 2)
                if end < 0:
                    raise _Refused("not_json")
                pos = end + 2
            else:
                break
        self.pos = pos

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def value(self, depth: int) -> Any:
        self.skip()
        char = self.peek()
        if char == "{":
            return self.obj(depth + 1)
        if char == "[":
            return self.arr(depth + 1)
        if char == '"':
            return self.string()
        number = _NUMBER.match(self.text, self.pos)
        if number:
            self.pos = number.end()
            token = number.group(0)
            try:
                return float(token) if any(mark in token for mark in ".eE") else int(token)
            except ValueError:  # an integer over the interpreter's digit limit
                raise _Refused("not_json") from None
        for word, literal in _LITERALS:
            if self.text.startswith(word, self.pos):
                self.pos += len(word)
                return literal
        raise _Refused("not_json")

    def string(self) -> str:
        try:
            text, end = scanstring(self.text, self.pos + 1, True)
        except ValueError:
            raise _Refused("not_json") from None
        if _SURROGATE.search(text):  # a lone surrogate cannot be encoded, hashed or printed
            raise _Refused("not_json")
        self.pos = end
        return text

    def obj(self, depth: int) -> _Obj:
        if depth > MAX_DEPTH:
            raise _Refused("too_deep")
        result = _Obj()
        result.line, result.lines = self.line(self.pos), {}
        self.pos += 1
        self.skip()
        if self.peek() == "}":
            self.pos += 1
            return result
        while True:
            self.skip()
            if self.peek() != '"':
                raise _Refused("not_json")
            key_line = self.line(self.pos)
            key = self.string()
            if key in result:
                raise _Refused("duplicate_key")
            self.skip()
            if self.peek() != ":":
                raise _Refused("not_json")
            self.pos += 1
            result[key] = self.value(depth)
            result.lines[key] = key_line
            self.skip()
            char = self.peek()
            if char == "}":
                self.pos += 1
                return result
            if char != ",":
                raise _Refused("not_json")
            self.pos += 1
            self.skip()
            if self.peek() == "}":  # a trailing comma
                self.pos += 1
                return result

    def arr(self, depth: int) -> _Arr:
        if depth > MAX_DEPTH:
            raise _Refused("too_deep")
        result = _Arr()
        result.line, result.lines = self.line(self.pos), []
        self.pos += 1
        self.skip()
        if self.peek() == "]":
            self.pos += 1
            return result
        while True:
            self.skip()
            result.lines.append(self.line(self.pos))
            result.append(self.value(depth))
            self.skip()
            char = self.peek()
            if char == "]":
                self.pos += 1
                return result
            if char != ",":
                raise _Refused("not_json")
            self.pos += 1
            self.skip()
            if self.peek() == "]":  # a trailing comma
                self.pos += 1
                return result


def _load_jsonc(content: bytes) -> Any:
    if len(content) > MAX_DOCUMENT_BYTES:
        raise _Refused("too_large")
    if content.startswith(b"\xef\xbb\xbf"):
        content = content[3:]
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise _Refused("not_utf8") from None
    reader = _Reader(text)
    value = reader.value(0)
    reader.skip()
    if reader.pos != len(text):
        raise _Refused("not_json")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _raw_json(value: Any) -> str:
    """The value exactly as found, as one canonical JSON string (5.6's `*-raw:` and `other:` forms)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Parts:
    def __init__(self) -> None:
        self.servers: list[McpServerEntry] = []
        self.hooks: list[HookCommand] = []
        self.settings: list[SettingFlag] = []
        self.plugins: list[MarketplacePlugin] = []
        self.references: list[str] = []
        self.truncated = False


def _error_document(path: str, kind: str, code: str, content: bytes) -> ConfigDocument:
    return ConfigDocument(path=path, kind=kind, error=code, servers=(), hooks=(), settings=(), plugins=(), references=(),
                          truncated=False, sha256=_sha256(content))


def _parse(kind: str, path: str, content: bytes, build) -> ConfigDocument:
    try:
        root = _load_jsonc(content)
        if not isinstance(root, _Obj):
            raise _Refused("not_an_object")
        parts = _Parts()
        build(parts, root, path)
    except _Refused as refused:
        return _error_document(path, kind, refused.code, content)
    return ConfigDocument(
        path=path, kind=kind, error="truncated" if parts.truncated else None, servers=tuple(parts.servers),
        hooks=tuple(parts.hooks), settings=tuple(parts.settings), plugins=tuple(parts.plugins),
        references=tuple(parts.references), truncated=parts.truncated, sha256=_sha256(_canonical(root)),
    )


def _strings(value: Any) -> dict[str, str]:
    return {key: item for key, item in value.items() if isinstance(item, str)} if isinstance(value, _Obj) else {}


def _server(name: str, line: int, entry: _Obj) -> McpServerEntry:
    command = entry.get("command") if isinstance(entry.get("command"), str) and entry.get("command") else None
    url = entry.get("url") if isinstance(entry.get("url"), str) else None
    declared = entry.get("type")
    # Plan decision P15: an explicit `type` decides the transport, as the agents that honour it connect; without
    # one, `command` means stdio and `url` means HTTP. The URL and launcher rules read every entry regardless.
    if declared is None:
        transport = "stdio" if command else "http" if url else "unknown"
    elif declared in ("http", "streamable-http"):
        transport = "http"
    elif declared in ("sse", "stdio"):
        transport = declared
    else:
        transport = "unknown"
    raw_args = entry.get("args")
    args = tuple(item for item in raw_args if isinstance(item, str)) if isinstance(raw_args, _Arr) else ()
    return McpServerEntry(name=name, line=line, transport=transport, url=url, command=command, args=args,
                          env=_strings(entry.get("env")), headers=_strings(entry.get("headers")),
                          raw_sha256=_sha256(_canonical(entry)))


def _servers(parts: _Parts, maps: list[Any]) -> None:
    """Every server of every server map; a name in two maps (`mcpServers` and `servers`) is a duplicate key."""
    seen: set[str] = set()
    for servers in maps:
        if not isinstance(servers, _Obj):
            continue
        for name, entry in servers.items():
            if name in seen:
                raise _Refused("duplicate_key")
            seen.add(name)
            if not isinstance(entry, _Obj):
                continue
            if len(parts.servers) >= MAX_SERVERS:
                parts.truncated = True
                continue
            parts.servers.append(_server(name, servers.lines[name], entry))


def _hooks(parts: _Parts, events: Any) -> None:
    """`{Event: [{"matcher"?: str, "hooks": [{"type": "command", "command": str}]}]}`, flattened in document
    order. Both shapes agents accept are read at once: a nested `{"hooks": {Event: ...}}` object and event keys
    beside it, so a hook cannot hide as a sibling of the nested map."""
    if not isinstance(events, _Obj):
        return
    for event, groups in events.items():
        if event == "hooks" and isinstance(groups, _Obj):
            _hooks(parts, groups)
            continue
        if not isinstance(groups, _Arr):
            continue
        for group in groups:
            if not isinstance(group, _Obj) or not isinstance(group.get("hooks"), _Arr):
                continue
            matcher = group.get("matcher") if isinstance(group.get("matcher"), str) else None
            for hook in group["hooks"]:
                if not isinstance(hook, _Obj) or not isinstance(hook.get("command"), str):
                    continue
                if hook.get("type", "command") != "command":
                    continue
                if len(parts.hooks) >= MAX_HOOKS:
                    parts.truncated = True
                    return
                parts.hooks.append(HookCommand(event=event, matcher=matcher, index=len(parts.hooks),
                                               command=hook["command"], line=hook.lines["command"]))


def _references(parts: _Parts, value: Any) -> None:
    if isinstance(value, str):
        parts.references.append(value)
    elif isinstance(value, _Arr):
        parts.references.extend(item for item in value if isinstance(item, str))


def _build_mcp(parts: _Parts, root: _Obj, _path: str) -> None:
    _servers(parts, [root.get("mcpServers"), root.get("servers")])


def _build_settings(parts: _Parts, root: _Obj, _path: str) -> None:
    permissions = root.get("permissions")
    if isinstance(permissions, _Obj):
        mode = permissions.get("defaultMode")
        if isinstance(mode, str):
            parts.settings.append(SettingFlag("permissions.defaultMode", mode, permissions.lines["defaultMode"]))
        allow = permissions.get("allow")
        if isinstance(allow, _Arr):
            parts.settings.extend(SettingFlag("permissions.allow", item, allow.lines[index])
                                  for index, item in enumerate(allow) if isinstance(item, str))
    enable_all = root.get("enableAllProjectMcpServers")
    if isinstance(enable_all, bool):
        parts.settings.append(SettingFlag("enableAllProjectMcpServers", enable_all, root.lines["enableAllProjectMcpServers"]))
    _hooks(parts, root.get("hooks"))


def _build_hooks(parts: _Parts, root: _Obj, _path: str) -> None:
    _hooks(parts, root.get("hooks"))


def _marketplace_root(path: str) -> str:
    """The parent of `.claude-plugin` (5.6), else the document's directory."""
    segments = path.split("/")
    if len(segments) >= 2 and segments[-2] == ".claude-plugin":
        return "/".join(segments[:-2])
    return "/".join(segments[:-1])


def _build_marketplace(parts: _Parts, root: _Obj, path: str) -> None:
    plugins = root.get("plugins")
    if not isinstance(plugins, _Arr):
        return
    base = _marketplace_root(path)
    names: set[str] = set()
    for item in plugins:
        if not isinstance(item, _Obj) or not isinstance(item.get("name"), str) or not item["name"]:
            continue
        if item["name"] in names:  # two plugins of one name: the same ambiguity as a repeated key
            raise _Refused("duplicate_key")
        names.add(item["name"])
        if len(parts.plugins) >= MAX_PLUGINS:
            parts.truncated = True
            continue
        parts.plugins.append(MarketplacePlugin(item["name"], item.lines["name"],
                                               plugin_source(item.get("source"), marketplace_root=base)))


def _build_plugin(parts: _Parts, root: _Obj, _path: str) -> None:
    # Both inline server maps are read, with `_build_mcp`'s duplicate-name check (5.2 `reference_kind`): a referenced
    # file with `hooks` and a VS Code `servers` map is parsed here. Only `mcpServers` names other files by a string.
    servers = root.get("mcpServers")
    _servers(parts, [servers, root.get("servers")])
    if not isinstance(servers, _Obj):
        _references(parts, servers)
    hooks = root.get("hooks")
    if isinstance(hooks, _Obj):
        _hooks(parts, hooks)
    else:
        _references(parts, hooks)


def parse_mcp_config(path: str, content: bytes) -> ConfigDocument:
    """`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`: servers from `mcpServers` and `servers`."""
    return _parse("mcp", path, content, _build_mcp)


def parse_settings(path: str, content: bytes) -> ConfigDocument:
    """`.claude/settings.json` and `.claude/settings.local.json`: the SW-CFG-008 flags and the hook commands."""
    return _parse("settings", path, content, _build_settings)


def parse_hooks(path: str, content: bytes) -> ConfigDocument:
    """A plugin's `hooks/hooks.json`."""
    return _parse("hooks", path, content, _build_hooks)


def parse_marketplace(path: str, content: bytes) -> ConfigDocument:
    """`.claude-plugin/marketplace.json`: its plugins and their sources."""
    return _parse("marketplace", path, content, _build_marketplace)


def parse_plugin_manifest(path: str, content: bytes) -> ConfigDocument:
    """`.claude-plugin/plugin.json`, or a referenced file with hooks and servers: inline servers (`mcpServers` and
    `servers`) and hooks; string values of `mcpServers` and `hooks` are `references` to other files."""
    return _parse("plugin", path, content, _build_plugin)


_PARSERS = {"mcp": parse_mcp_config, "hooks": parse_hooks, "settings": parse_settings,
            "marketplace": parse_marketplace, "plugin": parse_plugin_manifest}


def parse_document(kind: str, path: str, content: bytes) -> ConfigDocument:
    if kind not in _PARSERS:
        raise ValueError(f"unknown document kind {kind!r}")
    return _PARSERS[kind](path, content)


def reference_kind(content: bytes) -> str | None:
    """The parser for a file a plugin manifest references (plan review: the JSON shape decides, never the file
    name). Read with the same bounded JSONC reader: `plugin` when the root object has `hooks` and `mcpServers` or
    `servers` (`parse_plugin_manifest` reads both inline shapes), `hooks` with `hooks` only, `mcp` with `mcpServers`
    or `servers` only, None for an object with none of them (inventory only). A file the reader refuses is `mcp`,
    so the caller's `parse_document("mcp", ...)` reports the refusal as a document error instead of skipping it.
    One level only: the caller drops the references of a referenced file."""
    try:
        root = _load_jsonc(content)
    except _Refused:
        return "mcp"
    if not isinstance(root, _Obj):
        return "mcp"
    hooks = "hooks" in root
    servers = "mcpServers" in root or "servers" in root
    if hooks and servers:
        return "plugin"
    if hooks:
        return "hooks"
    return "mcp" if servers else None


class UrlParts(NamedTuple):
    scheme: str
    userinfo: str | None
    host: str
    port: str | None
    path: str


def url_parts(url: object) -> UrlParts | None:
    """An absolute URL split without `urllib` (the engine imports no `urllib`): scheme and host lower-cased,
    IPv6 brackets removed; None when `url` is not a string of that shape or holds whitespace."""
    if not isinstance(url, str):
        return None
    match = _URL.fullmatch(url)
    if match is None:
        return None
    authority = match.group(2)
    userinfo, at, hostport = authority.rpartition("@")
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            return None
        host, rest = hostport[1:end], hostport[end + 1:]
    else:
        host, colon, port = hostport.partition(":")
        rest = colon + port
    if not host or (rest and not _PORT.fullmatch(rest)):
        return None
    return UrlParts(match.group(1).lower(), userinfo if at else None, host.lower(), rest[1:] or None, match.group(3))


def _valid_host(host: str) -> bool:
    """An IP literal (IPv6 came bracketed, so it holds `:`) or a DNS name of LDH labels, 1 to 63 characters each,
    at most 253 in all: the host every client reads the same way."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return ":" not in host and len(host) <= 253 and all(_LABEL.fullmatch(label) for label in host.split("."))


def _canonical_url(value: object) -> str | None:
    """`url:` plus the URL with scheme and host lower-cased, query and fragment dropped, and a trailing `/`, `.git`
    and `/` removed; None (the caller then uses `url-raw:`) unless `value` is an absolute `https` URL whose authority
    holds no userinfo, `\\` or `%` and whose host is a valid DNS name or IP literal. A browser and curl disagree on
    authorities outside that syntax (`https://github.com\\@evil.example/`), so no host is guessed for them."""
    match = _URL.fullmatch(value) if isinstance(value, str) else None
    if match is None or any(mark in match.group(2) for mark in "@\\%"):
        return None
    parts = url_parts(value)
    if parts is None or parts.scheme != "https" or not _valid_host(parts.host):
        return None
    host = f"[{parts.host}]" if ":" in parts.host else parts.host
    path = parts.path.removesuffix("/").removesuffix(".git").removesuffix("/")
    return f"url:https://{host}{':' + parts.port if parts.port else ''}{path}"


def plugin_source(value: object, *, marketplace_root: str) -> PluginSource:
    """Spec 5.6: every source value, valid or not, has one kind and one canonical string."""
    if isinstance(value, str):
        try:
            local = contain(marketplace_root, value)
        except UnsafePath:
            return PluginSource("local", None, None, None, None, None, "local-raw:" + _raw_json(value), "unsafe_path")
        return PluginSource("local", local, None, None, None, None, "local:" + local)
    if isinstance(value, dict) and value.get("source") in ("github", "url"):
        ref = value.get("ref") if isinstance(value.get("ref"), str) else None
        sha = value.get("sha") if isinstance(value.get("sha"), str) else None
        if value["source"] == "github":
            repo = value.get("repo")
            if isinstance(repo, str) and _REPO.fullmatch(repo):
                return PluginSource("github", None, repo, None, ref, sha, "github:" + repo.lower().removesuffix(".git"))
            return PluginSource("github", None, repo if isinstance(repo, str) else None, None, ref, sha,
                                "github-raw:" + _raw_json(repo))
        url = value.get("url")
        canonical = _canonical_url(url) or "url-raw:" + _raw_json(url)
        return PluginSource("url", None, None, url if isinstance(url, str) else None, ref, sha, canonical)
    return PluginSource("other", None, None, None, None, None, "other:" + _raw_json(value))


def has_declared_pin(source: PluginSource) -> bool:
    """Spec 5.6: a 40-hex `sha`, or without `sha` a 40-hex `ref`; a `sha` and a 40-hex `ref` that differ are no
    pin; an abbreviated `sha` is no pin whatever `ref` says."""
    ref_pin = source.ref is not None and _HEX40.fullmatch(source.ref) is not None
    if source.sha is not None:
        if _HEX40.fullmatch(source.sha) is None:
            return False
        return not (ref_pin and source.ref.lower() != source.sha.lower())  # type: ignore[union-attr]
    return ref_pin
