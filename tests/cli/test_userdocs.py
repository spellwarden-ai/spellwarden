"""Phase 3 batch 2a spec 11.2: the readers of the client table map each client's shape onto the engine's documents key by key,
and `codex_toml` gives Codex's TOML the lines findings point at."""
from __future__ import annotations

import pytest

from spellwarden_scan.agentconfig import parse_selected

from spellwarden_cli import codex_toml, userdocs

CODEX = b'''model = "o3"
notify = ["notify-send", "Codex"]

[mcp_servers.docs]
command = "npx"
args = ["-y", "docs-mcp@1.2.0"]

[mcp_servers.remote]
url = "https://remote.example.com/mcp"
bearer_token_env_var = "REMOTE_TOKEN"

[[hooks.PreToolUse]]
matcher = "Bash"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "./guard.sh"

[plugins."review@tools"]
enabled = true

[plugins._default]
enabled = false

[marketplaces.tools]
source = "https://user:pw@git.example.com/tools.git?x=1"
source_type = "git"

[marketplaces.local]
source = "/home/a/marketplace"
source_type = "local"
'''


def test_codex_toml_keeps_the_line_of_each_table_and_key():
    root = codex_toml.read(CODEX)
    assert root.lines["notify"] == 2 and root["mcp_servers"].lines == {"docs": 4, "remote": 8}
    assert root["mcp_servers"]["docs"].lines == {"command": 5, "args": 6}
    assert root["hooks"]["PreToolUse"][0].lines["matcher"] == 13
    assert root["hooks"]["PreToolUse"][0]["hooks"][0].lines["command"] == 16


def test_codex_toml_refuses_what_is_not_toml():
    with pytest.raises(ValueError):
        codex_toml.read(b"[unclosed")
    with pytest.raises(ValueError):
        codex_toml.read(b"\xff")


def test_the_codex_reader_gives_servers_hooks_notify_plugins_and_marketplaces():
    config = userdocs.read_codex_config("~/.codex/config.toml", CODEX)
    document = config.document
    assert (document.kind, document.error) == ("settings", None)
    assert [(s.name, s.transport, s.line) for s in document.servers] == [("docs", "stdio", 4), ("remote", "http", 8)]
    assert [(h.event, h.command) for h in document.hooks] == [("PreToolUse", "./guard.sh"), ("notify", "notify-send Codex")]
    entries = {(e.kind, e.name): e.facts for e in config.listing.entries}
    assert entries[("marketplace", "tools")] == {"source_url": "https://git.example.com/tools.git", "source_path": None}
    assert entries[("marketplace", "local")] == {"source_url": None, "source_path": "/home/a/marketplace"}
    assert entries[("plugin", "review")] == {"marketplace": "tools"} and ("plugin", "_default") not in entries
    assert userdocs.read_codex_config("~/.codex/config.toml", b"x = ").document is None


def test_windsurf_and_gemini_remote_addresses_become_urls():
    devin = userdocs.read_windsurf_mcp("~/.config/devin/mcp_config.json",
                                       b'{"mcpServers": {"t": {"serverUrl": "https://t.example.com/mcp"}}}')
    assert [(s.transport, s.url) for s in devin.servers] == [("http", "https://t.example.com/mcp")]
    gemini = userdocs.read_gemini_settings("~/.gemini/settings.json", b'''{"mcpServers": {
        "h": {"httpUrl": "https://h.example.com/mcp", "url": "https://h.example.com/sse"},
        "s": {"url": "https://s.example.com/sse"}, "c": {"command": "node"}},
      "hooks": {"BeforeTool": [{"matcher": "x", "hooks": [{"type": "command", "command": "./g.sh"}]}]}}''')
    assert [(s.name, s.transport, s.url) for s in gemini.servers] == [
        ("h", "http", "https://h.example.com/mcp"), ("s", "sse", "https://s.example.com/sse"), ("c", "stdio", None)]
    assert [(h.event, h.command, h.line) for h in gemini.hooks] == [("BeforeTool", "./g.sh", 4)]


def test_cursor_hook_entries_are_hook_groups():
    document = userdocs.read_cursor_hooks("~/.cursor/hooks.json", b'''{"version": 1, "hooks": {
        "beforeShellExecution": [{"command": "./audit.sh"}, {"command": "./prompt.sh", "type": "prompt"}, "x"]}}''')
    assert [(h.event, h.command, h.line) for h in document.hooks] == [("beforeShellExecution", "./audit.sh", 2)]


def test_claude_json_gives_one_document_per_project_with_servers():
    content = b'''{"mcpServers": {"a": {"command": "npx"}}, "projects": {
        "/home/u/app": {"mcpServers": {"db": {"command": "uvx"}}}, "/home/u/app/": {"mcpServers": {"cache": {"command": "uvx"}}},
        "/home/u/empty": {"mcpServers": {}}, "/home/u/none": {}}}'''
    found = userdocs.read_claude_json("~/.claude.json", content, lambda directory: "~/" + directory.strip("/").split("/")[-1])
    # one directory written twice is one document with the servers of both: nothing is skipped silently
    assert [(d.path, scope, [s.name for s in d.servers]) for d, scope in found] == [
        ("~/.claude.json", None, ["a"]), ("~/.claude.json#~/app", "~/app", ["db", "cache"])]
    twice = userdocs.read_claude_json("~/.claude.json", content.replace(b'"cache"', b'"db"'), lambda _directory: "~/app")
    assert [(d.path, d.error, d.servers) for d, _ in twice][1:] == [("~/.claude.json#~/app", "duplicate_key", ())]
    (refused, _), = userdocs.read_claude_json("~/.claude.json", b"[1]", str)
    assert refused.error == "not_an_object"


def test_state_files_list_plugins_and_marketplaces_with_reduced_sources():
    plugins = userdocs.read_claude_plugins("~/p.json", b'{"plugins": {"lint@tools": [{"installPath": "/h/x"}]}}')
    assert [(e.kind, e.path, e.name, e.facts) for e in plugins.entries] == [
        ("plugin", "~/p.json#lint@tools", "lint", {"marketplace": "tools", "install_path": "/h/x"})]
    markets = userdocs.read_claude_marketplaces("~/m.json", b'''{"a": {"source": {"source": "github", "repo": "o/r"}},
        "b": {"source": {"source": "directory", "path": "/h/m"}}}''')
    assert [e.facts for e in markets.entries] == [{"source_url": "https://github.com/o/r", "source_path": None},
                                                   {"source_url": None, "source_path": "/h/m"}]
    many = b'{"plugins": {' + b",".join(b'"p%d@m": []' % n for n in range(201)) + b"}}"
    assert userdocs.read_claude_plugins("~/p.json", many).cut == 1
    assert userdocs.read_claude_plugins("~/p.json", b"{").error[0] == "not_json"


def test_parse_selected_reads_the_selected_maps_and_refuses_an_unknown_kind():
    document = parse_selected("mcp", "x.json", b'{"a": {"s": {"command": "npx"}}}', lambda root: ([root.get("a")], None))
    assert [s.name for s in document.servers] == ["s"]
    assert parse_selected("mcp", "x.json", b"{", lambda _root: ([], None)).error == "not_json"
    with pytest.raises(ValueError):
        parse_selected("other", "x.json", b"{}", lambda _root: ([], None))
