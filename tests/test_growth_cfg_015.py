"""SW-CFG-015: MCP server given the whole home directory or the filesystem root (P6-9 spec 8.4, claims 15 to 19). The module's
`detect` is called directly; tests/test_p6_9_registered.py reads the registered rule through `scan_agent_config`."""
from __future__ import annotations

import ast
import inspect
import json
import os
import time

import pytest
from spellwarden_scan.agentconfig import parse_mcp_config, parse_selected
from spellwarden_scan.rules import growth_cfg_015
from spellwarden_scan.rules.growth_cfg_015 import ATLAS, MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, _PER_SERVER, detect

SPEED_FACTOR = float(os.environ.get("SPELLWARDEN_SPEED_FACTOR", "1"))
HOMES = ("~", "~/", "$HOME", "${HOME}", "$HOME/", "%USERPROFILE%", "$USERPROFILE", "/home/x", "/home/x/", "/Users/x", "/Users/x/",
         "C:\\Users\\x", "C:\\Users\\x\\", "c:/users/x")
ROOTS = ("/", "C:\\", "C:/", "C:", "/home", "/Users", "/root", "/Users/")
DEEPER = ("/Users/x/Documents", "~/projects", "$HOME/work/app", "C:\\Users\\x\\Desktop", ".", "./", "${workspaceFolder}", "${PWD}",
          "${workspaceRoot}", "src", "../x", "/srv/data", "/home/x/y", "/opt", "/Users/x/Desktop/", "")


def config(*documents):
    from spellwarden_scan.rules.config import AgentConfig

    return AgentConfig(documents)


def run(servers: dict, path: str = ".mcp.json", key: str = "mcpServers"):
    document = parse_mcp_config(path, json.dumps({key: servers}, indent=2).encode())
    assert document.error is None
    return list(detect(config(document)))


def files(*args: str, command: str = "npx") -> dict:
    return {"filesystem": {"command": command, "args": ["-y", "@modelcontextprotocol/server-filesystem", *args]}}


def test_module_constants():
    assert (RULE_ID, TITLE, SEVERITY) == ("SW-CFG-015", "MCP server given the whole home directory or the filesystem root", "medium")
    assert OWASP == ("MCP02", "ASI03") and NIST == ("AC-6",) and ATLAS == ("AML.T0053",) and MALICIOUS is False
    assert _PER_SERVER == 20


def test_module_imports_no_rule_module_at_top_level():
    tree = ast.parse(inspect.getsource(growth_cfg_015))
    imported = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
    assert not {"spellwarden_scan.rules.skill", "spellwarden_scan.rules.config", "spellwarden_scan.rules.mcp"} & imported


# --- claim 15: it fires -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", HOMES + ROOTS)
def test_an_argument_after_a_filesystem_servers_package_fires(path):
    findings = run(files(path))
    assert [(f.location.path, f.location.line) for f in findings] == [(".mcp.json", 3)]
    first = findings[0]
    assert (first.rule_id, first.severity, first.title, first.malicious_indicator) == (RULE_ID, "medium", TITLE, False)
    assert first.evidence in ("filesystem: args[2] is the whole home directory", "filesystem: args[2] is the filesystem root")
    assert len(first.fingerprint) == 64


@pytest.mark.parametrize("path", HOMES + ROOTS)
@pytest.mark.parametrize("form", ("--root {}", "--root={}", "--allowed-directories {}", "--allowed-dirs={}", "--workspace {}", "--directory {}",
                                  "--dir={}", "--base-dir {}", "--path={}", "--roots {}", "--allowed-dir {}"))
def test_the_value_of_a_flag_fires_for_any_server(form, path):
    servers = {"notes": {"command": "node", "args": ["server.js", *form.format(path).split(" ")]}}
    assert len(run(servers)) == 1


@pytest.mark.parametrize("path", HOMES + tuple(root for root in ROOTS if root != "C:"))
def test_the_host_side_of_a_bind_mount_fires(path):
    for flag_form in (["-v", f"{path}:/data"], ["-v", f"{path}:/data:ro"], [f"--volume={path}:/data"],
                      ["--mount", f"type=bind,src={path},dst=/data"], [f"--mount=type=bind,source={path},target=/data,readonly"]):
        for program in ("docker", "podman", "/usr/bin/docker", "docker.exe"):
            servers = {"box": {"command": program, "args": ["run", "-i", "--rm", *flag_form, "example/server:1.0"]}}
            (finding,) = run(servers)
            assert "bind mount" in finding.evidence, (flag_form, program)


def test_the_fingerprint_follows_the_server_the_form_and_the_index():
    first = run(files("~"))[0]
    again = run(files("~"))[0]
    other_form = run(files("/"))[0]
    other_index = run(files("/Users/x/Desktop", "~"))[0]
    assert first.fingerprint == again.fingerprint and len({first.fingerprint, other_form.fingerprint, other_index.fingerprint}) == 3


def test_a_name_that_says_file_system_or_fs_makes_the_server_filesystem_class():
    for name in ("file-system", "fs", "files", "FileSystem", "my_fs_server"):
        servers = {name: {"command": "node", "args": ["server.js", "~"]}}
        assert len(run(servers)) == 1, name
    assert run({"filesystem": {"command": "uvx", "args": ["mcp-server-fs", "/"]}}) != []
    # Arguments after a container image are the container's, so only a mount's host side is judged there (r0:F4).
    assert run({"box": {"command": "docker", "args": ["run", "-i", "mcp/filesystem", "/"]}}) == []


def _holding(kind: str, path: str, servers: dict):
    """A document of `kind` holding `servers` as the readers make one (a Codex or Gemini CLI settings file, a plugin manifest's
    inline servers, a hooks or marketplace document that a plugin names as its `mcpServers` file)."""
    text = json.dumps({"mcpServers": servers}, indent=2).encode()
    return parse_selected(kind, path, text, lambda root: ([root.get("mcpServers")], None))


def test_settings_and_plugin_documents_are_read_and_hooks_and_marketplace_documents_are_not():
    servers = files("~")
    for kind, path in (("settings", ".gemini/settings.json"), ("plugin", ".claude-plugin/plugin.json")):
        found = list(detect(config(_holding(kind, path, servers))))
        assert [(f.location.path, f.location.line) for f in found] == [(path, 3)], kind
    for kind in ("hooks", "marketplace"):
        assert list(detect(config(_holding(kind, "p/hooks/hooks.json", servers)))) == [], kind


# --- claim 16: quiet ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", DEEPER)
def test_a_deeper_path_a_project_variable_or_a_relative_path_is_quiet(path):
    assert run(files(path)) == []
    assert run({"notes": {"command": "node", "args": ["server.js", "--root", path]}}) == []
    assert run({"box": {"command": "docker", "args": ["run", "-v", f"{path}:/data", "img"]}}) == []


def test_the_container_side_of_a_mount_is_quiet():
    servers = {"box": {"command": "docker", "args": ["run", "-v", "/Users/x/Desktop:/", "--mount", "type=bind,src=/srv,dst=/Users/x", "img"]}}
    assert run(servers) == []
    assert run({"box": {"command": "docker", "args": ["run", "-v", "myvolume:/data", "img"]}}) == []


def test_a_server_that_is_not_filesystem_class_and_has_no_such_flag_is_quiet():
    assert run({"search": {"command": "node", "args": ["server.js", "/", "~"]}}) == []
    assert run({"search": {"command": "npx", "args": ["-y", "some-search-server", "--root-cause", "/"]}}) == []
    assert run({"search": {"command": "node", "args": ["server.js", "-v", "/:/data"]}}) == []  # -v of a program that is not docker or podman


def test_the_official_filesystem_server_examples_are_quiet():
    servers = {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/username/Desktop",
                                                         "/path/to/other/allowed/dir"]},
               "docker": {"command": "docker", "args": ["run", "-i", "--rm", "--mount", "type=bind,src=/Users/username/Desktop,dst=/projects/Desktop",
                                                        "--mount", "type=bind,src=/path/to/file.txt,dst=/projects/file.txt,ro", "mcp/filesystem", "/projects"]}}
    assert run(servers) == []


def test_a_path_argument_is_not_taken_for_the_name_of_the_package():
    assert run({"s": {"command": "node", "args": ["/srv/files/server.js", "~"]}}) == []  # `files` stands in a path, not in a name


# --- claims 17 and 18, the cap and the time ----------------------------------------------------------------------------------------

def test_the_evidence_and_the_report_never_hold_the_path_or_the_user_name():
    servers = {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/someone"]},
               "box": {"command": "docker", "args": ["run", "-v", "/home/someone:/data", "--mount", "type=bind,src=C:\\Users\\someone,dst=/d", "i"]}}
    findings = run(servers)
    assert len(findings) == 3
    assert not [f for f in findings if "someone" in f.evidence or "someone" in json.dumps(f.to_dict())]
    assert {f.evidence for f in findings} == {"filesystem: args[2] is the whole home directory",
                                              "box: args[2] is a bind mount of the home directory",
                                              "box: args[4] is a bind mount of the home directory"}


def test_a_grant_late_in_a_long_argument_list_is_found():
    servers = {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem",
                                                         *[f"/srv/data/{number}" for number in range(48)], "~"]}}
    (finding,) = run(servers)
    assert finding.evidence == "filesystem: args[50] is the whole home directory"


def test_a_server_yields_at_most_20_findings_and_the_last_counts_the_rest():
    servers = files(*["~"] * 25)
    findings = run(servers)
    assert len(findings) == 20
    assert findings[-1].evidence.endswith(" and 5 more arguments") and not findings[0].evidence.endswith("more arguments")


def test_every_environment_variable_is_not_a_check():
    servers = {"box": {"command": "docker", "args": ["run", "--env-file", "/Users/x/.env", "img"], "env": {"HOME": "/Users/x"}}}
    assert run(servers) == []


def test_a_long_argument_is_read_in_linear_time():
    for token in ("/", "~", "C:\\", "--root ", "-v ", "filesystem-", "/Users/x:"):
        argument = (token * (30_000 // len(token) + 1))[:30_000]
        started = time.perf_counter()
        run({"filesystem": {"command": "docker", "args": ["run", "-v", argument, "--mount", argument, "--root", argument, argument]}})
        assert time.perf_counter() - started < 3.0 * SPEED_FACTOR, token


def test_a_container_side_path_after_the_image_is_quiet_and_the_host_side_still_fires():
    quiet = {"filesystem": {"command": "docker", "args": ["run", "-i", "--rm", "-v", "/Users/me/work:/home/work", "mcp/filesystem", "/home"]}}
    assert run(quiet) == []
    loud = {"filesystem": {"command": "podman", "args": ["run", "-i", "-v", "/Users/me:/home/work", "mcp/filesystem", "/home"]}}
    (finding,) = run(loud)
    assert finding.evidence == "filesystem: args[3] is a bind mount of the home directory"


def test_the_value_of_a_flag_that_is_not_a_path_flag_is_quiet():
    assert run({"files": {"command": "uvx", "args": ["some-files-mcp", "--log-dir", "/"]}}) == []
    assert len(run({"files": {"command": "uvx", "args": ["some-files-mcp", "--root", "/"]}})) == 1

