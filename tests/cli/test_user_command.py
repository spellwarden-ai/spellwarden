"""Phase 3 batch 2a spec 11.3, T-3, T-5 and T-6: the flags of `scan --user`, its outputs per client, no change to the home,
no usage ping, and no connected mode from the repository variables."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import credential
from homes import isolate, make_home

from spellwarden_cli import ping


@pytest.mark.parametrize("extra, message", [
    (["somewhere"], "cannot be used with PATH"), (["--locked"], "cannot be used with --locked"),
    (["--baseline", "b.yml"], "cannot be used with --baseline"), (["--config", "c.yml"], "cannot be used with --config"),
    (["--inventory", "--probe"], "cannot be used with --probe"),
    (["--inventory", "--format", "sarif"], "--inventory writes only text, json, cyclonedx"),
])
def test_user_refuses_the_flags_of_a_repository_scan(run_cli, tmp_path, monkeypatch, extra, message):
    env = isolate(monkeypatch, make_home(tmp_path, "linux"))
    code, out, err = run_cli(["scan", "--user", *extra], env=env)
    assert (code, out) == (2, "") and message in err


@pytest.mark.parametrize("flag", [["--inventory"], ["--device-label", "x"]])
def test_inventory_and_the_device_label_need_user(run_cli, tmp_path, flag):
    code, _, err = run_cli(["scan", str(tmp_path), *flag])
    assert code == 2 and f"{flag[0]} needs --user" in err


def test_the_text_report_has_a_line_per_client_and_the_json_its_clients(run_cli, tmp_path, monkeypatch):
    env = isolate(monkeypatch, make_home(tmp_path, "linux"), "linux")
    code, out, err = run_cli(["scan", "--user", "--as-of", "2026-11-14"], env=env)
    assert code == 1, err
    lines = out.splitlines()
    assert "Claude Code: 4 servers, 2 skills, 1 plugin, 1 marketplace, 2 hooks, 2 instruction files" in lines
    assert "Cursor: 1 server, 1 hook" in lines
    code, out, _ = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--format", "json"], env=env)
    document = json.loads(out)
    assert [entry["client"] for entry in document["clients"]][:2] == ["claude-code", "claude-desktop"]
    assert all(item["clients"] for item in document["items"]) and document["exit_code"] == 1
    assert {"~/work/app", "outside-home:9a1042f5/app"} == {item["scope"] for item in document["items"] if "scope" in item}


def test_a_client_without_files_is_not_found_and_named_only_in_verbose_output(run_cli, tmp_path, monkeypatch):
    home = make_home(tmp_path, "linux")
    for directory in (home / ".cursor",):
        for path in sorted(directory.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        directory.rmdir()
    env = isolate(monkeypatch, home, "linux")
    _, out, err = run_cli(["scan", "--user", "--as-of", "2026-11-14"], env=env)
    assert "Cursor: not found" in out.splitlines() and "client_not_found" not in err
    _, _, err = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--verbose"], env=env)
    assert "notice client_not_found: Cursor" in err
    _, out, _ = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--format", "json"], env=env)
    assert {"client": "cursor", "found": False, "roots": []} in json.loads(out)["clients"]
    assert "client_not_found" not in out


def test_inventory_lists_every_item_without_judging_it(run_cli, tmp_path, monkeypatch):
    env = isolate(monkeypatch, make_home(tmp_path, "linux"), "linux")
    code, out, err = run_cli(["scan", "--user", "--inventory", "--as-of", "2026-11-14"], env=env)
    assert code == 0, err
    assert "  mcp-server ~/.cursor/mcp.json#search (http, https://search.example.com/sse)" in out.splitlines()
    assert "  skill ~/.agents/skills/shared (also Windsurf (Devin Desktop), Codex, Gemini CLI)" in out.splitlines()
    # 53 with the VS Code user files; Task 5 dropped that row, which gave 2 documents and 2 servers
    assert out.splitlines()[-1] == "49 items listed, not judged (--inventory)"
    code, out, _ = run_cli(["scan", "--user", "--inventory", "--as-of", "2026-11-14", "--format", "json"], env=env)
    assert json.loads(out)["findings"] == [] and json.loads(out)["probes"] == []


def test_sarif_results_of_a_user_scan_name_their_clients(run_cli, tmp_path, monkeypatch):
    env = isolate(monkeypatch, make_home(tmp_path, "linux"), "linux")
    _, out, _ = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--format", "sarif"], env=env)
    results = json.loads(out)["runs"][0]["results"]
    by_rule = {result["ruleId"]: result for result in results}
    assert by_rule["SW-SKL-007"]["properties"]["clients"] == ["claude-code", "vscode"]
    assert all("clients" in result["properties"] for result in results)


def _snapshot(home: Path) -> dict[str, tuple[bytes, int]]:
    return {path.relative_to(home).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in sorted(home.rglob("*")) if path.is_file()}


def test_a_user_run_changes_no_file_of_the_home_and_writes_only_its_outputs(run_cli, tmp_path, monkeypatch):
    home = make_home(tmp_path, "linux")
    env = isolate(monkeypatch, home, "linux")
    before = _snapshot(home)
    out = tmp_path / "out"
    code, _, err = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--format", "json", "--output", str(out / "r.json"),
                            "--format", "cyclonedx", "--output", str(out / "r.cdx.json")], env=env)
    assert code == 1, err
    assert _snapshot(home) == before  # no state file without --upload
    assert sorted(path.name for path in out.iterdir()) == ["r.cdx.json", "r.json"]


def test_a_user_run_sends_no_usage_ping_and_a_repository_scan_still_does(run_cli, tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(ping, "send_ping", lambda *_args, **kwargs: sent.append(kwargs))
    ci = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "GITHUB_REPOSITORY_OWNER_ID": "1"}
    env = {**isolate(monkeypatch, make_home(tmp_path, "linux"), "linux"), **ci}
    run_cli(["scan", "--user", "--as-of", "2026-11-14"], env=env)
    assert sent == []
    repo = tmp_path / "repo"
    repo.mkdir()
    run_cli(["scan", str(repo), "--as-of", "2026-11-14"], env=ci)
    assert len(sent) == 1


def test_the_repository_variables_start_no_connected_mode_in_a_user_run(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double  # nothing is scripted: any request would fail the test
    env = {**isolate(monkeypatch, make_home(tmp_path, "linux"), "linux"), "SPELLWARDEN_ORG": "acme",
           "SPELLWARDEN_API_KEY": credential("swk")}
    code, out, _ = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--format", "json"], env=env)
    document = json.loads(out)
    assert code == 1 and fake.requests == [] and "connected" not in document
    assert not any(error["code"].startswith("connected") for error in document["errors"])
