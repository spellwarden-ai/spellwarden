"""O3 spec 6.2 and claim E6: the `connected` mapping parses, validates and refuses unknown keys; `upload` has the
precedence flag, environment, file, default; `pack` and `required` have no flag or environment form and, on a request,
come from the base revision even under `--config` (invariant 5, P47)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import KEY_PATH, POLICY_PATH, git, orgs_answer, policy_answer, write_tree

from spellwarden_cli import main as cli
from spellwarden_cli import run
from spellwarden_cli.settings import CONNECTED_PACK_RE, Connected, Flags, Settings, SettingsError, load_settings

HEX = "3f2a" * 8


def settings_in(tmp_path: Path, connected: str | None, **kwargs) -> Settings:
    body = "version: 1\n" + (connected or "")
    write_tree(tmp_path, {".spellwarden/config.yml": body})
    return load_settings(str(tmp_path), config=None, flags=kwargs.pop("flags", Flags()), env=kwargs.pop("env", {}))


def test_connected_mapping_parses_and_defaults(tmp_path):
    assert Settings().connected == Connected(pack=None, upload=True, required=False)
    assert settings_in(tmp_path, None).connected == Connected()
    full = settings_in(tmp_path, f"connected:\n  pack: {HEX}@1.4\n  upload: false\n  required: true\n")
    assert full.connected == Connected(pack=f"{HEX}@1.4", upload=False, required=True)
    assert settings_in(tmp_path, "connected: {}\n").connected == Connected()


@pytest.mark.parametrize("good", ["baseline", HEX, f"{HEX}@1.4", "baseline@1.0", f"{HEX}@12.345"])
def test_connected_pack_grammar_accepts(good):
    assert CONNECTED_PACK_RE.fullmatch(good)


@pytest.mark.parametrize("bad", ["Baseline", "@1", "x", HEX.upper(), HEX[:-1], f"{HEX}@1", f"{HEX}@1.4.2", "baseline@", ""])
def test_connected_pack_grammar_refuses(bad, tmp_path):
    assert CONNECTED_PACK_RE.fullmatch(bad) is None
    with pytest.raises(SettingsError) as caught:
        settings_in(tmp_path, f"connected:\n  pack: {json.dumps(bad)}\n")
    assert "connected.pack" in str(caught.value)


def test_unknown_key_under_connected_is_an_error(tmp_path):
    with pytest.raises(SettingsError) as caught:
        settings_in(tmp_path, "connected:\n  packs: baseline\n")
    assert "connected: unknown key 'packs'" in str(caught.value)


@pytest.mark.parametrize("text", ["connected: yes please\n", "connected: [a]\n", "connected:\n  upload: 1\n",
                                  "connected:\n  required: 'true'\n", "connected:\n  pack: 3\n"])
def test_connected_values_have_their_types(tmp_path, text):
    with pytest.raises(SettingsError):
        settings_in(tmp_path, text)


def test_upload_precedence_flag_env_file_default(tmp_path):
    assert settings_in(tmp_path, None).connected.upload is True
    assert settings_in(tmp_path, "connected:\n  upload: false\n").connected.upload is False
    assert settings_in(tmp_path, "connected:\n  upload: false\n", env={"SPELLWARDEN_UPLOAD": "true"}).connected.upload is True
    assert settings_in(tmp_path, "connected:\n  upload: true\n", env={"SPELLWARDEN_UPLOAD": "false"}).connected.upload is False
    both = settings_in(tmp_path, "connected:\n  upload: false\n", env={"SPELLWARDEN_UPLOAD": "false"}, flags=Flags(upload=True))
    assert both.connected.upload is True
    with pytest.raises(SettingsError) as caught:
        settings_in(tmp_path, None, env={"SPELLWARDEN_UPLOAD": "maybe"})
    assert "SPELLWARDEN_UPLOAD" in str(caught.value)


def test_pack_and_required_have_no_flag_or_env_form(tmp_path):
    parser = cli.build_parser()
    for flag in ("--pack", "--required", "--connected"):
        with pytest.raises(SystemExit):
            parser.parse_args(["scan", flag, "x"])
    env = {"SPELLWARDEN_PACK": "baseline", "SPELLWARDEN_REQUIRED": "true", "SPELLWARDEN_CONNECTED_REQUIRED": "true"}
    assert settings_in(tmp_path, None, env=env).connected == Connected()
    args = parser.parse_args(["scan", "--upload"])
    assert args.upload is True and parser.parse_args(["scan", "--no-upload"]).upload is False
    assert parser.parse_args(["scan"]).upload is None


def test_in_free_mode_the_connected_settings_are_read_and_ignored(make_repo, run_cli, tmp_path):
    plain = make_repo(tmp_path / "a", {"README.md": "x\n", ".mcp.json": '{"mcpServers": {"s": {"url": "http://m.example.com/x"}}}\n'})
    with_mapping = make_repo(tmp_path / "b", {
        "README.md": "x\n", ".mcp.json": '{"mcpServers": {"s": {"url": "http://m.example.com/x"}}}\n',
        ".spellwarden/config.yml": "version: 1\nconnected:\n  pack: baseline@1.0\n  upload: false\n  required: false\n"})
    outputs = []
    for repo in (plain, with_mapping):
        code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--as-of", "2026-12-01"])
        assert err == ""
        outputs.append((code, json.loads(out)))
    (code_a, report_a), (code_b, report_b) = outputs
    assert code_a == code_b == 1
    assert report_a == report_b and "connected" not in report_b


def test_a_malformed_connected_mapping_is_settings_invalid_in_free_mode_too(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "r", {"README.md": "x\n", ".spellwarden/config.yml": "version: 1\nconnected:\n  packs: x\n"})
    code, out, _err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"])
    report = json.loads(out)
    assert code == 2 and [e["code"] for e in report["errors"]] == ["settings_invalid"]


# --- a pull request: pack and required come from the base revision (invariant 5, P47) ------------------------------

def request_env(tmp_path: Path, base_sha: str) -> dict[str, str]:
    payload = tmp_path / "event.json"
    payload.write_text(json.dumps({"pull_request": {"number": 7, "head": {"repo": {"full_name": "acme/agents"}},
                                                    "base": {"sha": base_sha}}}), encoding="utf-8")
    return {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(payload),
            "GITHUB_REPOSITORY": "acme/agents", "GITHUB_REF_PROTECTED": "false"}


def commit(repo: Path, files: dict[str, str]) -> str:
    write_tree(repo, files)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", "head")
    return git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def seen(monkeypatch):
    """The `ScanOptions` the command built, with the real scan still running."""
    captured: list[run.ScanOptions] = []
    real = run.scan

    def spy(options):
        captured.append(options)
        return real(options)

    monkeypatch.setattr(run, "scan", spy)
    return captured


def test_on_a_request_connected_settings_come_from_the_base_even_with_config_flag(make_repo, run_cli, tmp_path, seen):
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", ".spellwarden/config.yml": "version: 1\n"})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {".spellwarden/config.yml": "version: 1\nconnected:\n  required: true\n  pack: baseline\n  upload: false\n"})
    env = request_env(tmp_path, base)
    # without --config: the whole file comes from the base
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"], env=env)
    assert seen[-1].settings.connected == Connected()
    # with --config naming the request's own file: upload follows it, pack and required still come from the base
    head_file = repo / ".spellwarden" / "config.yml"
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(head_file)], env=env)
    assert seen[-1].settings.connected == Connected(pack=None, upload=False, required=False)
    report = json.loads(out)
    assert code == 0 and "connected" not in report


def test_under_config_the_base_connected_mapping_applies_and_is_announced(make_repo, run_cli, tmp_path, seen):
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", ".spellwarden/config.yml":
                                         f"version: 1\nconnected:\n  required: true\n  pack: {HEX}\n"})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {".spellwarden/config.yml": "version: 1\n", "other.yml": "version: 1\nconnected:\n  required: false\n"})
    env = request_env(tmp_path, base)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "other.yml")], env=env)
    assert seen[-1].settings.connected == Connected(pack=HEX, upload=True, required=True)
    notice = next(n for n in json.loads(out)["notices"] if n["code"] == "settings_from_base")
    assert base[:12] in notice["message"]


def test_off_a_request_config_names_the_whole_file(make_repo, run_cli, tmp_path, seen):
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", "other.yml": "version: 1\nconnected:\n  required: true\n"})
    run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "other.yml")])
    assert seen[-1].settings.connected.required is True


def test_under_config_an_invalid_base_file_does_not_change_a_free_mode_scan(make_repo, run_cli, tmp_path, seen):
    """F3, invariant 1: 1.1.1 never read the base file under `--config`; only its `connected` mapping is read now."""
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", ".spellwarden/config.yml": "version: 1\nfail-on: extreme\n"})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {"ci.yml": "version: 1\n"})
    env = request_env(tmp_path, base)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "ci.yml")], env=env)
    report = json.loads(out)
    assert code == 0 and report["errors"] == [] and "connected" not in report
    assert seen[-1].settings.connected == Connected()
    assert not [n for n in report["notices"] if "config.yml" in n["message"]]  # the baseline notice is 1.1.1's own


def test_under_config_a_base_connected_pack_adds_no_notice_in_free_mode(make_repo, run_cli, tmp_path, seen):
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", ".spellwarden/config.yml":
                                         f"version: 1\nfail-on: extreme\nconnected:\n  pack: {HEX}\n"})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {"ci.yml": "version: 1\n"})
    env = request_env(tmp_path, base)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "ci.yml")], env=env)
    report = json.loads(out)
    assert code == 0 and not [n for n in report["notices"] if "config.yml" in n["message"]]
    assert seen[-1].settings.connected.pack == HEX


# --- the defaults under --config must not weaken connected mode (invariant 5; review finding r1:F1, r1:F2) -----------

def test_under_config_a_base_mapping_that_says_required_with_a_defect_is_settings_invalid_without_a_credential(
        make_repo, run_cli, tmp_path):
    """A fork request with no credential, `--config ci.yml` and a base that requires connected mode but has a typo in
    its connected mapping exits 2 (settings_invalid), never 0 in free mode."""
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", ".spellwarden/config.yml":
                                         "version: 1\nconnected:\n  required: true\n  packs: baseline\n"})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {"ci.yml": "version: 1\n"})
    env = request_env(tmp_path, base)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "ci.yml")], env=env)
    report = json.loads(out)
    assert code == 2 and [e["code"] for e in report["errors"]] == ["settings_invalid"]
    assert "packs" in report["errors"][0]["message"]


def test_under_config_with_a_credential_an_invalid_base_connected_mapping_or_base_file_is_settings_invalid(
        make_repo, run_cli, tmp_path, api_double):
    """With a key present the base connected mapping is refused when invalid, as it is without `--config`; the
    repository's pack is never dropped silently."""
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", ".spellwarden/config.yml":
                                         f"version: 1\nconnected:\n  pack: {HEX}\n  required: maybe\n"})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {"ci.yml": "version: 1\n"})
    env = {**request_env(tmp_path, base), "SPELLWARDEN_API_KEY": "sw" + "k_" + "a" * 40}
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "ci.yml")], env=env)
    report = json.loads(out)
    assert code == 2 and [e["code"] for e in report["errors"]] == ["settings_invalid"]
    assert "connected.required" in report["errors"][0]["message"]
    # a base file the YAML reader refuses is refused too
    repo2 = make_repo(tmp_path / "repo2", {"README.md": "x\n", ".spellwarden/config.yml": "version: 1\nx: &a [*a]\n"})
    base2 = git(repo2, "rev-parse", "HEAD").strip()
    commit(repo2, {"ci.yml": "version: 1\n"})
    env2 = {**request_env(tmp_path, base2), "SPELLWARDEN_API_KEY": "sw" + "k_" + "a" * 40}
    code, out, _ = run_cli(["scan", str(repo2), "--format", "json", "--no-telemetry", "--config", str(repo2 / "ci.yml")], env=env2)
    assert code == 2 and [e["code"] for e in json.loads(out)["errors"]] == ["settings_invalid"]
    # without a credential, a truthy `required` with a defect still fails closed; a defect without `required` keeps
    # free mode unchanged (invariant 1)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "ci.yml")],
                           env=request_env(tmp_path, base))
    assert code == 2 and [e["code"] for e in json.loads(out)["errors"]] == ["settings_invalid"]
    repo3 = make_repo(tmp_path / "repo3", {"README.md": "x\n", ".spellwarden/config.yml":
                                          f"version: 1\nconnected:\n  pack: {HEX}\n  upload: maybe\n"})
    base3 = git(repo3, "rev-parse", "HEAD").strip()
    commit(repo3, {"ci.yml": "version: 1\n"})
    code, out, _ = run_cli(["scan", str(repo3), "--format", "json", "--no-telemetry", "--config", str(repo3 / "ci.yml")],
                           env=request_env(tmp_path, base3))
    assert code == 0 and json.loads(out)["errors"] == []


def test_under_config_in_connected_mode_an_unreadable_base_keeps_its_notice(make_repo, run_cli, tmp_path, api_double):
    """r1:F2: a key run whose base commit cannot be read says so (`base_unavailable`) even under `--config`, where the
    base connected mapping defaulted."""
    fake, _ = api_double
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", "ci.yml": "version: 1\n"})
    env = {**request_env(tmp_path, "0" * 40), "SPELLWARDEN_API_KEY": "sw" + "k_" + "a" * 40, "GITHUB_SERVER_URL": "https://github.com",
           "GITHUB_SHA": git(repo, "rev-parse", "HEAD").strip(), "GITHUB_RUN_ID": "9"}
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--config", str(repo / "ci.yml"),
                            "--baseline", str(repo / "ci.yml")], env=env)
    report = json.loads(out)
    assert code in (0, 2), out[:400]
    codes = [n["code"] for n in report["notices"]]
    assert codes.count("base_unavailable") == 1, codes
