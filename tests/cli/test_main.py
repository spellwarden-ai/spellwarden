"""Spec 6.2: the `scan` and `version` commands, the format and output
pairing, every output written before the exit (settings errors and crashes
included), claims C10 and C11 (JSON determinism)."""
from __future__ import annotations

import json
import os
import random

import pytest

from spellwarden_scan import RULES_VERSION, __version__
from spellwarden_cli import files, main, run

SKILL = "---\nname: deploy\ndescription: Deploys.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\nRun it.\n"
PIPE = "curl https://get.example/install | sh\n"


def _repo(make_repo, tmp_path, extra=None):
    return make_repo(tmp_path / "repo", {"skills/deploy/SKILL.md": SKILL, "skills/deploy/run.sh": PIPE, **(extra or {})})


def test_version(run_cli):
    assert run_cli(["version"]) == (0, f"spellwarden {__version__} (rules {RULES_VERSION})\n", "")


def test_findings_fail_at_high_by_default_and_never_passes(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    code, out, _ = run_cli(["scan", str(repo), "--as-of", "2026-12-01"])
    assert code == 1
    assert "high SW-SKL-007 skills/deploy/run.sh:1 Remote script piped to a shell" in out
    assert out.rstrip().endswith("1 findings (0 critical, 1 high, 0 medium, 0 low), 0 accepted; failed at high")
    assert run_cli(["scan", str(repo), "--fail-on", "never"])[0] == 0
    assert run_cli(["scan", str(repo), "--fail-on", "critical"])[0] == 0
    assert run_cli(["scan", str(repo)], env={"SPELLWARDEN_FAIL_ON": "never"})[0] == 0


def test_path_defaults_to_the_working_directory(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    assert run_cli(["scan", "--quiet"], cwd=repo)[0] == 1


def test_an_empty_repository_passes_with_the_notice(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "hello"})
    code, out, _ = run_cli(["scan", str(repo)])
    assert code == 0
    assert "notice no_agent_content : No agent content found" in out
    assert out.rstrip().endswith("passed")


def test_a_file_as_path_exits_two_with_outputs_written(run_cli, tmp_path):
    (tmp_path / "file.txt").write_text("x")
    out = tmp_path / "r.json"
    code, _, _ = run_cli(["scan", str(tmp_path / "file.txt"), "--format", "json", "--output", str(out)])
    assert code == 2
    assert [e["code"] for e in json.loads(out.read_text())["errors"]] == ["path_not_directory"]


@pytest.mark.parametrize("config", ["version: 1\nprobe-private: true\n", "version: 2\n", "version: 1\nfail_on: high\n"])
def test_a_settings_error_writes_every_output_and_exits_two(make_repo, run_cli, tmp_path, config):
    repo = _repo(make_repo, tmp_path, {".spellwarden/config.yml": config})
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.txt"
    code, _, _ = run_cli(["scan", str(repo), "--format", "json", "--output", str(out_json), "--format", "text",
                          "--output", str(out_md)])
    assert code == 2
    document = json.loads(out_json.read_text())
    assert document["exit_code"] == 2 and document["items"] == [] and document["findings"] == []
    assert [e["code"] for e in document["errors"]] == ["settings_invalid"]
    assert "settings_invalid" in out_md.read_text()


def test_a_crash_exits_two_with_outputs_written(make_repo, run_cli, tmp_path, monkeypatch):
    repo = _repo(make_repo, tmp_path)

    def boom(_options):
        raise RuntimeError("forced")

    monkeypatch.setattr(run, "scan", boom)
    out = tmp_path / "r.json"
    code, _, _ = run_cli(["scan", str(repo), "--format", "json", "--output", str(out)])
    assert code == 2
    errors = json.loads(out.read_text())["errors"]
    assert [e["code"] for e in errors] == ["crash"] and "forced" in errors[0]["message"]


def test_an_unexpected_handler_error_is_exit_two_not_a_traceback(run_cli, monkeypatch):
    def boom(_args):
        raise ValueError("bad")

    monkeypatch.setattr(main, "cmd_version", boom)
    code, out, err = run_cli(["version"])
    assert (code, out) == (2, "") and "internal error: ValueError: bad" in err and "Traceback" not in err


def test_formats_pair_with_outputs_and_at_most_one_goes_to_stdout(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    out = tmp_path / "deep" / "r.json"
    code, stdout, stderr = run_cli(["scan", str(repo), "--format", "json", "--output", str(out), "--format", "text"])
    assert code == 1 and json.loads(out.read_text())["exit_code"] == 1
    assert "failed at high" in stdout and "wrote the json report" in stderr
    assert run_cli(["scan", str(repo), "--format", "json", "--format", "text"])[0] == 2
    assert run_cli(["scan", str(repo), "--output", "x.json"])[0] == 2
    assert run_cli(["scan", str(repo), "--format", "yaml"])[0] == 2
    assert run_cli(["scan", str(repo), "--as-of", "01/12/2026"])[0] == 2
    assert run_cli(["scan", str(repo), "--probe", "--no-probe"])[0] == 2


def test_quiet_prints_only_the_outputs(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    code, stdout, stderr = run_cli(["scan", str(repo), "--quiet", "--format", "json", "--output", str(tmp_path / "r.json")])
    assert (code, stdout, stderr) == (1, "", "")
    code, _, stderr = run_cli(["scan", str(repo), "--verbose", "--format", "json", "--output", str(tmp_path / "r.json")])
    assert "items discovered" in stderr and "scan took" in stderr


def test_output_files_are_replaced_atomically(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    out = tmp_path / "r.json"
    out.write_text("old")
    run_cli(["scan", str(repo), "--format", "json", "--output", str(out)])
    assert json.loads(out.read_text())["schema"] == 1
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".spellwarden-")] == []


def test_every_scan_flag_is_accepted(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    code, _, _ = run_cli(["scan", str(repo), "--no-probe", "--no-probe-private", "--no-telemetry", "--locked",
                          "--baseline", ".spellwarden/baseline.yml", "--config", str(tmp_path / "c.yml"), "--quiet"])
    assert code == 2  # the --config file does not exist: settings_invalid
    (tmp_path / "c.yml").write_text("version: 1\n")
    assert run_cli(["scan", str(repo), "--probe", "--probe-private", "--config", str(tmp_path / "c.yml"), "--quiet"])[0] == 1


def test_json_and_text_are_byte_identical_across_shuffled_listings(make_repo, run_cli, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", {
        "skills/b/SKILL.md": SKILL, "skills/b/run.sh": PIPE, "skills/a/SKILL.md": SKILL, "skills/a/x.sh": PIPE * 2,
        ".mcp.json": json.dumps({"mcpServers": {"z": {"url": "http://z.example"}, "a": {"command": "npx", "args": ["a"]}}}),
        ".claude/settings.json": json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})})
    real = files.list_files
    outputs = []
    for seed in range(3):
        def shuffled(*args, seed=seed, **kwargs):
            fileset = real(*args, **kwargs)
            entries = list(fileset.entries)
            random.Random(seed).shuffle(entries)
            return files.FileSet(fileset.root, tuple(entries), fileset.repo_prefix, fileset.notices, fileset.errors)

        monkeypatch.setattr(files, "list_files", shuffled)
        out_json, out_text = tmp_path / f"r{seed}.json", tmp_path / f"r{seed}.txt"
        run_cli(["scan", str(repo), "--as-of", "2026-12-01", "--format", "json", "--output", str(out_json),
                 "--format", "text", "--output", str(out_text)])
        outputs.append((out_json.read_bytes(), out_text.read_bytes()))
    assert outputs[0] == outputs[1] == outputs[2]
    text = outputs[0][0].decode()
    assert str(tmp_path) not in text and "2026-12-01" in text


@pytest.mark.skipif(os.name == "nt", reason="Windows file names cannot hold a colon")
@pytest.mark.parametrize("fmt", ["text", "markdown"])
def test_a_name_cannot_become_a_ci_workflow_command(fmt, make_repo, run_cli, tmp_path):
    # Spec 6.13, D58: a skill directory named `::error title=...::` heads its block in the text report; printed to a
    # GitHub Actions log, an unescaped line would run as a workflow command.
    name = "::error title=Spoof::pwn"
    repo = make_repo(tmp_path / "repo", {f"{name}/SKILL.md": SKILL, f"{name}/run.sh": PIPE})
    code, out, _ = run_cli(["scan", str(repo), "--format", fmt])
    assert code == 1
    assert not [line for line in out.splitlines() if line.lstrip().startswith("::")]
    if fmt == "text":
        assert out.splitlines()[0] == "\\x3a:error title=Spoof::pwn"


@pytest.mark.skipif(os.name == "nt", reason="Windows file names cannot hold control characters")
def test_hostile_names_are_escaped_in_text_and_json(make_repo, run_cli, tmp_path):
    name = "evil‮\x1b[31m"
    repo = make_repo(tmp_path / "repo", {f"skills/{name}/SKILL.md": SKILL, f"skills/{name}/run.sh": PIPE})
    code, out, _ = run_cli(["scan", str(repo)])
    assert "‮" not in out and "\x1b" not in out and "evil\\u{202E}\\x1b[31m" in out
    code, out, _ = run_cli(["scan", str(repo), "--format", "json"])
    assert "‮" not in out and "\x1b" not in out and "\\u202e" in out


# --- O3 spec 6.2, invariant 2, claims E5 and E6 ------------------------------------------------------------------------

from conftest import credential  # noqa: E402

CREDENTIAL_VARIABLES = ("SPELLWARDEN_API_KEY", "SPELLWARDEN_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                        "ACTIONS_ID_TOKEN_REQUEST_TOKEN")


def _json(run_cli, repo, *args, env=None, as_of="2026-12-01"):
    given = ["--as-of", as_of] if as_of else []
    code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", *given, *args], env=env)
    return code, (json.loads(out) if out else None), err


def test_both_credentials_is_connected_config_exit_2_and_no_request(make_repo, run_cli, tmp_path, monkeypatch):
    repo = _repo(make_repo, tmp_path)
    listed = []
    monkeypatch.setattr(files, "list_files", lambda *_a, **_k: listed.append(1))  # nothing is read once the run is refused
    code, report, err = _json(run_cli, repo, env={"SPELLWARDEN_ORG": "acme", "SPELLWARDEN_API_KEY": credential("swk")})
    assert code == 2 and [e["code"] for e in report["errors"]] == ["connected_config"] and listed == []
    assert report["findings"] == [] and "connected" not in report
    assert credential("swk") not in json.dumps(report) + err


@pytest.mark.parametrize("value", [credential("swc"), credential("swt"), "sw" + "k_" + "a" * 39, "sw" + "k_" + "a" * 41,
                                   "sw" + "k_" + "a" * 39 + "!", "not a key"])
def test_invalid_key_shape_is_connected_key_invalid_with_no_request(make_repo, run_cli, tmp_path, value, monkeypatch):
    repo = _repo(make_repo, tmp_path)
    monkeypatch.setattr(files, "list_files", lambda *_a, **_k: pytest.fail("a refused key must stop the run first"))
    code, report, err = _json(run_cli, repo, env={"SPELLWARDEN_API_KEY": value})
    assert code == 2 and [e["code"] for e in report["errors"]] == ["connected_key_invalid"]
    assert value not in json.dumps(report) + err


def test_a_valid_key_shape_is_accepted_and_the_run_goes_on(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    code, report, err = _json(run_cli, repo, env={"SPELLWARDEN_API_KEY": credential("swk")}, as_of=None)
    assert code == 1 and report["errors"] == [] and [f["rule_id"] for f in report["findings"]] == ["SW-SKL-007"]
    assert credential("swk") not in json.dumps(report) + err


def test_as_of_in_connected_mode_is_connected_config(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    code, report, _ = _json(run_cli, repo, env={"SPELLWARDEN_ORG": "acme"})
    assert code == 2 and [e["code"] for e in report["errors"]] == ["connected_config"]
    assert "--as-of" in report["errors"][0]["message"]
    code, report, _ = _json(run_cli, repo, env={"SPELLWARDEN_API_KEY": credential("swk")})
    assert [e["code"] for e in report["errors"]] == ["connected_config"]
    # free mode: --as-of is as before
    code, report, _ = _json(run_cli, repo)
    assert code == 1 and report["errors"] == []
    # without --as-of the connected variables alone do not stop the scan
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"], env={"SPELLWARDEN_ORG": "acme"})
    assert json.loads(out)["errors"] == []


def test_as_of_with_required_true_in_ci_is_connected_config(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path, {".spellwarden/config.yml": "version: 1\nconnected:\n  required: true\n"})
    event = tmp_path / "event.json"
    event.write_text('{"ref": "refs/heads/main"}', encoding="utf-8")
    ci_env = {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event),
              "GITHUB_REPOSITORY": "acme/agents"}
    code, report, _ = _json(run_cli, repo, env=ci_env)
    assert code == 2 and [e["code"] for e in report["errors"]] == ["connected_config"]
    code, report, _ = _json(run_cli, repo)  # local: required without CI does not turn connected mode on
    assert report["errors"] == []


def test_the_four_variables_are_gone_from_the_environment_the_scan_receives(make_repo, run_cli, tmp_path, monkeypatch):
    repo = _repo(make_repo, tmp_path)
    captured: list = []
    real = run.scan

    def spy(options):
        captured.append((options, dict(os.environ)))
        return real(options)

    monkeypatch.setattr(run, "scan", spy)
    values = {"SPELLWARDEN_API_KEY": credential("swk"), "SPELLWARDEN_ID_TOKEN": "idt0ken",
              "ACTIONS_ID_TOKEN_REQUEST_URL": "http://127.0.0.1:1/t", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "r3qt0k",
              "SPELLWARDEN_ORG": "acme"}
    values.pop("SPELLWARDEN_ORG")  # org and key together are refused before the scan reads anything
    _json(run_cli, repo, env=values, as_of=None)
    options, environment = captured[0]
    assert not set(CREDENTIAL_VARIABLES) & set(options.env) and not set(CREDENTIAL_VARIABLES) & set(environment)
    creds = options.credentials
    assert (creds.key.value, creds.id_token.value, creds.request_url.value, creds.request_token.value) == (
        values["SPELLWARDEN_API_KEY"], "idt0ken", "http://127.0.0.1:1/t", "r3qt0k")
    assert repr(creds).count("***") >= 4 and "idt0ken" not in repr(creds)


def test_every_git_call_of_a_scan_gets_an_explicit_environment_without_the_credentials(make_repo, run_cli, tmp_path, monkeypatch):
    from spellwarden_cli import ci

    repo = _repo(make_repo, tmp_path)
    environments: list = []
    real_run = files.subprocess.run

    def spy(command, *args, **kwargs):
        if command and command[0].endswith("git") or command[0] == "git":
            environments.append(kwargs.get("env"))
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(files.subprocess, "run", spy)
    _json(run_cli, repo, env={"SPELLWARDEN_API_KEY": credential("swk"), "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "r3qt0k"},
          as_of=None)
    assert environments and all(env is not None for env in environments)
    assert all(not set(CREDENTIAL_VARIABLES) & set(env) for env in environments)
    assert ci.git_remote_of  # the remote lookup takes the same explicit environment (tests/cli/test_ci.py)


@pytest.mark.parametrize("raw, honoured", [
    ("http://127.0.0.1:8123/api", "http://127.0.0.1:8123/api"), ("http://[::1]:8123/api", "http://[::1]:8123/api"),
    ("http://localhost:8123/api", "http://127.0.0.1:8123/api"),
    ("https://example.com/api", None), ("http://example.com:80/api", None), ("http://127.0.0.1/api", None),
    ("http://127.0.0.1:0/api", None), ("ftp://127.0.0.1:21/", None)])
def test_api_url_is_honoured_for_loopback_forms_only_and_prints_api_url_override(make_repo, run_cli, tmp_path, monkeypatch,
                                                                              raw, honoured):
    repo = _repo(make_repo, tmp_path)
    captured: list = []
    real = run.scan
    monkeypatch.setattr(run, "scan", lambda options: (captured.append(options), real(options))[1])
    code, report, err = _json(run_cli, repo, "--verbose", env={"SPELLWARDEN_API_URL": raw})
    assert captured[0].api_url == honoured
    notices = [n["code"] for n in report["notices"]]
    if honoured is None:
        assert "api_url_override" not in notices and "SPELLWARDEN_API_URL ignored" in err
    else:
        assert "api_url_override" in notices and "SPELLWARDEN_API_URL ignored" not in err


def test_without_the_variable_there_is_no_override_notice_and_no_line(make_repo, run_cli, tmp_path):
    code, report, err = _json(run_cli, _repo(make_repo, tmp_path), "--verbose")
    assert "api_url_override" not in [n["code"] for n in report["notices"]] and "SPELLWARDEN_API_URL" not in err


def test_no_credential_appears_in_any_artefact(make_repo, run_cli, tmp_path):
    repo = _repo(make_repo, tmp_path)
    secrets = {"SPELLWARDEN_API_KEY": credential("swk"), "SPELLWARDEN_ID_TOKEN": "idt0ken-" + "x" * 12,
               "ACTIONS_ID_TOKEN_REQUEST_URL": "http://127.0.0.1:9/token-endpoint-url",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "r3qt0ken-" + "y" * 12}
    outputs = {fmt: tmp_path / f"out.{fmt}" for fmt in ("json", "sarif", "markdown", "gitlab-codequality", "text")}
    args = ["scan", str(repo), "--no-telemetry", "--verbose"]
    for fmt, path in outputs.items():
        args += ["--format", fmt, "--output", str(path)]
    code, out, err = run_cli(args, env={**secrets, "SPELLWARDEN_API_URL": "http://127.0.0.1:9/api"})
    haystack = out + err + "".join(path.read_text(encoding="utf-8") for path in outputs.values())
    assert haystack
    for value in secrets.values():
        assert value not in haystack


def _captured_options(monkeypatch):
    captured: list = []
    real = run.scan
    monkeypatch.setattr(run, "scan", lambda options: (captured.append(options), real(options))[1])
    return captured


@pytest.mark.parametrize(("sub", "scope"), [("", ""), ("services/agent", "services/agent"), ("a b", None)])
def test_the_scan_scope_is_computed_once_in_cmd_scan_and_passed_on_the_options(make_repo, run_cli, tmp_path, monkeypatch,
                                                                              sub, scope):
    """O3 P41: the grammar of 8.4 decides; a root outside it is None, which connected mode refuses before any request."""
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", **({f"{sub}/README.md": "x\n"} if sub else {})})
    captured = _captured_options(monkeypatch)
    code, _, _ = _json(run_cli, repo / sub if sub else repo)
    assert code == 0 and [options.scope for options in captured] == [scope]


def test_the_scope_outside_a_repository_is_empty(run_cli, tmp_path, monkeypatch):
    (tmp_path / "plain").mkdir()
    captured = _captured_options(monkeypatch)
    _json(run_cli, tmp_path / "plain")
    assert captured[0].scope == ""
