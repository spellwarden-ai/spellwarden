"""Phase 3 batch 2a spec 11.4 and T-9: the workstation upload's body has the documented shape and nothing else, lists at most 50
errors and notices with their totals, carries the project directory of a project-scoped server, is refused locally over the
caps, keeps the device's identity in the state file, and a failing answer exits 2 with the server's code."""
from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import jsonschema
import pytest
from conftest import credential
from homes import isolate, make_home

from spellwarden_cli import userscan, workstation

UPLOAD = "/api/v1/orgs/acme/workstations/inventory"
TOP = {"schema", "install_id", "device_label", "os", "scanner", "mode", "complete", "clients", "items", "findings", "errors",
       "notices", "errors_total", "notices_total"}
ITEM = {"n", "clients", "kind", "name", "path", "scope", "transport", "endpoint", "command_identity", "command_reason", "plugin",
        "marketplace", "format"}
FINDING = {"item", "rule_id", "severity", "line", "suppressed"}
CLIENT = {"client", "found", "roots", "roots_total"}


def upload_env(monkeypatch, home: Path) -> dict[str, str]:
    return {**isolate(monkeypatch, home, "linux"), "SPELLWARDEN_WORKSTATION_ORG": "acme",
            "SPELLWARDEN_WORKSTATION_KEY": credential("swk")}


def answered(fake, status: int = 200, body=None) -> None:
    fake.script("POST", UPLOAD, status, body if body is not None else {"device": {
        "id": "d" * 32, "label": "Anna's laptop", "uploaded_at": "2026-11-14T10:00:00Z", "expires_at": "2027-02-12T10:00:00Z"}})


def test_the_body_has_the_documented_shape_and_the_key_goes_in_the_header(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    answered(fake)
    home = make_home(tmp_path, "linux")
    code, out, err = run_cli(["scan", "--user", "--upload", "--device-label", " Anna's\u200b laptop ", "--as-of", "2026-11-14"],
                             env=upload_env(monkeypatch, home))
    assert code == 1, err  # the findings decide the exit code; the upload succeeded
    assert "notice workstation_uploaded: uploaded the inventory of Anna's laptop (2026-11-14T10:00:00Z)" in err
    (method, path, headers, body), = fake.requests
    assert (method, path, headers["Authorization"]) == ("POST", UPLOAD, f"Bearer {credential('swk')}")
    assert set(body) == TOP and body["schema"] == 1 and body["os"] == "linux" and body["mode"] == "scan"
    assert body["device_label"] == "Anna's laptop" and len(body["install_id"]) == 32
    assert body["complete"] is True and body["errors"] == [] and body["errors_total"] == 0
    assert all(set(item) == ITEM for item in body["items"]) and all(set(f) == FINDING for f in body["findings"])
    assert [item["n"] for item in body["items"]] == list(range(1, len(body["items"]) + 1))
    by_path = {item["path"]: item for item in body["items"]}
    assert by_path["~/.claude.json#~/work/app#db"]["scope"] == "~/work/app"
    assert by_path["~/.claude.json#outside-home:9a1042f5/app#db"]["scope"] == "outside-home:9a1042f5/app"
    assert by_path["~/.claude.json#outside-home:9a1042f5/app#db"]["endpoint"] == "https://db.example.com/mcp"
    assert by_path["~/.codex/config.toml#docs"]["command_identity"].startswith("cmd:npx docs-mcp@1.2.0 args=")
    assert by_path["~/.claude/plugins/known_marketplaces.json#tools"]["marketplace"] == "https://git.example.com/tools.git"
    assert by_path["~/.claude/plugins/installed_plugins.json#lint@tools"]["marketplace"] == "https://git.example.com/tools.git"
    assert {f["item"] for f in body["findings"]} <= set(by_path[path]["n"] for path in by_path)
    assert all(root.startswith("~/") for entry in body["clients"] for root in entry["roots"])
    assert all(set(entry) == CLIENT for entry in body["clients"])
    counts = {entry["client"]: (len(entry["roots"]), entry["roots_total"]) for entry in body["clients"]}
    # 1.16.2: the total is sent beside the list cut at 8. 1.20.0: each path a row's pattern matches is a root, so four clients
    # of the fixture home are over the cap (Engine 1.20.0: scan selection, 7.9)
    assert counts == {"claude-code": (8, 12), "claude-desktop": (1, 1), "cursor": (8, 10), "vscode": (8, 20),
                      "windsurf": (8, 12), "codex": (6, 6), "gemini-cli": (6, 6)}


def test_the_state_file_keeps_the_install_id_and_the_label(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    answered(fake)
    answered(fake)
    home = make_home(tmp_path, "linux")
    env = upload_env(monkeypatch, home)
    run_cli(["scan", "--user", "--upload", "--device-label", "Anna's laptop"], env=env)
    state = home / ".config" / "spellwarden" / "workstation.json"
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert set(saved) == {"schema", "install_id", "device_label"} and saved["device_label"] == "Anna's laptop"
    assert credential("swk") not in state.read_text(encoding="utf-8")
    if sys.platform != "win32":
        assert stat.S_IMODE(state.stat().st_mode) == 0o600
    code, _, err = run_cli(["scan", "--user", "--upload"], env=env)  # the label is reused
    assert code == 1, err
    first, second = (request[3] for request in fake.requests)
    assert first["install_id"] == second["install_id"] == saved["install_id"]


def test_the_first_upload_needs_a_label(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    code, out, _ = run_cli(["scan", "--user", "--upload", "--format", "json"],
                           env=upload_env(monkeypatch, make_home(tmp_path, "linux")))
    assert code == 2 and json.loads(out)["errors"][0]["code"] == "workstation_label_missing" and fake.requests == []


def test_a_failing_answer_exits_2_with_the_server_code_and_keeps_the_outputs(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    answered(fake, 403, {"error": "plan_required", "message": "Workstation inventories are part of the Enterprise plan.",
                         "plan_needed": "enterprise"})
    out = tmp_path / "r.json"
    code, _, err = run_cli(["scan", "--user", "--upload", "--device-label", "x", "--format", "json", "--output", str(out)],
                           env=upload_env(monkeypatch, make_home(tmp_path, "linux")))
    assert code == 2 and out.exists()
    assert "error workstation_upload_failed (plan_required): the workstation inventory was not uploaded: Workstation " \
           "inventories are part of the Enterprise plan." in err


def test_over_the_caps_nothing_is_sent(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    monkeypatch.setattr(workstation, "ITEMS_MAX", 3)
    code, _, err = run_cli(["scan", "--user", "--upload", "--device-label", "x"],
                           env=upload_env(monkeypatch, make_home(tmp_path, "linux")))
    assert code == 2 and fake.requests == [] and "error workstation_upload_too_large: nothing was uploaded" in err


def test_at_most_50_errors_and_notices_are_listed_with_their_totals(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    answered(fake)
    home = make_home(tmp_path, "linux")
    for number in range(60):  # a directory where a rule file is expected cannot be read: one error each
        (home / ".claude" / "rules" / f"d{number:02d}.md").mkdir()
    code, _, _ = run_cli(["scan", "--user", "--upload", "--device-label", "x"], env=upload_env(monkeypatch, home))
    body = fake.requests[0][3]
    assert code == 2 and body["complete"] is False
    assert len(body["errors"]) == 50 and body["errors_total"] == 60
    assert body["errors"] == sorted(body["errors"], key=lambda error: (error["code"], error["path"]))
    assert set(body["errors"][0]) == {"code", "path"}


def test_the_roots_cut_per_client_carry_their_total(run_cli, tmp_path, monkeypatch, api_double):
    # 1.16.2 (README "Limits": an output cap shows the count left out): `roots` holds at most ROOTS_MAX roots of a client,
    # and `roots_total`, always present, the number before the cut, as the report on the workstation lists them all
    fake, _ = api_double
    answered(fake)
    monkeypatch.setattr(workstation, "ROOTS_MAX", 1)
    home = make_home(tmp_path, "linux")
    out = tmp_path / "report.json"
    run_cli(["scan", "--user", "--upload", "--device-label", "x", "--format", "json", "--output", str(out)],
            env=upload_env(monkeypatch, home))
    listed = {entry["client"]: entry["roots"] for entry in json.loads(out.read_text(encoding="utf-8"))["clients"]}
    sent = {entry["client"]: entry for entry in fake.requests[0][3]["clients"]}
    assert set(sent) == set(listed)
    assert any(len(roots) > 1 for roots in listed.values())  # the fixture home has a client over the patched cap
    for client, roots in listed.items():
        assert sent[client]["roots"] == roots[:1]
        assert sent[client]["roots_total"] == len(roots)
        assert type(sent[client]["roots_total"]) is int


def test_clean_applies_the_servers_rules():
    assert workstation.clean("  An\u0007na\u200b's\u00a0laptop  ") == "Anna's\u00a0laptop"
    assert workstation.clean("x" * 70) == "x" * 64 and workstation.clean("\u200b") == ""


@pytest.mark.parametrize("platform, env, parts", [
    ("linux", {}, (".config", "spellwarden")), ("linux", {"XDG_CONFIG_HOME": "relative"}, (".config", "spellwarden")),
    ("darwin", {}, ("Library", "Application Support", "spellwarden")), ("win32", {}, ("AppData", "Roaming", "spellwarden")),
])
def test_the_state_directory_of_each_system(tmp_path, platform, env, parts):
    assert workstation.state_directory(platform, env, str(tmp_path)) == str(tmp_path.joinpath(*parts))


def test_a_repository_scan_ignores_the_workstation_variables(run_cli, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".cursor").mkdir(parents=True)
    (repo / ".cursor" / "mcp.json").write_text('{"mcpServers": {"x": {"command": "npx", "args": ["x"]}}}', encoding="utf-8")
    args = ["scan", str(repo), "--as-of", "2026-11-14", "--format", "json"]
    plain = run_cli(args)
    with_variables = run_cli(args, env={"SPELLWARDEN_WORKSTATION_ORG": "acme",
                                        "SPELLWARDEN_WORKSTATION_KEY": credential("swk")})
    assert with_variables == plain


def test_the_workstation_key_leaves_the_environment_first():
    from spellwarden_cli.secret import read_credentials

    env = {"SPELLWARDEN_WORKSTATION_KEY": credential("swk"), "SPELLWARDEN_WORKSTATION_ORG": "acme"}
    found = read_credentials(env)
    assert env == {"SPELLWARDEN_WORKSTATION_ORG": "acme"}
    assert found.workstation_key.value == credential("swk") and found.workstation_org == "acme"
    assert credential("swk") not in repr(found)


def test_upload_without_the_workstation_variables_stops_before_any_client_file_is_read(run_cli, tmp_path, monkeypatch):
    env = isolate(monkeypatch, make_home(tmp_path, "linux"), "linux")
    monkeypatch.setattr(userscan, "discover_home", lambda *_args: pytest.fail("a client file was read"))
    code, out, _ = run_cli(["scan", "--user", "--upload", "--device-label", "Anna's laptop", "--format", "json"], env=env)
    (error,) = json.loads(out)["errors"]
    assert code == 2 and error["code"] == "workstation_no_credential" and "SPELLWARDEN_WORKSTATION_ORG" in error["message"]
    code, out, _ = run_cli(["scan", "--user", "--upload", "--format", "json"],
                           env={**env, "SPELLWARDEN_WORKSTATION_ORG": "acme"})
    assert code == 2 and "SPELLWARDEN_WORKSTATION_KEY" in json.loads(out)["errors"][0]["message"]


# --- phase 3 batch 2c spec 11.2 and T-60 (F1): the upload runs before the reports are written, and every report carries it ---

FORMATS = ("text", "json", "sarif", "markdown", "gitlab-codequality", "cyclonedx")
SARIF_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "sarif-schema-2.1.0.json"


def _every_format(tmp_path: Path) -> tuple[list[str], dict[str, Path]]:
    paths = {fmt: tmp_path / "out" / f"report.{fmt}" for fmt in FORMATS}
    args = ["scan", "--user", "--upload", "--device-label", "x", "--as-of", "2026-11-14"]
    for fmt, path in paths.items():
        args += ["--format", fmt, "--output", str(path)]
    return args, paths


def _refused(fake, _monkeypatch) -> None:
    answered(fake, 403, {"error": "plan_required", "message": "Workstation inventories are part of the Enterprise plan.",
                         "plan_needed": "enterprise"})


def _too_large(_fake, monkeypatch) -> None:
    monkeypatch.setattr(workstation, "ITEMS_MAX", 3)


def _crashed(_fake, monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise RuntimeError("CANARY-EXCEPTION-TEXT")

    monkeypatch.setattr(workstation, "upload", boom)


@pytest.mark.parametrize("failure, code, detail", [
    (_refused, "workstation_upload_failed", "plan_required"),
    (_too_large, "workstation_upload_too_large", None),
    (_crashed, "workstation_upload_failed", "crash"),
])
def test_a_failed_upload_is_an_error_of_every_report_and_exits_2(run_cli, tmp_path, monkeypatch, api_double, failure, code,
                                                                  detail):
    fake, _ = api_double
    failure(fake, monkeypatch)
    args, paths = _every_format(tmp_path)
    exit_code, _, err = run_cli(args, env=upload_env(monkeypatch, make_home(tmp_path, "linux")))
    assert exit_code == 2, err
    texts = {fmt: path.read_text(encoding="utf-8") for fmt, path in paths.items()}  # a crash in the upload writes them all
    report = json.loads(texts["json"])
    (error,) = [entry for entry in report["errors"] if entry["code"] == code]
    assert report["exit_code"] == 2 and error["path"] == "" and error.get("detail") == detail
    assert f"error {code} " in texts["text"] and f"- {code}: " in texts["markdown"]
    sarif = json.loads(texts["sarif"])
    schema = json.loads(SARIF_SCHEMA.read_bytes().replace(b"\r\n", b"\n"))
    jsonschema.validators.validator_for(schema)(schema).validate(sarif)
    (invocation,) = sarif["runs"][0]["invocations"]
    assert invocation["executionSuccessful"] is False
    # one notification per error of the run, and this run has the one error (batch 2c spec 11.2)
    assert [entry["descriptor"]["id"] for entry in invocation["toolExecutionNotifications"]] == [code]
    properties = {entry["name"]: entry["value"] for entry in json.loads(texts["cyclonedx"])["metadata"]["properties"]}
    assert properties["spellwarden:exit_code"] == "2" and properties["spellwarden:complete"] == "false"
    assert properties["spellwarden:errors"] == "1"  # a CycloneDX document counts the error and names none (P21)
    # Code Quality lists findings only and makes no issue for the upload: the exit code 2 says it (batch 2c spec 11.2)
    assert isinstance(json.loads(texts["gitlab-codequality"]), list) and code not in texts["gitlab-codequality"]
    assert "CANARY-EXCEPTION-TEXT" not in "".join(texts.values()) + err  # the exception's class, never its text
    assert f"error {code}" in err  # the stderr line of 1.14.0, after the "wrote" lines
    assert err.index("wrote the json report") < err.index(f"error {code}")


def test_the_request_is_sent_before_any_report_is_written(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    answered(fake)
    args, paths = _every_format(tmp_path)
    existed = []
    real = workstation.upload

    def spy(document, **kwargs):
        existed.append([path.exists() for path in paths.values()])
        return real(document, **kwargs)

    monkeypatch.setattr(workstation, "upload", spy)
    exit_code, _, err = run_cli(args, env=upload_env(monkeypatch, make_home(tmp_path, "linux")))
    assert exit_code == 1, err  # the findings decide the exit code; the upload succeeded
    assert existed == [[False] * len(FORMATS)] and all(path.exists() for path in paths.values())


def test_a_successful_upload_is_a_notice_of_the_reports(run_cli, tmp_path, monkeypatch, api_double):
    fake, _ = api_double
    answered(fake)
    args, paths = _every_format(tmp_path)
    exit_code, _, err = run_cli(args, env=upload_env(monkeypatch, make_home(tmp_path, "linux")))
    texts = {fmt: path.read_text(encoding="utf-8") for fmt, path in paths.items()}
    report = json.loads(texts["json"])
    (notice,) = [entry for entry in report["notices"] if entry["code"] == "workstation_uploaded"]
    assert exit_code == 1 and report["exit_code"] == 1, err
    assert notice == {"code": "workstation_uploaded", "path": "", "message": "uploaded the inventory of x"}
    assert "notice workstation_uploaded " in texts["text"]
    assert not any(error["code"].startswith("workstation_upload") for error in report["errors"])
    assert "invocations" not in json.loads(texts["sarif"])["runs"][0]
    # a report holds no timestamp (README "Reports"): the server's time of the upload is in the stderr line only (P20)
    assert "10:00:00Z" not in "".join(texts.values())
    assert "notice workstation_uploaded: uploaded the inventory of x (2026-11-14T10:00:00Z)" in err


def test_a_run_without_upload_writes_what_it_wrote_before(run_cli, tmp_path, monkeypatch):
    env = isolate(monkeypatch, make_home(tmp_path, "linux"), "linux")
    _, out, _ = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--format", "json"], env=env)
    report = json.loads(out)
    assert not any(entry["code"].startswith("workstation_") for entry in report["notices"] + report["errors"])
    _, out, _ = run_cli(["scan", "--user", "--as-of", "2026-11-14", "--format", "sarif"], env=env)
    assert "invocations" not in json.loads(out)["runs"][0]
