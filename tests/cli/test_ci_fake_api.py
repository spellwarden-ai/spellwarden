"""O3 plan P23, Task 11: `fixtures/ci/fake_api.py` (the loopback fake of the service), its script and
`fixtures/ci/check_connected.py`, the same pieces `release.yml`'s `e2e-connected` job runs against the built wheel. Here
the command runs in process against the fake on a real loopback socket, once with an OIDC token and once with a CI key."""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from conftest import connected_github, credential, scan_json

from spellwarden_scan import pack_sha256, validate_pack

CI = Path(__file__).resolve().parents[2] / "fixtures" / "ci"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"ci_fixture_{name}", CI / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fake_api, check_connected = _load("fake_api"), _load("check_connected")
SCRIPT = json.loads((CI / "script.json").read_text(encoding="utf-8"))


@pytest.fixture
def fake(tmp_path):
    record = tmp_path / "recording.json"
    server = fake_api.serve(SCRIPT, port=0, record=str(record))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], record
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _scan(run_cli, tmp_path, fixture_tools, port: int, **credentials: str):
    repo = tmp_path / "fx"
    fixture_tools[0].build("findings@connected", repo)
    env = connected_github(tmp_path, "push", {"repository": {"default_branch": "main", "visibility": "private"}},
                           SPELLWARDEN_API_URL=f"http://127.0.0.1:{port}/api", GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="scan",
                           **credentials)
    return scan_json(run_cli, repo, env)


def test_the_script_is_a_pack_the_command_accepts():
    policy = next(route for route in SCRIPT["routes"] if route["path"].endswith("/ci/policy"))["body"]["policy"]
    assert validate_pack(policy["document"]).pack_id == policy["pack_id"] and pack_sha256(policy["document"]) == policy["sha256"]


def test_an_unscripted_request_is_a_404_and_is_recorded_as_unscripted(fake):
    port, record = fake
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/nothing")
    assert caught.value.code == 404
    assert json.loads(record.read_text(encoding="utf-8"))[0]["unscripted"] is True


def test_the_oidc_run_against_the_fake_passes_check_connected(run_cli, tmp_path, fixture_tools, fake):
    port, record = fake
    code, report, out, err = _scan(run_cli, tmp_path, fixture_tools, port, SPELLWARDEN_ORG="acme",
                                   ACTIONS_ID_TOKEN_REQUEST_URL=f"http://127.0.0.1:{port}/idtoken?api-version=2.0",
                                   ACTIONS_ID_TOKEN_REQUEST_TOKEN="runner-request-token")
    assert code == 1, err
    recording = json.loads(record.read_text(encoding="utf-8"))
    assert check_connected.check(recording, report, "oidc") == []
    block = report["connected"]
    assert (block["registry"]["checked"], block["registry"]["not_admitted"], block["registry"]["unidentified"]) == (1, 1, 1)
    assert block["upload"]["status"] == "uploaded" and "api_url_override" in [n["code"] for n in report["notices"]]
    assert [f["rule_id"] for f in report["findings"] if not f["suppressed"]] == ["SW-CFG-001", "SW-REG-001", "SW-REG-003"]
    for secret in ("fake.provider.token", "runner-request-token", fake_api.CI_TOKEN):
        assert secret not in out + err
    assert [request["method"] + " " + request["path"].split("?")[0] for request in recording][:2] == [
        "GET /idtoken", "POST /api/public/ci/token"]


def test_the_key_run_against_the_fake_passes_check_connected(run_cli, tmp_path, fixture_tools, fake):
    port, record = fake
    code, report, out, err = _scan(run_cli, tmp_path, fixture_tools, port, SPELLWARDEN_API_KEY=credential("swk"))
    assert code == 1, err
    assert check_connected.check(json.loads(record.read_text(encoding="utf-8")), report, "key") == []
    assert report["connected"]["credential"] == "key" and report["connected"]["upload"]["attested"] is False
    assert credential("swk") not in out + err


def test_the_command_line_of_check_connected_exits_1_on_a_leak(run_cli, tmp_path, fixture_tools, fake, capsys):
    port, record = fake
    _, report, _, _ = _scan(run_cli, tmp_path, fixture_tools, port, SPELLWARDEN_ORG="acme",
                            ACTIONS_ID_TOKEN_REQUEST_URL=f"http://127.0.0.1:{port}/idtoken?api-version=2.0",
                            ACTIONS_ID_TOKEN_REQUEST_TOKEN="runner-request-token")
    recording = json.loads(record.read_text(encoding="utf-8"))
    report_path = tmp_path / "report.json"
    recording_path = tmp_path / "rec.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    recording_path.write_text(json.dumps(recording), encoding="utf-8")
    assert check_connected.main([str(recording_path), str(report_path), "--credential", "oidc"]) == 0
    assert capsys.readouterr().out == "ok connected oidc\n"
    leaked = [dict(request) for request in recording]
    check = next(request for request in leaked if request["path"].endswith("registry-check"))
    check["body"] = {**check["body"], "note": "fake.provider.token"}
    recording_path.write_text(json.dumps(leaked), encoding="utf-8")
    assert check_connected.main([str(recording_path), str(report_path), "--credential", "oidc"]) == 1
    assert "the provider token is in POST /api/v1/orgs/acme/ci/registry-check" in capsys.readouterr().out
    assert check_connected.main([str(recording_path), str(report_path), "--credential", "key"]) == 1   # another sequence
