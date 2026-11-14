"""Phase 3 batch 2a spec 11.3, 11.4, T-4: the canaries planted in every secret place of every fixture home (environment
values, headers, the target of `bearer_token_env_var`, URL user names, queries and fragments of endpoints and of marketplace
sources, stdio arguments and a configuration finding's matched line) appear in no output format and not in the upload body."""
from __future__ import annotations

import json

import pytest
from conftest import credential
from homes import BEARER, CANARIES, SYSTEMS, isolate, make_home

FORMATS = ("text", "json", "sarif", "markdown", "gitlab-codequality", "cyclonedx")


@pytest.mark.parametrize("system", SYSTEMS)
def test_no_canary_reaches_any_output_or_the_upload_body(run_cli, tmp_path, monkeypatch, api_double, system):
    fake, _ = api_double
    fake.script("POST", "/api/v1/orgs/acme/workstations/inventory", 200, {"device": {"uploaded_at": "2026-11-14T10:00:00Z"}})
    home = make_home(tmp_path, system)
    planted = "".join(path.read_text(encoding="utf-8") for path in home.rglob("*") if path.is_file())
    assert all(canary in planted for canary in CANARIES if canary != "CANARY-BEARER-VALUE")  # every place is planted
    env = {**isolate(monkeypatch, home, system), **BEARER, "SPELLWARDEN_WORKSTATION_ORG": "acme",
           "SPELLWARDEN_WORKSTATION_KEY": credential("swk")}
    out = tmp_path / "out"
    args = ["scan", "--user", "--upload", "--device-label", "Anna's laptop", "--as-of", "2026-11-14"]
    for fmt in FORMATS:
        args += ["--format", fmt, "--output", str(out / f"report.{fmt}")]
    code, stdout, stderr = run_cli(args, env=env)
    assert code == 1, stderr
    texts = {fmt: (out / f"report.{fmt}").read_text(encoding="utf-8") for fmt in FORMATS}
    texts["stdout and stderr"] = stdout + stderr
    texts["upload body"] = json.dumps(fake.requests[0][3])
    for name, text in texts.items():
        assert not [canary for canary in CANARIES if canary in text], name
    # the findings that matched a secret line are still reported, by location, with no excerpt
    findings = json.loads(texts["json"])["findings"]
    assert {f["rule_id"] for f in findings} >= {"SW-CFG-002", "SW-CFG-005", "SW-CFG-010"}
    assert all(f["evidence"] == "" for f in findings if f["rule_id"].startswith("SW-CFG-"))
