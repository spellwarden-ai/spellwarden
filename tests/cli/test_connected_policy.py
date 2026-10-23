"""O3 spec 6.5, claim E9: the organisation's policy and rules once the session is established: the document is
validated and compiled, the rules run in every output, what the server left out is a notice, a defect in the
document is an error, and the org-rule time budget is enforced per package."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from conftest import (EXCHANGE_PATH, KEY_PATH, POLICY_PATH, connected_gitlab, credential, orgs_answer, org_rule, policy_answer,
                      probe_rule, scan_json, session_answer)

from spellwarden_scan import __version__
from spellwarden_cli import connected, probing

SKILL = "---\nname: deploy\ndescription: Deploys.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\nRun it.\n"
BASTION = "#!/bin/sh\nssh deploy@bastion.staging.example\n"
ID_TOKEN = "id.jwt." + "x" * 20
PACK = "b" * 32


def env_of(**more: str) -> dict[str, str]:
    return connected_gitlab(SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN, **more)


def skill_repo(make_repo, tmp_path: Path, files: dict | None = None) -> Path:
    return make_repo(tmp_path / "repo", {"skills/deploy/SKILL.md": SKILL, "skills/deploy/run.sh": BASTION, **(files or {})})


def serve(fake, answer: dict) -> None:
    fake.script("POST", EXCHANGE_PATH, 201, session_answer(run={"identity": "gitlab:gitlab.com/acme/tools", "event": "push"}))
    fake.script("GET", POLICY_PATH, 200, answer)


def notice(report: dict, code: str) -> dict:
    return next(entry for entry in report["notices"] if entry["code"] == code)


def test_org_rules_document_is_applied_and_reported(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    answer = policy_answer([org_rule()])
    serve(fake, answer)
    repo = skill_repo(make_repo, tmp_path)
    outputs = {fmt: tmp_path / f"out.{fmt}" for fmt in ("json", "sarif", "markdown", "gitlab-codequality")}
    args = [arg for fmt, path in outputs.items() for arg in ("--format", fmt, "--output", str(path))]
    code, text, err = run_cli(["scan", str(repo), "--no-telemetry", *args, "--format", "text"], env=env_of())
    assert code == 1, err  # SW-ORG-010 is high
    report = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert [f["rule_id"] for f in report["findings"]] == ["SW-ORG-010"] and report["findings"][0]["item"] == "skills/deploy"
    jsonschema.validate(report, json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(
        encoding="utf-8")))
    policy = report["connected"]["policy"]
    assert policy["source"] == "org_rules" and policy["chosen_by"] == "organisation"
    assert policy["pack_id"] == "a" * 32 and policy["version"] == "1.3" and policy["sha256"] == answer["policy"]["sha256"]
    assert policy["org_rule_ids"] == ["SW-ORG-010"] and policy["skipped"] == []
    assert policy["gate"] == {"enabled": True, "scope": "changed", "stdio": True, "plugins": True}
    # text: the finding, then the connected line after the summary
    assert "high SW-ORG-010 skills/deploy/run.sh:2 Mentions the staging bastion" in text
    lines = text.rstrip("\n").splitlines()
    assert lines[-2].endswith("failed at high")
    assert lines[-1] == ("Connected to Acme as gitlab:gitlab.com/acme/tools (oidc): 1 organisation rules (organisation rules, "
                         "chosen by the organisation), registry gate on, scope changed")
    # SARIF carries the rule and the result, Markdown the section, Code Quality the check name
    document = json.loads(outputs["sarif"].read_text(encoding="utf-8"))
    (sarif_run,) = document["runs"]
    assert "SW-ORG-010" in [rule["id"] for rule in sarif_run["tool"]["driver"]["rules"]]
    assert [r["ruleId"] for r in sarif_run["results"]] == ["SW-ORG-010"]
    markdown = outputs["markdown"].read_text(encoding="utf-8")
    assert "**Connected mode**" in markdown and "Connected to Acme as gitlab:gitlab.com/acme/tools" in markdown.replace("\\", "")
    assert [i["check_name"] for i in json.loads(outputs["gitlab-codequality"].read_text(encoding="utf-8"))] == ["SW-ORG-010"]


def test_the_organisation_rules_are_applied_to_the_whole_package_set_in_order(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, policy_answer([org_rule("SW-ORG-011", "ssh deploy"), org_rule("SW-ORG-010")]))
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 1 and sorted(f["rule_id"] for f in report["findings"]) == ["SW-ORG-010", "SW-ORG-011"]
    assert report["connected"]["policy"]["org_rule_ids"] == ["SW-ORG-010", "SW-ORG-011"]


def test_repository_pack_is_requested_and_reported(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, policy_answer([org_rule()], source="pack", chosen_by="repository", pack_name="Team pack", version="1.4"))
    repo = skill_repo(make_repo, tmp_path, {".spellwarden/config.yml": f"version: 1\nconnected:\n  pack: {PACK}@1.4\n"})
    code, out, _ = run_cli(["scan", str(repo), "--no-telemetry"], env=env_of())
    assert code == 1
    assert fake.requests[1][1] == f"{POLICY_PATH}?scanner={__version__}&pack={PACK}@1.4"
    assert out.rstrip("\n").splitlines()[-1] == ("Connected to Acme as gitlab:gitlab.com/acme/tools (oidc): 1 organisation "
                                                   "rules (pack Team pack 1.4, chosen by this repository), registry gate on, "
                                                   "scope changed")


def test_a_pack_answer_with_no_org_rules_applies_the_baseline_only(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, policy_answer([], source="pack", chosen_by="repository", pack_name="Plain", version="2.0"))
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 0 and report["findings"] == []  # the baseline has nothing to say about this skill
    assert report["connected"]["policy"]["org_rule_ids"] == [] and report["connected"]["policy"]["source"] == "pack"


def test_skipped_rules_give_the_notice_and_the_text_line_and_keep_the_exit_code(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    skipped = [{"id": "SW-ORG-007", "why": "needs_scanner", "version": "1.3.0"}, {"id": "SW-ORG-009", "why": "compile_error"}]
    serve(fake, policy_answer([], skipped=skipped))
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n"})
    code, out, _ = run_cli(["scan", str(repo), "--no-telemetry"], env=env_of())
    assert code == 0  # the exit code is not changed by a gap the dashboard marks
    lines = out.rstrip("\n").splitlines()
    assert lines[-1] == "2 organisation rules need a newer scanner and were not applied: SW-ORG-007, SW-ORG-009"
    assert lines[-2].startswith("Connected to Acme as ")
    assert "notice org_rules_skipped : 2 organisation rules were not applied (SW-ORG-007, SW-ORG-009)" in out
    assert "SW-ORG-007 needs scanner 1.3.0" in out


def test_skipped_rules_are_in_the_report_block(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    skipped = [{"id": "SW-ORG-007", "why": "needs_scanner", "version": "1.3.0"}]
    serve(fake, policy_answer([], skipped=skipped))
    code, report, _, _ = scan_json(run_cli, make_repo(tmp_path / "repo", {"README.md": "x\n"}), env_of())
    assert code == 0 and report["connected"]["policy"]["skipped"] == skipped
    assert notice(report, "org_rules_skipped")["message"].startswith("1 organisation rules were not applied (SW-ORG-007)")


@pytest.mark.parametrize("spec", [
    {"id": "SW-ORG-030", "title": "Unknown predicate", "severity": "low", "area": "mcp",
     "detection": {"kind": "probe", "predicate": "no_such_predicate", "values": ["1"]}},
    {"id": "SW-ORG-031", "title": "Bad severity", "severity": "urgent", "area": "skill",
     "detection": {"kind": "pattern", "pattern": "x"}},
    {"id": "SW-ORG-032", "title": "Backtracking", "severity": "low", "area": "skill",
     "detection": {"kind": "pattern", "pattern": "(a+)+b"}},
], ids=["unknown predicate", "bad severity", "pattern too complex"])
def test_a_rule_the_server_failed_to_filter_is_policy_invalid(make_repo, run_cli, tmp_path, api_double, spec):
    fake, _ = api_double
    serve(fake, policy_answer([spec]))
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 2 and [e["code"] for e in report["errors"]] == ["policy_invalid"] and "connected" not in report
    assert spec["id"] in report["errors"][0]["message"] or "pack" in report["errors"][0]["message"]


def test_a_document_that_is_not_a_pack_is_policy_invalid(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    answer = policy_answer([])
    answer["policy"]["document"]["schema"] = 2
    serve(fake, answer)
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 2 and [e["code"] for e in report["errors"]] == ["policy_invalid"]


def test_zero_budget_is_org_rules_incomplete_exit_2(make_repo, run_cli, tmp_path, api_double, monkeypatch):
    fake, _ = api_double
    serve(fake, policy_answer([org_rule()]))
    ticks = iter(range(0, 10_000, 11))  # every look at the clock is 11 s after the last: the 10 s budget ends at once
    monkeypatch.setattr(connected, "CLOCK", lambda: next(ticks))
    repo = skill_repo(make_repo, tmp_path, {"skills/deploy/more.sh": "\n".join(f"echo {n}" for n in range(20)) + "\n"})
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    assert code == 2 and "connected" in report
    (error,) = [e for e in report["errors"] if e["code"] == "org_rules_incomplete"]
    assert error["message"] == ("Organisation rule(s) SW-ORG-010 did not finish on skills/deploy within 10 seconds. The scan "
                                "is incomplete.")


def test_a_budget_that_holds_leaves_the_scan_complete(make_repo, run_cli, tmp_path, api_double, monkeypatch):
    fake, _ = api_double
    serve(fake, policy_answer([org_rule()]))
    monkeypatch.setattr(connected, "CLOCK", lambda: 5.0)
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 1 and report["errors"] == []


def test_mcp_rules_with_probing_off_give_mcp_rules_need_probe(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, policy_answer([probe_rule(), org_rule()]))
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert "mcp_rules_need_probe" in [n["code"] for n in report["notices"]] and code == 1
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([org_rule()]))  # skill rules only: nothing to say
    _, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path / "second"), env_of())
    assert "mcp_rules_need_probe" not in [n["code"] for n in report["notices"]]


def test_mcp_rules_reach_the_probe_phase_with_a_budget_each(make_repo, run_cli, tmp_path, api_double, monkeypatch):
    fake, _ = api_double
    serve(fake, policy_answer([probe_rule()]))
    seen: dict = {}

    def run_phase(_targets, rules, **kwargs):
        seen.update(rules=[rule.id for rule in rules], org_budget=kwargs.get("org_budget"))
        return [], []

    monkeypatch.setattr(probing, "run_phase", run_phase)
    repo = make_repo(tmp_path / "repo", {".mcp.json": '{"mcpServers": {"s": {"url": "https://mcp.example.com/mcp"}}}'})
    scan_json(run_cli, repo, env_of(), "--probe")
    assert "SW-ORG-020" in seen["rules"] and callable(seen["org_budget"])


def test_newer_pack_rules_version_applies_with_policy_newer_than_scanner(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, policy_answer([org_rule()], rules_version="2099.1.1"))
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 1 and [f["rule_id"] for f in report["findings"]] == ["SW-ORG-010"]  # applied: it validates and compiles
    assert "2099.1.1" in notice(report, "policy_newer_than_scanner")["message"]


@pytest.mark.parametrize(("status", "error", "expected"), [
    (404, "pack_not_found", "policy_not_found"), (404, "pack_version_not_found", "policy_not_found"),
    (404, "pack_not_allowed", "policy_not_found"), (404, "org_not_found", "connected_auth"),
    (404, "not_found", "connected_unavailable"),
])
def test_404_codes_map_as_spec_6_3(make_repo, run_cli, tmp_path, api_double, status, error, expected):
    fake, _ = api_double
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, status, {"error": error, "message": f"the server says {error}"})
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 2 and [e["code"] for e in report["errors"]] == [expected]


def test_429_is_connected_rate_limited_with_the_server_message(make_repo, run_cli, tmp_path, api_double):
    fake, clock = api_double
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, 429, {"error": "rate_limited", "message": "20 policy calls an hour"},
                headers={"Retry-After": "3"}, times=2)
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env_of())
    assert code == 2 and report["errors"] == [{"code": "connected_rate_limited", "path": "", "message":
                                              "A Spellwarden limit, not an outage, stopped this call: 20 policy calls an hour."}]
    assert clock.slept == [3.0]  # one retry after Retry-After, then the limit is reported


def test_the_key_path_reads_the_same_policy(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([org_rule()]))
    env = connected_gitlab(SPELLWARDEN_API_KEY=credential("swk"))
    code, report, _, _ = scan_json(run_cli, skill_repo(make_repo, tmp_path), env)
    assert code == 1 and report["connected"]["credential"] == "key"
    assert [f["rule_id"] for f in report["findings"]] == ["SW-ORG-010"]


def test_registry_none_and_gate_posture_show_in_the_connected_line(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    for index, (registry, gate, expected) in enumerate([
            (None, {}, "not in plan"), ("acme", {"enabled": False}, "off"), ("acme", {"scope": "all"}, "on, scope all")]):
        fake.script("POST", EXCHANGE_PATH, 201, session_answer())
        fake.script("GET", POLICY_PATH, 200, policy_answer([], registry=registry, gate=gate))
        repo = make_repo(tmp_path / f"repo{index}", {"README.md": "x\n"})
        _, out, _ = run_cli(["scan", str(repo), "--no-telemetry"], env=env_of())
        assert out.rstrip("\n").splitlines()[-1].endswith(f"registry gate {expected}"), out
