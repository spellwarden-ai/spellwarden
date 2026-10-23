"""O3 spec 6.7, 6.9 and 6.10 (`Results:`), claim E11, plan Task 10: the results upload. When it happens (after the exit
code is decided, before any output file is written), what it sends (the reductions of invariant 3), what each answer
becomes (a notice and the report's `upload` block, never a different exit code), and the shared upload fixtures."""
from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest
from conftest import (CHECK_PATH, EXCHANGE_PATH, HEAD, KEY_PATH, POLICY_PATH, SCANS_PATH, SHA, admit_all, connected_github,
                      connected_gitlab, credential, git, orgs_answer, policy_answer, scan_json, session_answer, write_tree)

from spellwarden_scan import __version__
from spellwarden_cli import connected
from spellwarden_cli.output import markdown, text
from spellwarden_cli.report import Notice

DASH = "https://dash.spellwarden.ai/acme"
ID_TOKEN = "id.jwt." + "x" * 20
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ci"
SKILL = "---\nname: deploy\ndescription: Deploys.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\nRun it.\n"
BASTION = "#!/bin/sh\nssh deploy@bastion.staging.example\n"
LIMITS = policy_answer([])["limits"]


def uploaded(url: str = f"{DASH}/repositories/r1") -> dict:
    return {"scan": "s1", "repository": "r1", "url": url}


def serve(fake, answer: object = None, *, status: int = 201, policy: dict | None = None, times: int = 1,
          scans: bool = True) -> None:
    fake.script("POST", EXCHANGE_PATH, 201, session_answer(run={
        "identity": "gitlab:gitlab.com/acme/tools", "event": "push", "sha": SHA}))
    fake.script("GET", POLICY_PATH, 200, policy or policy_answer([]))
    fake.script("POST", CHECK_PATH, 200, admit_all, times=5)
    if scans:
        fake.script("POST", SCANS_PATH, status, uploaded() if answer is None else answer, times=times)


def env_of(**more: str) -> dict[str, str]:
    return connected_gitlab(SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN, **more)


def key_env(tmp_path: Path, **more: str) -> dict[str, str]:
    return connected_github(tmp_path, "push", {"repository": {"default_branch": "main", "visibility": "private"}},
                            SPELLWARDEN_API_KEY=credential("swk"), GITHUB_RUN_ATTEMPT="2", GITHUB_JOB="scan", **more)


def repo_of(make_repo, tmp_path: Path, files: dict | None = None) -> Path:
    return make_repo(tmp_path / "repo", {"skills/deploy/SKILL.md": SKILL, "skills/deploy/run.sh": BASTION, **(files or {})})


def posts(fake) -> list[tuple]:
    return [request for request in fake.requests if request[1] == SCANS_PATH]


def codes(entries: list[dict]) -> list[str]:
    return [entry["code"] for entry in entries]


def notice(report: dict, code: str) -> dict:
    return next(entry for entry in report["notices"] if entry["code"] == code)


# --- when it happens ---------------------------------------------------------------------------------------------------

def test_upload_happens_in_ci_for_request_and_default_branch_after_the_exit_code_and_before_any_output_file(
        make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    out_json, out_sarif = tmp_path / "out.json", tmp_path / "out.sarif"
    seen: dict = {}

    def answer(body: dict) -> dict:
        seen["files"] = [path.exists() for path in (out_json, out_sarif)]  # nothing is written when the scan is posted
        seen["exit_code"] = body["report"]["exit_code"]
        return uploaded()

    serve(fake, scans=False)
    fake.script("POST", SCANS_PATH, 201, answer)
    code, _, err = run_cli(["scan", str(repo_of(make_repo, tmp_path)), "--no-telemetry", "--format", "json", "--output", str(out_json),
                            "--format", "sarif", "--output", str(out_sarif)], env=env_of())
    assert code == 0, err
    assert seen == {"files": [False, False], "exit_code": 0}
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["connected"]["upload"] == {"status": "uploaded", "attested": True, "url": f"{DASH}/repositories/r1"}
    (request,) = posts(fake)
    assert request[2]["Authorization"].startswith("Bearer swt_")  # the CI token of the exchange
    assert request[3]["run"]["kind"] == "default_branch" and request[3]["report"]["exit_code"] == 0


def test_a_request_uploads_too_and_a_plain_branch_does_not(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = repo_of(make_repo, tmp_path)
    base = git(repo, "rev-parse", "HEAD").strip()
    write_tree(repo, {"README.md": "x\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "head")
    payload = {"pull_request": {"number": 3, "head": {"repo": {"full_name": "acme/tools"}, "sha": HEAD, "ref": "feature/x"},
                                "base": {"sha": base}}, "repository": {"default_branch": "main"}}
    env = connected_github(tmp_path, "pull_request", payload, GITHUB_HEAD_REF="feature/x", SPELLWARDEN_ORG="acme",
                           SPELLWARDEN_ID_TOKEN=ID_TOKEN)
    serve(fake)
    code, report, _, err = scan_json(run_cli, repo, env)
    assert code == 0, err
    (request,) = posts(fake)
    run = request[3]["run"]
    assert (run["kind"], run["event"], run["request_number"], run["head_sha"], run["head_ref"]) == (
        "request", "pull_request", 3, HEAD, "feature/x")
    # a push to another branch is the run kind `branch`: nothing is sent, and the notice says why
    fake.requests.clear()
    fake._answers.clear()
    serve(fake)
    branch = connected_gitlab(SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN, CI_COMMIT_REF_NAME="topic")
    _, report, _, _ = scan_json(run_cli, repo, branch)
    assert posts(fake) == [] and report["connected"]["upload"] == {"status": "skipped", "reason": "branch"}
    assert notice(report, "upload_skipped")["message"].startswith("The results were not uploaded: ")


def test_key_upload_carries_an_idempotency_key_from_run_url_job_and_attempt(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    fake.script("POST", CHECK_PATH, 200, admit_all)
    fake.script("POST", SCANS_PATH, 201, uploaded())
    code, report, _, err = scan_json(run_cli, repo_of(make_repo, tmp_path), key_env(tmp_path))
    assert code == 0, err
    (request,) = posts(fake)
    body = request[3]
    key = body["run"]["idempotency_key"]
    assert re.fullmatch(r"[A-Za-z0-9._:#/-]{16,128}", key) and key == "https://github.com/acme/tools/actions/runs/9#scan#2"
    assert credential("swk") not in json.dumps(body)  # a credential is a header, never part of a body (invariant 2)
    assert body["run"]["repository"] == {"identity": "github:github.com/acme/tools", "url": "https://github.com/acme/tools",
                                         "visibility": "private", "scope": ""}
    assert report["connected"]["upload"] == {"status": "uploaded", "attested": False, "url": f"{DASH}/repositories/r1"}


def test_other_ci_without_run_id_sends_nothing_and_notices_upload_skipped_no_run_id(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    fake.script("POST", CHECK_PATH, 200, admit_all)
    env = {"CI": "true", "SPELLWARDEN_DEFAULT_BRANCH": "main", "SPELLWARDEN_API_KEY": credential("swk")}
    repo = repo_of(make_repo, tmp_path)
    git(repo, "remote", "add", "origin", "https://git.example.com/acme/tools.git")
    git(repo, "branch", "-M", "main")
    _, report, _, err = scan_json(run_cli, repo, env)
    assert report["connected"]["upload"] == {"status": "skipped", "reason": "no_run_id"}, err
    assert posts(fake) == [] and "upload_skipped" in codes(report["notices"])
    # with SPELLWARDEN_RUN_ID the key is built from it
    fake.requests.clear()
    fake._answers.clear()
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    fake.script("POST", CHECK_PATH, 200, admit_all)
    fake.script("POST", SCANS_PATH, 201, uploaded())
    scan_json(run_cli, repo, {**env, "SPELLWARDEN_RUN_ID": "build 77"})
    (request,) = posts(fake)
    assert request[3]["run"]["provider"] == "other" and request[3]["run"]["run_url"] is None
    assert re.fullmatch(r"[A-Za-z0-9._:#/-]{16,128}", request[3]["run"]["idempotency_key"])
    assert "build_77" in request[3]["run"]["idempotency_key"]


# --- what each answer becomes --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("status, body, upload, notice_code", [
    (202, {"skipped": "branch"}, {"status": "skipped", "reason": "branch"}, "upload_skipped"),
    (202, {"skipped": "event_not_reportable"}, {"status": "skipped", "reason": "event_not_reportable"}, "upload_skipped"),
    (202, {"skipped": "default_branch_unconfirmed"}, {"status": "skipped", "reason": "default_branch_unconfirmed"}, "upload_skipped"),
    (409, {"error": "upload_in_progress", "message": "Another upload of this run is running."},
     {"status": "failed", "error": "upload_in_progress"}, "upload_failed"),
    (500, {"error": "internal", "request_id": "req-1"},
     {"status": "failed", "error": "internal", "request_id": "req-1"}, "upload_failed"),
], ids=["branch", "event_not_reportable", "default_branch_unconfirmed", "in progress", "500"])
def test_202_reasons_and_409_and_other_failures_map_to_notices_and_never_change_the_exit_code(
        status, body, upload, notice_code, make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    free_code, _, _ = run_cli(["scan", str(repo_of(make_repo, tmp_path / "free")), "--no-telemetry"], env={})
    serve(fake, body, status=status, times=2)
    code, report, out, err = scan_json(run_cli, repo_of(make_repo, tmp_path), env_of())
    assert code == free_code and report["errors"] == [], err        # exit code equal to the free-mode run
    assert report["connected"]["upload"] == upload
    message = notice(report, notice_code)["message"]
    assert "req-1" in message if status == 500 else True
    assert notice_code in out


def test_local_and_disabled_give_their_notices(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    fake.script("POST", CHECK_PATH, 200, admit_all)
    _, report, _, err = scan_json(run_cli, repo_of(make_repo, tmp_path), {"SPELLWARDEN_API_KEY": credential("swk")})
    assert report["connected"]["upload"] == {"status": "skipped", "reason": "local"}, err
    assert notice(report, "upload_ci_only")["message"] == "Results are uploaded from CI runs only; this local run uploaded nothing."
    serve(fake)
    _, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path / "second"), env_of(), "--no-upload")
    assert report["connected"]["upload"] == {"status": "skipped", "reason": "disabled"} and posts(fake) == []
    assert "upload_disabled" in codes(report["notices"])
    fake.requests.clear()
    fake._answers.clear()
    serve(fake)
    repo = repo_of(make_repo, tmp_path / "third", {".spellwarden/config.yml": "version: 1\nconnected:\n  upload: false\n"})
    _, report, _, _ = scan_json(run_cli, repo, env_of())
    assert report["connected"]["upload"]["reason"] == "disabled" and posts(fake) == []
    fake.requests.clear()
    fake._answers.clear()
    serve(fake)
    _, report, _, _ = scan_json(run_cli, repo, env_of(SPELLWARDEN_UPLOAD="true"), "--upload")  # the flag beats the file
    assert report["connected"]["upload"]["status"] == "uploaded"


def test_201_gives_uploaded_with_attested_the_text_line_the_markdown_link_and_the_json_block(
        make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    out_md = tmp_path / "r.md"
    code, out, err = run_cli(["scan", str(repo_of(make_repo, tmp_path)), "--no-telemetry", "--format", "markdown",
                              "--output", str(out_md), "--format", "text"], env=env_of())
    assert code == 0, err
    assert out.rstrip("\n").splitlines()[-1] == f"Results: {DASH}/repositories/r1"
    assert f"Results: <{DASH}/repositories/r1>" in out_md.read_text(encoding="utf-8")
    assert f"notice uploaded : Results were uploaded to {DASH}/repositories/r1." in out


def test_an_answer_url_outside_the_dashboard_is_not_kept(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, uploaded("https://evil.example/phish"))
    _, report, out, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), env_of())
    assert report["connected"]["upload"] == {"status": "uploaded", "attested": True} and "evil.example" not in out


def test_pull_request_target_with_a_fork_head_connects_gates_uploads_head_sha_and_pins_it_in_request_links(
        make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = repo_of(make_repo, tmp_path)
    base = git(repo, "rev-parse", "HEAD").strip()
    write_tree(repo, {"skills/deploy/more.md": "more\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fork head")
    payload = {"pull_request": {"number": 8, "head": {"repo": {"full_name": "forker/tools"}, "sha": HEAD, "ref": "patch-1"},
                                "base": {"sha": base}}, "repository": {"default_branch": "main"}}
    env = connected_github(tmp_path, "pull_request_target", payload, GITHUB_HEAD_REF="patch-1", SPELLWARDEN_ORG="acme",
                           SPELLWARDEN_ID_TOKEN=ID_TOKEN)
    serve(fake)
    code, report, _, err = scan_json(run_cli, repo, env)
    assert code == 0, err
    assert report["connected"]["run"]["kind"] == "request" and "fork_free_mode" not in codes(report["notices"])
    (check,) = [request[3] for request in fake.requests if request[1] == CHECK_PATH]
    assert check["repository"]["head_sha"] == HEAD
    (upload,) = [request[3] for request in posts(fake)]
    assert upload["run"]["head_sha"] == HEAD and upload["run"]["head_ref"] == "patch-1" and upload["run"]["request_number"] == 8


def test_upload_is_not_retried_after_a_timeout_but_is_after_a_429_or_a_connect_failure(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = repo_of(make_repo, tmp_path)
    serve(fake, scans=False)
    fake.script("POST", SCANS_PATH, 201, uploaded(), delay=11.0)   # slower than the 10 s deadline: a timeout
    fake.script("POST", SCANS_PATH, 201, uploaded())               # would be the retry: it must not be used
    _, report, _, _ = scan_json(run_cli, repo, env_of())
    assert report["connected"]["upload"]["status"] == "failed" and len(posts(fake)) == 1
    fake.requests.clear()
    fake._answers.clear()
    serve(fake, scans=False)
    fake.script("POST", SCANS_PATH, 429, {"error": "rate_limited"}, headers={"Retry-After": "1"})
    fake.script("POST", SCANS_PATH, 201, uploaded())
    _, report, _, _ = scan_json(run_cli, repo, env_of())
    assert report["connected"]["upload"]["status"] == "uploaded" and len(posts(fake)) == 2
    fake.requests.clear()
    fake._answers.clear()
    serve(fake, scans=False)
    fake.script("POST", SCANS_PATH, 0, None)                       # refused before the request was sent
    fake.script("POST", SCANS_PATH, 201, uploaded())
    _, report, _, _ = scan_json(run_cli, repo, env_of())
    assert report["connected"]["upload"]["status"] == "uploaded"


# --- the body ------------------------------------------------------------------------------------------------------------

def report_dict(**more) -> dict:
    """A report as `report.to_json_dict` writes it, with what the reductions act on."""
    base = {"schema": 1, "scanner_version": __version__, "rules_version": "2026.10.3", "as_of": "2026-10-23", "items": [],
            "findings": [], "probes": [], "lock": {"status": "not_checked", "added": [], "removed": [], "changed": []},
            "notices": [], "errors": [], "fail_on": "high", "exit_code": 0,
            "connected": {"credential": "oidc", "org": {"slug": "acme", "name": "Acme"}, "run": {}, "policy": {},
                          "registry": None, "upload": None}}
    return {**base, **more}


def finding(index: int, severity: str = "high", *, suppressed: bool = False) -> dict:
    return {"rule_id": "SW-SKL-007", "severity": severity, "title": "Remote script piped to a shell",
            "location": {"path": f"skills/s{index}/run.sh", "line": 2}, "evidence": "curl | sh", "fingerprint": f"{index:064x}",
            "malicious_indicator": False, "item": f"skills/s{index}", "suppressed": suppressed,
            "baseline": {"reason": "ok", "added": "2026-10-01", "expires": "2026-11-01"} if suppressed else None}


def test_reductions_and_their_record():
    findings = [finding(n, "low") for n in range(300)] + [finding(1000 + n, "critical") for n in range(300)]
    findings.sort(key=lambda f: ["critical", "high", "medium", "low"].index(f["severity"]))   # report order
    probes = [{"item": f"s{n}", "status": "probed", "skip_reason": None, "transport": "http", "spec_version": "2025-06-18",
               "auth_mode": "none", "migration_status": "ok", "findings": [finding(n)], "checklist": [{"x": 1}]}
              for n in range(250)]
    loud = [{"code": "findings_truncated", "path": "", "message": "x" * 400 + " " + "sw" + "k_" + "a" * 40} for _ in range(60)]
    report = report_dict(findings=findings, probes=probes, notices=loud, errors=loud[:55],
                         items=[{"kind": "skill", "path": f"s{n}", "name": "s", "plugin": None} for n in range(2100)])
    body, dropped, cut = connected.reduce_report(report, LIMITS)
    assert dropped == 100 and len(body["findings"]) == 500
    assert [f["severity"] for f in body["findings"][:300]] == ["critical"] * 300     # highest severity first, none re-ordered
    assert len(body["items"]) == 2000 and len(body["probes"]) == 200
    assert all("findings" not in probe and "checklist" not in probe for probe in body["probes"])
    assert len(body["notices"]) == 50 and len(body["errors"]) == 50
    assert all(len(n["message"]) <= 300 for n in body["notices"]) and "swk_" not in json.dumps(body)   # cut, masked
    assert "upload" not in body["connected"]
    assert cut == ["findings", "items", "probes", "notices", "errors"]       # the order of 8.4
    assert body["upload_truncated"] == 100 and body["upload_truncated_fields"] == cut
    assert report["connected"]["upload"] is None and len(report["findings"]) == 600       # the input is not changed


def test_suppressed_findings_travel_with_their_baseline_and_an_untouched_report_records_no_cut():
    report = report_dict(findings=[finding(1), finding(2, "low", suppressed=True)])
    body, dropped, cut = connected.reduce_report(report, LIMITS)
    assert (dropped, cut) == (0, []) and "upload_truncated" not in body and "upload_truncated_fields" not in body
    assert body["findings"][1]["baseline"] == {"reason": "ok", "added": "2026-10-01", "expires": "2026-11-01"}


def test_a_body_over_the_limit_drops_items_then_probes_and_records_them():
    heavy = [{"kind": "skill", "path": "p" * 900, "name": "n" * 200, "plugin": None} for _ in range(2000)]
    probes = [{"item": "i" * 900, "status": "probed", "skip_reason": None, "transport": None, "spec_version": None,
               "auth_mode": None, "migration_status": None} for _ in range(200)]
    report = report_dict(items=heavy, probes=probes, findings=[finding(n) for n in range(10)])
    limits = {**LIMITS, "upload_max_bytes": 60_000}
    body, dropped, cut = connected.reduce_report(report, limits)
    assert body["items"] == [] and cut == ["items", "probes"] or "probes" in cut
    assert len(json.dumps(body)) <= 60_000 and dropped == 0
    assert body["upload_truncated_fields"] == cut


def test_the_body_validates_against_the_field_table_fixture(run_cli, tmp_path, api_double, fixture_tools):
    """`upload-1.2.0.json` is the body of the wrappers' fixture repository (`connected`) on a push to the default branch
    of a GitHub repository, a CI token, one server not admitted; the code repository validates the same file."""
    fake, _ = api_double
    repo = tmp_path / "fx"
    fixture_tools[0].build("connected", repo)
    fake.script("POST", EXCHANGE_PATH, 201, session_answer(run={"identity": "github:github.com/acme/tools", "event": "push",
                                                                "sha": SHA}))
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    fake.script("POST", CHECK_PATH, 200, lambda body: admit_all(body, refuse_server=True))
    fake.script("POST", SCANS_PATH, 201, uploaded())
    env = connected_github(tmp_path, "push", {"repository": {"default_branch": "main", "visibility": "private"}},
                           SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN, GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="scan")
    code, report, _, err = scan_json(run_cli, repo, env)
    assert code == 1, err
    (request,) = posts(fake)
    body = request[3]
    assert validate_fields(body) == [] and "upload" not in body["report"]["connected"]
    recorded = json.loads((FIXTURES / "upload-1.2.0.json").read_text(encoding="utf-8"))
    assert validate_fields(recorded) == []
    assert normalised(body) == normalised(recorded)
    # a richer body, with every kind of member the table knows, is valid too
    rich = json.loads(json.dumps(recorded))
    rich["report"]["findings"] += [finding(1), finding(2, "low", suppressed=True)]
    rich["report"]["probes"] = [{"item": ".mcp.json#s", "status": "probed", "skip_reason": None, "transport": "http",
                                 "spec_version": "2025-06-18", "auth_mode": "none", "migration_status": "ok"}]
    rich["report"]["notices"] = [{"code": "uploaded", "path": "", "message": "ok", "detail": None}]
    rich["report"]["upload_truncated"], rich["report"]["upload_truncated_fields"] = 3, ["findings"]
    rich["run"].update(request_number=42, head_sha="2" * 40)
    assert validate_fields(rich) == []
    for path, value in (("run.kind", "branch"), ("run.repository.scope", "/abs"), ("report.exit_code", 4),
                        ("report.findings[0].fingerprint", "xyz")):
        broken = json.loads(json.dumps(rich))
        set_path(broken, path, value)
        assert validate_fields(broken) != [], path
    assert report is not None


def test_the_recorded_body_is_free_of_credentials_and_deterministic():
    text_ = (FIXTURES / "upload-1.2.0.json").read_text(encoding="utf-8")
    assert not re.search(r"sw[kctri]_[A-Za-z0-9_-]{40}", text_) and "Bearer" not in text_ and "eyJ" not in text_
    assert text_.endswith("\n") and json.loads(text_)["schema"] == 1
    fields = json.loads((FIXTURES / "upload-fields.json").read_text(encoding="utf-8"))
    assert all(set(entry) <= {"path", "type", "max", "min", "enum", "pattern"} and {"path", "type"} <= set(entry) for entry in fields)
    for entry in fields:
        if "pattern" in entry:
            re.compile(entry["pattern"])


def test_the_report_schema_describes_the_uploaded_block(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    _, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), env_of())
    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(report, schema)
    truncated = {**report, "upload_truncated": 3, "upload_truncated_fields": ["findings"]}
    jsonschema.validate(truncated, schema)


def test_the_notice_texts_hold_no_dash_and_no_exclamation_mark():
    for block in ({"status": "uploaded", "url": f"{DASH}/r", "attested": True}, {"status": "failed", "error": "x"},
                  {"status": "skipped", "reason": "branch"}, {"status": "skipped", "reason": "event_not_reportable"},
                  {"status": "skipped", "reason": "default_branch_unconfirmed"}, {"status": "skipped", "reason": "no_run_id"},
                  {"status": "skipped", "reason": "local"}, {"status": "skipped", "reason": "disabled"}):
        notice_ = connected.upload_notice(block)
        assert isinstance(notice_, Notice) and not any(mark in notice_.message for mark in "!–—")
    assert text.connected_lines and markdown.connected_section


# --- the field table (tests/fixtures/ci/upload-fields.json) ----------------------------------------------------------------

def fields_table() -> list[dict]:
    return json.loads((FIXTURES / "upload-fields.json").read_text(encoding="utf-8"))


def _walk(node: object, parts: list[str]) -> list[tuple[bool, object]]:
    """Every value the dotted path with `[]` for list members reaches, as `(present, value)`."""
    if not parts:
        return [(True, node)]
    head, rest = parts[0], parts[1:]
    many = head.endswith("[]")
    name = head[:-2] if many else head
    if not isinstance(node, dict):
        return []
    if name not in node:
        return [(False, None)]
    value = node[name]
    if many:
        return [found for item in value for found in _walk(item, rest)] if isinstance(value, list) else [(True, value)]
    return _walk(value, rest)


def validate_fields(body: dict) -> list[str]:
    """A tiny validator of the table in 8.4: every field present has its type, bound, enumeration and pattern; a field
    that is absent is fine only where the table allows null."""
    problems = []
    for entry in fields_table():
        types = entry["type"].split("|")
        for present, value in _walk(body, entry["path"].split(".")):
            if not present:
                if "null" not in types:
                    problems.append(f"{entry['path']}: missing")
                continue
            if value is None:
                if "null" not in types:
                    problems.append(f"{entry['path']}: null")
                continue
            kind = ("boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else "string" if
                    isinstance(value, str) else "array" if isinstance(value, list) else "object")
            if kind not in types:
                problems.append(f"{entry['path']}: {kind} is not {entry['type']}")
                continue
            size = len(value) if kind in ("string", "array") else value if kind == "integer" else None
            if size is not None and "max" in entry and size > entry["max"]:
                problems.append(f"{entry['path']}: over {entry['max']}")
            if size is not None and "min" in entry and size < entry["min"]:
                problems.append(f"{entry['path']}: under {entry['min']}")
            if "enum" in entry and value not in entry["enum"]:
                problems.append(f"{entry['path']}: {value!r} not in the enumeration")
            if "pattern" in entry and kind == "string" and not re.search(entry["pattern"], value):
                problems.append(f"{entry['path']}: {value!r} does not match")
    return problems


def set_path(body: dict, path: str, value: object) -> None:
    node = body
    parts = path.split(".")
    for part in parts[:-1]:
        if part.endswith("]"):
            name, index = part[:-1].split("[")
            node = node[name][int(index)]
        else:
            node = node[part]
    node[parts[-1]] = value


def normalised(body: dict) -> dict:
    """The body with what differs between runs and releases replaced: the sha values (40 or 64 hex), the date, the versions."""
    text_ = json.dumps(body, sort_keys=True)
    text_ = re.sub(r'"[0-9a-f]{40}"|"[0-9a-f]{64}"', '"<sha>"', text_)
    text_ = re.sub(r'"as_of": "[0-9-]+"', '"as_of": "<date>"', text_)
    text_ = re.sub(r'"(scanner_version|rules_version)": "[^"]+"', r'"\1": "<version>"', text_)
    return json.loads(text_)
