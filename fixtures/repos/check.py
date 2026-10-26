"""Asserts one fixture case (plan P10): python fixtures/check.py <case> <report json> <exit code> <outputs>.

<report json> may not exist (a run that stopped before the scan writes none). <exit code> is the Action's
`exit-code` output, or `-`. <outputs> is a JSON file of the Action's outputs, `env` (SW_OUT_EXIT, SW_OUT_FINDINGS,
SW_OUT_SARIF, SW_OUT_OUTCOME), or `report` (GitLab: derived from the report, with SW_JOB_STATUS_FILE holding
$CI_JOB_STATUS). Optional: SW_PING_FILE (the listener's capture), SW_CODEQUALITY_FILE, SW_FIXTURE_REPO (where
`absent_files` must not appear, besides the working directory), SW_ANNOTATIONS_FILE (the codes of the notices and
warnings the Action wrote to the log, one per line; `annotations` is checked only when it is set). On a GitHub `pull_request` run the case's
`on_request` keys replace the others (spec 9.5: the settings file and the baseline come from the base commit,
which a repository built by make_repo.py does not hold); in a GitLab child pipeline that is a request (spec 10.3,
D47) `on_request` and then `on_gitlab_request` apply (there `--probe` is also off, as for a fork). On a GitHub pull
request from a fork (SW_FORK=true), `on_fork_request` applies after `on_request` (spec 6.8: `--probe` is off). Exits 1
listing every failed assertion."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from make_repo import load_case

HEX64 = re.compile(r"[0-9a-f]{64}")
PING_FIELDS = {"schema", "version", "rules_version", "ci", "org", "a2a"}
CODEQUALITY_SEVERITIES = {"critical", "major", "minor", "info"}


def _json(path: str | None):
    if not path or not Path(path).is_file():
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except ValueError:
        return "malformed"


def _outputs(mode: str, report) -> dict[str, str]:
    if mode == "env":
        return {"exit-code": os.environ.get("SW_OUT_EXIT", ""), "findings": os.environ.get("SW_OUT_FINDINGS", ""),
                "sarif-file": os.environ.get("SW_OUT_SARIF", ""), "outcome": os.environ.get("SW_OUT_OUTCOME", "")}
    if mode == "report":
        status_file = Path(os.environ.get("SW_JOB_STATUS_FILE", "job-status.txt"))
        status = status_file.read_text(encoding="utf-8").strip() if status_file.is_file() else ""
        outcome = "success" if status == "success" else ("failure" if status else "")
        if isinstance(report, dict):
            unsuppressed = sum(1 for f in report["findings"] if not f["suppressed"])
            exit_code = str(report["exit_code"])
        else:
            unsuppressed, exit_code = 0, ("2" if outcome == "failure" else "")
        sarif = "spellwarden.sarif" if Path("spellwarden.sarif").is_file() else ""
        return {"exit-code": exit_code, "findings": str(unsuppressed), "sarif-file": sarif, "outcome": outcome}
    data = _json(mode)
    if not isinstance(data, dict):
        raise SystemExit(f"cannot read the outputs file {mode}")
    return {key: str(data.get(key, "")) for key in ("exit-code", "findings", "sarif-file", "outcome")}


def check(case: str, report_path: str, exit_arg: str, outputs_mode: str) -> list[str]:
    expect = load_case(case)
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        expect = {**expect, **expect["on_request"]}
        if os.environ.get("SW_FORK") == "true":
            expect = {**expect, **expect["on_fork_request"]}
    elif os.environ.get("GITLAB_CI") == "true" and (
            os.environ.get("CI_MERGE_REQUEST_IID")
            or (os.environ.get("CI_PIPELINE_SOURCE") == "parent_pipeline" and os.environ.get("CI_COMMIT_REF_PROTECTED") != "true")):
        expect = {**expect, **expect["on_request"], **expect["on_gitlab_request"]}
    problems: list[str] = []
    report = _json(report_path)
    if report == "malformed":
        problems.append(f"the report {report_path} is not JSON")
        report = None
    outputs = _outputs(outputs_mode, report)
    want = str(expect["exit_code"])
    if outputs["exit-code"] != want:
        problems.append(f"exit-code output is {outputs['exit-code']!r}, expected {want}")
    if exit_arg != "-" and exit_arg != want:
        problems.append(f"exit code argument is {exit_arg!r}, expected {want}")
    if outputs["findings"] != str(expect["findings"]):
        problems.append(f"findings output is {outputs['findings']!r}, expected {expect['findings']}")
    if outputs["outcome"] and (outputs["outcome"] == "success") != (expect["exit_code"] == 0):
        problems.append(f"the step outcome is {outputs['outcome']}, expected {'success' if want == '0' else 'failure'}")
    if expect["report"] == "required" and report is None:
        problems.append("no JSON report was written")
    if expect["report"] == "absent" and report is not None:
        problems.append("a JSON report was written although the scan should not have run")
    if report is None and outputs["sarif-file"]:
        problems.append("sarif-file must be empty when no report was written")
    if isinstance(report, dict):
        problems += _check_report(expect, report)
    if outputs["sarif-file"]:
        problems += _check_sarif(expect, outputs["sarif-file"])
    if os.environ.get("SW_CODEQUALITY_FILE") and Path(os.environ["SW_CODEQUALITY_FILE"]).is_file():
        problems += _check_codequality(expect, os.environ["SW_CODEQUALITY_FILE"])
    if expect["ping"]:
        problems += _check_ping(os.environ.get("SW_PING_FILE", ""))
    if os.environ.get("SW_ANNOTATIONS_FILE"):
        path = Path(os.environ["SW_ANNOTATIONS_FILE"])
        logged = set(path.read_text(encoding="utf-8").split()) if path.is_file() else set()
        for code in expect["annotations"]:
            if code not in logged:
                problems.append(f"the Action did not log the {code} annotation")
    for name in expect["absent_files"]:
        places = [Path.cwd()] + ([Path(os.environ["SW_FIXTURE_REPO"])] if os.environ.get("SW_FIXTURE_REPO") else [])
        for place in places:
            if (place / name).exists():
                problems.append(f"{place / name} exists: a file name was executed as a command")
    return problems


def _check_report(expect: dict, report: dict) -> list[str]:
    problems = []
    if report.get("exit_code") != expect["exit_code"]:
        problems.append(f"report exit_code is {report.get('exit_code')}, expected {expect['exit_code']}")
    accepted = sum(1 for f in report["findings"] if f["suppressed"])
    if accepted != expect["accepted"]:
        problems.append(f"{accepted} accepted findings, expected {expect['accepted']}")
    notices = {n["code"] for n in report["notices"]}
    errors = {e["code"] for e in report["errors"]}
    for code in expect["notices"]:
        if code not in notices:
            problems.append(f"notice {code} missing (got {sorted(notices)})")
    for code in expect["errors"]:
        if code not in errors:
            problems.append(f"error {code} missing (got {sorted(errors)})")
    if not expect["errors"] and errors:
        problems.append(f"unexpected errors {sorted(errors)}")
    if expect["sarif_prefix"]:
        for finding in report["findings"]:
            if finding["location"]["path"].startswith(expect["sarif_prefix"]):
                problems.append(f"report path {finding['location']['path']} carries the repository prefix")
    if expect["lock"] is not None:
        lock = report["lock"]
        if lock["status"] != expect["lock"]["status"]:
            problems.append(f"lock status {lock['status']}, expected {expect['lock']['status']}")
        for key in ("added", "removed", "changed"):
            if key in expect["lock"]:
                got = sorted(change["path"] for change in lock[key])
                if got != sorted(expect["lock"][key]):
                    problems.append(f"lock {key} {got}, expected {sorted(expect['lock'][key])}")
    problems += _check_connected(expect, report)
    problems += _check_agents(expect, report)
    if expect["probes"] is not None:
        got = {p["item"]: (p["status"], p["skip_reason"]) for p in report["probes"]}
        for wanted in expect["probes"]:
            if got.get(wanted["item"]) != (wanted["status"], wanted["skip_reason"]):
                problems.append(f"probe {wanted['item']}: {got.get(wanted['item'])}, expected {(wanted['status'], wanted['skip_reason'])}")
    return problems


def _check_agents(expect: dict, report: dict) -> list[str]:
    """The `agents` key of a case (O4 spec 6.9, 7): the report's `agents` list holds exactly the agents the case names, each
    with its status, migration status and signature status; a case without the key must produce no list at all (a
    repository without agent cards reports as 1.2.1 did)."""
    got, wanted = report.get("agents"), expect["agents"]
    if wanted is None:
        return [] if got is None else ["the report holds an agents list although the case has no agent card"]
    if not isinstance(got, list):
        return ["the report holds no agents list"]
    seen = {agent["item"]: (agent["status"], agent["migration_status"], agent["signature_status"]) for agent in got}
    problems = [f"agent {item} is not in the report" for item in (w["item"] for w in wanted) if item not in seen]
    for want in wanted:
        have = seen.get(want["item"])
        expected = (want["status"], want["migration_status"], want["signature_status"])
        if have is not None and have != expected:
            problems.append(f"agent {want['item']} is {have}, expected {expected}")
    extra = sorted(set(seen) - {w["item"] for w in wanted})
    return problems + ([f"unexpected agents {extra}"] if extra else [])


def _check_connected(expect: dict, report: dict) -> list[str]:
    """The `connected` key of a case (O3 spec 6.9): the report's connected block holds the credential kind, the gate's
    counts and the upload outcome the case names; a case without the key must produce no block at all (free mode adds
    nothing to the report)."""
    block, wanted = report.get("connected"), expect["connected"]
    if wanted is None:
        return [] if block is None else ["the report holds a connected block although the case runs in free mode"]
    if not isinstance(block, dict):
        return ["the report holds no connected block"]
    problems = []
    if block.get("credential") != wanted["credential"]:
        problems.append(f"connected credential {block.get('credential')!r}, expected {wanted['credential']!r}")
    registry = block.get("registry") or {}
    for key in ("checked", "not_admitted", "unidentified"):
        if key in wanted and registry.get(key) != wanted[key]:
            problems.append(f"connected registry {key} is {registry.get(key)!r}, expected {wanted[key]}")
    upload = (block.get("upload") or {}).get("status")
    if "upload" in wanted and upload != wanted["upload"]:
        problems.append(f"connected upload is {upload!r}, expected {wanted['upload']!r}")
    return problems


def _check_sarif(expect: dict, path: str) -> list[str]:
    sarif = _json(path)
    if not isinstance(sarif, dict):
        return [f"the SARIF file {path} is missing or not JSON"]
    problems = []
    if sarif.get("version") != "2.1.0" or len(sarif.get("runs", [])) != 1:
        return ["the SARIF file is not one SARIF 2.1.0 run"]
    results = sarif["runs"][0].get("results", [])
    if len(results) != expect["findings"] + expect["accepted"]:
        problems.append(f"{len(results)} SARIF results, expected {expect['findings'] + expect['accepted']}")
    suppressed = sum(1 for r in results if r.get("suppressions"))
    if suppressed != expect["accepted"]:
        problems.append(f"{suppressed} suppressed SARIF results, expected {expect['accepted']}")
    for result in results:
        if not HEX64.fullmatch(result.get("partialFingerprints", {}).get("spellwarden/v1", "")):
            problems.append(f"result {result.get('ruleId')} has no spellwarden/v1 fingerprint")
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        if expect["sarif_prefix"] and not uri.startswith(expect["sarif_prefix"]):
            problems.append(f"SARIF uri {uri} does not start with {expect['sarif_prefix']}")
    return problems


def _check_codequality(expect: dict, path: str) -> list[str]:
    entries = _json(path)
    if not isinstance(entries, list):
        return [f"{path} is not a JSON array"]
    problems = []
    if len(entries) != expect["findings"]:
        problems.append(f"{len(entries)} Code Quality entries, expected {expect['findings']}")
    for entry in entries:
        if entry.get("severity") not in CODEQUALITY_SEVERITIES or not HEX64.fullmatch(entry.get("fingerprint", "")):
            problems.append(f"Code Quality entry {entry.get('check_name')} has a bad severity or fingerprint")
        if expect["sarif_prefix"] and not entry["location"]["path"].startswith(expect["sarif_prefix"]):
            problems.append(f"Code Quality path {entry['location']['path']} does not start with {expect['sarif_prefix']}")
    return problems


def _check_ping(path: str) -> list[str]:
    body = _json(path)
    if not isinstance(body, dict):
        return [f"no ping body was captured in {path!r}"]
    problems = []
    if set(body) != PING_FIELDS:
        problems.append(f"the ping body has fields {sorted(body)}, expected exactly {sorted(PING_FIELDS)}")
    provider = "github" if os.environ.get("GITHUB_ACTIONS") == "true" else "gitlab"
    if body.get("schema") != 1 or body.get("ci") != provider:
        problems.append(f"the ping says schema {body.get('schema')} and ci {body.get('ci')}, expected 1 and {provider}")
    if body.get("org") is not None and not HEX64.fullmatch(str(body.get("org"))):
        problems.append("the ping org is neither null nor 64 hex characters")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    problems = check(*argv[1:5])
    for problem in problems:
        print(f"FAIL {argv[1]}: {problem}")
    if not problems:
        print(f"ok {argv[1]}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
