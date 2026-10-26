"""Spec 7.4: `scripts/e2e.py` prepares the pre-release Action test: the hash-pinned requirements file that installs
this run's wheel with --no-index, a fixture case's expected exit code, and a synthetic pull request event."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import e2e  # noqa: E402

DEPS = "# generated\npyyaml==6.0.2 \\\n    --hash=sha256:" + "1" * 64 + " \\\n    --hash=sha256:" + "2" * 64 + "\n"


def test_requirements_pins_the_local_wheel_offline(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "spellwarden-1.0.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel bytes")
    deps = tmp_path / "deps.txt"
    deps.write_text(DEPS)
    house = tmp_path / "house"
    out = tmp_path / "req.txt"
    assert e2e.main(["requirements", "--dist", str(dist), "--wheelhouse", str(house), "--deps", str(deps),
                     "--out", str(out)]) == 0
    text = out.read_text()
    lines = text.splitlines()
    assert lines[0] == "--no-index"
    assert lines[1] == "--find-links " + house.resolve().as_uri()
    assert lines[2] == "spellwarden==1.0.0 --hash=sha256:" + hashlib.sha256(b"wheel bytes").hexdigest()
    assert text.endswith(DEPS.split("\n", 1)[1])
    assert (house / wheel.name).read_bytes() == b"wheel bytes"


def test_requirements_refuses_zero_wheels(tmp_path):
    (tmp_path / "dist").mkdir()
    deps = tmp_path / "deps.txt"
    deps.write_text(DEPS)
    args = ["requirements", "--dist", str(tmp_path / "dist"), "--wheelhouse", str(tmp_path / "h"), "--deps", str(deps),
            "--out", str(tmp_path / "r.txt")]
    assert e2e.main(args) == 2


def test_expected_exit_reads_the_case_through_the_fixture_loader(tmp_path, capsys):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "make_repo.py").write_text(
        "import json\nfrom pathlib import Path\nHERE = Path(__file__).parent\n"
        "def load_case(case):\n    name, _, variant = case.partition('@')\n"
        "    doc = json.loads((HERE / name / 'expect.json').read_text())\n"
        "    return {**doc, **doc.get('variants', {}).get(variant, {})}\n")
    (fixtures / "permissions").mkdir()
    (fixtures / "permissions" / "expect.json").write_text(json.dumps({"exit_code": 1, "variants": {"v": {"exit_code": 2}}}))
    assert e2e.main(["expected-exit", "permissions", "--fixtures", str(fixtures)]) == 0
    assert e2e.main(["expected-exit", "permissions@v", "--fixtures", str(fixtures)]) == 0
    assert capsys.readouterr().out == "1\n2\n"


def test_event_writes_a_pull_request_event(tmp_path):
    path = tmp_path / "event.json"
    assert e2e.main(["event", str(path), "--repository", "spellwarden-ai/spellwarden"]) == 0
    event = json.loads(path.read_text())
    assert event["pull_request"]["number"] == 1
    assert event["pull_request"]["head"]["repo"]["full_name"] == "spellwarden-ai/spellwarden"


def test_sarif_validates_against_the_vendored_schema(tmp_path):
    valid = tmp_path / "valid.sarif"
    valid.write_text(json.dumps({
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "spellwarden", "rules": [{"id": "SW-CFG-001"}]}},
                  "results": [{"ruleId": "SW-CFG-001", "level": "error", "message": {"text": "Plain HTTP."},
                               "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".mcp.json"},
                                                                   "region": {"startLine": 1}}}]}]}],
    }), encoding="utf-8")
    assert e2e.main(["sarif", str(valid)]) == 0
    broken = tmp_path / "broken.sarif"
    broken.write_text(json.dumps({"version": "2.1.0", "runs": "not a list"}), encoding="utf-8")
    assert e2e.main(["sarif", str(broken)]) == 1


# --- the connected fixture case (O3 Task 9) ------------------------------------------------------------------------------

def _fixture_tools():
    import importlib

    root = str(Path(__file__).resolve().parents[1] / "fixtures" / "repos")
    sys.path.insert(0, root)
    for name in ("make_repo", "check"):
        sys.modules.pop(name, None)
    try:
        return importlib.import_module("make_repo"), importlib.import_module("check")
    finally:
        sys.path.remove(root)
        for name in ("make_repo", "check"):
            sys.modules.pop(name, None)


def test_the_case_loader_knows_the_connected_inputs_and_key():
    make_repo, _ = _fixture_tools()
    case = make_repo.load_case("connected")
    assert case["inputs"]["org"] == "acme" and case["inputs"]["upload"] == "true" and case["inputs"]["api-key"] == ""
    assert case["connected"]["credential"] == "oidc"
    assert make_repo.load_case("connected@key")["inputs"]["org"] == ""            # a variant merges its inputs key by key
    assert make_repo.load_case("connected@key")["connected"]["credential"] == "key"
    free = make_repo.load_case("findings")
    assert free["connected"] is None and free["inputs"]["org"] == "" and free["inputs"]["default-branch"] == ""
    assert make_repo.GITLAB_VARIABLES["org"] == "SW_ORG" and make_repo.GITLAB_VARIABLES["upload"] == "SW_UPLOAD"


def test_the_connected_check_asserts_credential_counts_and_upload_and_a_free_case_has_no_block():
    make_repo, check = _fixture_tools()
    expect = make_repo.load_case("connected")
    block = {"credential": "oidc", "registry": {"checked": 6, "not_admitted": 1, "unidentified": 1},
             "upload": {"status": "uploaded"}}
    assert check._check_connected(expect, {"connected": block}) == []
    assert len(check._check_connected(expect, {})) == 1                            # no block at all
    wrong = {**block, "credential": "key", "registry": {"checked": 5, "not_admitted": 1, "unidentified": 1},
             "upload": {"status": "failed"}}
    assert len(check._check_connected(expect, {"connected": wrong})) == 3
    free = make_repo.load_case("findings")
    assert check._check_connected(free, {}) == []
    assert check._check_connected(free, {"connected": block}) != []               # free mode adds nothing to the report


def test_the_a2a_case_names_its_agents_and_the_check_asserts_them(tmp_path):
    """O4 spec 7, claim W1: the fixture repository of the wrapper e2e holds a card signed with a key of its own `a2a.keys`
    file, an unsigned 0.3 card and a look-alike `agent.json`; the check compares the report's `agents` list with the case."""
    make_repo, check = _fixture_tools()
    case = make_repo.load_case("a2a")
    assert case["findings"] == 2 and case["notices"] == ["a2a_not_card"] and len(case["agents"]) == 2
    on_request = {**case, **case["on_request"]}
    assert "a2a_signature_unverified" in on_request["notices"] and on_request["agents"][1]["signature_status"] == "unverified"
    report = {"agents": [{"item": agent["item"], "status": agent["status"], "migration_status": agent["migration_status"],
                          "signature_status": agent["signature_status"]} for agent in case["agents"]]}
    assert check._check_agents(case, report) == []
    assert check._check_agents(case, {}) == ["the report holds no agents list"]
    wrong = {"agents": [{**report["agents"][0], "signature_status": "invalid"}, report["agents"][1],
                        {"item": "a2a-card:x", "status": "checked", "migration_status": "ready", "signature_status": "unsigned"}]}
    assert len(check._check_agents(case, wrong)) == 2
    free = make_repo.load_case("findings")
    assert check._check_agents(free, {}) == [] and check._check_agents(free, report) != []
    assert check.PING_FIELDS == {"schema", "version", "rules_version", "ci", "org", "a2a"}
    built = tmp_path / "fx"
    make_repo.build("a2a", built)
    assert (built / ".well-known" / "jwks.json").is_file() and (built / "public/.well-known/agent-card.json").is_file()
    assert (built / ".spellwarden" / "config.yml").read_text() == "version: 1\na2a:\n  keys: .well-known/jwks.json\n"
    assert (built / "tools/.well-known/agent.json").read_text().startswith("// ")


def test_a_real_scan_of_the_a2a_fixture_passes_the_case_s_own_report_check(tmp_path):
    from spellwarden_cli.main import main

    make_repo, check = _fixture_tools()
    built, written = tmp_path / "fx", tmp_path / "report.json"
    expect = make_repo.build("a2a", built)
    code = main(["scan", str(built), "--format", "json", "--output", str(written), "--no-telemetry"])
    assert code == expect["exit_code"] == 0 and check._check_report(expect, json.loads(written.read_text())) == []
