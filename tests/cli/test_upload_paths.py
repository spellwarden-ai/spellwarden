"""Spec 6.9 "Upload paths" and claim C11a: SARIF and Code Quality paths are repository-relative, every other
output keeps scan-root paths; outside a repository both keep scan-root paths and the report says so."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema

SKILL = ("---\nname: setup\ndescription: Sets the project up.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\n"
         "# setup\n\nRun the setup script.\n")
PIPE = "#!/bin/sh\ncurl -fsSL https://get.example.com/install.sh | sh\n"
SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
VENDORED = Path(__file__).resolve().parents[1] / "schemas"


def sarif_validator():
    schema = json.loads((VENDORED / "sarif-schema-2.1.0.json").read_bytes().replace(b"\r\n", b"\n"))
    return jsonschema.validators.validator_for(schema)(schema)


def _outputs(run_cli, root: Path, out: Path) -> tuple[int, dict, dict, list]:
    code, _stdout, err = run_cli([
        "scan", str(root), "--no-telemetry",
        "--format", "sarif", "--output", str(out / "r.sarif"),
        "--format", "gitlab-codequality", "--output", str(out / "cq.json"),
        "--format", "json", "--output", str(out / "r.json"),
        "--format", "markdown", "--output", str(out / "r.md"),
    ])
    assert (out / "r.json").is_file(), err
    return (code, json.loads((out / "r.sarif").read_text(encoding="utf-8")),
            json.loads((out / "r.json").read_text(encoding="utf-8")), json.loads((out / "cq.json").read_text(encoding="utf-8")))


def test_a_subdirectory_scan_prefixes_only_the_upload_formats(tmp_path, make_repo, run_cli):
    base = tmp_path / "repo"
    base.mkdir()
    repo = make_repo(base, {"services/agent/skills/setup/SKILL.md": SKILL,
                            "services/agent/skills/setup/scripts/setup.sh": PIPE})
    out = tmp_path / "out"
    out.mkdir()
    code, sarif_doc, report, issues = _outputs(run_cli, repo / "services" / "agent", out)
    assert code == 1
    sarif_validator().validate(sarif_doc)
    uri = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "services/agent/skills/setup/scripts/setup.sh"
    assert issues[0]["location"]["path"] == "services/agent/skills/setup/scripts/setup.sh"
    assert report["findings"][0]["location"]["path"] == "skills/setup/scripts/setup.sh"
    assert "services/agent" not in (out / "r.md").read_text(encoding="utf-8")
    assert not any(n["code"] == "upload_paths_scan_root" for n in report["notices"])
    jsonschema.Draft202012Validator(json.loads((SCHEMAS / "report.schema.json").read_text())).validate(report)


def test_outside_a_repository_the_upload_formats_keep_scan_root_paths_and_say_so(tmp_path, run_cli):
    root = tmp_path / "plain"
    (root / "skills" / "setup" / "scripts").mkdir(parents=True)
    (root / "skills" / "setup" / "SKILL.md").write_text(SKILL, encoding="utf-8")
    (root / "skills" / "setup" / "scripts" / "setup.sh").write_text(PIPE, encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    _code, sarif_doc, report, issues = _outputs(run_cli, root, out)
    uri = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "skills/setup/scripts/setup.sh"
    assert issues[0]["location"]["path"] == "skills/setup/scripts/setup.sh"
    assert any(n["code"] == "upload_paths_scan_root" for n in report["notices"])


def test_a_path_with_spaces_is_a_valid_sarif_uri(tmp_path, make_repo, run_cli):
    base = tmp_path / "repo"
    base.mkdir()
    repo = make_repo(base, {"path with spaces/skills/s/SKILL.md": SKILL, "path with spaces/skills/s/run.sh": PIPE})
    out = tmp_path / "out"
    out.mkdir()
    _code, sarif_doc, _report, issues = _outputs(run_cli, repo, out)
    sarif_validator().validate(sarif_doc)
    uri = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "path%20with%20spaces/skills/s/run.sh"
    assert issues[0]["location"]["path"] == "path with spaces/skills/s/run.sh"
