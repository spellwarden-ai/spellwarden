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
