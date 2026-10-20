"""Spec 6.14: the files and reports of 1.0.0 are a contract. Every later release must still read the 1.0.0 lock,
baseline and settings files, and must produce reports that validate against the 1.0.0 schemas plus additions.
While the version is 1.0.0 the reports are byte-identical to the recorded ones."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest
import yaml
from conftest import _RUNNER_VARIABLES

from spellwarden_scan import __version__

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "1.0.0"
_spec = importlib.util.spec_from_file_location("record_1_0_0", ROOT / "tests" / "golden" / "record_1_0_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)


def _schema(name: str) -> dict:
    return json.loads((GOLDEN / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


def _plus_additions(schema):
    """The frozen schema with every `additionalProperties: false` and `unevaluatedProperties: false` removed:
    a later release may add optional fields (6.14), never remove or change one."""
    schema = copy.deepcopy(schema)

    def walk(node):
        if isinstance(node, dict):
            for key in ("additionalProperties", "unevaluatedProperties"):
                if node.get(key) is False:
                    del node[key]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
    return schema


def _validate(document, schema) -> None:
    validator = jsonschema.validators.validator_for(schema)(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    assert not errors, [f"{list(e.absolute_path)}: {e.message}" for e in errors[:10]]


@pytest.fixture(scope="module")
def fresh(tmp_path_factory):
    # A module-scoped fixture runs before the function-scoped autouse one that removes the CI variables, so it
    # removes them itself: on a pull request in CI the scan would read the settings and the baseline from the base
    # revision (spec 6.3) instead of the golden repository's own.
    base = tmp_path_factory.mktemp("golden")
    out = base / "out"
    out.mkdir()
    with pytest.MonkeyPatch.context() as patch:
        for name in _RUNNER_VARIABLES:
            patch.delenv(name, raising=False)
        code = record.scan(record.build_repo(base / "repo"), out)
    return code, out


def test_this_release_reads_the_1_0_0_inputs(fresh):
    code, out = fresh
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["errors"] == []
    assert report["lock"]["status"] == "ok", report["lock"]
    assert code == report["exit_code"] == 1
    accepted = [f for f in report["findings"] if f["suppressed"]]
    assert [f["rule_id"] for f in accepted] == ["SW-CFG-001"]
    assert accepted[0]["baseline"] == {"reason": "Internal test server on the private staging network.",
                                       "added": "2027-01-10", "expires": "2027-04-10"}
    assert not any(f["location"]["path"].startswith("docs/") for f in report["findings"])


def test_the_1_0_0_input_files_validate_against_their_frozen_schemas():
    state = GOLDEN / "repo" / ".spellwarden"
    as_json = lambda data: json.loads(json.dumps(data, default=str))  # noqa: E731 (YAML dates become ISO strings)
    _validate(as_json(yaml.safe_load((state / "config.yml").read_text(encoding="utf-8"))), _schema("settings"))
    _validate(as_json(yaml.safe_load((state / "baseline.yml").read_text(encoding="utf-8"))), _schema("baseline"))
    _validate(json.loads((state / "lock.json").read_text(encoding="utf-8")), _schema("lock"))


@pytest.mark.parametrize("which", ["recorded", "fresh"])
def test_reports_validate_against_the_frozen_report_schema_plus_additions(fresh, which):
    out = GOLDEN / "out" if which == "recorded" else fresh[1]
    _validate(json.loads((out / "report.json").read_text(encoding="utf-8")), _plus_additions(_schema("report")))


def test_the_fresh_sarif_validates_against_the_full_sarif_schema(fresh):
    schema = json.loads((ROOT / "tests" / "schemas" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    _validate(json.loads((fresh[1] / "report.sarif").read_text(encoding="utf-8")), schema)


@pytest.mark.skipif(__version__ != "1.0.0", reason="byte equality is the 1.0.0 release's own promise")
def test_reports_are_byte_identical_to_the_recorded_ones(fresh):
    for _fmt, name in record.OUTPUTS:
        assert (fresh[1] / name).read_bytes() == (GOLDEN / "out" / name).read_bytes(), name


@pytest.mark.skipif(__version__ != "1.0.0", reason="the frozen schemas are the 1.0.0 schemas")
def test_the_frozen_schemas_are_this_release_s():
    for name in record.SCHEMAS:
        frozen = (GOLDEN / "schemas" / f"{name}.schema.json").read_bytes()
        assert frozen == (ROOT / "schemas" / f"{name}.schema.json").read_bytes(), name
