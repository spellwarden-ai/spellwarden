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

from spellwarden_scan import RULES_VERSION, __version__

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "1.0.0"
_spec = importlib.util.spec_from_file_location("record_1_0_0", ROOT / "tests" / "golden" / "record_1_0_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)


def _schema(name: str) -> dict:
    return json.loads((GOLDEN / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


CURRENT_RULE_ID = "^SW-(SKL|MCP|CFG|REG|A2A|ORG)-[0-9]{3}$"


def _plus_additions(schema):
    """The frozen schema with every `additionalProperties: false` and `unevaluatedProperties: false` removed and the
    rule-id grammar widened to the current one (SW-REG came in 1.2.0, SW-A2A in 1.3.0: a new rule is an addition the
    README allows in a minor release, O4 spec 6.11): a later release may add optional fields (6.14), never remove or
    change one."""
    schema = copy.deepcopy(schema)

    def walk(node):
        if isinstance(node, dict):
            for key in ("additionalProperties", "unevaluatedProperties"):
                if node.get(key) is False:
                    del node[key]
            rule_id = node.get("rule_id")
            if isinstance(rule_id, dict) and "pattern" in rule_id:
                rule_id["pattern"] = CURRENT_RULE_ID
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


# Phase C, claim E10 and O3 invariant 1, claim E4: a free-mode scan of the 1.0.0 golden repository differs from the
# recorded 1.0.0 reports in exactly the places each names the scanner version, plus the four normalised differences of
# the connected release (P5, P32): the `rules_version` value, the three SW-REG descriptors of the SARIF rule table, the
# `ruleIndex` of every SARIF result (renumbered through the table with those three removed), and the three added lines
# of `spellwarden rules` (pinned by tests/cli/test_rules_unchanged.py: the golden set holds no `rules` output). The JSON
# report embeds no skill result, so it gains no `package_sha256` and no `connected` key.
_VERSION_MARKERS = {"report.json": '"scanner_version": "{v}"', "report.sarif": '"semanticVersion": "{v}"',
                    "report.md": "Spellwarden {v}, rules "}
_RULES_VERSION_MARKERS = {"report.json": '"rules_version": "{r}"', "report.md": ", rules {r}."}
RECORDED_RULES_VERSION = "2026.10.2"
REGISTRY_IDS = ("SW-REG-001", "SW-REG-002", "SW-REG-003")
# O4 spec invariant 4: the eighteen A2A descriptors sort before SW-CFG, so every existing `ruleIndex` moves by eighteen.
A2A_IDS = tuple(f"SW-A2A-{number:03d}" for number in range(1, 19))
ADDED_IDS = (*REGISTRY_IDS, *A2A_IDS)


def _normalised_sarif(text: str, *, produced: bool) -> dict:
    """The SARIF document with the descriptors of the rules added since 1.0.0 (the three registry rules and the eighteen
    A2A rules) removed and every `ruleIndex` remapped through the reduced table; the version is put back to the recorded one."""
    document = json.loads(text)
    driver = document["runs"][0]["tool"]["driver"]
    if produced:
        assert driver["semanticVersion"] == __version__
        driver["semanticVersion"] = "1.0.0"
        table = driver["rules"]
        assert [r["id"] for r in table] == sorted(r["id"] for r in table)
        kept = [r for r in table if r["id"] not in ADDED_IDS]
        assert len(table) - len(kept) == 21
        new_index = {old: kept.index(rule) for old, rule in enumerate(table) if rule in kept}
        for result in document["runs"][0]["results"]:
            assert result["ruleIndex"] in new_index, result
            result["ruleIndex"] = new_index[result["ruleIndex"]]
        driver["rules"] = kept
    return document


@pytest.mark.skipif(__version__ == "1.0.0", reason="1.0.0 compares the bytes as they are")
def test_reports_differ_from_the_recorded_ones_only_in_the_normalised_differences(fresh):
    for _fmt, name in record.OUTPUTS:
        recorded = (GOLDEN / "out" / name).read_bytes().decode("utf-8")
        produced = (fresh[1] / name).read_bytes().decode("utf-8")
        if name == "report.sarif":
            assert _normalised_sarif(produced, produced=True) == _normalised_sarif(recorded, produced=False)
            continue
        for markers, now, then in ((_VERSION_MARKERS, __version__, "1.0.0"),
                                   (_RULES_VERSION_MARKERS, RULES_VERSION, RECORDED_RULES_VERSION)):
            marker = markers.get(name)
            if marker is not None:
                assert recorded.count(marker.format(v=then, r=then)) == 1, name
                assert produced.count(marker.format(v=now, r=now)) == 1, name
                produced = produced.replace(marker.format(v=now, r=now), marker.format(v=then, r=then))
        assert produced == recorded, name


def test_the_free_mode_report_has_no_connected_key_and_no_package_hash(fresh):
    report = json.loads((fresh[1] / "report.json").read_text(encoding="utf-8"))
    assert "connected" not in report and "package_sha256" not in json.dumps(report)
    assert not any(f["rule_id"].startswith("SW-REG-") for f in report["findings"])


def _required_fields(schema, path=()) -> set[tuple]:
    """Every `(path, name)` the schema requires, at any depth."""
    found: set[tuple] = set()
    if isinstance(schema, dict):
        for name in schema.get("required", ()) if isinstance(schema.get("required"), list) else ():
            found.add((path, name))
        for key, value in schema.items():
            found |= _required_fields(value, path + (key,))
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            found |= _required_fields(value, path + (index,))
    return found


def _current_schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


def test_1_0_0_reports_validate_against_the_1_2_0_schemas():
    _validate(json.loads((GOLDEN / "out" / "report.json").read_text(encoding="utf-8")), _current_schema("report"))


@pytest.mark.parametrize("name", ["settings", "baseline", "lock"])
def test_1_2_0_input_schemas_require_no_more_than_1_0_0_did(name):
    assert _required_fields(_current_schema(name)) <= _required_fields(_schema(name))


def test_1_2_0_report_schema_keeps_every_1_0_0_required_field():
    assert _required_fields(_schema("report")) <= _required_fields(_current_schema("report"))


def test_1_0_0_input_files_validate_against_the_1_2_0_input_schemas():
    state = GOLDEN / "repo" / ".spellwarden"
    as_json = lambda data: json.loads(json.dumps(data, default=str))  # noqa: E731
    _validate(as_json(yaml.safe_load((state / "config.yml").read_text(encoding="utf-8"))), _current_schema("settings"))
    _validate(as_json(yaml.safe_load((state / "baseline.yml").read_text(encoding="utf-8"))), _current_schema("baseline"))
    _validate(json.loads((state / "lock.json").read_text(encoding="utf-8")), _current_schema("lock"))


def test_c1_a_report_of_a_repository_with_agent_cards_validates_against_the_1_0_0_schema_plus_additions(tmp_path):
    """O4 claim C1: the card fixture repository (an unsigned 0.3 card, a card with plain HTTP and a look-alike file) gives
    SW-A2A findings, an `agents` list and a notice; the frozen schema accepts all of it once its rule-id pattern is widened."""
    from spellwarden_cli.main import main

    files = {
        "legacy/agent-card.json": json.dumps({"protocolVersion": "0.3.0", "name": "Legacy", "url": "https://legacy.example.com/a2a",
                                              "version": "1", "skills": []}),
        "public/.well-known/agent-card.json": json.dumps({
            "name": "Http", "description": "d", "version": "1", "capabilities": {},
            "supportedInterfaces": [{"url": "http://agent.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "s", "name": "n", "description": "d", "tags": ["t"]}]}),
        "tools/.well-known/agent.json": "// not a card\n{}",
    }
    for relative, content in files.items():
        (tmp_path / "repo" / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "repo" / relative).write_text(content, encoding="utf-8")
    written = tmp_path / "report.json"
    code = main(["scan", str(tmp_path / "repo"), "--format", "json", "--output", str(written), "--no-telemetry"])
    report = json.loads(written.read_text(encoding="utf-8"))
    assert code == 1 and {f["rule_id"] for f in report["findings"]} >= {"SW-A2A-002", "SW-A2A-004", "SW-A2A-012"}
    assert len(report["agents"]) == 2 and "a2a_not_card" in {n["code"] for n in report["notices"]}
    _validate(report, _plus_additions(_schema("report")))
    with pytest.raises(AssertionError):  # without the widening the frozen pattern refuses an SW-A2A id
        _validate(report, _schema("report"))
