"""Engine 1.20.0 (D45, C40a): `fixture_reports.as_version` sets the rules version back to the one a recorded release printed,
wherever a report prints it, and the golden tests of 1.17.0 and 1.18.0 leave out the two fixture homes whose files 1.20.0
changes, while their records keep them. `fixtures/selection` is a fixture root added after both records."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reports = _module("fixture_reports", ROOT / "tests" / "golden" / "fixture_reports.py")
NEW, OLD = "2026.11.8", "2026.11.7"


def test_the_rules_version_is_set_back_in_the_json_markdown_and_html_reports():
    data = f'{{"scanner_version": "1.20.0", "rules_version": "{NEW}"}}'.encode()
    assert reports.as_version("json", data, "1.20.0", "1.19.0", current_rules=NEW) == \
        f'{{"scanner_version": "1.19.0", "rules_version": "{OLD}"}}'.encode()
    data = f"Spellwarden 1.20.0, rules {NEW}. Generated on 2026-11-17.".encode()
    assert reports.as_version("markdown", data, "1.20.0", "1.18.0", current_rules=NEW) == \
        f"Spellwarden 1.18.0, rules {OLD}. Generated on 2026-11-17.".encode()
    data = f'<p class="meta">Spellwarden 1.20.0, rules {NEW}, as of 2026-11-17'.encode()
    assert reports.as_version("html", data, "1.20.0", "1.17.0", current_rules=NEW) == \
        f'<p class="meta">Spellwarden 1.17.0, rules {OLD}, as of 2026-11-17'.encode()


def test_the_rules_version_property_of_a_cyclonedx_document_is_set_back():
    document = {"serialNumber": "urn:uuid:x", "metadata": {
        "tools": {"components": [{"name": "Spellwarden", "version": "1.20.0"}]},
        "properties": [{"name": "spellwarden:mode", "value": "repository"}, {"name": "spellwarden:rules_version", "value": NEW}]}}
    back = json.loads(reports.as_version("cyclonedx", json.dumps(document).encode(), "1.20.0", "1.19.0", current_rules=NEW))
    assert "serialNumber" not in back
    assert back["metadata"]["tools"]["components"] == [{"name": "Spellwarden", "version": "1.19.0"}]
    assert back["metadata"]["properties"] == [{"name": "spellwarden:mode", "value": "repository"},
                                              {"name": "spellwarden:rules_version", "value": OLD}]


def test_a_target_that_is_no_recorded_release_or_the_same_rules_version_changes_nothing():
    data = f'"rules_version": "{NEW}"'.encode()
    assert reports.as_version("json", data, "1.20.0", "1.20.0", current_rules=NEW) == data
    data = f'"rules_version": "{OLD}"'.encode()
    assert reports.as_version("json", data, "1.19.0", "1.19.0", current_rules=OLD) == data
    assert reports.RECORDED_RULES == {"1.17.0": OLD, "1.18.0": OLD, "1.19.0": OLD}


def test_the_older_golden_tests_skip_the_fixture_homes_this_release_changes():
    assert reports.FIXTURES_CHANGED_IN_1_20_0 == ("tests/fixtures/homes/common", "tests/fixtures/homes/windows")
    for name in ("test_golden_1_17_0", "test_golden_1_18_0"):
        module = _module(f"{name}_for_skip", ROOT / "tests" / f"{name}.py")
        roots = module._roots()
        assert not set(roots) & set(reports.FIXTURES_CHANGED_IN_1_20_0), name
        assert {"tests/fixtures/homes/linux", "tests/fixtures/homes/macos"} <= set(roots), name
        assert set(reports.FIXTURES_CHANGED_IN_1_20_0) <= set(module._recorded()["roots"]), name  # the records keep them


def test_the_older_golden_tests_skip_the_fixture_whose_reports_1_22_0_changes():
    """P6-4 spec 6.9: the normalised reading adds SW-SKL-007 to one fixture; the four release records keep it, their tests skip it."""
    assert reports.FIXTURES_CHANGED_IN_1_22_0 == ("fixtures/skills/SW-SKL-032/positive",)
    for name in ("test_golden_1_17_0", "test_golden_1_18_0", "test_golden_1_19_0", "test_golden_1_20_0"):
        module = _module(f"{name}_for_1_22_0_skip", ROOT / "tests" / f"{name}.py")
        assert not set(module._roots()) & set(reports.FIXTURES_CHANGED_IN_1_22_0), name
        assert "fixtures/skills/SW-SKL-032/negative" in module._roots(), name
        assert set(reports.FIXTURES_CHANGED_IN_1_22_0) <= set(module._recorded()["roots"]), name


def test_the_selection_fixture_is_a_root_added_after_both_records():
    record = _module("record_1_17_0_for_roots", ROOT / "tests" / "golden" / "record_1_17_0.py")
    release = _module("record_release_1_18_0_for_roots", ROOT / "tests" / "golden" / "record_release_1_18_0.py")
    assert "fixtures/selection" in record.ROOT_GLOBS
    assert "fixtures/selection" in record.ADDED_AFTER_1_17_0
    assert release.ADDED_AFTER_1_18_0 == ("fixtures/selection", "fixtures/repos/follow-links/repo")
