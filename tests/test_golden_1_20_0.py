"""1.21.0 (P6-15 fix guidance spec 6.12 E-7, 6.13): for every fixture root, the seven reports are the released 1.20.0's byte for
byte, with the same exit code, once `golden_fix.before_fix_guidance` has taken out what 1.21.0 adds (the fix sentences, the pages,
the setting lines, the "How to fix" sections, SARIF `help` and CycloneDX `recommendation`) and set the two corrected rule links
back to the upper-case id, and the scanner's version is set back where a report prints it (a CycloneDX document's `serialNumber`
is left out). tests/golden/record_release_1_20_0.py recorded the digests from the tag v1.20.0; this test runs offline on Linux
and Windows."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from golden_fix import before_fix_guidance

from spellwarden_scan import __version__

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("record_release_1_20_0", ROOT / "tests" / "golden" / "record_release_1_20_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
RECORDED_PATH = record.GOLDEN / "outputs.json"


def _recorded() -> dict:
    return json.loads(RECORDED_PATH.read_text(encoding="utf-8"))


def _roots() -> list[str]:
    # 1.22.0 (P6-4 spec 6.9): the fixture whose reports normalisation changes is skipped; the record keeps it
    if not RECORDED_PATH.exists():
        return ["(not recorded)"]
    return sorted(set(_recorded()["roots"]) - set(record.reports.FIXTURES_CHANGED_IN_1_22_0))


def test_the_record_is_the_release_and_covers_every_fixture_root():
    recorded = _recorded()
    assert (recorded["scanner_version"], recorded["release_tag"], recorded["as_of"]) == ("1.20.0", "v1.20.0", record.reports.AS_OF)
    assert set(recorded["roots"]) == set(record.scan_roots()) - set(record.ADDED_AFTER_1_20_0)
    formats = {fmt for fmt, _ in record.reports.ALL_FORMATS}
    assert all(set(entry["outputs"]) == formats for entry in recorded["roots"].values())


@pytest.mark.parametrize("root", _roots())
def test_each_report_is_the_1_20_0_report_but_for_the_fix_guidance(root, tmp_path):
    expected = _recorded()["roots"][root]
    code, outputs = record.reports.render(record.reports.build_repo(root, tmp_path / "repo"), tmp_path / "out",
                                          formats=record.reports.ALL_FORMATS)
    got = {fmt: record.digest(record.reports.as_version(fmt, before_fix_guidance(fmt, data), __version__, record.RECORDED_VERSION))
           for fmt, data in outputs.items()}
    assert code == expected["exit_code"]
    assert got == expected["outputs"]
