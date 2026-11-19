"""1.19.0: a scan without `--staged` writes, for every fixture root, the reports the released 1.18.0 writes, byte for byte
in its seven formats, once the scanner's version is set back to 1.18.0 where a report prints it (and a CycloneDX document's
`serialNumber`, a digest of the whole document, is left out), with the same exit code. tests/golden/record_release_1_18_0.py
recorded the digests from the tag v1.18.0; this test runs offline on Linux and Windows."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from spellwarden_scan import __version__

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("record_release_1_18_0", ROOT / "tests" / "golden" / "record_release_1_18_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
RECORDED_PATH = record.GOLDEN / "outputs.json"


def _recorded() -> dict:
    return json.loads(RECORDED_PATH.read_text(encoding="utf-8"))


def _roots() -> list[str]:
    return sorted(_recorded()["roots"]) if RECORDED_PATH.exists() else ["(not recorded)"]


def test_the_record_is_the_release_and_covers_every_fixture_root():
    recorded = _recorded()
    assert (recorded["scanner_version"], recorded["release_tag"], recorded["as_of"]) == ("1.18.0", "v1.18.0", record.reports.AS_OF)
    assert set(recorded["roots"]) == set(record.scan_roots()) - set(record.ADDED_AFTER_1_18_0)
    assert {"fixtures/html-escape", "fixtures/presets", "fixtures/repos/preset/repo"} <= set(recorded["roots"])
    formats = {fmt for fmt, _ in record.reports.ALL_FORMATS}
    assert all(set(entry["outputs"]) == formats for entry in recorded["roots"].values())


@pytest.mark.parametrize("root", _roots())
def test_without_staged_every_report_is_the_1_18_0_report_but_for_the_version(root, tmp_path):
    expected = _recorded()["roots"][root]
    code, outputs = record.reports.render(record.reports.build_repo(root, tmp_path / "repo"), tmp_path / "out",
                                          formats=record.reports.ALL_FORMATS)
    got = {fmt: record.digest(record.reports.as_version(fmt, data, __version__, record.RECORDED_VERSION))
           for fmt, data in outputs.items()}
    assert code == expected["exit_code"]
    assert got == expected["outputs"]
