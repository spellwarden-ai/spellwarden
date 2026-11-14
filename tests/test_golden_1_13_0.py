"""Phase 3 batch 2a spec 11.5 and T-8: a repository scan without `--format cyclonedx` gives the reports 1.13.0 gave, byte for
byte, apart from the scanner version each report names (recorded by tests/golden/record_1_13_0.py at 1.13.0)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from conftest import _RUNNER_VARIABLES

from spellwarden_scan import __version__

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "1.13.0"
_spec = importlib.util.spec_from_file_location("record_1_13_0", ROOT / "tests" / "golden" / "record_1_13_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)


@pytest.fixture(scope="module")
def fresh(tmp_path_factory):
    base = tmp_path_factory.mktemp("golden-1-13-0")
    out = base / "out"
    out.mkdir()
    with pytest.MonkeyPatch.context() as patch:  # the scan must read the golden repository's own baseline, as a local run
        for name in _RUNNER_VARIABLES:
            patch.delenv(name, raising=False)
        code = record.scan(record.build_repo(base / "repo"), out)
    return code, out


def test_the_scan_still_fails_on_its_findings(fresh):
    code, _ = fresh
    assert code == 1


@pytest.mark.parametrize("fmt, name", record.OUTPUTS)
def test_each_report_is_the_1_13_0_report_byte_for_byte(fresh, fmt, name):
    _, out = fresh
    produced = (out / name).read_bytes().decode("utf-8")
    recorded = (GOLDEN / "out" / name).read_bytes().decode("utf-8")
    assert record.as_recorded(produced, __version__) == recorded, f"the {fmt} report changed"
