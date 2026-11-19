"""1.18.0: the JSON reports of fixtures/presets under `strict` and `low-noise` are the recorded golden files (changing a row of
`presets.ROWS` changes them; record them again with tests/golden/record_1_18_0.py and review the diff)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("record_1_18_0", ROOT / "tests" / "golden" / "record_1_18_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)


@pytest.mark.parametrize("name", ["strict", "low-noise"])
def test_each_preset_report_of_the_fixture_is_the_recorded_one(name, tmp_path):
    golden = (record.GOLDEN / "presets" / f"{name}.json").read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    assert record.preset_report(tmp_path, name) == golden
    document = json.loads(golden)
    assert document["preset"]["name"] == name and document["preset"]["source"] == "flag"
    # no row of the table is stated here: the golden file is the statement, and a changed row records it again
    assert document["preset"]["changed"] == sum("preset_from" in entry for entry in document["findings"])
    assert [entry["code"] for entry in document["notices"]].count("preset") == 1
    assert document["scanner_version"] == record.STORED_VERSION
