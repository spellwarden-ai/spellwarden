"""1.22.0 (P6-4 spec 6.9): the seven reports of `fixtures/skills/SW-SKL-032/positive` are the recorded golden files
(tests/golden/record_1_22_0.py; record them again after a change and review the diff). It is the one fixture whose findings the
normalised reading changes: SW-SKL-007 is added at line 26, its evidence starts with "Matched after normalising: " and its
fingerprint is computed from the line as written; every finding of 1.21.0 is there unchanged."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from spellwarden_scan.evidence import fingerprint

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("record_1_22_0", ROOT / "tests" / "golden" / "record_1_22_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)


@pytest.fixture(scope="module")
def produced(tmp_path_factory):
    return record.outputs(tmp_path_factory.mktemp("disguised"))


def _golden(name: str) -> str:
    return (record.GOLDEN / name).read_bytes().replace(b"\r\n", b"\n").decode("utf-8")


@pytest.mark.parametrize("name", [name for _, name in record.reports.ALL_FORMATS])
def test_each_report_is_the_recorded_one(produced, name):
    code, written = produced
    assert code == 1
    assert written[name] == _golden(name), name


def test_the_added_finding_quotes_line_26_as_written(produced):
    _, written = produced
    findings = json.loads(written["report.json"])["findings"]
    assert sorted((f["rule_id"], f["location"]["line"]) for f in findings) == [
        ("SW-SKL-004", 26), ("SW-SKL-007", 26), ("SW-SKL-032", 16), ("SW-SKL-032", 17), ("SW-SKL-032", 21), ("SW-SKL-032", 26)]
    line = (ROOT / record.FIXTURE / "SKILL.md").read_text(encoding="utf-8").splitlines()[25]
    (added,) = [f for f in findings if f["rule_id"] == "SW-SKL-007"]
    assert added["evidence"].startswith("Matched after normalising: echo '")
    assert added["fingerprint"] == fingerprint("SW-SKL-007", "SKILL.md", line)
    assert not [f for f in findings if f["rule_id"] != "SW-SKL-007" and f["evidence"].startswith("Matched after normalising: ")]
