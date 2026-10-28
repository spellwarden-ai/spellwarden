"""Claim E10: each recording of the release gate (spec 7.1) normalises to its committed expected output,
`<body>.expected.json`, written by `tests/otel/write_expected.py`."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from otel_support import recorded_bodies, recorded_encoding, recorded_signal
from spellwarden_scan.otel import decode, normalise

BODIES = recorded_bodies()


def expected_path(body: Path) -> Path:
    return body.with_name(body.name + ".expected.json")


def actual(body: Path) -> dict:
    request = decode(body.read_bytes(), signal=recorded_signal(body), encoding=recorded_encoding(body))
    return normalise(request, content=True).to_dict(content=True)


@pytest.mark.skipif(not BODIES, reason="no recordings yet: the release gate (spec 7.1) adds them")
@pytest.mark.parametrize("body", BODIES, ids=[path.name for path in BODIES])
def test_a_recording_normalises_to_its_expected_output(body):
    assert actual(body) == json.loads(expected_path(body).read_text(encoding="utf-8"))


def test_every_expected_output_has_its_recording():
    root = Path(__file__).resolve().parents[1] / "fixtures" / "otel" / "recorded"
    for path in root.rglob("*.expected.json"):
        assert path.with_name(path.name[: -len(".expected.json")]).exists(), path
