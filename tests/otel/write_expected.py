"""Writes `<body>.expected.json` next to every recorded body (spec 7.1): `uv run --locked python tests/otel/write_expected.py`.
Run it once when a recording is committed, then read the diff: the expected outputs are the claim E10 pins."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from otel_support import recorded_bodies  # noqa: E402
from test_recorded import actual, expected_path  # noqa: E402

if __name__ == "__main__":
    for body in recorded_bodies():
        expected_path(body).write_text(json.dumps(actual(body), indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        print(expected_path(body))
