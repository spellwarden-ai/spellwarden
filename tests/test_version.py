"""The current release is 1.8.0, the rule batch of nine new rules (SW-SKL-032 to 037, SW-CFG-012 to 014; 1.7.1 was a faster OTLP protobuf reader, 1.7.0 added the OTLP decoder and normaliser `spellwarden_scan.otel` and the command `spellwarden otel normalise`; 1.6.0 added the Zuplo export target; 1.5.0 read the snake_case spellings of 0.x agent card members; 1.4.0 added SW-A2A-019, 1.3.0
was the O4 agent card release). The package metadata says the same version as the code. The rules version is 2026.11.1 because
the baseline gained nine rules (69 rules in all; a new rule is a minor version, README "Compatibility").
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_versions():
    assert __version__ == "1.8.0"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert RULES_VERSION == "2026.11.1"
    assert len(RuleSet.baseline()) == 69
