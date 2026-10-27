"""The current release is 1.5.0, which reads the snake_case spellings of 0.x agent card members (1.4.0 added SW-A2A-019, 1.3.0
was the O4 agent card release). The package metadata says the same version as the code. The rules version is 2026.10.6 because
what the A2A rules detect changed (still 60 rules; a change to what a rule detects is a minor version, README "Compatibility").
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_versions():
    assert __version__ == "1.5.0"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert RULES_VERSION == "2026.10.6"
    assert len(RuleSet.baseline()) == 60
