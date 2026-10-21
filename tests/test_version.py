"""Spec 5.1 (Phase C): the current release is 1.1.0, an engine release that only adds names (org rules, packs,
exports, tool input schemas). It keeps the rules version of 0.3.0 and 1.0.0, because no baseline rule changed what it
detects, and the package metadata says the same version as the code."""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_c1_versions():
    assert __version__ == "1.1.0"
    assert RULES_VERSION == "2026.10.2"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert len(RuleSet.baseline()) == 38
