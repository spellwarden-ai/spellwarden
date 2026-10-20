"""Spec 5.1: the current release is 1.0.0, which keeps the rules version of 0.3.0 (ten rules were added there, none since),
and the package metadata says the same version as the code."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_o1_versions():
    assert __version__ == "1.0.0"
    assert re.fullmatch(r"20\d\d\.(0[1-9]|1[0-2])\.[1-9]\d*", RULES_VERSION) and RULES_VERSION != "2026.10.1"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert len(RuleSet.baseline()) == 38
