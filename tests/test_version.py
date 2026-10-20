"""Spec 5.1: the O1 release is 0.3.0 with a new rules version (ten rules were added), and the package metadata says
the same version as the code."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_o1_versions():
    assert __version__ == "0.3.0"
    assert re.fullmatch(r"20\d\d\.(0[1-9]|1[0-2])\.[1-9]\d*", RULES_VERSION) and RULES_VERSION != "2026.10.1"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert len(RuleSet.baseline()) == 38
