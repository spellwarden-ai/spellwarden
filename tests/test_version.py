"""O4 spec 7: the current release is 1.3.0, the agent card release of the 1.2 engine. The package metadata says the same version
as the code. (Task 4 of the O4 plan moves the rules version and the rule count when the eighteen A2A rules join the baseline.)"""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_o4_versions():
    assert __version__ == "1.3.0"
    assert RULES_VERSION == "2026.10.3"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert len(RuleSet.baseline()) == 41
