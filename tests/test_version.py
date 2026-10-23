"""O3 spec 7: the current release is 1.2.0, the connected-mode release of the 1.1 engine. Its rules version is 2026.10.3
because the baseline gains the three registry gate rules, which no scan emits; the 38 detection rules are those of
1.0.0, and the package metadata says the same version as the code."""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_o3_versions():
    assert __version__ == "1.2.0"
    assert RULES_VERSION == "2026.10.3"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert len(RuleSet.baseline()) == 41
