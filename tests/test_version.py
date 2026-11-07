"""The current release is 1.9.0, graded severities for SW-MCP-001 and SW-MCP-011 and whole streamed answers in the probe (1.8.1 was linear skill discovery, 1.8.0 was the rule batch of five new rules, SW-SKL-032, SW-SKL-036, SW-SKL-037, SW-CFG-012, SW-CFG-013; 1.7.1 was a faster OTLP protobuf reader, 1.7.0 added the OTLP decoder and normaliser `spellwarden_scan.otel` and the command `spellwarden otel normalise`; 1.6.0 added the Zuplo export target; 1.5.0 read the snake_case spellings of 0.x agent card members; 1.4.0 added SW-A2A-019, 1.3.0
was the O4 agent card release). The package metadata says the same version as the code. The rules version is 2026.11.2 because
two rules grade their severity (65 rules in all, as since 1.8.0, when the baseline gained five).
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_versions():
    assert __version__ == "1.9.0"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert RULES_VERSION == "2026.11.2"
    assert len(RuleSet.baseline()) == 65
