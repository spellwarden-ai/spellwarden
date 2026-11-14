"""The current release is 1.14.0, which adds `spellwarden scan --user` (the agent clients' configuration in a home directory,
with an opt-in workstation upload) and `--format cyclonedx` without changing a rule (1.13.0 widened the MCP probe to prompts, resources, resource templates and server instructions, tags every rule with MITRE ATLAS and OWASP Agentic Skills Top 10 ids and finds instruction files (1.12.0 added steering and concealment forms to SW-MCP-011 beside 1.11.1's unchanged patterns; 1.11.1 set TLS 1.2 as the minimum of the CLI's own connections and closed the code scanning alerts without changing a result; 1.11.0 made SW-MCP-011 read collapsed whitespace and need the words that aim each pattern at the model or the user; 1.10.0 scoped the archive limits of `unpack_zip(root=...)` to the entries under the root and added `scan_skill_package(kind="instructions")`; 1.9.1 tagged each rule with the OWASP MCP Top Ten entry it detects; 1.9.0 graded severities for SW-MCP-001 and SW-MCP-011 and read whole streamed answers in the probe; 1.8.1 was linear skill discovery, 1.8.0 was the rule batch of five new rules, SW-SKL-032, SW-SKL-036, SW-SKL-037, SW-CFG-012, SW-CFG-013; 1.7.1 was a faster OTLP protobuf reader, 1.7.0 added the OTLP decoder and normaliser `spellwarden_scan.otel` and the command `spellwarden otel normalise`; 1.6.0 added the Zuplo export target; 1.5.0 read the snake-case spellings of 0.x agent card members; 1.4.0 added SW-A2A-019, 1.3.0
was the O4 agent card release)). The package metadata says the same version as the code. The rules version is 2026.11.6 because
SW-MCP-011 reads more places and every rule carries two more kinds of tag (2026.11.5 added forms to SW-MCP-011; 2026.11.4 narrowed SW-MCP-011; 2026.11.3 changed sixteen rules' and three enforcement rules' OWASP MCP tags; 65 rules in all, as since 1.8.0, when the baseline gained five).
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_versions():
    assert __version__ == "1.14.0"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert RULES_VERSION == "2026.11.6"
    assert len(RuleSet.baseline()) == 65
