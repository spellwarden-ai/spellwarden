"""The current release is 1.17.0, which adds the model-assisted analyzer (`spellwarden scan --analyze`, advisory and off by
default) and the description lint without changing a rule (1.16.2: `spellwarden lock` and `lock --check` exit 2 and write or confirm no lock when content was
left unread, the workstation upload counts each client's roots and the CI upload's field table names the instruction file fields,
without changing a rule (1.16.1: unread agent content no longer looks like a pass (an oversize repository file of agent
content and a `scan --user` link out of the home are errors, the probe follows `nextCursor`, and `--locked` compares a list with a
cut text) without changing a rule; 1.16.0: `spellwarden scan --user --upload` uploads before it writes its reports, every report
except a GitLab Code Quality file carries the upload's outcome, and the machine-wide scan reads VS Code's user and profile
`mcp.json` without changing a rule; 1.15.0
added SW-MCP-012 (a probed server's tools changed since they were approved, raised only with an
approved list), `spellwarden_scan.toolhash`, the lock file's probed tool pins and the ToolHive and Docker MCP Gateway exports (1.14.0
added `spellwarden scan --user` (the agent clients' configuration in a home directory,
with an opt-in workstation upload) and `--format cyclonedx` without changing a rule (1.13.0 widened the MCP probe to prompts, resources, resource templates and server instructions, tags every rule with MITRE ATLAS and OWASP Agentic Skills Top 10 ids and finds instruction files (1.12.0 added steering and concealment forms to SW-MCP-011 beside 1.11.1's unchanged patterns; 1.11.1 set TLS 1.2 as the minimum of the CLI's own connections and closed the code scanning alerts without changing a result; 1.11.0 made SW-MCP-011 read collapsed whitespace and need the words that aim each pattern at the model or the user; 1.10.0 scoped the archive limits of `unpack_zip(root=...)` to the entries under the root and added `scan_skill_package(kind="instructions")`; 1.9.1 tagged each rule with the OWASP MCP Top Ten entry it detects; 1.9.0 graded severities for SW-MCP-001 and SW-MCP-011 and read whole streamed answers in the probe; 1.8.1 was linear skill discovery, 1.8.0 was the rule batch of five new rules, SW-SKL-032, SW-SKL-036, SW-SKL-037, SW-CFG-012, SW-CFG-013; 1.7.1 was a faster OTLP protobuf reader, 1.7.0 added the OTLP decoder and normaliser `spellwarden_scan.otel` and the command `spellwarden otel normalise`; 1.6.0 added the Zuplo export target; 1.5.0 read the snake-case spellings of 0.x agent card members; 1.4.0 added SW-A2A-019, 1.3.0
was the O4 agent card release))))). The package metadata says the same version as the code. The rules version is 2026.11.7 because
SW-MCP-012 is new (66 rules) (2026.11.6: SW-MCP-011 reads more places and every rule carries two more kinds of tag; 2026.11.5 added forms to SW-MCP-011; 2026.11.4 narrowed SW-MCP-011; 2026.11.3 changed sixteen rules' and three enforcement rules' OWASP MCP tags; 65 rules in all, as since 1.8.0, when the baseline gained five).
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_versions():
    assert __version__ == "1.17.0"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert RULES_VERSION == "2026.11.7"
    assert len(RuleSet.baseline()) == 66


def test_the_changelog_has_the_1_16_0_entry_above_1_15_0():
    """Phase 3 batch 2c spec 11.4: the entry says what F1 and F2 change."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.16.0 (") < text.index("## 1.15.0 (")
    entry = " ".join(text[text.index("## 1.16.0 ("):text.index("## 1.15.0 (")].split())
    # 1.16.1 made the sentence say which format carries no outcome (review Low, batch 2c)
    for needle in ("`scan --user --upload` sends the upload before writing the reports",
                   "every report except a GitLab Code Quality file carries its outcome", "exit code 2 in each of them",
                   "it was printed on stderr only", "VS Code's user and profile `mcp.json` files",
                   "stable and Insiders, on Linux, macOS and Windows", "a run can find servers it did not read before"):
        assert needle in entry, needle


def test_the_changelog_has_the_1_16_1_entry_above_1_16_0():
    """1.16.1: the phase 3 review fixes (High 1 to 3, Medium 9)."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.16.1 (2026-11-16)") < text.index("## 1.16.0 (")
    entry = " ".join(text[text.index("## 1.16.1 ("):text.index("## 1.16.0 (")].split())
    for needle in ("Rules version 2026.11.7, unchanged", "`unreadable`", "`file_too_large`", "`symlink_skipped`", "`nextCursor`",
                   "`tools_not_compared`", "`probe_list_incomplete`", "exit 2", "exit 3"):
        assert needle in entry, needle


def test_the_changelog_has_the_1_16_2_entry_above_1_16_1():
    """1.16.2: the lock refuses unread content, `roots_total`, the field table's instruction file rows, the format checks."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.16.2 (2026-11-16)") < text.index("## 1.16.1 (")
    entry = " ".join(text[text.index("## 1.16.2 ("):text.index("## 1.16.1 (")].split())
    for needle in ("Rules version 2026.11.7, unchanged", "`spellwarden lock`", "`lock --check`", "exit 2", "exit 3",
                   "`roots_total`", "upload-fields.json", "`date-time`", "`iri-reference`"):
        assert needle in entry, needle


def test_the_changelog_has_the_1_17_0_entry_above_1_16_2():
    """1.17.0 (Phase 4 batch B spec 11.7): the analyzer and the description lint. No measured rate is published with this
    release, and one line says so."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.17.0 (2026-11-17)") < text.index("## 1.16.2 (")
    raw = text[text.index("## 1.17.0 ("):text.index("## 1.16.2 (")]
    entry = " ".join(raw.split())
    for needle in ("Rules version 2026.11.7, unchanged",
                   "1.17.0: an optional model-assisted analyzer (`--analyze`) that sends a skill's SKILL.md and scripts to an "
                   "OpenAI-compatible endpoint you name, with your key from `SPELLWARDEN_MODEL_KEY`, and reports advisory, "
                   "model-assisted findings with quoted spans; never changes the exit code. A description lint (SW-LINT-001 to "
                   "SW-LINT-004), informational.",
                   "`analysis_incomplete`", "`model_assisted`", "`description_lint`",
                   "the rule count stays 66", "`SkillScanResult.lint`", "fifth module"):
        assert needle in entry, needle
    assert "filled before the release" not in text and raw.count("\nMeasured rates: ") == 1
    assert 'Measured rates: none are published for analyzer version 1 yet, so every result says "Unmeasured model".' in entry
