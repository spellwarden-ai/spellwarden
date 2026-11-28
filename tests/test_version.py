"""The current release is 1.28.0, in which an executable file read as Markdown whose first line starts with `#!` is read as a script
and the command's reports group the findings in tests and fixtures (rules version 2026.11.12, 68 rules); 1.27.0 made SW-SKL-010 report
binary content only, read a readable text file listed as executable as a script and added `in_tests_or_fixtures` (rules version
2026.11.11); 1.26.0 links the Markdown report back to
the rule pages and the dashboard without changing a rule
(rules version 2026.11.10, unchanged); 1.25.0 adds two rules (rules version 2026.11.10; P6-9); 1.24.0 makes the normalised scan faster and ends a scan that reaches a time limit incomplete
(`--time-limit`, `Deadline`, `TimeLimit`), without changing a rule (rules version 2026.11.9, unchanged); 1.23.0 reads an archive's
links inside the scanned tree, measures the path bound on the path
in the repository, bounds an archive's entries and makes the command's link out of the scan root an error, without changing a
rule (rules version 2026.11.9, unchanged); 1.22.0 made skill rules also read a normalised copy of the text and the rules read text
up to 10 MiB (rules version 2026.11.9); 1.21.0 gives every finding its rule's fix sentence and page without changing a rule; 1.20.0 reads more of the agent files the vendors document and makes SW-CFG-012 and SW-CFG-013 judge
the servers of settings documents (rules version 2026.11.8); 1.19.0 added `spellwarden scan --staged` (the pre-commit hook runs it), limits on SKILL.md
front matter and the analyzer's span rule without changing a rule (1.18.0 added a pre-commit hook definition, the HTML report
and presets without changing a rule). 1.17.0 added the model-assisted analyzer (`spellwarden scan --analyze`, advisory and off by
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
was the O4 agent card release))))). The package metadata says the same version as the code. The rules version is 2026.11.9 because skill rules also read a normalised copy of the text (66 rules) (2026.11.8: SW-CFG-012 and SW-CFG-013 read settings documents; 2026.11.7: SW-MCP-012 is new; 2026.11.6: SW-MCP-011 reads more places and every rule carries two more kinds of tag; 2026.11.5 added forms to SW-MCP-011; 2026.11.4 narrowed SW-MCP-011; 2026.11.3 changed sixteen rules' and three enforcement rules' OWASP MCP tags; 65 rules in all, as since 1.8.0, when the baseline gained five).
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_versions():
    assert __version__ == "1.28.0"
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"] == __version__
    assert RULES_VERSION == "2026.11.12"
    assert len(RuleSet.baseline()) == 68


def test_the_rules_version_parses_as_three_integers_and_follows_2026_11_9_in_numeric_order():
    """D11 (P6-9 spec 8.12): `2026.11.10` sorts before `2026.11.9` as text and after it as numbers. The one place the command
    compares two rules versions is `connected._version`, which reads each part as an integer."""
    from spellwarden_cli.connected import _version

    parts = tuple(int(part) for part in RULES_VERSION.split("."))
    assert len(parts) == 3 and parts > (2026, 11, 9)
    assert _version(RULES_VERSION) > _version("2026.11.9") and RULES_VERSION < "2026.11.9"


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


def test_the_changelog_has_the_1_18_0_entry_above_1_17_0():
    """1.18.0: the hook, the HTML report and presets; nothing changes without a preset; the table is published by reference."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.18.0 (") < text.index("## 1.17.0 (2026-11-17)")
    raw = text[text.index("## 1.18.0 ("):text.index("## 1.17.0 (")]
    entry = " ".join(raw.split())
    for needle in ("Rules version 2026.11.7, unchanged (66 rules)",
                   "1.18.0: added a pre-commit hook definition (`.pre-commit-hooks.yaml`), the HTML report (`--format html`), "
                   "presets (`--preset strict|balanced|low-noise`, the `preset` setting and `SPELLWARDEN_PRESET`) with the rule "
                   "table. Unchanged: every output and exit code of a scan without a preset or with `balanced`; the rules and "
                   "their versions (`RULES_VERSION` 2026.11.7).",
                   "README's \"Presets\"", "`spellwarden rules --preset NAME`", "`preset_from`", "`SW_PRESET`",
                   "v1.17.0", "Linux and Windows",
                   "The scan covers the whole repository and never uploads, and its exit code is the scanner's. Outside CI a "
                   "hook run sends no usage ping; in CI its scan sends the usage ping like any scan in CI, and `--no-telemetry` "
                   "in the hook's `args`, or any other switch in the README's \"The usage ping\", turns it off."):
        assert needle in entry, needle
    assert "never uploads and sends no usage ping" not in entry
    assert ("The HTML report: `--format html` writes one self-contained file holding the versions, the date, the preset when "
            "one applies, the outcome and exit code, the counts by severity, the notices and errors, every item with its "
            "findings, and the lint notes and the analyzer's verdicts when present. The connected-mode details and the "
            "instruction-file scopes are in the JSON report, not in the HTML report.") in entry
    assert "holding what the JSON report holds" not in entry
    assert ("Lone surrogates: a string with a lone surrogate (a `\\uD800` to `\\uDFFF` escape without its pair) in the JSON answer "
            "of a probed server or of the service is read with U+FFFD in its place") in entry
    assert ("SKILL.md front matter and the settings and baseline files are read the same way" in entry
            and "Every request to the service is valid UTF-8" in entry)
    assert ("When two keys of one object would become equal, both are kept: the later one gets U+FFFD and a number appended, so "
            "no value is dropped.") in entry
    for character in ("\u2014", "\u2013", "!"):
        assert character not in raw


def test_the_changelog_has_the_1_19_0_entry_above_1_18_0():
    """1.19.0: `--staged` and the hook, the front-matter limits, the span rule, the unread file's path, and the dated correction
    of 1.18.0's sentence on unchanged outputs."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.19.0 (2026-11-") < text.index("## 1.18.0 (")
    raw = text[text.index("## 1.19.0 ("):text.index("## 1.18.0 (")]
    entry = " ".join(raw.split())
    for needle in ("Rules version 2026.11.7, unchanged (66 rules)",
                   "under `--analyze`, the `limit` of a skill with a file the scan did not read gains `path`",
                   "the hook now reads the request's own settings file, baseline and `a2a.keys` file",
                   "1.19.0: added `spellwarden scan --staged`, which reads the git index only and sends nothing to Spellwarden, "
                   "and the pre-commit hook now runs it",
                   "`staged_credentials_ignored`", "`staged_unavailable` (exit 2)",
                   "`.pre-commit-hooks.yaml` runs `spellwarden scan --staged`",
                   "64 KiB of text, 2,000 YAML nodes, a nesting depth of 32 and 50 aliases",
                   "`spellwarden_scan.frontmatter.FrontmatterLimit`", "`no_verdict` with the reason `off_schema`",
                   '`ANALYZER_VERSION` stays "1"', "its `limit` now names the file in `path`",
                   "1.18.0 had two exceptions to unchanged outputs: a `--probe` exit path, and the lock hash of a tool input "
                   "schema holding a lone surrogate, which changes once and raises SW-MCP-012, so exit 3 under `--locked` once "
                   "after upgrading."):
        assert needle in entry, needle
    assert "runs offline" not in entry
    for character in ("\u2014", "\u2013", "!"):
        assert character not in raw


def test_the_hook_file_ships_in_the_sdist_and_pre_commit_is_a_development_dependency():
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert ".pre-commit-hooks.yaml" in project["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert any(entry.startswith("pre-commit>=") for entry in project["dependency-groups"]["dev"])


def test_the_changelog_has_the_1_20_0_entry_above_1_19_0():
    """Engine 1.20.0 (spec 7.18): the two rules first, then selection, `--follow-links`, `scan --user` and two versions on one
    repository."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.20.0 (2026-11-") < text.index("## 1.19.0 (")
    raw = text[text.index("## 1.20.0 ("):text.index("## 1.19.0 (")]
    entry = " ".join(raw.split())
    assert entry.startswith("## 1.20.0 (2026-11-23) Rules version 2026.11.8: SW-CFG-012 and SW-CFG-013 also judge the MCP servers "
                            "of settings documents; no other rule changed (66 rules).")
    for needle in ("`trust: true`", '`default_tools_approval_mode = "approve"`', "`scan --user` takes no baseline",
                   "No fingerprint of an existing finding changes", "has not been measured", "`.codex/config.toml`",
                   "`.github/hooks/`", "`github-agent`", "registry gate", "exit 3", "`instructions_limit`", "`--follow-links`",
                   "off by default", "`symlink_skipped`", "`lock --check`", "`scan --locked`", "`SW_FOLLOW_LINKS`",
                   "`%APPDATA%/devin/`", "1.19.0 read no skill for it", "`workstation_upload_too_large`", "`removed`"):
        assert needle in entry, needle
    assert entry.index("The two rules.") < entry.index("Selection.") < entry.index("`--follow-links`:") \
        < entry.index("`scan --user`:")
    for character in ("—", "–", "!"):
        assert character not in raw


def test_the_changelog_has_the_1_21_0_entry_above_1_20_0():
    """P6-15 spec 6.11: every output change of the fix guidance, no rule detects anything new, and the correction of the two rule
    links, in the spec's words; the date is set when the release is tagged."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.21.0 (") < text.index("## 1.20.0 (")
    raw = text[text.index("## 1.21.0 ("):text.index("## 1.20.0 (")]
    entry = " ".join(raw.split())
    assert "Rules version 2026.11.8, unchanged (66 rules): no rule detects anything new" in entry
    for needle in ("`fix`", "`rule_url`", "`fix_lines`", "`schemas/report.schema.json`", "\"How to fix\"", "`write in`", "`help`",
                   "`helpUri`", "`properties.fix_lines`", "No `fixes` object is written", "`recommendation`",
                   "GitLab Code Quality is unchanged", "`read_only=true`", "`mcp-server-kubernetes`", "`kubernetes-mcp-server`",
                   "`\"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS\": \"true\"`", "`ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS = \"true\"`",
                   "Codex's `config.toml`",
                   "leaves out `fix`, `rule_url` and `fix_lines`",
                   "The rule link of the HTML report and the `source.url` of the CycloneDX file now write the rule id in lower case, "
                   "the address of the rule's page. Up to 1.20.0 they wrote it in upper case, an address that answered with Page "
                   "not found."):
        assert needle in entry, needle
    for character in ("—", "–", "!"):
        assert character not in raw


def test_the_changelog_has_the_1_22_0_entry_above_1_21_0():
    """P6-4 spec 6.8.3: the build's part of the entry (the rules and steps that ship, the evidence prefix, the keyword, the steps
    left out and the read limit); the orchestrator sets the date and adds the lines of the recorded benchmark entry."""
    from spellwarden_scan import normalise

    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.22.0 (") < text.index("## 1.21.0 (")
    raw = text[text.index("## 1.22.0 ("):text.index("## 1.21.0 (")]
    entry = " ".join(raw.split())
    assert "Rules version 2026.11.9 (66 rules):" in entry and f"{len(normalise.RULES)} skill rules also read" in entry
    for rule_id in normalise.RULES:
        assert rule_id in entry, rule_id
    assert "The steps, in this order: " + ", ".join(f"`{step}`" for step in normalise.STEPS) + "." in entry
    for needle in ("No rule id is added, removed or renamed", "`Matched after normalising:`", "`normalise`",
                   "`spellwarden_scan.normalise`", "Steps left out.", "`findings_truncated`", "`TextLimit`", "10 MiB", "1 MiB",
                   "`unreadable`", "`benchmarks/RESULTS.md`", "`rule_benchmark.py steps`"):
        assert needle in entry, needle
    for character in ("\u2014", "\u2013", "!"):
        assert character not in raw


def test_the_changelog_has_the_1_23_0_entry_above_1_22_0():
    """P6-10 spec 7.10 and 7.11: the count first, then every behaviour change, the command's link out of the scan root with its
    way out among them, and what stays as it was; the orchestrator sets the date when the release is tagged."""
    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.23.0 (") < text.index("## 1.22.0 (")
    raw = text[text.index("## 1.23.0 ("):text.index("## 1.22.0 (")]
    entry = " ".join(raw.split())
    assert "Rules version 2026.11.9, unchanged (66 rules): no rule detects anything new" in entry
    assert entry.index("35 read whole since 1.10.0") < entry.index("Links in an archive.")
    for needle in ("Of the 39 entries of the first catalog round", "closes the other four", "258 characters", "24.8 MiB zipped",
                   "`ArchiveError.why`", "`outside`", "`dangling`", "`chain`", "`directory`", "`through_link`", "`unsafe_target`",
                   "`special`", "measured on the path inside the archive's top directory", "`ArchiveLimits.max_entries` (100,000)",
                   "`archive_entries`", "`REPOSITORY_LIMITS`", "50 MiB zipped", "`list_zip(data, limits=REPOSITORY_LIMITS)`",
                   "by the owner's decision", "is the error `unsafe_path` and an incomplete scan (exit 2)",
                   "`spellwarden lock` writes no lock", "replace the link with the file it names",
                   "leave it out with `exclude` in `.spellwarden/config.yml`", "exit 2 from `scan --locked`, not exit 3",
                   "stays the notice `symlink_skipped`", "is still read at its target", "`scan --user` keeps its own rule"):
        assert needle in entry, needle
    for character in ("—", "–", "!"):
        assert character not in raw


def test_the_changelog_has_the_1_24_0_entry_above_1_23_0():
    """Speed and deadline spec 12.2 and T20: the rules count first, the speed work with the profile line each change removed and the
    times before and after, the library argument and the exception, the command flag and the error with its way out, the report
    code and the granularity; the orchestrator sets the date when the release is tagged."""
    import re

    text = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.24.0 (") < text.index("## 1.23.0 (")
    raw = text[text.index("## 1.24.0 ("):text.index("## 1.23.0 (")]
    entry = " ".join(raw.split())
    assert entry.startswith("## 1.24.0 (")
    assert "Rules version 2026.11.9, unchanged (66 rules): no rule detects anything new, and every finding 1.23.0 reports keeps" in entry
    for needle in ("`Deadline`", "`Deadline.after(seconds)`", "`TimeLimit`", "`path`", "`stage`", "`time_limit`", "`--time-limit`",
                   "split the content", "leave a file out with `exclude` in `.spellwarden/config.yml`", "or raise the limit",
                   "Granularity.", "`benchmarks/speed_profile.py profile`", "`benchmarks/speed_profile.py check`",
                   "`benchmarks/speed_profile.py overshoot`", "`skl_008_lines`", "`schemas/report.schema.json`", "after `staged_unavailable`",
                   "whole or not at all", "keep their findings", "`--user` refuses the flag", "the reason `time_limit`"):
        assert needle in entry, needle
    # the measured figures are in it: the profile of each change, and the times of (a), (b) and (c) before and after, on and off
    for label in ("(a)", "(b)", "(c)"):
        part = entry[entry.index(label + " "):]
        assert re.match(rf"\{label[0]}[abc]\) [^:]*: (\d+\.\d+) s before and (\d+\.\d+) s after with normalisation on, "
                        r"(\d+\.\d+) s before and (\d+\.\d+) s after with it off", part), label
    assert re.search(r"put SW-SKL-008 at \d+\.\d+ s and SW-SKL-012 at \d+\.\d+ s", entry)
    assert re.search(r"this step at \d+\.\d+ s", entry) and re.search(r"this step at \d+\.\d+ s\.", entry)
    assert re.search(r"at most \d+\.\d+ s past the limit on this machine", entry)
    assert re.search(r"Looking at the clock adds \d+\.\d+ per cent to a scan", entry)
    assert not re.search(r"<[a-z_0-9]+>", raw), "a figure of the measurements is still a slot"
    for character in ("\u2014", "\u2013", "!"):
        assert character not in raw
