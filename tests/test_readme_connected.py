"""O3 spec 13 and 6.10, plan Task 11: the README's "Connected mode" section has the subsections the spec names in order,
one heading per gate reason whose GitHub anchor is the one the Markdown report links (`markdown.REASON_ANCHORS`), a
table of every connected error code with the fix, the exact two-job recipe for pull requests from forks, and the two
sentences of the old README replaced. The section holds no dash character and no exclamation mark."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from spellwarden_scan.gate import GATE_REASONS
from spellwarden_cli.output.markdown import REASON_ANCHORS
from spellwarden_cli.report import CONNECTED_ERRORS

README = Path(__file__).resolve().parents[1] / "README.md"
SECTION = "### Connected mode\n"
SUBSECTIONS = ["Turning it on", "What is sent", "The calls", "Run kinds and which events report",
               "Pull requests from forks: the two-job recipe", "The gate", "connected.required and the Dependabot exemption",
               "Errors and their fixes", "Proxies", "Line endings and archives", "The test hook", "Unsupported setups"]


def readme() -> str:
    return README.read_text(encoding="utf-8").replace("\r\n", "\n")


def section() -> str:
    text = readme()
    assert text.count(SECTION) == 1 and text.index("## The `spellwarden` command") < text.index(SECTION)
    rest = text[text.index(SECTION) + len(SECTION):]
    ends = [rest.index(marker) for marker in ("\n### ", "\n## ") if marker in rest]
    return rest[:min(ends)]


def headings(text: str, level: int) -> list[str]:
    inside_code = False
    found = []
    for line in text.split("\n"):
        if line.startswith("```"):
            inside_code = not inside_code
        elif not inside_code and line.startswith("#" * level + " "):
            found.append(line[level + 1:])
    return found


def github_slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation other than hyphens and underscores removed, spaces to hyphens."""
    kept = "".join(char for char in heading.lower() if char.isalnum() or char in " -_")
    return kept.replace(" ", "-")


def test_the_subsections_are_the_specs_in_order():
    assert headings(section(), 4) == SUBSECTIONS


def test_each_gate_reason_has_one_heading_whose_anchor_is_the_reports_link():
    gate = section()[section().index("\n#### The gate\n"):]
    reason_headings = [heading for heading in headings(gate, 5) if heading.startswith("Gate reason: ")]
    assert len(reason_headings) == len(GATE_REASONS)
    slugs = [github_slug(heading) for heading in reason_headings]
    for reason in GATE_REASONS:
        assert REASON_ANCHORS[reason].removeprefix("#") in slugs, reason
    assert len(set(slugs)) == len(slugs)


def test_the_errors_table_has_every_connected_error_code_with_a_fix():
    text = section()
    table = text[text.index("\n#### Errors and their fixes\n"):text.index("\n#### Proxies\n")]
    rows = {match.group(1): match.group(2) for match in re.finditer(r"^\| `([a-z_]+)` \| (.+) \|$", table, re.M)}
    assert set(rows) == set(CONNECTED_ERRORS)
    assert all(len(fix) > 20 for fix in rows.values())
    # the messages of 6.9 that name the fix are quoted as the command prints them
    assert "The organisation did not accept this pipeline's identity: <server message>. Check the CI connection under Settings, CI connections, or the SPELLWARDEN_API_KEY secret." in rows["connected_auth"]
    assert "The organisation's subscription is not active. Machine access is paused until billing is restored; people can still sign in." in rows["connected_subscription"]
    assert "Connected mode needs a CI key. Create one under Settings, API keys, with access CI." in rows["connected_ci_key_required"]
    assert "This repository requires connected mode (.spellwarden/config.yml) and the run could not connect: <detail>." in rows["connected_required"]
    assert "A Spellwarden limit, not an outage, stopped this call: <server message>." in rows["connected_rate_limited"]
    assert "The private registry could not be checked (<code>). The scan is incomplete." in rows["registry_check_failed"]


def test_the_fork_recipe_is_the_two_job_workflow_of_the_spec():
    text = section()
    block = re.search(r"```yaml\n(on:\n  pull_request:.*?)```", text, re.S)
    assert block is not None
    workflow = yaml.safe_load(block.group(1))
    jobs = workflow["jobs"]
    inside = "github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository"
    outside = ("github.event_name == 'pull_request_target' && "
               "github.event.pull_request.head.repo.full_name != github.repository")
    assert workflow[True].keys() == {"pull_request", "pull_request_target"}      # `on` loads as the key True
    assert jobs["same-repository"]["if"] == inside and jobs["outside-contribution"]["if"] == outside
    assert jobs["outside-contribution"]["permissions"] == {"contents": "read", "id-token": "write", "pull-requests": "write"}
    steps = jobs["outside-contribution"]["steps"]
    assert steps[0]["with"] == {"ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False}
    assert len(steps) == 2 and steps[1]["uses"].startswith("spellwarden-ai/scan@") and steps[1]["with"] == {"org": "acme"}


def test_the_old_sentences_are_replaced_and_the_schemas_section_names_the_block():
    text = readme()
    assert "The `spellwarden` command does not load org rules or packs yet" not in text
    assert "In connected mode the command applies the organisation's CI policy (see Connected mode)." in text
    assert "so the Action and the component stay at 1.0.0" not in text
    assert "The Action and the component release at the same version." in text
    schemas = text[text.index("### Schemas and compatibility"):text.index("\n## Versions")]
    assert "`connected` block" in schemas and "`upload_truncated`" in schemas
    assert "`api.py`" in text[text.index("## Development"):]                      # the fourth network module is named


def test_the_section_holds_no_dash_character_and_no_exclamation_mark():
    prose = re.sub(r"```.*?```", "", section(), flags=re.S)       # the recipe's `!=` is workflow syntax, not copy
    assert not re.search("[\u2013\u2014!]", prose)


def test_the_section_states_the_limits_the_command_enforces():
    from spellwarden_cli import api

    text = section()
    assert f"{int(api.RUN_BUDGET_SECONDS)} seconds" in text and f"{int(api.REQUEST_TIMEOUT_SECONDS)} seconds" in text
    assert "2 MiB" in text and "840 seconds" in text
    for phrase in ("SPELLWARDEN_ORG", "SPELLWARDEN_API_KEY", "SPELLWARDEN_ID_TOKEN", "SPELLWARDEN_UPLOAD", "SPELLWARDEN_API_URL",
                   "SPELLWARDEN_RUN_ID", "SPELLWARDEN_DEFAULT_BRANCH", "HTTPS_PROXY", "NO_PROXY", "--no-upload", "fetch-depth: 0"):
        assert phrase in text, phrase


def test_the_changelog_has_the_1_2_0_section_with_the_release_date_left_to_the_owner():
    import sys

    sys.path.insert(0, str(README.parent / "scripts"))
    try:
        import release_manifest
    finally:
        sys.path.remove(str(README.parent / "scripts"))
    changelog = (README.parent / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.match(r"# Changelog\n\n## 1\.2\.0 \((RELEASE_DATE|\d{4}-\d{2}-\d{2})\)\n", changelog)  # dated by Task 12
    body = release_manifest.changelog_section(changelog, "1.2.0")
    assert "Connected mode" in body and "SW-REG-003" in body and "2026.10.3" in body
    assert not re.search("[\u2013\u2014!]", body)


def _table_options() -> dict[tuple[str, str], set[str]]:
    """The 'Pinned command forms' table: `(launcher, kind)` to the options in its cell."""
    text = section()
    start = text.index("**Pinned command forms.**")
    found: dict[tuple[str, str], set[str]] = {}
    for line in text[start:].split("\n\n")[2].split("\n"):
        cells = [cell.strip() for cell in line.strip("|").split(" | ")]
        if len(cells) == 3 and cells[0].startswith("`"):
            found[(cells[0].strip("`"), cells[1])] = set(re.findall(r"`([^`]+)`", cells[2]))
    return found


def test_the_pinned_command_forms_table_lists_each_launchers_closed_option_sets():
    from spellwarden_scan.identity import _SPECS, QUIET_FLAGS

    expected: dict[tuple[str, str], set[str]] = {}
    for launcher, spec in _SPECS.items():
        overrides = set(spec.overrides)
        if launcher == "docker run":
            overrides.add("--entrypoint")
        if spec.override_prefix:
            overrides.add(spec.override_prefix + "<key>")
        hashed_values = set(spec.values) - set(QUIET_FLAGS[launcher]) - overrides  # a quiet or override option is never hashed
        for kind, options in (("Quiet flags (dropped)", QUIET_FLAGS[launcher]), ("On/off flags (hashed)", spec.flags),
                              ("Value options (hashed)", hashed_values), ("Artefact options", spec.artefacts),
                              ("Registry and index options", spec.sources), ("Overrides (launch override)", overrides)):
            if options:
                expected[(launcher, kind)] = set(options)
    assert _table_options() == expected


def test_the_launch_override_reason_lists_every_override_env_name():
    from spellwarden_scan.identity import LAUNCH_OVERRIDE_ENV

    gate = section()
    body = gate[gate.index("##### Gate reason: launch override"):gate.index("##### Gate reason: resolver override")]
    listed = set(re.findall(r"`([A-Z][A-Z0-9_]+)`", body[body.index("an `env` entry"):]))
    assert listed == LAUNCH_OVERRIDE_ENV
