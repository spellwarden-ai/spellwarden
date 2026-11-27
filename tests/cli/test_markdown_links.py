"""Scan links back (spec 5.1 to 5.4, claims C1 to C7): the Markdown report's surface medium, its linked rule ids, its guide links
retagged with the medium, and its footer. `report.FIX_TAGS` and every other report keep their links."""
from __future__ import annotations

import dataclasses
import re

import pytest
from fix_guidance_report import BASELINE, report, report_of, three

from spellwarden_scan.evidence import fingerprint
from spellwarden_scan.model import Finding, LintNote, Location

from spellwarden_cli import analysis, ci, presets, run
from spellwarden_cli.output import FORMATS, markdown
from spellwarden_cli.report import ReportFinding, SkillLint, rule_url

MEDIUM_VALUES = ("cli", "github-action", "gitlab-component", "ci")
UNKNOWN = Finding("SW-SKL-999", "high", "Not in the rule set", Location("skills/x/run.sh", 1), "x",
                  fingerprint("SW-SKL-999", "skills/x/run.sh", "x"), False)
LINT = (SkillLint("skills/report", (LintNote("SW-LINT-001", "skills/report", "The description is short."),)),)
ANALYSIS = ({"skill": "skills/report", "status": "analyzed", "model": "m", "categories": []},)


def context(provider: str | None = "github", *, event: str = "push", is_request: bool = False, ref: str = "main",
            visibility: str = "public") -> ci.CiContext:
    return ci.CiContext(provider=provider, event=event, is_request=is_request, request_number=None, fork=False,
                        dependabot=False, protected_ref=False, identity=None, ref_name=ref, default_branch="main",
                        visibility=visibility)


def docs(rule_id: str, medium: str, campaign: str) -> str:
    return f"https://spellwarden.ai/docs/rules/{rule_id.lower()}?utm_source=scanner&utm_medium={medium}&utm_campaign={campaign}"


def test_c1_the_medium_table_is_closed_and_each_medium_is_a_plain_token():
    assert markdown.MEDIUMS == {"github": "github-action", "gitlab": "gitlab-component", "other": "ci", None: "cli"}
    for medium in markdown.MEDIUMS.values():
        assert re.fullmatch(r"[a-z0-9_.-]{1,64}", medium), medium


def test_c2_links_for_offers_the_badge_only_on_a_public_github_default_branch_run_with_the_invitation():
    assert markdown.links_for(context(), invite=True) == markdown.MarkdownLinks("github-action", True, True)
    negations = {"invite off": (context(), False), "gitlab": (context("gitlab"), True),
                 "request run": (context(event="pull_request", is_request=True), True),
                 "branch run": (context(ref="feature"), True), "private": (context(visibility="private"), True)}
    for name, (ctx, invite) in negations.items():
        links = markdown.links_for(ctx, invite=invite)
        assert links.badge is False and links.invite is invite, name
    for provider, medium in markdown.MEDIUMS.items():
        assert markdown.links_for(context(provider), invite=False).medium == medium
    assert markdown.links_for(ci.LOCAL, invite=True) == markdown.MarkdownLinks("cli", True, False)
    assert markdown.links_for(context("jenkins"), invite=True).medium == "ci"  # never a value outside the table


def test_c3_without_links_the_report_is_a_local_run_with_no_invitation():
    text = markdown.render(report())
    assert text == markdown.render(report(), markdown.MarkdownLinks()) == FORMATS["markdown"](report())
    assert markdown.LOCAL_LINKS == markdown.MarkdownLinks("cli", False, False)
    assert "utm_medium=cli" in text and "Spellwarden dashboard" not in text
    assert "<!-- spellwarden-summary-only -->" not in text


@pytest.mark.parametrize("medium", MEDIUM_VALUES)
def test_c4_each_baseline_rule_id_in_the_table_links_to_its_page(medium):
    text = markdown.render(report_of([*three(), ReportFinding(UNKNOWN, "skills/x")]), markdown.MarkdownLinks(medium=medium))
    rows = [line for line in text.split("\n") if line.startswith("| ") and not line.startswith("| Severity |")]
    assert {line.split(" | ")[1] for line in rows} == {
        f"[SW-SKL-009]({docs('SW-SKL-009', medium, 'rule-docs')})", f"[SW-CFG-013]({docs('SW-CFG-013', medium, 'rule-docs')})",
        "SW-ORG-001", "SW-SKL-999"}  # an organisation rule has no page, and an id the set lacks stays plain
    for line in rows:
        assert len(re.findall(r"(?<!\\)\|", line)) == 5, line


@pytest.mark.parametrize("medium", MEDIUM_VALUES)
def test_c5_the_how_to_fix_links_carry_the_medium(medium):
    text = markdown.render(report(), markdown.MarkdownLinks(medium=medium))
    for rule_id in ("SW-CFG-013", "SW-SKL-009"):
        assert f"[Rule page]({docs(rule_id, medium, 'rule-fix')})" in text, rule_id


def test_c5_for_a_local_run_the_how_to_fix_link_is_the_fix_tags_address():
    for rule in BASELINE:
        assert markdown.tagged(rule.page, "cli", "rule-fix") == rule_url(rule), rule.id


@pytest.mark.usefixtures("example_rows")
@pytest.mark.parametrize("medium", MEDIUM_VALUES)
def test_c6_the_lint_analyzer_and_preset_links_carry_the_medium(medium):
    rich = dataclasses.replace(presets.apply(report(), presets.STRICT), lint=LINT, analysis=ANALYSIS)
    text = markdown.render(rich, markdown.MarkdownLinks(medium=medium))
    lint = markdown.tagged(markdown.LINT_GUIDE_PAGE, medium, "description-lint")
    analyzer = markdown.tagged(markdown.ANALYZER_GUIDE_PAGE, medium, "analyzer")
    preset = markdown.tagged(markdown.PRESETS_GUIDE_PAGE, medium, "presets")
    assert f"[What each check means]({lint})" in text
    assert f"[How it works and what it was measured on]({analyzer})" in text
    assert f"[How presets work]({preset})" in text and f" See {presets.GUIDE_URL}" not in text
    if medium == "cli":  # a local run's guide links keep their bytes
        assert (lint, analyzer, preset) == (run.LINT_GUIDE_URL, analysis.ANALYZER_GUIDE_URL, presets.GUIDE_URL)


@pytest.mark.parametrize("medium", MEDIUM_VALUES)
def test_c7_the_footer_points_at_the_rules_on_the_site_and_at_the_source_code(medium):
    lines = markdown.render(report(), markdown.MarkdownLinks(medium=medium)).split("\n")
    assert lines[-1] == ""
    assert lines[-2] == ("Spellwarden 1.21.0, rules 2026.11.8. [What each rule checks](https://spellwarden.ai/docs/rules"
                         f"?utm_source=scanner&utm_medium={medium}&utm_campaign=rule-docs), "
                         "[source code](https://github.com/spellwarden-ai/spellwarden)")
    for gone in ("RULES_URL", "LINT_GUIDE_URL", "ANALYZER_GUIDE_URL"):
        assert not hasattr(markdown, gone), gone
