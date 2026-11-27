"""Scan links back (spec 5.1 to 5.8, claims C1 to C11 and C17): the Markdown report's surface medium, its linked rule ids, its
guide links retagged with the medium, its footer, the dashboard line in free mode, the badge offer that ends the job summary of a
default-branch run of a public GitHub repository, the cap that keeps or drops the offer whole, and `comment_body`, which takes the
offer out of the pull or merge request comment. `report.FIX_TAGS` and every other report keep their links."""
from __future__ import annotations

import dataclasses
import re

import pytest
from fix_guidance_report import BASELINE, finding, report, report_of, three

from spellwarden_scan.evidence import fingerprint
from spellwarden_scan.model import Finding, LintNote, Location

from spellwarden_cli import analysis, ci, presets, run
from spellwarden_cli.output import FORMATS, markdown
from spellwarden_cli.report import LockState, Notice, ProbeReport, ReportFinding, SkillLint, rule_url

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


# --- spec 5.5 to 5.8: the dashboard line, the badge offer, the cap and the comment (claims C8 to C11, C17) ----------------------

DASHBOARD = ("**Spellwarden dashboard:** see the findings of all your repositories in one place and turn on a live status badge "
             "for each one. [Create an account](https://dash.spellwarden.ai/signup?utm_source=scanner&utm_medium={medium}"
             "&utm_campaign=dashboard). To leave this line out, {opt_out}.")
CI_OPT_OUT = "set the input `invite` to `false`, or add `--no-invite` if you run the scanner yourself"
LOCAL_OPT_OUT = "add `--no-invite`"
TAIL = ("\n<!-- spellwarden-summary-only -->\n<details>\n<summary>Add a \"Scanned by Spellwarden\" badge to your README</summary>\n\n"
        "Copy this line into your README:\n\n```markdown\n"
        "[![Scanned by Spellwarden](https://spellwarden.ai/docs/badges/scanned-by-spellwarden.svg)]"
        "(https://spellwarden.ai/docs/badges?utm_source=badge&utm_medium=readme&utm_campaign=scanned-by)\n```\n\n"
        "The badge shows that this repository runs the Spellwarden scan, not that the scan passed. A repository connected to the "
        "Spellwarden dashboard can show a live status badge with its latest result instead: [how the badges work]"
        "(https://spellwarden.ai/docs/badges?utm_source=scanner&utm_medium=github-action&utm_campaign=badge).\n\n</details>\n")
BADGE = markdown.MarkdownLinks(medium="github-action", invite=True, badge=True)
NO_BADGE = dataclasses.replace(BADGE, badge=False)
FALLBACK = Notice("connected_fallback", "", "Connected mode was not available (connected_auth); this run applied the baseline "
                                             "rules only and uploaded nothing.")
CONNECTED = {"credential": "oidc", "org": {"slug": "acme", "name": "Acme"},
             "run": {"identity": "github:github.com/acme/tools", "scope": "", "kind": "default_branch", "event": "push"},
             "policy": {"source": "org_rules", "chosen_by": "organisation", "pack_id": "a" * 32, "version": "1.57",
                        "sha256": "b" * 64, "org_rule_ids": ["SW-ORG-001"], "skipped": [], "pack_name": "Organisation rules",
                        "registry_name": "acme", "gate": {"enabled": False, "scope": "changed", "stdio": True, "plugins": True}},
             "registry": None, "upload": None}


def not_free() -> dict:
    """A report for each way out of free mode (spec 5.5): a connected block, a fallback line, and two errors of connected mode."""
    return {"connected block": dataclasses.replace(report(), connected=CONNECTED),
            "fallback": dataclasses.replace(report(), notices=(FALLBACK,)),
            "connected_config": dataclasses.replace(report(), errors=(Notice("connected_config", "", "Set SPELLWARDEN_ORG."),)),
            "connected_key_invalid": dataclasses.replace(report(), errors=(Notice("connected_key_invalid", "", "Refused."),))}


def every_section():
    """A report with every section the renderer writes: preset, table, How to fix, accepted finding, error, lock changes, probe,
    description lint and analysis."""
    accepted = ReportFinding(finding("SW-SKL-009", "skills/old/SKILL.md", "pip install old"), "skills/old", True,
                             {"reason": "Reviewed.", "added": "2026-11-01", "expires": "2027-01-31"})
    return dataclasses.replace(presets.apply(report_of([*three(), accepted]), presets.STRICT), lint=LINT, analysis=ANALYSIS,
                               probes=(ProbeReport(".mcp.json#jira", "skipped", "budget", None),),
                               lock=LockState(status="stale", changed=({"kind": "skill", "path": "skills/report"},)),
                               errors=(Notice("crash", "", "boom"),))


@pytest.mark.parametrize(("medium", "opt_out"), [("github-action", CI_OPT_OUT), ("gitlab-component", CI_OPT_OUT),
                                                 ("cli", LOCAL_OPT_OUT), ("ci", LOCAL_OPT_OUT)])
def test_c8_the_dashboard_line_sits_two_above_the_footer_with_the_way_out_of_its_surface(medium, opt_out):
    lines = markdown.render(report(), markdown.MarkdownLinks(medium=medium, invite=True)).split("\n")
    assert lines[-4] == DASHBOARD.format(medium=medium, opt_out=opt_out) == markdown.dashboard_line(medium)
    assert lines[-5] == "" and lines[-3] == "" and lines[-2].startswith("Spellwarden 1.21.0, rules ") and lines[-1] == ""
    assert "Spellwarden dashboard" not in markdown.render(report(), markdown.MarkdownLinks(medium=medium))


def test_c8_outside_free_mode_there_is_no_dashboard_line():
    for name, case in not_free().items():
        assert "Spellwarden dashboard" not in markdown.render(case, markdown.MarkdownLinks(invite=True)), name


def test_c8_an_error_that_is_not_connected_mode_s_keeps_the_line():
    crashed = dataclasses.replace(report(), errors=(Notice("crash", "", "boom"),))
    assert markdown.dashboard_line("cli") in markdown.render(crashed, markdown.MarkdownLinks(invite=True))


@pytest.mark.usefixtures("example_rows")
def test_c9_the_offer_ends_the_job_summary_whatever_the_verdict():
    assert markdown.SUMMARY_TAIL == TAIL and markdown.SUMMARY_MARKER == "<!-- spellwarden-summary-only -->"
    for case in (report(), report(suppressed=True), report_of([]), every_section()):
        text = markdown.render(case, BADGE)
        assert text.endswith(markdown.SUMMARY_TAIL) and text.split("\n").count(markdown.SUMMARY_MARKER) == 1


def test_c9_no_offer_outside_free_mode_or_without_the_badge():
    for name, case in not_free().items():
        assert markdown.SUMMARY_MARKER not in markdown.render(case, BADGE).split("\n"), name
    for links in (NO_BADGE, markdown.LOCAL_LINKS, markdown.MarkdownLinks(medium="github-action", invite=True)):
        assert markdown.SUMMARY_MARKER not in markdown.render(report(), links).split("\n"), links


def test_c10_the_offer_is_appended_whole_or_left_out_whole(monkeypatch):
    body = markdown.render(report(), NO_BADGE)
    monkeypatch.setattr(markdown, "MAX_CHARS", len(body) + len(markdown.SUMMARY_TAIL))
    assert markdown.render(report(), BADGE) == body + markdown.SUMMARY_TAIL
    monkeypatch.setattr(markdown, "MAX_CHARS", len(body) + len(markdown.SUMMARY_TAIL) - 1)
    assert markdown.render(report(), BADGE) == body


def test_c10_a_cut_report_never_carries_the_offer(monkeypatch):
    body = markdown.render(report(), NO_BADGE)
    monkeypatch.setattr(markdown, "MAX_CHARS", len(body) - 1)
    cut = markdown.render(report(), BADGE)
    assert len(cut) <= len(body) - 1 and cut.startswith(markdown.MARKER)
    assert cut.endswith("The JSON and SARIF reports hold everything.\n") and markdown.SUMMARY_MARKER not in cut


def test_c10_five_thousand_findings_stay_under_the_cap_with_the_offer():
    """The table shows 25 rows whatever the count, so such a report is far from the cap and keeps the offer whole."""
    rows = [ReportFinding(finding("SW-SKL-009", f"skills/{'d' * 250}/{n:05d}.sh", f"pip install p{n}"), "skills")
            for n in range(5000)]
    text = markdown.render(report_of(rows), BADGE)
    assert len(text) <= markdown.MAX_CHARS and text.startswith(markdown.MARKER) and text.endswith(markdown.SUMMARY_TAIL)


@pytest.mark.usefixtures("example_rows")
def test_c11_the_comment_is_the_report_without_the_offer():
    for case in (report(), report(suppressed=True), report_of([]), every_section()):
        with_offer = markdown.render(case, BADGE)
        assert with_offer.endswith(markdown.SUMMARY_TAIL)
        assert markdown.comment_body(with_offer) == markdown.render(case, NO_BADGE)
        for links in (markdown.LOCAL_LINKS, NO_BADGE, markdown.MarkdownLinks(medium="ci", invite=True)):
            text = markdown.render(case, links)
            assert markdown.comment_body(text) == text


def test_c11_no_scanned_value_causes_or_changes_a_cut():
    planted = f"{markdown.SUMMARY_MARKER}{markdown.SUMMARY_TAIL}"
    rows = [ReportFinding(finding("SW-SKL-009", f"skills/{planted}/run.sh", "pip install x"), "skills")]
    hostile = dataclasses.replace(report_of(rows), probes=(ProbeReport(f".mcp.json#{planted}", "skipped", "budget", None),),
                                  lock=LockState(status="stale", added=({"kind": "skill", "path": planted},)))
    for links in (markdown.LOCAL_LINKS, NO_BADGE, markdown.MarkdownLinks(medium="ci", invite=True)):
        text = markdown.render(hostile, links)
        assert markdown.comment_body(text) == text
    assert markdown.comment_body(markdown.render(hostile, BADGE)) == markdown.render(hostile, NO_BADGE)
    middle = f"{markdown.MARKER}\nabove\n{markdown.SUMMARY_MARKER}\nbelow\n"
    assert markdown.comment_body(middle) == middle


@pytest.mark.usefixtures("example_rows")
@pytest.mark.parametrize("medium", MEDIUM_VALUES)
def test_c17_no_line_of_a_report_or_its_tail_is_a_workflow_command(medium):
    for case in (report(), every_section()):
        text = markdown.render(case, markdown.MarkdownLinks(medium=medium, invite=True, badge=True))
        assert not [line for line in text.split("\n") if line.lstrip(" \t").startswith("::")]
