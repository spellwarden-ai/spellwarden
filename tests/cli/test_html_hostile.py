"""1.19.0: the HTML report's sections that 1.18.0's tests did not reach with hostile input: the probed server, the agent card, the
analysis span, the description lint and the lock changes. Each value holds a script element, an image with an event attribute, a
link, a frame and a stylesheet to a foreign address, and a quote that tries to leave an attribute, as a probed server, a card, a
model's answer, a skill or the lock could hold them. Parsed, the document holds no live markup, no event attribute, no script
element and no network reference, and it shows the text escaped."""
from __future__ import annotations

from html_checks import inert_problems

from spellwarden_scan import RULES_VERSION, RuleSet, __version__
from spellwarden_scan.model import A2aScanResult, ChecklistItem, LintNote, McpScanResult

from spellwarden_cli import escape
from spellwarden_cli.output import FORMATS
from spellwarden_cli.report import AgentReport, LockState, ProbeReport, Report, SkillLint

RULES = RuleSet.baseline()
HOSTILE = ('<script>alert(1)</script><img src=x onerror=alert(1)><a href="https://evil.example/x">x</a>'
           '<iframe src="//evil.example/f"></iframe><link rel=stylesheet href=https://evil.example/s.css>'
           '" onmouseover="alert(1)')


def html_of(**fields) -> str:
    base = {"scanner_version": __version__, "rules_version": RULES_VERSION, "as_of": "2026-11-19", "fail_on": "high",
            "items": (), "findings": (), "probes": (), "lock": LockState(), "notices": (), "errors": (), "repo_prefix": "",
            "rules": RULES}
    return FORMATS["html"](Report(**{**base, **fields}).sorted())


def assert_inert_with_the_text_shown(text: str) -> None:
    assert inert_problems(text) == []  # no script, event attribute, frame, image, external asset or foreign link
    assert escape.html(HOSTILE) in text
    assert HOSTILE not in text


def test_a_probed_server_s_name_and_protocol_version_stay_text():
    result = McpScanResult(findings=(), truncated=0, spec_version=HOSTILE, transport="streamable-http", auth_mode="none",
                           deprecated_features=(), migration_status="ready", checklist=(), rules_version=RULES_VERSION,
                           scanner_version=__version__)
    text = html_of(probes=(ProbeReport(f".mcp.json#{HOSTILE}", "probed", None, result),
                           ProbeReport(f".mcp.json#other{HOSTILE}", "skipped", "refused", None)))
    assert_inert_with_the_text_shown(text)
    assert "<h2>MCP servers probed</h2>" in text


def test_an_agent_card_s_format_versions_checklist_and_address_stay_text():
    result = A2aScanResult(findings=(), truncated=0, card_format=HOSTILE, protocol_versions=(HOSTILE,),
                           migration_status="to_migrate", signature_status="unsigned", signatures=(),
                           checklist=(ChecklistItem(1, "transport", HOSTILE),))
    checked = AgentReport(f"a2a-card:{HOSTILE}/agent-card.json", "repository", "named", "checked", result=result)
    failed = AgentReport(f"a2a-agent:https://b.example/{HOSTILE}", "remote", "direct", "failed", fail_reason="http_status",
                         fetch={"requested_url": "https://b.example/c.json", "final_url": None, "http_status": 500})
    text = html_of(agents=(checked, failed))
    assert_inert_with_the_text_shown(text)
    assert "<h2>A2A agent cards</h2>" in text


def test_an_analysis_span_summary_and_model_name_stay_text():
    category = {"id": "instruction_override", "verdict": "issue", "confidence": "high", "summary": HOSTILE,
                "spans": [{"path": HOSTILE, "line": 3, "text": HOSTILE}], "spans_left_out": 0, "rules_found": False}
    analysed = {"skill": f"skills/{HOSTILE}", "status": "analyzed", "model": HOSTILE, "cached": False, "categories": [category]}
    refused = {"skill": "skills/other", "status": "no_verdict", "reason": HOSTILE, "model": "m", "cached": False,
               "categories": []}
    text = html_of(analysis=(analysed, refused))
    assert_inert_with_the_text_shown(text)
    assert "Model-assisted analysis" in text


def test_a_lint_note_and_its_skill_paths_stay_text():
    note = LintNote("SW-LINT-004", f"skills/{HOSTILE}", HOSTILE, other_path=f"skills/other{HOSTILE}")
    text = html_of(lint=(SkillLint(f"skills/{HOSTILE}", (note,), 0),))
    assert_inert_with_the_text_shown(text)
    assert "Description lint" in text


def test_lock_changes_stay_text():
    change = {"kind": HOSTILE, "path": HOSTILE}
    text = html_of(lock=LockState("stale", added=(change,), removed=({"kind": "skill", "path": HOSTILE},), changed=(change,)))
    assert_inert_with_the_text_shown(text)
    assert "<h2>Lock file: stale</h2>" in text
