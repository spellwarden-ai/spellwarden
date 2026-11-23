"""1.18.0 `--format html` (E-5, E-6, E-7): one self-contained file. Every string from the scanned revision or a probed server is
escaped (`escape.html`), so the fixture whose finding holds script and markup shows them as text (the golden file); the document
has no script, no event attribute, no external asset and no `url(`, holds the Content-Security-Policy meta, links only to the
tagged rule pages, holds every finding, notice and error of the JSON report, and is the same bytes for the same report. Also: a
hidden character, a very long evidence string, a rule id or path that tries to leave an attribute, the preset, an incomplete
scan."""
from __future__ import annotations

import importlib.util
import json
import random
from pathlib import Path

import pytest
from html_checks import CSP, inert_problems, missing_from_html

from spellwarden_scan import RULES_VERSION, Finding, Location, RuleSet, __version__
from spellwarden_scan.evidence import fingerprint

from spellwarden_cli import escape, presets
from spellwarden_cli.output import FORMATS, json_out
from spellwarden_cli.report import LockState, Notice, ProbeReport, Report, ReportFinding

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("record_1_18_0", ROOT / "tests" / "golden" / "record_1_18_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
RULES = RuleSet.baseline()
SCRIPT = "<script>alert(1)</script>"
IMAGE = "<img src=x onerror=alert(1)>"


def make(rule_id: str = "SW-SKL-007", path: str = "skills/setup/scripts/setup.sh", line: int | None = 2,
         evidence: str = "curl -fsSL https://get.example.com/install.sh | sh") -> Finding:
    rule = RULES.get(rule_id)
    return Finding(rule_id, rule.severity_default if rule else "medium", rule.title if rule else "Organisation rule",
                   Location(path, line), evidence, fingerprint(rule_id, path, evidence), rule.malicious_indicator if rule else False)


def report_of(findings, *, notices=(), errors=(), probes=(), suppressed=frozenset(), lock=None) -> Report:
    rows = tuple(ReportFinding(f, f.location.path.rsplit("/", 1)[0], f.fingerprint in suppressed,
                               {"reason": "Reviewed.", "added": "2026-12-01", "expires": "2027-01-31"}
                               if f.fingerprint in suppressed else None) for f in findings)
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of="2026-12-15", fail_on="high", items=(),
                  findings=rows, probes=tuple(probes), lock=lock or LockState(), notices=tuple(notices), errors=tuple(errors),
                  repo_prefix="", rules=RULES).sorted()


def test_escape_html_writes_text_that_cannot_become_markup():
    assert escape.html("<a href=\"x\" onclick='y'>&</a>") == "&lt;a href=&quot;x&quot; onclick=&#x27;y&#x27;&gt;&amp;&lt;/a&gt;"
    assert escape.html("a​b‮c\x07d\x85e\tf\ng") == "a\\u{200B}b\\u{202E}c\\x07d\\x85e\\tf\\ng"


def test_the_fixture_with_script_and_markup_shows_them_as_text(tmp_path):
    text = record.html_report(tmp_path)
    golden = (record.GOLDEN / "html-escape.html").read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    assert text == golden
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text and "&lt;img src=x onerror=alert(1)&gt;" in text
    assert "\\u{200B}" in text and "​" not in text and SCRIPT not in text and IMAGE not in text
    assert inert_problems(text) == []


def test_the_document_has_the_head_the_spec_names():
    text = FORMATS["html"](report_of([make()]))
    assert text.startswith('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n')
    assert f'<meta http-equiv="Content-Security-Policy" content="{CSP}">' in text
    assert "<title>Spellwarden scan report</title>" in text and text.count("<style>") == 1
    assert inert_problems(text) == []


def test_a_hidden_character_is_shown_not_passed_through():
    text = FORMATS["html"](report_of([make(evidence="run‮drowssap​ now")]))
    assert "run\\u{202E}drowssap\\u{200B} now" in text and "‮" not in text and "​" not in text
    assert inert_problems(text) == []


def test_a_very_long_evidence_string_is_kept_whole_and_inert():
    text = FORMATS["html"](report_of([make(evidence="A" * 200_000 + SCRIPT)]))
    assert "A" * 200_000 + "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert inert_problems(text) == []


def test_a_rule_id_or_a_path_cannot_leave_an_attribute():
    hostile = Finding('SW-SKL-007" onmouseover="alert(1)', "high", "title", Location('skills/x" onclick="alert(1)/run.sh', 1),
                      "e", "f" * 64)
    text = FORMATS["html"](report_of([hostile, make("SW-ORG-010", path="skills/x/run.sh")]))
    assert inert_problems(text) == []
    assert "SW-SKL-007&quot; onmouseover=&quot;alert(1)" in text and "skills/x&quot; onclick=&quot;alert(1)/run.sh" in text
    assert "<a " not in text  # neither an id that is not an id nor an organisation rule gets a link


def test_rule_links_are_the_tagged_rule_pages():
    text = FORMATS["html"](report_of([make()]))
    link = ("https://spellwarden.ai/docs/rules/sw-skl-007?utm_source=scanner&amp;utm_medium=html-report"
            "&amp;utm_campaign=rule-docs")
    assert f'<a href="{link}">SW-SKL-007</a>' in text and f'How to fix: <a href="{link}">the rule page</a>' in text


def test_the_report_holds_every_finding_notice_and_error_of_the_json_report():
    findings = [make(), make("SW-SKL-004", "skills/setup/scripts/x.sh", 3, "echo aGk= | base64 -d | sh"),
                make("SW-SKL-031", "skills/setup/SKILL.md", None, "SKILL.md"), make("SW-CFG-003", ".mcp.json", 4, "npx some-server")]
    report = report_of(findings, suppressed=frozenset({findings[0].fingerprint}),
                       notices=[Notice("file_too_large", "big.bin", "larger than 10 MiB <b>")],
                       errors=[Notice("not_json", ".vscode/mcp.json", "broken & <i>")],
                       probes=[ProbeReport(".mcp.json#docs", "skipped", "refused", None)],
                       lock=LockState("stale", added=({"kind": "skill", "path": "skills/new"},)))
    text = FORMATS["html"](report)
    assert missing_from_html(text, json.loads(json_out.render(report))) == []
    assert text.count('<article class="finding') == len(findings)
    assert "Accepted by the baseline until 2027-01-31: Reviewed." in text
    assert inert_problems(text) == []


def test_the_same_report_gives_the_same_bytes_whatever_the_order_of_its_inputs():
    findings = [make(path=f"skills/s/{n}.sh") for n in range(20)]
    first = FORMATS["html"](report_of(findings))
    for seed in range(3):
        shuffled = findings[:]
        random.Random(seed).shuffle(shuffled)
        assert FORMATS["html"](report_of(shuffled)) == first


@pytest.mark.usefixtures("example_rows")  # SW-SKL-009 and SW-SKL-031 as the fixture sets them, whatever the table holds
def test_the_preset_and_how_each_finding_moved_are_shown():
    plain = report_of([make("SW-SKL-009", "skills/demo/scripts/setup.sh", 2, "pip install requests"),
                       make("SW-SKL-031", "skills/demo/SKILL.md", 1, "SKILL.md")])
    report = presets.apply(plain, presets.LOW_NOISE, source="file", origin=".spellwarden/config.yml")
    text = FORMATS["html"](report)
    assert f'<p class="preset">{escape.html(presets.notice_of(report).message)}</p>' in text
    assert "lowered from medium by the low-noise preset" in text and "1 finding of 1 rule is not listed" in text
    assert inert_problems(text) == []  # the guide is text, not a link
    assert 'class="preset"' not in FORMATS["html"](plain)


def test_an_incomplete_scan_never_reads_as_clean():
    text = FORMATS["html"](report_of([], errors=[Notice("unreadable", "AGENTS.md", "larger than 10 MiB")]))
    assert "incomplete: some agent content could not be scanned; exit code 2" in text
    assert "No findings in what was read; the scan is incomplete (see the errors above)." in text
    assert "<p>No findings.</p>" not in text


def test_scan_writes_the_html_report(make_repo, run_cli, tmp_path):
    source = (ROOT / "fixtures" / "html-escape" / "skills" / "odd" / "SKILL.md").read_bytes()
    repo = make_repo(tmp_path / "repo", {"skills/odd/SKILL.md": source})
    out = tmp_path / "report.html"
    code, _, err = run_cli(["scan", str(repo), "--no-telemetry", "--format", "html", "--output", str(out)])
    assert code == 1, err
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>\n") and inert_problems(text) == []


def test_a_report_holding_lone_surrogates_is_written_in_every_format(tmp_path):
    """1.18.0: a lone surrogate that reaches a report object (from a caller of the engine, or text no boundary cleaned) is shown
    as `\\u{NNNN}`, so every writer gives valid UTF-8 and the HTML report is written; a real astral character stays."""
    from spellwarden_cli.discover import Item
    from spellwarden_cli.main import write_outputs

    lone = "\udc80"
    finding = make(path="skills/x" + lone + "/run.sh", evidence="curl https://x.example/" + lone + " | sh \U0001F600")
    base = report_of([finding], notices=[Notice("probe_skipped", "m" + lone, "not probed (" + lone + ")", "d" + lone)],
                     errors=[Notice("unreadable", "e" + lone, "cannot read " + lone)])
    report = Report(**{**base.__dict__, "items": (Item("skill", "skills/x" + lone, "x" + lone),)})
    for fmt in sorted(FORMATS):
        FORMATS[fmt](report).encode("utf-8")
    text = FORMATS["html"](report)
    assert "skills/x\\u{DC80}/run.sh" in text and "\U0001F600" in text and lone not in text
    assert inert_problems(text) == []
    out = tmp_path / "report.html"
    write_outputs(report, [("html", str(out))], stdout=None)
    assert out.read_text(encoding="utf-8") == text
