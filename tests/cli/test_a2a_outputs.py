"""O4 spec 6.10 and claims W1 (output part), C1: what the text, Markdown, SARIF and Code Quality reports say about agent cards,
the key source next to every signature status, the note on remote agents, and the escaping of every string from a card."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from a2a_cards import card_bytes, clean_card

from spellwarden_scan import CardOrigin, RuleSet, SignatureOutcome, __version__, evaluate_agent_card, parse_agent_card
from spellwarden_scan.model import Finding, Location

from spellwarden_cli.output import FORMATS, agents as agent_view
from spellwarden_cli.report import AgentReport, LockState, Notice, Report, ReportFinding, to_json_dict

RULES = RuleSet.baseline()
HOSTILE = "a\tb\nc\x1b[31m|`x``<script>@channel\u202e.sh"
SIGNED = Path(__file__).resolve().parents[1] / "fixtures" / "a2a" / "signed"
SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(encoding="utf-8"))


def report_of(*agents: AgentReport, findings=(), notices=()) -> Report:
    return Report(scanner_version=__version__, rules_version="2026.10.5", as_of="2026-10-26", fail_on="high", items=(),
                  findings=tuple(findings), probes=(), lock=LockState(), notices=tuple(notices), errors=(), repo_prefix="",
                  rules=RULES, agents=tuple(agents)).sorted()


def agent_of(content: bytes, path: str, outcomes=(), *, source: str = "repository", origin: CardOrigin | None = None,
             counts: bool = True) -> tuple[AgentReport, list[ReportFinding]]:
    origin = origin or CardOrigin("repository", "well_known")
    result = evaluate_agent_card(parse_agent_card(path, content), RULES, origin=origin, signatures=outcomes, location_path=path)
    item = f"a2a-card:{path}" if source == "repository" else f"a2a-agent:{path}"
    report = AgentReport(item, source, origin.path_form, "checked", result=result, counts_toward_exit=counts)
    return report, [ReportFinding(finding, item) for finding in result.findings]


def verified(source: str, form: str = "as_served", unsigned=()) -> tuple[SignatureOutcome, ...]:
    return (SignatureOutcome(0, "ES256", "k1", None, source, "verified", form, tuple(unsigned)),)


def signed_card() -> bytes:
    return card_bytes({**clean_card(), "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c2ln"}]})


def test_the_text_report_has_a_section_with_the_key_source_next_to_the_signature_status():
    keys, jku = agent_of(signed_card(), "a/agent-card.json", verified("keys_file")), agent_of(
        signed_card(), "b/agent-card.json", verified("jku", "spec", ["/x-vendor"]))
    text = FORMATS["text"](report_of(keys[0], jku[0]))
    assert "A2A agent cards\n" in text
    assert "a2a-card:a/agent-card.json (repository, well_known): format 1.0, protocol 1.0, migration ready" in text
    assert "    signature verified with the trusted key file" in text
    assert "    signature verified with the key set the card names" in text
    assert "    verified without these members: /x-vendor" in text
    assert "    13. Re-run the Spellwarden scan" in text
    assert text.index("A2A agent cards") < text.index("0 findings") and "Findings on remote agents" not in text


def test_an_unverified_signature_says_how_to_verify_it():
    unverified = (SignatureOutcome(0, "ES256", "k1", "https://a.example/jwks.json", None, "key_unavailable", detail="no_key_source"),)
    text = FORMATS["text"](report_of(agent_of(signed_card(), "c/agent-card.json", unverified)[0]))
    assert "signature not verified (no_key_source); to verify it, set a2a.keys to a key file of the repository, or run with --probe" in text
    markdown = FORMATS["markdown"](report_of(agent_of(signed_card(), "c/agent-card.json", unverified)[0]))
    assert "set a2a.keys to a key file of the repository, or run with \\-\\-probe" in markdown or "run with --probe" in markdown


def test_skipped_and_failed_agents_say_why_and_a_not_signed_card_says_so():
    skipped = AgentReport("a2a-agent:https://a.example/", "remote", "well_known", "skipped", skip_reason="probe_off")
    failed = AgentReport("a2a-agent:https://b.example/", "remote", "direct", "failed", fail_reason="http_status",
                         fetch={"requested_url": "https://b.example/c.json", "final_url": None, "http_status": 500})
    unsigned = agent_of(card_bytes(clean_card()), "p/agent-card.json")[0]
    text = FORMATS["text"](report_of(skipped, failed, unsigned))
    assert "a2a-agent:https://a.example/ (remote agent, well_known): skipped (probe_off)" in text
    assert "a2a-agent:https://b.example/ (remote agent, direct): failed (http_status 500)" in text
    assert "    not signed" in text


def test_the_remote_note_appears_in_text_and_markdown_only_when_a_remote_agent_does_not_count():
    counting, _ = agent_of(card_bytes(clean_card()), "https://c.example/", source="remote",
                           origin=CardOrigin("remote", "well_known", "https://c.example/", "https://c.example/x"))
    exempt = AgentReport(counting.item, "remote", "well_known", "checked", result=counting.result, counts_toward_exit=False)
    for fmt in ("text", "markdown"):
        assert agent_view.REMOTE_NOTE not in FORMATS[fmt](report_of(counting))
        assert agent_view.REMOTE_NOTE in FORMATS[fmt](report_of(exempt))
    assert agent_view.REMOTE_NOTE == "Findings on remote agents do not fail a pull or merge request; they fail the default-branch run."


def test_the_markdown_report_has_a_table_and_what_each_agent_still_needs():
    card = {**clean_card(), "url": "https://agent.example.com/", "security": []}
    legacy = agent_of(card_bytes(card), "x/agent-card.json")[0]
    ready = agent_of(signed_card(), "y/agent-card.json", verified("keys_file"))[0]
    markdown = FORMATS["markdown"](report_of(legacy, ready))
    assert "**A2A agent cards:**" in markdown and "| Agent | Origin | Card | Signature |" in markdown
    assert "| `a2a-card:y/agent-card.json` | repository, well\\_known | format 1.0, protocol 1.0, migration ready |" in markdown
    assert "signature verified with the trusted key file" in markdown
    assert "- 2. Move url, preferredTransport and additionalInterfaces" in markdown and "- 6. Rename security to securityRequirements" in markdown
    assert markdown.index("**A2A agent cards:**") < markdown.index("Spellwarden " + __version__)


def test_every_string_from_a_card_is_escaped_in_both_formats():
    hostile = SignatureOutcome(0, "ES256", "k1", None, "keys_file", "verified", "spec", (f"/x-{HOSTILE}",))
    report = agent_of(signed_card(), f"a/{HOSTILE}/agent-card.json", (hostile,))[0]
    text, markdown = FORMATS["text"](report_of(report)), FORMATS["markdown"](report_of(report))
    for out in (text, markdown):
        assert "\x1b" not in out and "\u202e" not in out and "\t" not in out
    assert "\\x1b" in text and "\\u{202E}" in text  # a terminal sees the escape written out, never the control character
    assert "&lt;script&gt;" in markdown  # outside a code span the HTML is escaped; inside one it is literal text



def test_long_members_are_cut_to_300_characters():
    hostile = SignatureOutcome(0, "ES256", "k1", None, "keys_file", "verified", "spec", ("/" + "m" * 1000,))
    view = agent_view.view_of(agent_of(signed_card(), "a/agent-card.json", (hostile,))[0])
    assert len(view.unsigned[0]) == 300 and view.unsigned[0].endswith("...")


def test_sarif_gives_a_remote_agent_a_logical_location_and_a_repository_card_a_physical_file():
    card, repo_findings = agent_of(card_bytes({**clean_card(), "supportedInterfaces": [
        {"url": "http://agent.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}), "card/agent-card.json")
    origin = CardOrigin("remote", "well_known", "https://agent.example.com/", "https://agent.example.com/.well-known/agent-card.json")
    remote, remote_findings = agent_of(card_bytes(clean_card()), "https://agent.example.com/", source="remote", origin=origin)
    remote_findings = [ReportFinding(Finding(f.finding.rule_id, f.finding.severity, f.finding.title, Location(".spellwarden/config.yml"),
                                             f.finding.evidence, f.finding.fingerprint), f.item) for f in remote_findings]
    document = json.loads(FORMATS["sarif"](report_of(card, remote, findings=[*repo_findings, *remote_findings])))
    results = document["runs"][0]["results"]
    by_item = {result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: result for result in results}
    assert "logicalLocations" not in by_item["card/agent-card.json"]["locations"][0]
    logical = by_item[".spellwarden/config.yml"]["locations"][0]["logicalLocations"]
    assert logical == [{"fullyQualifiedName": "a2a-agent:https://agent.example.com/", "kind": "resource"}]
    rules = {rule["id"]: rule for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    assert len([rule for rule in rules if rule.startswith("SW-A2A")]) == 19
    assert rules["SW-A2A-015"]["properties"]["security-severity"] == "9.5" and "ASI03" in rules["SW-A2A-015"]["properties"]["tags"]


def test_code_quality_lists_the_agent_card_findings_like_any_other():
    card, findings = agent_of(card_bytes(clean_card()), "card/agent-card.json")
    entries = json.loads(FORMATS["gitlab-codequality"](report_of(card, findings=findings)))
    assert [entry["check_name"] for entry in entries] == ["SW-A2A-012"] and entries[0]["severity"] == "info"


def test_the_json_report_with_agents_validates_against_the_schema_and_a_report_without_has_no_agents_key():
    card, findings = agent_of(signed_card(), "card/agent-card.json", verified("keys_file"))
    skipped = AgentReport("a2a-agent:https://a.example/", "remote", "direct", "skipped", skip_reason="fork")
    failed = AgentReport("a2a-agent:https://b.example/", "remote", "well_known", "failed", fail_reason="timeout",
                         fetch={"requested_url": "https://b.example/.well-known/agent-card.json", "final_url": None, "http_status": None})
    document = to_json_dict(report_of(skipped, failed, card, findings=findings, notices=[Notice("a2a_agents_need_probe", "", "m")]))
    jsonschema.validate(document, SCHEMA)
    assert [agent["item"] for agent in document["agents"]] == sorted(agent["item"] for agent in document["agents"])
    assert "agents" not in to_json_dict(report_of())
