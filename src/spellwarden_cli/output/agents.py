"""What the text and Markdown reports say about each A2A agent (O4 spec 6.10): one description both formats render, so that they
cannot disagree. Plain strings, not yet escaped: every string from a card is cut to 300 characters here and escaped by the
caller (`escape.terminal`, `escape.markdown`)."""
from __future__ import annotations

from dataclasses import dataclass

from spellwarden_cli.report import AgentReport, Report

CUT = 300
KEY_SOURCES = {"keys_file": "the trusted key file", "jku": "the key set the card names"}
HOW_TO_VERIFY = "set a2a.keys to a key file of the repository, or run with --probe to fetch the key set the card names"
REMOTE_NOTE = "Findings on remote agents do not fail a pull or merge request; they fail the default-branch run."
SOURCES = {"repository": "repository", "remote": "remote agent"}


def short(text: object) -> str:
    text = str(text)
    return text if len(text) <= CUT else text[:CUT - 3] + "..."


@dataclass(frozen=True)
class AgentView:
    item: str
    origin: str
    summary: str
    signature: str | None
    unsigned: tuple[str, ...]
    checklist: tuple[str, ...]


def signature_text(agent: AgentReport) -> str | None:
    """The signature status with the key source next to it (6.6 step 5); when unverified, how to verify."""
    result = agent.result
    if result is None:
        return None
    outcomes = result.signatures
    status = result.signature_status
    if status == "unsigned":
        return "not signed"
    if status == "verified":
        verified = next(o for o in outcomes if o.outcome == "verified")
        return f"signature verified with {KEY_SOURCES.get(verified.key_source or '', 'a key')}"
    if status == "invalid":
        failed = {o.outcome.replace("_", " ") for o in outcomes if o.outcome not in ("no_key", "key_unavailable")}
        return f"signature invalid ({short(', '.join(sorted(failed)))})"
    if status == "refused":
        return "signature refused: " + short("; ".join(o.detail or o.outcome.replace("_", " ") for o in outcomes if o.outcome in (
            "malformed", "refused_alg")))
    reasons = sorted({o.detail or o.outcome.replace("_", " ") for o in outcomes})
    how = f"; to verify it, {HOW_TO_VERIFY}" if any(o.detail == "no_key_source" for o in outcomes) else ""
    return f"signature not verified ({short(', '.join(reasons))}){how}"


def view_of(agent: AgentReport) -> AgentView:
    origin = SOURCES[agent.source] + (f", {agent.path_form}" if agent.path_form else "")
    result = agent.result
    if result is None:
        why = agent.skip_reason if agent.status == "skipped" else agent.fail_reason
        extra = f" {agent.fetch['http_status']}" if agent.fetch and agent.fetch.get("http_status") else ""
        return AgentView(agent.item, origin, f"{agent.status} ({why}{extra})", None, (), ())
    unsigned = tuple(short(pointer) for outcome in result.signatures for pointer in outcome.unsigned_members)
    versions = ", ".join(result.protocol_versions) or "none declared"
    summary = f"format {result.card_format}, protocol {versions}, migration {result.migration_status}"
    checklist = tuple(f"{item.order}. {short(item.text)}" for item in result.checklist)
    return AgentView(agent.item, origin, summary, signature_text(agent), unsigned, checklist)


def views(report: Report) -> list[AgentView]:
    return [view_of(agent) for agent in report.agents]


def remote_note_applies(report: Report) -> bool:
    return any(not agent.counts_toward_exit for agent in report.agents)
