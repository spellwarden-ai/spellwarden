"""Phase 3 batch 2a spec 11.3 and 11.6: the report fields of `scan --user` exist, are written only in a `--user` report, and the
schema and the code lists agree; the three user-only instruction formats say when they apply."""
from __future__ import annotations

import json
from pathlib import Path

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

from spellwarden_cli import instruction_files
from spellwarden_cli.discover import Item
from spellwarden_cli.report import ERROR_CODES, NOTICE_CODES, LockState, Report, to_json_dict

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(encoding="utf-8"))


def report(items=(), clients=None) -> Report:
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of="2026-11-14", fail_on="high",
                  items=tuple(items), findings=(), probes=(), lock=LockState(), notices=(), errors=(), repo_prefix=None,
                  rules=RuleSet.baseline(), clients=clients)


def test_a_repository_item_and_report_carry_none_of_the_new_fields():
    document = to_json_dict(report([Item("mcp-server", ".mcp.json#files", "files")]))
    assert document["items"] == [{"kind": "mcp-server", "path": ".mcp.json#files", "name": "files", "plugin": None}]
    assert "clients" not in document


def test_a_user_item_carries_its_clients_and_scope_and_the_report_its_client_list():
    item = Item("mcp-server", "~/.claude.json#~/work/app#db", "db", clients=("claude-code",), scope="~/work/app")
    clients = ({"client": "claude-code", "found": True, "roots": ["~/.claude.json"]},
               {"client": "cursor", "found": False, "roots": []})
    document = to_json_dict(report([item], clients=clients))
    assert document["items"] == [{"kind": "mcp-server", "path": "~/.claude.json#~/work/app#db", "name": "db", "plugin": None,
                                  "clients": ["claude-code"], "scope": "~/work/app"}]
    assert document["clients"] == [dict(entry) for entry in clients]


def test_the_schema_lists_the_new_codes_formats_and_clients():
    defs = SCHEMA["$defs"]
    assert defs["error"]["properties"]["code"]["enum"] == list(ERROR_CODES)
    assert defs["item"]["properties"]["format"]["enum"] == list(instruction_files.FORMATS)
    assert defs["client_name"]["enum"] == ["claude-code", "claude-desktop", "cursor", "vscode", "windsurf", "codex", "gemini-cli"]
    for code in ("user_instructions_limit", "user_skills_limit", "workstation_no_credential", "workstation_label_missing",
                 "workstation_upload_too_large", "workstation_upload_failed"):
        assert code in ERROR_CODES
    assert {"workstation_uploaded", "client_not_found"} <= set(NOTICE_CODES)


def test_the_user_only_instruction_formats_say_when_they_apply():
    scoped, readable = instruction_files.front_matter_of("claude-rule", b"---\npaths:\n  - \"src/**/*.ts\"\n---\n# Rule\n")
    assert readable and scoped["globs"] == ["src/**/*.ts"]
    assert instruction_files.instruction_scope("claude-rule", "~/.claude/rules/ts.md", scoped) == \
        "Applied to files matching: src/**/*.ts"
    assert instruction_files.instruction_scope("claude-rule", "~/.claude/rules/all.md", None) == instruction_files.ALWAYS
    assert instruction_files.instruction_scope("codex-agents-md", "~/.codex/AGENTS.md", None) == instruction_files.ALWAYS
    assert instruction_files.instruction_scope("windsurf-rules", "~/.codeium/windsurf/memories/global_rules.md", None) == \
        instruction_files.ALWAYS
    assert instruction_files.instruction_scope("devin-rules", "~/.devin/global_rules.md", None) == instruction_files.ALWAYS
    manual, _ = instruction_files.front_matter_of("devin-rules", b"---\ntrigger: manual\n---\nx\n")
    assert instruction_files.instruction_scope("devin-rules", "~/.devin/rules/x.md", manual) == instruction_files.ASKED
    # a repository file keeps its 1.13.0 scope: `global_rules.md` under `.windsurf/rules/` is a rule like any other
    assert instruction_files.instruction_scope("windsurf-rules", ".windsurf/rules/global_rules.md", None) == instruction_files.ASKED
    assert instruction_files.format_of(".claude/rules/x.md") is None  # the user formats are never given by a path
