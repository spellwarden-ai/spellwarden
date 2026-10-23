"""O3 spec 6.6 and 6.10 ("Not admitted" section), claim E10, plan Task 9: the registry gate. The candidates of a run, the
scope on a request, the check, the SW-REG findings and their baseline rule. The API is `FakeApi` behind the transport
seams of `connected.py`; a call nobody scripted fails the test, so "no call" is asserted by not scripting it."""
from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import jsonschema
import pytest
from conftest import (CHECK_PATH, EXCHANGE_PATH, HEAD, POLICY_PATH, SHA, admit_all, connected_github, connected_gitlab, git, policy_answer, scan_json,
                      session_answer, write_tree)

from spellwarden_scan import identity as ident
from spellwarden_scan.gate import GATE_REASONS, gate_finding, resolver_binding, unhashable_binding
from spellwarden_cli import ci, files, probing
from spellwarden_cli.output import markdown

DASH = "https://dash.spellwarden.ai/acme"
ID_TOKEN = "id.jwt." + "x" * 20
SKILL = "---\nname: {name}\ndescription: Does {name}.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\nRun it.\n"
PINNED_UVX = {"command": "uvx", "args": ["mcp-server-git==0.6.2"]}
PIN = "ab" * 20
OTHER_PIN = "cd" * 20
MARKETPLACES = {"acme-tools": {"source": {"source": "github", "repo": "acme/claude-tools", "sha": PIN}}}


def skill(name: str) -> str:
    return SKILL.format(name=name)


def mcp(servers: dict) -> str:
    return json.dumps({"mcpServers": servers}, indent=2) + "\n"


def marketplace(plugins: list[dict]) -> str:
    return json.dumps({"name": "m", "plugins": plugins}, indent=2) + "\n"


def settings_json(markets: dict | None = None, enabled: dict | None = None) -> str:
    document: dict = {}
    if markets is not None:
        document["extraKnownMarketplaces"] = markets
    if enabled is not None:
        document["enabledPlugins"] = enabled
    return json.dumps(document, indent=2) + "\n"


def env_of(**more: str) -> dict[str, str]:
    """A push to the default branch of a GitLab project: a `default_branch` run, so the scope is `all`."""
    return connected_gitlab(SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN, **more)


def request_env(tmp_path: Path, base: str, **more: str) -> dict[str, str]:
    payload = {"pull_request": {"number": 3, "head": {"repo": {"full_name": "acme/tools"}, "sha": HEAD, "ref": "feature/x"},
                                "base": {"sha": base}}, "repository": {"default_branch": "main"}}
    return connected_github(tmp_path, "pull_request", payload, GITHUB_HEAD_REF="feature/x", GITHUB_REF_NAME="3/merge",
                            SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN, **more)


def commit(repo: Path, files_: dict[str, str | None], message: str = "head") -> str:
    for path, content in files_.items():
        if content is None:
            git(repo, "rm", "-q", "--", path)
    write_tree(repo, {path: content for path, content in files_.items() if content is not None})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD").strip()


def check_answer(**lists: list) -> dict:
    """A check answer: per list, one entry per sent item, in order; None is admitted, a string is the request URL (the
    URL template for servers) of an item that is not."""
    answer: dict = {"schema": 1}
    for name in ("skills", "servers", "stdio", "plugins", "marketplaces"):
        items = []
        for entry in lists.get(name, []):
            if entry is None:
                items.append({"path": "", "admitted": True, "exported_name": None, "request_url": None})
            else:
                key = "request_url_template" if name == "servers" else "request_url"
                items.append({"path": "", "admitted": False, "exported_name": None, key: entry})
        answer[name] = items
    return answer


def serve(fake, answer: dict | None = None, *, policy: dict | None = None, session_run: dict | None = None) -> None:
    fake.script("POST", EXCHANGE_PATH, 201, session_answer(run=session_run or {
        "identity": "gitlab:gitlab.com/acme/tools", "event": "push"}))
    fake.script("GET", POLICY_PATH, 200, policy or policy_answer([]))
    if answer is not None:
        fake.script("POST", CHECK_PATH, 200, answer)


def checks(fake) -> list[dict]:
    return [request[3] for request in fake.requests if request[1] == CHECK_PATH]


def block(report: dict) -> dict:
    return report["connected"]["registry"]


def codes(entries: list[dict]) -> list[str]:
    return [entry["code"] for entry in entries]


def regs(report: dict) -> list[dict]:
    return [f for f in report["findings"] if f["rule_id"].startswith("SW-REG")]


ALL = policy_answer([], gate={"scope": "all"})  # the gate judges every item of a request, changed or not


def base_repo(make_repo, tmp_path: Path, extra: dict | None = None) -> Path:
    return make_repo(tmp_path / "repo", {
        "skills/deploy/SKILL.md": skill("deploy"), "skills/review/SKILL.md": skill("review"),
        ".mcp.json": mcp({"docs": {"url": "https://mcp.example.com/docs?b=2&a=1"}, "git": PINNED_UVX}),
        ".claude-plugin/marketplace.json": marketplace([
            {"name": "lint", "source": {"source": "github", "repo": "acme/lint", "sha": PIN}}]),
        ".claude/settings.json": settings_json(MARKETPLACES, {"lint@acme-tools": True}),
        **(extra or {})})


# --- candidates and the check body -----------------------------------------------------------------------------------

def test_candidates_per_kind_and_the_check_body(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, check_answer(skills=[None, None], servers=[None], stdio=[None], plugins=[None], marketplaces=[None]))
    repo = base_repo(make_repo, tmp_path)
    code, report, out, err = scan_json(run_cli, repo, env_of())
    assert code == 0, err
    (body,) = checks(fake)
    url = "https://mcp.example.com/docs?b=2&a=1"
    assert body["schema"] == 1
    assert body["repository"] == {"identity": "gitlab:gitlab.com/acme/tools", "scope": "", "head_sha": SHA, "visibility": "private"}
    package = lambda name: ident.package_sha256({"SKILL.md": skill(name).encode()})  # noqa: E731
    assert body["skills"] == [{"path": "skills/deploy", "name": "deploy", "identity": package("deploy"), "links": False},
                              {"path": "skills/review", "name": "review", "identity": package("review"), "links": False}]
    assert [(s["path"], s["name"], s["identity"]) for s in body["servers"]] == [(".mcp.json", "docs", ident.server_identity(url))]
    assert isinstance(body["servers"][0]["line"], int)
    assert url not in json.dumps(fake.requests) and "mcp.example.com" not in json.dumps(fake.requests)  # only the hash leaves
    assert [(s["path"], s["name"], s["identity"]) for s in body["stdio"]] == [
        (".mcp.json", "git", "cmd:uvx mcp-server-git==0.6.2")]
    assert [(p["path"], p["name"], p["identity"], p["source_url"], p["pin"]) for p in body["plugins"]] == [
        (".claude-plugin/marketplace.json", "lint", f"git:https://github.com/acme/lint@{PIN}", "https://github.com/acme/lint", PIN)]
    assert [(m["path"], m["name"], m["identity"], m["source_url"], m["pin"]) for m in body["marketplaces"]] == [
        (".claude/settings.json", "acme-tools", f"git:https://github.com/acme/claude-tools@{PIN}",
         "https://github.com/acme/claude-tools", PIN)]
    registry = block(report)
    assert registry["checked"] == 6 and registry["not_admitted"] == 0 and registry["unidentified"] == 0
    assert registry["out_of_scope"] == 0 and registry["gate"] is True and registry["scope_applied"] == "all"
    market = next(item for item in registry["items"] if item["kind"] == "marketplace")
    assert market["enabled_plugins"] == ["lint"]  # enabledPlugins are listed under their marketplace
    assert regs(report) == []
    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(report, schema)  # the registry block and its items are what the schema describes


def test_gate_stdio_false_and_gate_plugins_false_drop_those_kinds(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, check_answer(skills=[None, None], servers=[None]),
          policy=policy_answer([], gate={"stdio": False, "plugins": False}))
    code, report, _, _ = scan_json(run_cli, base_repo(make_repo, tmp_path), env_of())
    (body,) = checks(fake)
    assert code == 0 and body["stdio"] == [] and body["plugins"] == [] and body["marketplaces"] == []
    assert block(report)["stdio"] is False and block(report)["plugins"] is False
    assert {item["kind"] for item in block(report)["items"]} == {"skill", "server"}


def test_undeclared_marketplace_is_inventory_with_plugin_marketplace_unknown(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    repo = make_repo(tmp_path / "repo", {".claude/settings.json": settings_json(enabled={"lint@elsewhere": True})})
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    assert code == 0 and checks(fake) == []  # nothing to judge, so no call
    unknown = next(n for n in report["notices"] if n["code"] == "plugin_marketplace_unknown")
    assert unknown["path"] == ".claude/settings.json" and "lint@elsewhere" in unknown["message"]


UNHASHABLE_SKILL = {"skills/deploy/SKILL.md": skill("deploy")}


def test_each_unidentifiable_case_is_sw_reg_003_with_its_reason_and_no_call(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)  # no check is scripted: any call fails the test
    servers = {
        "hosted": {"url": "https://${HOST}/mcp"}, "badport": {"url": "https://mcp.example.com:99999/mcp"},
        "plain": {"url": "http://mcp.example.com/mcp"},
        "loose": {"command": "npx", "args": ["x"]}, "node": {"command": "node", "args": ["server.js"]},
        "override": {"command": "npx", "args": ["-y", "@acme/fs@1.2.3"], "env": {"NODE_OPTIONS": "--require ./x.js"}},
        "mirror": PINNED_UVX,
    }
    repo = make_repo(tmp_path / "repo", {".mcp.json": mcp(servers), "pip.conf": "[global]\nindex-url = https://pip.example.com/simple\n"})
    code, report, _, err = scan_json(run_cli, repo, env_of())
    assert code == 1, err
    by_name = {f["evidence"].split(": ")[0]: f["evidence"].split(": ", 1)[1] for f in regs(report)}
    assert by_name == {"hosted": "unresolved", "badport": "unresolved", "plain": "insecure", "loose": "unpinned",
                       "node": "unknown_launcher", "override": "launch_override", "mirror": "resolver_override"}
    assert all(f["rule_id"] == "SW-REG-003" and f["severity"] == "high" for f in regs(report))
    assert block(report)["checked"] == 0 and block(report)["unidentified"] == 7 and checks(fake) == []


def test_unhashable_skill_from_a_dependency_directory_in_the_git_listing(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    repo = make_repo(tmp_path / "repo", {**UNHASHABLE_SKILL, "skills/deploy/node_modules/dep/index.js": "x\n"})
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    (finding,) = regs(report)
    assert code == 1 and finding["rule_id"] == "SW-REG-003" and finding["location"] == {"path": "skills/deploy", "line": None}
    assert finding["evidence"] == "deploy (skills/deploy/node_modules): unhashable" and finding["item"] == "skills/deploy"
    assert checks(fake) == []


def test_unhashable_skill_when_the_walk_skipped_a_dependency_directory(tmp_path, run_cli, api_double):
    fake, _ = api_double
    serve(fake)
    repo = write_tree(tmp_path / "plain", {**UNHASHABLE_SKILL, "skills/deploy/node_modules/dep/index.js": "x\n"})
    if files.work_tree_top(str(repo)) is not None:
        pytest.skip("the temporary directory is inside a git work tree")
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    (finding,) = regs(report)
    assert code == 1 and finding["evidence"] == "deploy (skills/deploy/node_modules): unhashable"


@pytest.mark.parametrize("config, dropped", [
    ("version: 1\nexclude:\n  - \"**/*.js\"\n", "skills/deploy/run.js"),
    ("version: 1\ninclude:\n  - \"**/*.md\"\n", "skills/deploy/run.js"),
], ids=["exclude", "include"])
def test_unhashable_skill_when_the_settings_drop_one_of_its_files(config, dropped, make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    repo = make_repo(tmp_path / "repo", {**UNHASHABLE_SKILL, "skills/deploy/run.js": "x\n", ".spellwarden/config.yml": config})
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    (finding,) = regs(report)
    assert code == 1 and finding["evidence"] == f"deploy ({dropped}): unhashable"


def test_unhashable_skill_with_an_unfollowed_member_link(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    repo = tmp_path / "repo"
    write_tree(repo, UNHASHABLE_SKILL)
    try:
        os.symlink("../../../outside", repo / "skills" / "deploy" / "ext")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    make_repo(repo, {})
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    (finding,) = regs(report)
    assert code == 1 and finding["evidence"] == "deploy (skills/deploy/ext): unhashable"


def _real_git_repo(make_repo, tmp_path: Path, extra: dict) -> Path:
    return make_repo(tmp_path / "repo", {**UNHASHABLE_SKILL, **extra})


def test_export_attributes_make_a_skill_unhashable_through_git_check_attr(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    repo = _real_git_repo(make_repo, tmp_path, {
        "skills/deploy/.gitattributes": "docs/** export-ignore\n", "skills/deploy/docs/notes.md": "n\n",
        "skills/review/SKILL.md": skill("review"), "skills/review/run.sh": "echo $Format:%H$\n",
        ".gitattributes": "skills/review/run.sh export-subst\n"})
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    found = {f["item"]: f["evidence"] for f in regs(report)}
    assert code == 1 and found == {"skills/deploy": "deploy (skills/deploy/docs/notes.md): unhashable",
                                   "skills/review": "review (skills/review/run.sh): unhashable"}
    assert checks(fake) == []


def test_outside_git_a_gitattributes_naming_export_ignore_anywhere_makes_every_skill_unhashable(tmp_path, run_cli, api_double):
    fake, _ = api_double
    serve(fake)
    repo = write_tree(tmp_path / "plain", {**UNHASHABLE_SKILL, "elsewhere/.gitattributes": "*.txt export-ignore\n"})
    if files.work_tree_top(str(repo)) is not None:
        pytest.skip("the temporary directory is inside a git work tree")
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    (finding,) = regs(report)
    assert code == 1 and finding["evidence"] == "deploy (elsewhere/.gitattributes): unhashable"


def test_export_attribute_paths_asks_git_and_is_none_outside_a_work_tree(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a/x.txt": "x\n", "a/y.txt": "y\n", "b/z.txt": "z\n",
                                         ".gitattributes": "a/x.txt export-ignore\nb/* -export-subst\n"})
    got = ci.export_attribute_paths(str(repo), ["a/x.txt", "a/y.txt", "b/z.txt"], git=None, env=dict(os.environ))
    assert got == ["a/x.txt", "b/z.txt"]  # unset counts: any value but "unspecified"
    assert ci.export_attribute_paths(str(repo / "a"), ["x.txt", "y.txt"], git=None, env=dict(os.environ)) == ["x.txt"]
    plain = tmp_path / "plain"
    plain.mkdir()
    if files.work_tree_top(str(plain)) is None:
        assert ci.export_attribute_paths(str(plain), ["x"], git=None, env=dict(os.environ)) is None


def test_skill_items_carry_links_true_when_a_member_link_was_followed(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, check_answer(skills=[None]))
    repo = tmp_path / "repo"
    write_tree(repo, {**UNHASHABLE_SKILL, "shared/helper.sh": "echo hi\n"})
    try:
        os.symlink("../../shared/helper.sh", repo / "skills" / "deploy" / "helper.sh")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    make_repo(repo, {})
    code, report, _, err = scan_json(run_cli, repo, env_of())
    assert code == 0, err
    (body,) = checks(fake)
    assert [skill_item["links"] for skill_item in body["skills"]] == [True]


# --- SW-REG-003 bindings (P48) -----------------------------------------------------------------------------------------

def _accept(repo: Path, finding: dict, rule: str | None = None, days: int = 30) -> None:
    """A baseline entry accepting `finding`, added yesterday (`--as-of` is refused in connected mode, so the dates follow
    the clock) and expiring `days` after it was added."""
    added = datetime.now(UTC).date() - timedelta(days=1)
    lines = ["version: 1", "accepted:", f"  - fingerprint: \"{finding['fingerprint']}\"", f"    rule: {rule or finding['rule_id']}",
             f"    path: {finding['location']['path']}", "    reason: accepted by the test", f"    added: {added.isoformat()}",
             f"    expires: {(added + timedelta(days=days)).isoformat()}"]
    write_tree(repo, {".spellwarden/baseline.yml": "\n".join(lines) + "\n"})


def test_a_base_acceptance_of_one_unpinned_entry_does_not_suppress_another(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = make_repo(tmp_path / "repo", {".mcp.json": mcp({"a": {"command": "npx", "args": ["a"]}})})
    serve(fake)
    _, first, _, _ = scan_json(run_cli, repo, env_of())
    (only,) = regs(first)
    _accept(repo, only)                       # the baseline accepts the SW-REG-003 of entry a
    base = commit(repo, {})
    commit(repo, {".mcp.json": mcp({"a": {"command": "npx", "args": ["a"]}, "b": {"command": "npx", "args": ["b"]}})})
    fake.requests.clear()
    serve(fake)
    _, report, _, _ = scan_json(run_cli, repo, env_of())   # a default-branch run judges both
    by_name = {f["evidence"].split(": ")[0]: f for f in regs(report)}
    assert by_name["a"]["suppressed"] is True and by_name["a"]["fingerprint"] == only["fingerprint"]
    assert by_name["b"]["suppressed"] is False and by_name["b"]["fingerprint"] != only["fingerprint"]
    fake.requests.clear()
    serve(fake)
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base))
    assert [(f["evidence"].split(": ")[0], f["suppressed"]) for f in regs(report)] == [("b", False)] and code == 1


def test_bindings_are_the_entry_hash_the_resolver_files_and_the_skill_files(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double

    def finding_of(repo: Path, name: str) -> dict:
        fake.requests.clear()
        serve(fake)
        _, report, _, _ = scan_json(run_cli, repo, env_of())
        return next(f for f in regs(report) if f["evidence"].startswith(f"{name}"))

    one = make_repo(tmp_path / "one", {".mcp.json": mcp({"s": PINNED_UVX}), "pip.conf": "[global]\nindex-url = https://a.example.com/\n"})
    two = make_repo(tmp_path / "two", {".mcp.json": mcp({"s": PINNED_UVX}), "pip.conf": "[global]\nindex-url = https://b.example.com/\n"})
    assert finding_of(one, "s")["fingerprint"] != finding_of(two, "s")["fingerprint"]  # a changed resolver file is a new finding
    assert finding_of(one, "s")["fingerprint"] == gate_finding(
        "stdio", ".mcp.json", 3, "s", None, "resolver_override",
        resolver_binding(_raw_of(one, "s"), {"pip.conf": (one / "pip.conf").read_bytes()})).fingerprint
    skill_one = make_repo(tmp_path / "s1", {**UNHASHABLE_SKILL, "skills/deploy/node_modules/a.js": "x\n"})
    skill_two = make_repo(tmp_path / "s2", {"skills/deploy/SKILL.md": skill("deploy") + "More.\n",
                                           "skills/deploy/node_modules/a.js": "x\n"})
    first, second = finding_of(skill_one, "deploy"), finding_of(skill_two, "deploy")
    assert first["fingerprint"] != second["fingerprint"]  # an edit to SKILL.md is a new finding
    assert first["fingerprint"] == gate_finding(
        "skill", "skills/deploy", None, "deploy", None, "unhashable",
        unhashable_binding({"SKILL.md": skill("deploy").encode()}, ["skills/deploy/node_modules"])).fingerprint


def _raw_of(repo: Path, name: str) -> str:
    from spellwarden_scan import parse_document

    document = parse_document("mcp", ".mcp.json", (repo / ".mcp.json").read_bytes())
    return next(server.raw_sha256 for server in document.servers if server.name == name)


def test_a_base_acceptance_does_not_survive_a_resolver_file_or_skill_change(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = make_repo(tmp_path / "repo", {".mcp.json": mcp({"s": PINNED_UVX}), "pip.conf": "[global]\nindex-url = https://a.example.com/\n",
                                         **UNHASHABLE_SKILL, "skills/deploy/node_modules/a.js": "x\n"})
    serve(fake)
    _, first, _, _ = scan_json(run_cli, repo, env_of())
    accepted = regs(first)
    assert len(accepted) == 2
    added = datetime.now(UTC).date() - timedelta(days=1)
    lines = ["version: 1", "accepted:"]
    for finding in accepted:
        lines += [f"  - fingerprint: \"{finding['fingerprint']}\"", f"    rule: {finding['rule_id']}",
                  f"    path: {finding['location']['path']}", "    reason: accepted", f"    added: {added.isoformat()}",
                  f"    expires: {(added + timedelta(days=30)).isoformat()}"]
    write_tree(repo, {".spellwarden/baseline.yml": "\n".join(lines) + "\n"})
    base = commit(repo, {})
    commit(repo, {"pip.conf": "[global]\nindex-url = https://evil.example.com/\n", "skills/deploy/SKILL.md": skill("deploy") + "Edited.\n"})
    fake.requests.clear()
    serve(fake)
    _, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base))
    assert [f["suppressed"] for f in regs(report)] == [False, False]  # both are new findings: nothing is accepted
    assert {f["fingerprint"] for f in regs(report)}.isdisjoint({f["fingerprint"] for f in accepted})


# --- budget, anchors, not admitted ---------------------------------------------------------------------------------------

def test_the_gate_still_runs_after_200_s_of_probing(make_repo, run_cli, tmp_path, api_double, monkeypatch):
    fake, clock = api_double
    serve(fake, check_answer(skills=[None, None], servers=[None], stdio=[None], plugins=[None], marketplaces=[None]))

    def slow_phase(_targets, _rules, **_kwargs):
        clock.advance(200)  # P50: the run budget counts time inside requests only
        return [], []

    monkeypatch.setattr(probing, "run_phase", slow_phase)
    code, report, _, err = scan_json(run_cli, base_repo(make_repo, tmp_path), env_of(), "--probe")
    assert code == 0, err
    assert len(checks(fake)) == 1 and report["errors"] == []


def test_markdown_reason_links_use_reason_anchors():
    assert set(markdown.REASON_ANCHORS) == set(GATE_REASONS)
    assert markdown.REASON_ANCHORS["resolver_override"] == "#gate-reason-resolver-override"
    assert markdown.REASON_ANCHORS["unhashable"] == "#gate-reason-unhashable"
    assert all(anchor == f"#gate-reason-{reason.replace('_', '-')}" for reason, anchor in markdown.REASON_ANCHORS.items())


def test_not_admitted_items_are_sw_reg_001_or_002_at_the_right_location_high_in_sarif_and_markdown(
        make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    template = f"{DASH}/mcp-servers?add=1&url="
    request = f"{DASH}/skills?add=git&url=u&ref=r&path=skills%2Fdeploy"
    serve(fake, check_answer(skills=[request, None], servers=[template], stdio=[f"{DASH}/registry?allow=command"],
                             plugins=["https://evil.example/phish"], marketplaces=[None]))
    out_json, out_sarif, out_md = tmp_path / "r.json", tmp_path / "r.sarif", tmp_path / "r.md"
    code, _, err = run_cli(["scan", str(base_repo(make_repo, tmp_path)), "--no-telemetry", "--format", "json", "--output", str(out_json),
                            "--format", "sarif", "--output", str(out_sarif), "--format", "markdown", "--output", str(out_md)],
                           env=env_of())
    assert code == 1, err
    report = json.loads(out_json.read_text(encoding="utf-8"))
    by_item = {f["item"]: f for f in regs(report)}
    assert {f["rule_id"] for f in regs(report)} == {"SW-REG-001", "SW-REG-002"} and all(f["severity"] == "high" for f in regs(report))
    assert by_item["skills/deploy"]["location"] == {"path": "skills/deploy", "line": None}
    assert by_item[".mcp.json#docs"]["rule_id"] == "SW-REG-002" and by_item[".mcp.json#docs"]["location"]["path"] == ".mcp.json"
    assert isinstance(by_item[".mcp.json#docs"]["location"]["line"], int)
    assert by_item[".mcp.json#git"]["rule_id"] == "SW-REG-002"          # stdio
    assert by_item[".claude-plugin/marketplace.json#lint"]["rule_id"] == "SW-REG-001"
    items = {(item["kind"], item["name"]): item for item in block(report)["items"]}
    assert items[("server", "docs")]["request_url"] == template + quote("https://mcp.example.com/docs", safe="")  # no query, no hash
    assert items[("plugin", "lint")]["request_url"] is None  # not under the dashboard address: never kept, never printed
    sarif = json.loads(out_sarif.read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert {r["ruleId"] for r in results} == {"SW-REG-001", "SW-REG-002"} and all(r["level"] == "error" for r in results)
    text = out_md.read_text(encoding="utf-8")
    assert "**Not admitted in the private registry**" in text
    assert f"[Request admission]({request})" in text
    assert "evil.example" not in text
    assert f"[Request admission]({template}{quote('https://mcp.example.com/docs', safe='')})" in text


def test_unidentified_items_in_markdown_say_why_and_link_the_readme_anchor(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    out_md = tmp_path / "r.md"
    repo = make_repo(tmp_path / "repo", {".mcp.json": mcp({"loose": {"command": "npx", "args": ["x"]}})})
    code, _, _ = run_cli(["scan", str(repo), "--no-telemetry", "--format", "markdown", "--output", str(out_md)], env=env_of())
    text = out_md.read_text(encoding="utf-8")
    assert code == 1 and "**Not admitted in the private registry**" in text
    assert "cannot be judged ([unpinned](https://github.com/spellwarden-ai/spellwarden#gate-reason-unpinned))" in text
    assert "loose (stdio, `.mcp.json`)" in text


# --- scope -------------------------------------------------------------------------------------------------------------

def _scoped_repo(make_repo, tmp_path: Path):
    repo = make_repo(tmp_path / "repo", {
        "skills/deploy/SKILL.md": skill("deploy"), "skills/review/SKILL.md": skill("review"),
        ".mcp.json": mcp({"docs": {"url": "https://mcp.example.com/docs"}, "git": PINNED_UVX}),
        ".claude-plugin/marketplace.json": marketplace([{"name": "lint", "source": {"source": "github", "repo": "acme/lint", "sha": PIN}}]),
        ".claude/settings.json": settings_json(MARKETPLACES, {"lint@acme-tools": True})})
    return repo, git(repo, "rev-parse", "HEAD").strip()


def test_scope_judges_exactly_the_added_or_changed_items(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo, base = _scoped_repo(make_repo, tmp_path)
    commit(repo, {
        "skills/deploy/run.sh": "echo hi\n",                                                       # a changed skill file: in
        ".mcp.json": mcp({"docs": {"url": "https://mcp.example.com/docs"}, "git": PINNED_UVX,       # unchanged entries: out
                          "new": {"url": "https://mcp.example.com/new"},                            # a new entry: in
                          "uvx": {"command": "uvx", "args": ["other==1.0.0"]}}),                    # a new launch: in
        ".claude-plugin/marketplace.json": marketplace([
            {"name": "lint", "source": {"source": "github", "repo": "acme/lint", "sha": OTHER_PIN}}]),   # a changed pin: in
    })
    serve(fake, check_answer(skills=[None], servers=[None], stdio=[None], plugins=[None]))
    code, report, _, err = scan_json(run_cli, repo, request_env(tmp_path, base))
    assert code == 0, err
    (body,) = checks(fake)
    assert [s["path"] for s in body["skills"]] == ["skills/deploy"]
    assert [s["name"] for s in body["servers"]] == ["new"] and [s["name"] for s in body["stdio"]] == ["uvx"]
    assert [p["identity"] for p in body["plugins"]] == [f"git:https://github.com/acme/lint@{OTHER_PIN}"] and body["marketplaces"] == []
    registry = block(report)
    assert registry["scope"] == "changed" and registry["scope_applied"] == "changed"
    assert registry["checked"] == 4 and registry["out_of_scope"] == 4  # review, docs, git, the marketplace
    assert {item["name"] for item in registry["items"] if not item["in_scope"]} == {"review", "docs", "git", "acme-tools"}
    assert report["connected"]["run"]["kind"] == "request"


def test_renamed_launch_with_the_same_name_and_a_new_resolver_file_are_in_scope(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo, base = _scoped_repo(make_repo, tmp_path)
    commit(repo, {".mcp.json": mcp({"docs": {"url": "https://mcp.example.com/docs"},
                                    "git": {"command": "uvx", "args": ["mcp-server-git==0.7.0"]}})})
    serve(fake, check_answer(stdio=[None]))
    scan_json(run_cli, repo, request_env(tmp_path, base))
    assert [s["identity"] for s in checks(fake)[0]["stdio"]] == ["cmd:uvx mcp-server-git==0.7.0"]
    # a new resolver file of the launcher family puts every entry of that family in scope, the document unchanged
    second, base_two = _scoped_repo(make_repo, tmp_path / "second")
    commit(second, {"pip.conf": "[global]\nindex-url = https://pip.example.com/simple\n"})
    fake.requests.clear()
    serve(fake)
    _, report, _, _ = scan_json(run_cli, second, request_env(tmp_path, base_two))
    assert {(f["evidence"].split(": ")[0], f["evidence"].split(": ", 1)[1]) for f in regs(report)} == {("git", "resolver_override")}


def test_a_new_enabled_plugin_puts_its_marketplace_in_scope(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo, base = _scoped_repo(make_repo, tmp_path)
    commit(repo, {".claude/settings.json": settings_json(MARKETPLACES, {"lint@acme-tools": True, "fmt@acme-tools": True})})
    serve(fake, check_answer(marketplaces=[None]))
    scan_json(run_cli, repo, request_env(tmp_path, base))
    assert [m["name"] for m in checks(fake)[0]["marketplaces"]] == ["acme-tools"]


def test_server_query_change_between_base_and_head_is_in_scope_and_not_admitted(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo, base = _scoped_repo(make_repo, tmp_path)
    commit(repo, {".mcp.json": mcp({"docs": {"url": "https://mcp.example.com/docs?tenant=evil"}, "git": PINNED_UVX})})
    serve(fake, check_answer(servers=[f"{DASH}/mcp-servers?add=1&url="]))
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base))
    (body,) = checks(fake)
    assert code == 1 and body["servers"][0]["identity"] == ident.server_identity("https://mcp.example.com/docs?tenant=evil")
    assert [f["rule_id"] for f in regs(report)] == ["SW-REG-002"]


def test_scope_changed_on_pull_request_with_depth_1_diffs_the_first_parent(make_repo, run_cli, tmp_path, api_double):
    """The test merge commit of a `pull_request`: the diff is against its first parent, not the base tip."""
    fake, _ = api_double
    repo, first = _scoped_repo(make_repo, tmp_path / "origin")
    git(repo, "checkout", "-q", "-b", "feature")
    commit(repo, {"skills/deploy/run.sh": "echo feature\n"}, "feature")
    git(repo, "checkout", "-q", "main")
    base = commit(repo, {"skills/review/extra.sh": "echo base moved\n"}, "base moved")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "feature")
    merge = git(repo, "rev-parse", "HEAD").strip()
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth=1", repo.resolve().as_uri(), str(clone)], check=True, capture_output=True)
    env = request_env(tmp_path, base, GITHUB_SHA=merge)
    serve(fake, check_answer(skills=[None]))
    code, report, _, err = scan_json(run_cli, clone, env)
    del first
    assert code == 0, err
    assert [s["path"] for s in checks(fake)[0]["skills"]] == ["skills/deploy"]  # review changed on the base only: out


def test_missing_base_gives_gate_scope_all(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo, _ = _scoped_repo(make_repo, tmp_path)
    serve(fake, check_answer(skills=[None, None], servers=[None], stdio=[None], plugins=[None], marketplaces=[None]))
    payload = {"pull_request": {"number": 3, "head": {"repo": {"full_name": "acme/tools"}, "sha": HEAD, "ref": "f"}}}
    env = connected_github(tmp_path, "pull_request", payload, SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN)
    code, report, _, _ = scan_json(run_cli, repo, env)
    assert code == 0 and block(report)["scope_applied"] == "all" and block(report)["scope"] == "changed"
    assert "gate_scope_all" in codes(report["notices"]) and block(report)["checked"] == 6


def test_default_branch_runs_and_scope_all_judge_everything(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    answer = check_answer(skills=[None, None], servers=[None], stdio=[None], plugins=[None], marketplaces=[None])
    serve(fake, answer, policy=policy_answer([], gate={"scope": "all"}))
    repo, base = _scoped_repo(make_repo, tmp_path)
    commit(repo, {"README.md": "x\n"})
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base))
    assert code == 0 and block(report)["checked"] == 6 and block(report)["scope_applied"] == "all"
    assert "gate_scope_all" not in codes(report["notices"])  # the posture asked for `all`; nothing fell back
    fake.requests.clear()
    serve(fake, answer)
    _, report, _, _ = scan_json(run_cli, repo, env_of())
    assert block(report)["checked"] == 6 and block(report)["scope_applied"] == "all"   # a default-branch run


# --- the gate off, failing, too large, nothing to check ---------------------------------------------------------------------

def test_gate_disabled_is_registry_gate_off_and_no_call(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake, policy=policy_answer([], gate={"enabled": False}))
    code, report, out, _ = scan_json(run_cli, base_repo(make_repo, tmp_path), env_of())
    assert code == 0 and "registry_gate_off" in codes(report["notices"]) and report["connected"]["registry"] is None
    assert checks(fake) == []
    second = base_repo(make_repo, tmp_path / "team")
    fake.requests.clear()
    serve(fake, policy=policy_answer([], registry=None))
    _, report, _, _ = scan_json(run_cli, second, env_of())
    assert "registry_gate_off" not in codes(report["notices"]) and report["connected"]["registry"] is None  # a Team org: no notice
    assert checks(fake) == []


@pytest.mark.parametrize("status, body, code_name", [
    (503, {"error": "internal"}, "registry_check_failed"), (429, {"error": "rate_limited", "message": "Slow down."},
                                                            "connected_rate_limited"),
    (200, {"skills": "not a list"}, "registry_check_failed"), (200, {"schema": 1, "skills": [], "servers": [], "stdio": [],
                                                                  "plugins": [], "marketplaces": []}, "registry_check_failed"),
], ids=["503", "429", "malformed", "short answer"])
def test_failed_check_is_registry_check_failed_exit_2_and_no_sw_reg_findings(status, body, code_name, make_repo, run_cli,
                                                                              tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    fake.script("POST", CHECK_PATH, status, body, times=3)
    code, report, _, _ = scan_json(run_cli, base_repo(make_repo, tmp_path), env_of())
    assert code == 2 and code_name in codes(report["errors"]) and regs(report) == []
    error = next(e for e in report["errors"] if e["code"] == code_name)
    if code_name == "registry_check_failed":
        assert error["message"].endswith("The scan is incomplete.") and error["message"].startswith(
            "The private registry could not be checked (")


def test_over_the_caps_is_registry_check_too_large_with_counts(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    policy = policy_answer([])
    policy["limits"]["check_max"]["skills"] = 1
    serve(fake, policy=policy)
    code, report, _, _ = scan_json(run_cli, base_repo(make_repo, tmp_path), env_of())
    (error,) = [e for e in report["errors"] if e["code"] == "registry_check_too_large"]
    assert code == 2 and "2 skills (at most 1)" in error["message"] and checks(fake) == []


def test_no_identifiable_candidate_in_scope_makes_no_call(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    serve(fake)
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n"})
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    assert code == 0 and checks(fake) == [] and block(report)["checked"] == 0 and block(report)["items"] == []


# --- the baseline rule for SW-REG ----------------------------------------------------------------------------------------------

def test_sw_reg_baseline_entries_are_capped_at_90_days_and_read_from_the_base_on_a_request(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = make_repo(tmp_path / "repo", {".mcp.json": mcp({"a": {"command": "npx", "args": ["a"]}})})
    serve(fake)
    _, first, _, _ = scan_json(run_cli, repo, env_of())
    (finding,) = regs(first)
    _accept(repo, finding, days=90)  # 90 days in the working tree of a default-branch run: accepted
    fake.requests.clear()
    serve(fake)
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    assert code == 0 and regs(report)[0]["suppressed"] is True
    _accept(repo, finding, days=91)  # 91 days: baseline_invalid, nothing suppressed
    fake.requests.clear()
    serve(fake)
    code, report, _, _ = scan_json(run_cli, repo, env_of())
    assert code == 2 and "baseline_invalid" in codes(report["errors"]) and regs(report)[0]["suppressed"] is False
    # on a request the acceptance is the base revision's, whichever file `--baseline` names
    _accept(repo, finding, days=30)
    base = commit(repo, {})
    write_tree(repo, {"head-baseline.yml": "version: 1\naccepted: []\n"})
    commit(repo, {"head-baseline.yml": "version: 1\naccepted: []\n"})
    fake.requests.clear()
    serve(fake, policy=ALL)
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base), "--baseline", "head-baseline.yml")
    assert code == 0 and regs(report)[0]["suppressed"] is True
    assert "reg_baseline_from_base" in codes(report["notices"])
    fake.requests.clear()
    serve(fake, policy=ALL)
    _, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base))   # the default file is the base's already
    assert regs(report)[0]["suppressed"] is True and "reg_baseline_from_base" not in codes(report["notices"])


def test_a_head_baseline_accepting_sw_reg_is_ignored_on_a_request(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = make_repo(tmp_path / "repo", {".mcp.json": mcp({"a": {"command": "npx", "args": ["a"]}})})
    base = git(repo, "rev-parse", "HEAD").strip()
    serve(fake)
    _, first, _, _ = scan_json(run_cli, repo, env_of())
    (finding,) = regs(first)
    _accept(repo, finding)
    commit(repo, {})  # the request adds the acceptance of its own finding
    fake.requests.clear()
    serve(fake, policy=ALL)
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base))
    assert code == 1 and regs(report)[0]["suppressed"] is False  # the base revision holds no baseline
    fake.requests.clear()
    serve(fake, policy=ALL)
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base), "--baseline", ".spellwarden/baseline.yml")
    assert code == 1 and regs(report)[0]["suppressed"] is False and "reg_baseline_from_base" in codes(report["notices"])


@pytest.fixture
def fixture_tools(monkeypatch):
    """`make_repo` and `check` of `fixtures/repos` (check.py imports make_repo, so the directory joins the path); the
    modules leave `sys.modules` afterwards, `scripts/e2e.py` imports another `make_repo`."""
    import importlib
    import sys

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "fixtures" / "repos"))
    for name in ("make_repo", "check"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    yield importlib.import_module("make_repo"), importlib.import_module("check")
    for name in ("make_repo", "check"):
        sys.modules.pop(name, None)


def test_every_gate_reason_is_reachable_through_the_fixture_variants(run_cli, tmp_path, api_double, fixture_tools):
    """The fixture repository of the wrappers (`fixtures/repos/connected`, built by `make_repo.py`) reaches every
    reason of the closed list, the case itself (a resolver file) and its `reasons` variant (the rest), and its
    expectations (`expect.json` `connected`, asserted by `check.py`) are what the command reports."""
    fake, _ = api_double
    builder, checker = fixture_tools
    seen: set[str] = set()
    for case in ("connected", "connected@reasons"):
        dest = tmp_path / case.replace("@", "-")
        expect = builder.build(case, dest)
        fake.requests.clear()
        fake._answers.clear()
        serve(fake, policy=policy_answer([]))
        fake.script("POST", CHECK_PATH, 200, lambda body: admit_all(body, refuse_server=True))
        code, report, _, err = scan_json(run_cli, dest, env_of())
        assert report is not None, err
        seen |= {f["evidence"].split(": ", 1)[1] for f in regs(report) if f["rule_id"] == "SW-REG-003"}
        open_findings = [f for f in report["findings"] if not f["suppressed"]]
        assert code == expect["exit_code"] == 1 and len(open_findings) == expect["findings"], sorted(
            (f["rule_id"], f["evidence"]) for f in open_findings)
        wanted = {key: value for key, value in expect["connected"].items() if key != "upload"}  # the upload is Task 10's
        assert checker._check_connected({**expect, "connected": wanted}, report) == []
    assert seen == set(GATE_REASONS)
