"""Spec 6.6 and claim C7: the lock pins every configuration document, server, plugin, local plugin directory and
skill; `--locked` and `lock --check` name what changed; the lock is byte-deterministic and version-free."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import jsonschema
import pytest

from spellwarden_cli import commands, discover, files, lockfile
from spellwarden_cli.settings import Settings

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"

SKILL = ("---\nname: deploy\ndescription: Deploys the service.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\n"
         "# deploy\n\nRead the task, then act.\n")
MCP = json.dumps({"mcpServers": {"jira": {"type": "http", "url": "https://mcp.example.com/jira"}}}, indent=2)
SETTINGS = json.dumps({"permissions": {"defaultMode": "default"}}, indent=2)
MARKETPLACE = json.dumps({"name": "acme", "plugins": [
    {"name": "infra", "source": {"source": "github", "repo": "acme/infra-plugin", "ref": "v2"}},
    {"name": "local", "source": "./plugins/local"},
]}, indent=2)
MANIFEST = json.dumps({"name": "local", "description": "A local plugin."}, indent=2)
BASE = {
    ".claude/skills/deploy/SKILL.md": SKILL,
    ".mcp.json": MCP,
    ".claude/settings.json": SETTINGS,
    ".claude-plugin/marketplace.json": MARKETPLACE,
    "plugins/local/.claude-plugin/plugin.json": MANIFEST,
}


def _servers(count: int, *, first_url: str = "https://mcp0.example.com/mcp") -> str:
    servers = {f"s{n:03d}": {"type": "http", "url": first_url if n == 0 else f"https://mcp{n}.example.com/mcp"}
               for n in range(count)}
    return json.dumps({"mcpServers": servers}, indent=2)


def _repo(tmp_path: Path, make_repo, name: str = "repo", **changes: str) -> Path:
    base = tmp_path / name
    base.mkdir(parents=True, exist_ok=True)
    return make_repo(base, {**BASE, **changes})


def _items(repo: Path) -> list[dict]:
    return json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8"))["items"]


def _discovery(repo: Path):
    return discover.discover(files.list_files(str(repo), Settings()))


def _scan(run_cli, repo: Path, *extra: str) -> tuple[int, dict]:
    code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", *extra])
    assert out, err
    return code, json.loads(out)


def test_lock_writes_every_kind_of_item(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, _out, err = run_cli(["lock", str(repo)])
    assert code == 0, err
    items = _items(repo)
    keys = {(item["kind"], item["path"]) for item in items}
    assert {
        ("document", ".mcp.json"), ("document", ".claude/settings.json"), ("document", ".claude-plugin/marketplace.json"),
        ("document", "plugins/local/.claude-plugin/plugin.json"), ("mcp-server", ".mcp.json#jira"),
        ("plugin", ".claude-plugin/marketplace.json#infra"), ("plugin", ".claude-plugin/marketplace.json#local"),
        ("plugin-dir", "plugins/local"), ("skill", ".claude/skills/deploy"),
    } <= keys
    infra = next(item for item in items if item["path"] == ".claude-plugin/marketplace.json#infra")
    assert infra == {"kind": "plugin", "path": ".claude-plugin/marketplace.json#infra", "source": "github:acme/infra-plugin",
                     "pin": None, "ref": "v2"}
    settings = next(item for item in items if item["path"] == ".claude/settings.json")
    assert settings["doc_kind"] == "settings" and settings["status"] == "ok" and len(settings["sha256"]) == 64
    skill = next(item for item in items if item["kind"] == "skill")
    assert skill["name"] == "deploy"
    assert [(i["kind"], i["path"]) for i in items] == sorted((i["kind"], i["path"]) for i in items)
    jsonschema.Draft202012Validator(json.loads((SCHEMAS / "lock.schema.json").read_text())).validate(
        json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8")))


def test_the_lock_file_is_byte_identical_across_runs_and_listing_orders(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    assert run_cli(["lock", str(repo)])[0] == 0
    first = (repo / lockfile.LOCK_PATH).read_bytes()
    assert run_cli(["lock", str(repo)])[0] == 0
    assert (repo / lockfile.LOCK_PATH).read_bytes() == first
    assert first.endswith(b"\n") and b"\n  " in first
    found = _discovery(repo)
    shuffled = dataclasses.replace(found, documents=tuple(reversed(found.documents)), skills=tuple(reversed(found.skills)),
                                   plugin_dirs=tuple(reversed(found.plugin_dirs)), items=tuple(reversed(found.items)))
    assert lockfile.render_lock(lockfile.compute_lock(shuffled)) == lockfile.render_lock(lockfile.compute_lock(found)) == first


def test_moving_a_skill_keeps_its_hash_and_changes_its_path(tmp_path, make_repo):
    one = _repo(tmp_path, make_repo, "one")
    two_files = {path.replace(".claude/skills/deploy/", "skills/moved/deploy/"): text for path, text in BASE.items()}
    (tmp_path / "two").mkdir()
    two = make_repo(tmp_path / "two", two_files)
    skill_one = next(i for i in lockfile.compute_lock(_discovery(one))["items"] if i["kind"] == "skill")
    skill_two = next(i for i in lockfile.compute_lock(_discovery(two))["items"] if i["kind"] == "skill")
    assert skill_one["sha256"] == skill_two["sha256"]
    assert (skill_one["path"], skill_two["path"]) == (".claude/skills/deploy", "skills/moved/deploy")


CHANGES = {
    "skill byte": (".claude/skills/deploy/SKILL.md", SKILL + "One more line.\n", ("skill", ".claude/skills/deploy"), 3),
    "settings only": (".claude/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}),
                      ("document", ".claude/settings.json"), 1),
    "marketplace ref": (".claude-plugin/marketplace.json", MARKETPLACE.replace('"v2"', '"v3"'),
                        ("plugin", ".claude-plugin/marketplace.json#infra"), 3),
    "manifest reference": ("plugins/local/.claude-plugin/plugin.json",
                           json.dumps({"name": "local", "hooks": "./hooks/other.json"}),
                           ("document", "plugins/local/.claude-plugin/plugin.json"), 3),
    "malformed": (".mcp.json", "{", ("document", ".mcp.json"), 2),
    "truncated": (".mcp.json", _servers(201), ("document", ".mcp.json"), 2),
}


@pytest.mark.parametrize("case", sorted(CHANGES))
def test_each_change_makes_the_lock_stale_and_names_the_item(case, tmp_path, make_repo, run_cli):
    """`lock --check` exits 3 for every change; the scan under `--locked` reports the item as changed and exits by
    the precedence of 6.2 (a document error is 2, a high finding 1, else 3)."""
    path, text, (kind, item_path), scan_exit = CHANGES[case]
    repo = _repo(tmp_path, make_repo)
    assert run_cli(["lock", str(repo)])[0] == 0
    (repo / path).write_text(text, encoding="utf-8")
    code, out, _err = run_cli(["lock", str(repo), "--check"])
    assert code == 3
    assert item_path in out
    code, report = _scan(run_cli, repo, "--locked")
    assert code == scan_exit
    assert report["lock"]["status"] == "stale"
    assert {"kind": kind, "path": item_path} in report["lock"]["changed"]


def test_a_truncated_document_is_locked_as_truncated_and_its_kept_servers_are_judged(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo, **{".mcp.json": _servers(201, first_url="http://plain.example.com/mcp")})
    assert run_cli(["lock", str(repo)])[0] == 0
    items = _items(repo)
    document = next(i for i in items if i["kind"] == "document" and i["path"] == ".mcp.json")
    assert document["status"] == "truncated"
    assert sum(1 for i in items if i["kind"] == "mcp-server" and i["path"].startswith(".mcp.json#")) == 200
    code, report = _scan(run_cli, repo, "--locked")
    assert code == 2
    assert report["lock"]["status"] == "ok"
    assert any(e["code"] == "truncated" and e["path"] == ".mcp.json" for e in report["errors"])
    assert any(f["rule_id"] == "SW-CFG-001" for f in report["findings"])


def test_a_malformed_document_is_locked_with_its_error_status(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo, **{".mcp.json": '{"mcpServers": {"a": {}, "a": {}}}'})
    assert run_cli(["lock", str(repo)])[0] == 0
    document = next(i for i in _items(repo) if i["path"] == ".mcp.json")
    assert document["status"] == "error:duplicate_key"


def test_a_new_server_is_added(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    assert run_cli(["lock", str(repo)])[0] == 0
    servers = {"jira": {"type": "http", "url": "https://mcp.example.com/jira"},
               "confluence": {"type": "http", "url": "https://mcp.example.com/confluence"}}
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": servers}, indent=2), encoding="utf-8")
    code, report = _scan(run_cli, repo, "--locked")
    assert code == 3
    assert {"kind": "mcp-server", "path": ".mcp.json#confluence"} in report["lock"]["added"]
    assert {"kind": "document", "path": ".mcp.json"} in report["lock"]["changed"]
    assert report["lock"]["removed"] == []


def test_an_absent_lock_is_absent(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, report = _scan(run_cli, repo, "--locked")
    assert code == 3
    assert report["lock"]["status"] == "absent"
    code, out, _err = run_cli(["lock", str(repo), "--check"])
    assert code == 3 and "absent" in out


def test_without_locked_the_lock_is_not_checked(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, report = _scan(run_cli, repo)
    assert code == 0
    assert report["lock"]["status"] == "not_checked"


def test_an_unreadable_lock_file_is_exit_2(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    (repo / ".spellwarden").mkdir()
    (repo / lockfile.LOCK_PATH).write_text("{", encoding="utf-8")
    code, report = _scan(run_cli, repo, "--locked")
    assert code == 2
    assert any(e["code"] == "lock_unreadable" for e in report["errors"])
    assert run_cli(["lock", str(repo), "--check"])[0] == 2
    (repo / lockfile.LOCK_PATH).write_text(json.dumps({"lock_version": True, "items": []}), encoding="utf-8")
    assert run_cli(["lock", str(repo), "--check"])[0] == 2


def test_a_scanner_upgrade_does_not_make_the_lock_stale(tmp_path, make_repo, run_cli, monkeypatch):
    repo = _repo(tmp_path, make_repo)
    assert run_cli(["lock", str(repo)])[0] == 0
    document = json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8"))
    assert set(document) == {"lock_version", "items"}
    assert not any("version" in key for item in document["items"] for key in item)
    import spellwarden_cli
    import spellwarden_scan.version

    monkeypatch.setattr(spellwarden_scan.version, "__version__", "9.9.9")
    monkeypatch.setattr(spellwarden_scan.version, "RULES_VERSION", "2099.12.9")
    monkeypatch.setattr(spellwarden_cli, "__version__", "9.9.9")
    assert run_cli(["lock", str(repo), "--check"])[0] == 0


def test_root_skill_is_locked_as_dot(tmp_path, make_repo, run_cli):
    """Review Focus 2: a SKILL.md at the scan root is the skill item `.` (plan decision P13)."""
    base = tmp_path / "rootskill"
    base.mkdir()
    repo = make_repo(base, {"SKILL.md": SKILL, "scripts/run.sh": "#!/bin/sh\necho hi\n"})
    assert run_cli(["lock", str(repo)])[0] == 0
    skill = next(i for i in _items(repo) if i["kind"] == "skill")
    assert skill["path"] == "."
    assert skill["name"] == "."  # never the checkout directory's name (r0:F4)
    assert run_cli(["lock", str(repo), "--check"])[0] == 0


def test_root_skill_lock_does_not_depend_on_the_checkout_directory(tmp_path, make_repo, run_cli):
    """r0:F4: the lock travels with the project; a copy in a differently named directory still checks clean."""
    import shutil

    base = tmp_path / "first-name"
    base.mkdir()
    repo = make_repo(base, {"SKILL.md": SKILL, "scripts/run.sh": "#!/bin/sh\necho hi\n"})
    assert run_cli(["lock", str(repo)])[0] == 0
    clone = tmp_path / "renamed-clone"
    shutil.copytree(repo, clone)
    assert run_cli(["lock", str(clone), "--check"])[0] == 0


def test_the_lock_refuses_a_symlinked_spellwarden_directory(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (repo / ".spellwarden").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links need privileges on this runner")
    code, _out, err = run_cli(["lock", str(repo)])
    assert code == 2 and ("symbolic link" in err or "symlink" in err)  # the settings read refuses it first
    assert list(outside.iterdir()) == []


def test_write_in_root_refuses_a_symlinked_directory_and_a_symlinked_target(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / ".spellwarden").mkdir(parents=True)
    outside.mkdir()
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
        (root / ".spellwarden" / "lock.json").symlink_to(outside / "target.json")
    except OSError:
        pytest.skip("symbolic links need privileges on this runner")
    with pytest.raises(commands.CommandError, match="symbolic link"):
        commands.write_in_root(str(root), "linked/lock.json", b"{}")
    with pytest.raises(commands.CommandError, match="symbolic link"):
        commands.write_in_root(str(root), lockfile.LOCK_PATH, b"{}")
    assert list(outside.iterdir()) == []
    assert [p.name for p in (root / ".spellwarden").iterdir()] == ["lock.json"]  # no temporary file left behind


def test_the_scanners_own_files_do_not_change_a_root_skill_hash(tmp_path, make_repo, run_cli):
    base = tmp_path / "rootskill2"
    base.mkdir()
    repo = make_repo(base, {"SKILL.md": SKILL})
    assert run_cli(["lock", str(repo)])[0] == 0
    before = next(i for i in _items(repo) if i["kind"] == "skill")["sha256"]
    (repo / ".spellwarden" / "baseline.yml").write_text("version: 1\naccepted: []\n", encoding="utf-8")
    assert run_cli(["lock", str(repo), "--check"])[0] == 0
    (repo / "SKILL.md").write_text(SKILL + "More.\n", encoding="utf-8")
    assert run_cli(["lock", str(repo), "--check"])[0] == 3
    assert run_cli(["lock", str(repo)])[0] == 0
    assert next(i for i in _items(repo) if i["kind"] == "skill")["sha256"] != before


def test_other_files_under_spellwarden_still_count_in_a_root_skill_hash(tmp_path, make_repo, run_cli):
    """r0:F5: only the scanner's own files (lock, baseline, settings) are left out of a root package's hash, by exact
    path; a script the root SKILL.md runs from `.spellwarden/` is skill content, and changing it makes the lock stale."""
    base = tmp_path / "rootskill3"
    base.mkdir()
    repo = make_repo(base, {"SKILL.md": SKILL + "Run .spellwarden/setup.sh first.\n",
                            ".spellwarden/setup.sh": "#!/bin/sh\necho safe\n"})
    assert run_cli(["lock", str(repo)])[0] == 0
    (repo / ".spellwarden" / "setup.sh").write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
    code, out, _err = run_cli(["lock", str(repo), "--check"])
    assert code == 3
    assert "changed skill ." in out
    (repo / ".spellwarden" / "lock.json.bak").write_text("{}", encoding="utf-8")
    assert run_cli(["lock", str(repo)])[0] == 0
    (repo / ".spellwarden" / "lock.json.bak").write_text('{"x": 1}', encoding="utf-8")
    assert run_cli(["lock", str(repo), "--check"])[0] == 3  # a near-name is not an own file


@pytest.mark.parametrize("kind", ["skill\x1b[2J\x1b[31m", "**pwned** [x](https://evil.example)", "Skill", "", 7])
def test_a_lock_item_of_an_unknown_kind_is_unreadable(kind, tmp_path, make_repo, run_cli):
    """Spec 6.6, 6.13: the stored lock comes from the scanned revision; a kind outside the five the scanner writes is
    an unreadable lock (exit 2) and never reaches the terminal or the comment."""
    repo = _repo(tmp_path, make_repo)
    assert run_cli(["lock", str(repo)])[0] == 0
    document = json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8"))
    document["items"].append({"kind": kind, "path": "gone"})
    (repo / lockfile.LOCK_PATH).write_text(json.dumps(document), encoding="utf-8")
    code, out, err = run_cli(["lock", str(repo), "--check"])
    assert code == 2
    assert "\x1b" not in out + err and "pwned" not in out
    code, report = _scan(run_cli, repo, "--locked")
    assert code == 2
    assert report["lock"]["status"] == "not_checked"
    assert any(e["code"] == "lock_unreadable" for e in report["errors"])


def test_the_lock_kinds_are_the_ones_the_scanner_writes_and_the_schemas_list():
    report_schema = json.loads((SCHEMAS / "report.schema.json").read_text(encoding="utf-8"))
    lock_schema = json.loads((SCHEMAS / "lock.schema.json").read_text(encoding="utf-8"))
    assert set(report_schema["$defs"]["change"]["properties"]["kind"]["enum"]) == lockfile.KINDS
    assert {branch["properties"]["kind"]["const"] for branch in lock_schema["$defs"]["item"]["oneOf"]} == lockfile.KINDS


def test_describe_escapes_the_kind_and_the_path():
    from spellwarden_cli.report import LockState

    state = LockState(status="stale", added=({"kind": "skill\x1b[31m", "path": "a\x1b[2J‮"},))
    text = "\n".join(lockfile.describe(state))
    assert "\x1b" not in text and "‮" not in text
    assert "skill\\x1b[31m" in text


def test_own_files_are_excluded_by_exact_path():
    own = {".spellwarden/lock.json": b"a", ".spellwarden/baseline.yml": b"b", ".spellwarden/config.yml": b"c"}
    package = {**own, "SKILL.md": b"d"}
    assert lockfile._package_hash(".", package) == lockfile._package_hash(".", {"SKILL.md": b"d"})
    assert lockfile._package_hash(".", {**package, ".spellwarden/setup.sh": b"e"}) != lockfile._package_hash(".", package)


def test_unfollowed_member_links_enter_the_package_hash_without_colliding_with_files():
    # r2:F6: the hash of a package without such links is the bare canonical hash, unchanged; a link's target text
    # changes the hash, and a regular file holding the same text at the link's path gives another hash.
    from spellwarden_scan import canonical_sha256

    package = {"skills/x/SKILL.md": b"d"}
    assert lockfile._package_hash("skills/x", package) == canonical_sha256({"SKILL.md": b"d"})
    assert lockfile._package_hash("skills/x", package, {}) == canonical_sha256({"SKILL.md": b"d"})
    linked = lockfile._package_hash("skills/x", package, {"skills/x/run.sh": b"../../../a.sh"})
    assert linked != lockfile._package_hash("skills/x", package)
    assert linked != lockfile._package_hash("skills/x", package, {"skills/x/run.sh": b"../../../b.sh"})
    assert linked != lockfile._package_hash("skills/x", {**package, "skills/x/run.sh": b"../../../a.sh"})
    assert lockfile._package_hash("skills/moved", {"skills/moved/SKILL.md": b"d"},
                                  {"skills/moved/run.sh": b"../../../a.sh"}) == linked


def test_a_member_link_to_the_lock_keeps_the_lock_satisfiable(tmp_path, make_repo, run_cli):
    # r3 nit: `skills/x/state.json -> ../../.spellwarden/lock.json` hashed the lock into itself, so the lock was stale
    # forever. A member link whose target is the lock is still scanned, but left out of the package's lock hash like
    # the lock itself, with a notice. Only the lock: a link to the settings or the baseline is hashed (r4:R4-3).
    import os

    own = ".spellwarden/lock.json"

    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": "---\nname: x\ndescription: A demo.\n---\n\nRead.\n",
                                         ".spellwarden/config.yml": "version: 1\n"})
    try:
        os.symlink("../../" + own, repo / "skills" / "x" / "state.json")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    assert run_cli(["lock", str(repo)])[0] == 0
    assert run_cli(["lock", str(repo)])[0] == 0
    out = tmp_path / "report.json"
    code, _out, _err = run_cli(["scan", str(repo), "--no-telemetry", "--locked", "--format", "json", "--output", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["lock"]["status"] == "ok" and code == 0
    notice = next(n for n in report["notices"] if n["path"] == "skills/x/state.json")
    assert own in notice["message"] and "lock hash" in notice["message"]
    found = discover.discover(files.list_files(str(repo), Settings()))
    assert "skills/x/state.json" in found.skills[0].files  # still scanned


@pytest.mark.parametrize("own", [".spellwarden/config.yml", ".spellwarden/baseline.yml"])
def test_a_member_link_to_the_settings_or_the_baseline_is_locked(own, tmp_path, make_repo, run_cli):
    # r4:R4-3: `skills/x/run.sh -> ../../.spellwarden/config.yml` was left out of the lock like the lock itself, so a
    # YAML and shell polyglot could change what the skill runs without the lock going stale. Only the lock needs
    # leaving out (it would hash itself); the settings and the baseline reached by a member link are package content.
    import os

    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": "---\nname: x\ndescription: A demo.\n---\n\nRun run.sh.\n",
                                         ".spellwarden/config.yml": "version: 1\n",
                                         ".spellwarden/baseline.yml": "version: 1\naccepted: []\n"})
    try:
        os.symlink("../../" + own, repo / "skills" / "x" / "run.sh")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    assert run_cli(["lock", str(repo)])[0] == 0
    out = tmp_path / "report.json"
    code, _out, _err = run_cli(["scan", str(repo), "--no-telemetry", "--locked", "--format", "json", "--output", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["lock"]["status"] == "ok" and code == 0
    assert "skills/x/run.sh" not in {n["path"] for n in report["notices"]}
    # the reviewer's polyglot: still valid settings (or a valid baseline), and `sh skills/x/run.sh` now runs a command
    target = repo / own
    target.write_text("version: 1\naccepted: []\n# zz; echo changed-behaviour\n" if own.endswith("baseline.yml") else
                      "version: 1\nexclude:\n  - |\n    zz; echo changed-behaviour\n", encoding="utf-8")
    code, _out, _err = run_cli(["scan", str(repo), "--no-telemetry", "--locked", "--format", "json", "--output", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["lock"]["status"] == "stale"
    assert {"kind": "skill", "path": "skills/x"} in report["lock"]["changed"]
    assert code == 3


GOLDEN_REPO = Path(__file__).resolve().parents[1] / "golden" / "1.0.0" / "repo"
PLUGIN_SETTINGS = Path(__file__).resolve().parents[2] / "fixtures" / "config" / "plugins-settings" / ".claude" / "settings.json"


def test_lock_hash_unchanged_by_the_new_fields():
    """O3 spec 5.1: `raw_sha256` and the two plugin-settings lists are not lock inputs; the 1.0.0 lock still matches."""
    recorded = json.loads((GOLDEN_REPO / lockfile.LOCK_PATH).read_text(encoding="utf-8"))
    assert lockfile.compute_lock(discover.discover(files.list_files(str(GOLDEN_REPO), Settings()))) == recorded


def test_plugin_settings_add_only_the_document_item_to_the_lock(tmp_path, make_repo):
    repo = make_repo(tmp_path / "r", {".claude/settings.json": PLUGIN_SETTINGS.read_text(encoding="utf-8")})
    items = lockfile.compute_lock(_discovery(repo))["items"]
    assert [(item["kind"], item["path"]) for item in items] == [("document", ".claude/settings.json")]
