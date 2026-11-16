"""1.16.2 (README "Limits", "The lock file"): when discovery reports an error (content the repository holds that the scanner
left unread or refused, such as an `AGENTS.md` over 10 MiB), `spellwarden lock` writes no lock file and exits 2, and
`lock --check` exits 2, each naming the error and the way out. 1.16.1 exited 0 with a warning and wrote, or confirmed, a
lock that silently lacked the item. A clean repository behaves as before (0, and 3 for a stale lock)."""
from __future__ import annotations

import json

import pytest

from conftest import scan_json
from instruction_fixture import INJECTION

from spellwarden_cli import lockfile
from spellwarden_cli.files import FILE_MAX

ELEVEN_MB = 11_000_000
assert ELEVEN_MB > FILE_MAX
CLEAN_MCP = '{"mcpServers": {"docs": {"type": "http", "url": "https://mcp.example.com/mcp"}}}'


def _big_agents_md(repo) -> None:
    with open(repo / "AGENTS.md", "wb") as handle:
        handle.write(("# Agents\n\n" + INJECTION).encode("utf-8"))
        handle.truncate(ELEVEN_MB)


def _clean(make_repo, tmp_path, extra: dict | None = None):
    return make_repo(tmp_path / "repo", {".mcp.json": CLEAN_MCP, **(extra or {})})


def test_lock_writes_no_lock_file_and_exits_2_for_an_oversize_agents_md(make_repo, tmp_path, run_cli):
    repo = _clean(make_repo, tmp_path)
    _big_agents_md(repo)
    code, out, err = run_cli(["lock", str(repo)])
    assert (code, out) == (2, "")
    assert not (repo / lockfile.LOCK_PATH).exists()
    lines = err.splitlines()
    assert lines[0].startswith("spellwarden: error: unreadable AGENTS.md: larger than 10 MiB")
    assert "`exclude`" in lines[0]  # the error's own way out
    assert f"{lockfile.LOCK_PATH} was not written" in lines[-1] and "`exclude`" in lines[-1]
    assert "`spellwarden lock` again" in lines[-1]
    assert "warning" not in err


def test_an_existing_lock_file_is_left_untouched(make_repo, tmp_path, run_cli):
    repo = _clean(make_repo, tmp_path)
    assert run_cli(["lock", str(repo)])[0] == 0
    before = (repo / lockfile.LOCK_PATH).read_bytes()
    _big_agents_md(repo)
    code, _out, err = run_cli(["lock", str(repo)])
    assert code == 2 and "left as it was" in err
    assert (repo / lockfile.LOCK_PATH).read_bytes() == before


def test_lock_check_exits_2_when_content_was_not_read(make_repo, tmp_path, run_cli):
    repo = _clean(make_repo, tmp_path)
    assert run_cli(["lock", str(repo)])[0] == 0
    _big_agents_md(repo)
    code, out, err = run_cli(["lock", str(repo), "--check"])
    assert (code, out) == (2, "")
    assert "unreadable AGENTS.md:" in err
    assert f"{lockfile.LOCK_PATH} was not compared" in err and "`spellwarden lock --check` again" in err


def test_lock_check_exits_2_without_a_lock_file_too(make_repo, tmp_path, run_cli):
    # an incomplete read outranks an absent lock, as in `scan --locked` (2 over 3)
    repo = _clean(make_repo, tmp_path)
    _big_agents_md(repo)
    assert run_cli(["lock", str(repo), "--check"])[0] == 2


def test_lock_probe_stops_before_probing(make_repo, tmp_path, run_cli):
    # repository content left unread is the repository's own error; no server is probed and nothing is written
    repo = _clean(make_repo, tmp_path)
    _big_agents_md(repo)
    code, _out, err = run_cli(["lock", "--probe", str(repo)])
    assert code == 2 and "unreadable AGENTS.md:" in err
    assert not (repo / lockfile.LOCK_PATH).exists()


def test_scan_locked_already_exits_2_for_the_same_repository(make_repo, tmp_path, run_cli):
    repo = _clean(make_repo, tmp_path)
    assert run_cli(["lock", str(repo)])[0] == 0
    _big_agents_md(repo)
    code, report, _out, _err = scan_json(run_cli, repo, None, "--locked")
    assert code == 2
    assert ("unreadable", "AGENTS.md") in {(e["code"], e["path"]) for e in report["errors"]}


def test_exclude_is_the_way_out(make_repo, tmp_path, run_cli):
    repo = _clean(make_repo, tmp_path, {".spellwarden/config.yml": 'version: 1\nexclude: ["AGENTS.md"]\n'})
    _big_agents_md(repo)
    code, _out, err = run_cli(["lock", str(repo)])
    assert code == 0, err
    paths = {item["path"] for item in json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8"))["items"]}
    assert "AGENTS.md" not in paths
    assert run_cli(["lock", str(repo), "--check"])[0] == 0


def test_a_clean_repository_behaves_as_before(make_repo, tmp_path, run_cli):
    repo = _clean(make_repo, tmp_path, {"AGENTS.md": "# Agents\n\nRun the tests.\n"})
    code, out, err = run_cli(["lock", str(repo)])
    assert code == 0 and out.startswith(f"Wrote {lockfile.LOCK_PATH} with ") and err == ""
    assert run_cli(["lock", str(repo), "--check"])[0] == 0
    (repo / "AGENTS.md").write_text("# Agents\n\nRun the tests twice.\n", encoding="utf-8")
    code, out, _err = run_cli(["lock", str(repo), "--check"])
    assert code == 3 and "changed instructions AGENTS.md" in out


def _link(target: str, link) -> None:
    import os

    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")


SKILL = "---\nname: x\ndescription: A demo.\n---\n\nRead.\n"


def test_a_skill_member_link_to_the_lock_is_locked_by_the_first_lock(make_repo, tmp_path, run_cli):
    # review of 1.16.2, Major 3: the first `lock` holds the skill, so `lock --check` passes at once
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    _link("../../.spellwarden/lock.json", repo / "skills" / "x" / "state.json")
    code, _out, err = run_cli(["lock", str(repo)])
    assert code == 0, err
    items = json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8"))["items"]
    assert [(item["kind"], item["path"]) for item in items] == [("skill", "skills/x")]
    code, out, err = run_cli(["lock", str(repo), "--check"])
    assert code == 0, (out, err)
    code, report, _out, _err = scan_json(run_cli, repo, None, "--locked")
    assert code == 0 and report["lock"]["status"] == "ok"


def test_a_skill_member_link_to_the_lock_does_not_stop_a_scan_before_the_first_lock(make_repo, tmp_path, run_cli):
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    _link("../../.spellwarden/lock.json", repo / "skills" / "x" / "state.json")
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 0 and report["errors"] == []
    notice = next(n for n in report["notices"] if n["path"] == "skills/x/state.json")
    assert "does not exist yet" in notice["message"]


@pytest.mark.parametrize("link", [".mcp.json", ".claude/settings.json"])
def test_any_other_link_to_the_lock_stops_the_lock(make_repo, tmp_path, run_cli, link):
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    _link("../" * link.count("/") + ".spellwarden/lock.json", repo / link)
    code, _out, err = run_cli(["lock", str(repo)])
    assert code == 2 and f"unsafe_path {link}:" in err
    assert not (repo / lockfile.LOCK_PATH).exists()
