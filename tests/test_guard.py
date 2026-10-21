"""Claim E7, the running half (Phase C spec 5.5.1): the generated guard, run as `python -I spellwarden_guard.py pre`
in a subprocess, decides every event of `fixtures/guard_vectors.json` as the vector says, and the engine's own
detectors give the same decisions; unexpected input exits 0 with nothing on stdout and one line on stderr; `post`
writes the local activity log only to a regular file, mode 0600, rotated at 5 MiB; `-I` keeps planted modules out."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from guard_ci import BUILT_AT, load_vectors, problems_of, run_command, stdin_of, titles, vector_pack

from spellwarden_scan import orgrules
from spellwarden_scan.exports import hooks
from spellwarden_scan.exports.guard_template import TEMPLATE
from spellwarden_scan.package import CodeBlock
from spellwarden_scan.rules import patterns as P
from spellwarden_scan.rules import skill

VECTORS = load_vectors()
NAMES = titles()
LOG = "spellwarden-activity.jsonl"
PATH_FIELDS = {"Read": ("file_path",), "Grep": ("path",), "Glob": ("pattern", "path")}


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    """A checkout holding the project-mode export of the vector pack."""
    root = tmp_path_factory.mktemp("checkout")
    for path, content in hooks.hooks_files(vector_pack(), built_at=BUILT_AT, mode="project").items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(content)
    return root


def _guard(root: Path) -> Path:
    return root / ".claude" / "hooks" / "spellwarden_guard.py"


def _run(root: Path, phase: str, stdin: bytes, *, cwd=None, env=None):
    return run_command([sys.executable, "-I", str(_guard(root)), phase], stdin, cwd=cwd, env=env)


@pytest.mark.parametrize("item", VECTORS["vectors"], ids=lambda item: item["name"])
def test_each_vector_decides_as_it_says(project, item):
    assert problems_of(item, _run(project, "pre", stdin_of(item)), NAMES) == []


@pytest.mark.parametrize("item", VECTORS["invalid"], ids=lambda item: item["name"])
def test_unexpected_input_exits_0_with_one_stderr_line(project, item):
    result = _run(project, "pre", stdin_of(item))
    assert problems_of(item, result, NAMES) == []
    assert result.stdout == b""


def test_two_mib_of_input_is_unreadable(project):
    result = _run(project, "pre", b"a" * (2 * 1024 * 1024))
    assert (result.returncode, result.stdout) == (0, b"")
    assert len(result.stderr.decode().splitlines()) == 1


def test_an_unknown_phase_is_not_a_failure(project):
    result = _run(project, "during", b"{}")
    assert (result.returncode, result.stdout) == (0, b"")


def _commands(text: str) -> list[str]:
    return [entry[2] for entry in skill.logical_commands(CodeBlock("hook", "sh", text, 1))]


def _engine_decision(event: dict) -> tuple[str | None, str | None]:
    """The decision the engine's own detectors give, independently of the guard: deny checks first, then ask
    checks, each in rule id order (spec 5.5.1, decision D27)."""
    tool, tool_input = event["tool_name"], event.get("tool_input", {})
    org = {spec["id"]: orgrules.compile_pattern(spec["detection"]["pattern"]) for spec in VECTORS["org_rules"]}
    commands = _commands(tool_input["command"]) if tool in ("Bash", "PowerShell") else []
    paths = [tool_input[name] for name in PATH_FIELDS.get(tool, ()) if tool_input.get(name)]

    def secret(text: str) -> bool:
        return any(p.search(variant) for p in (P.SECRET_PATHS, P.MORE_SECRET_PATHS) for variant in (text, text.replace("\\", "/")))

    def mcp_verb() -> bool:
        if not tool.startswith("mcp__") or "__" not in tool[5:]:
            return False
        name = tool[5:].split("__", 1)[1].lower()
        return any(name.startswith(verb) or verb in name.replace("-", "_").split("_") for verb in hooks.MCP_VERBS)

    if any(list(skill.pipes_remote_to_shell([("hook", 1, text)])) for text in commands):
        return "deny", "SW-HK-001"
    if any(secret(text) for text in commands + paths):
        return "deny", "SW-HK-002"
    if any(orgrules.pattern_search(org["SW-ORG-001"], text) for text in commands):
        return "deny", "SW-ORG-001"
    if any(skill._DESTRUCTIVE.search(text) for text in commands) or mcp_verb():
        return "ask", "SW-GW-006"
    if any(orgrules.pattern_search(org["SW-ORG-002"], text) for text in commands):
        return "ask", "SW-ORG-002"
    return None, None


@pytest.mark.parametrize("item", VECTORS["vectors"], ids=lambda item: item["name"])
def test_the_engine_detectors_agree_with_each_vector(item):
    assert _engine_decision(item["event"]) == (item["decision"], item["rule_id"])


def _guard_namespace() -> dict:
    """The guard's functions, loaded without running its main."""
    source = hooks.guard_script(vector_pack()).decode("utf-8").replace('if __name__ == "__main__":', "if False:")
    namespace: dict = {}
    exec(compile(source, "spellwarden_guard.py", "exec"), namespace)
    return namespace


LOOP_PATTERNS = [r"curl\s.*\.sh$", r"^curl\s.*x", r"\bprod\b", r"(a|b)c{2}.*d$", r"^e.*f$"]
LOOP_TEXTS = ["curl https://x.example/i.sh", "curl https://x.example/i.sh tail", "e" + "z" * 9000 + "f",
              "y" * 5000 + "curl x", "curl " + "q" * 4000 + "x", "w" * 3580 + "prod" + "w" * 600, "w" * 4094 + "prod",
              "acc" + "d" * 4200, "acc" + "v" * 8000 + "d", "xacc" * 1500 + "d", "prod" + "u" * 7000 + "e" + "f"]


def test_the_guard_window_loop_equals_the_engine_pattern_search():
    guard = _guard_namespace()
    assert TEMPLATE.count("def windowed(") == 1
    for pattern in LOOP_PATTERNS:
        compiled = orgrules.compile_pattern(pattern)
        parts = [guard["re"].compile(part.pattern, part.flags & ~guard["re"].UNICODE) for part in compiled.parts]
        for text in LOOP_TEXTS:
            assert guard["windowed"](parts, text, compiled.anchored_end) == orgrules.pattern_search(compiled, text), (pattern, text[:20])
        assert list(guard["spans"](9000)) == list(orgrules.unit_windows("x" * 9000))


def _post_env(root: Path, **extra: str) -> dict:
    return dict(os.environ, CLAUDE_PROJECT_DIR=str(root), **extra)


POST_EVENT = json.dumps({"session_id": "s-7", "hook_event_name": "PostToolUse", "tool_name": "Bash",
                         "tool_input": {"command": "cat secret.txt"}, "tool_response": {"stdout": "hunter2"}}).encode()


def test_post_appends_one_line_without_tool_input(project):
    log = project / ".claude" / LOG
    log.unlink(missing_ok=True)
    for _ in range(2):
        result = _run(project, "post", POST_EVENT, env=_post_env(project))
        assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")
    lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert set(lines[0]) == {"at", "session_id", "tool_name", "hook"}
    assert lines[0]["session_id"] == "s-7" and lines[0]["tool_name"] == "Bash" and lines[0]["hook"] == "PostToolUse"
    assert "hunter2" not in log.read_text(encoding="utf-8") and "secret.txt" not in log.read_text(encoding="utf-8")
    if os.name == "posix":
        assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_post_rotates_at_five_mib(project):
    log = project / ".claude" / LOG
    log.write_bytes(b"x" * (5 * 1024 * 1024))
    result = _run(project, "post", POST_EVENT, env=_post_env(project))
    assert result.returncode == 0
    assert (project / ".claude" / (LOG + ".1")).stat().st_size == 5 * 1024 * 1024
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1
    (project / ".claude" / (LOG + ".1")).unlink()


def _refused(project: Path, make) -> None:
    log = project / ".claude" / LOG
    log.unlink(missing_ok=True)
    elsewhere = project / "elsewhere.txt"
    elsewhere.write_bytes(b"")
    make(log, elsewhere)
    result = _run(project, "post", POST_EVENT, env=_post_env(project))
    assert (result.returncode, result.stdout) == (0, b"")
    assert len(result.stderr.decode().splitlines()) == 1
    assert elsewhere.read_bytes() == b""
    assert not (project / ".claude" / (LOG + ".1")).exists()


def test_post_never_writes_through_a_symbolic_link(project):
    def link(log: Path, elsewhere: Path) -> None:
        try:
            os.symlink(elsewhere, log)
        except (OSError, NotImplementedError):
            pytest.skip("this runner cannot create symbolic links")

    _refused(project, link)
    (project / ".claude" / LOG).unlink()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_post_never_writes_to_a_fifo(project):
    _refused(project, lambda log, _elsewhere: os.mkfifo(log))
    (project / ".claude" / LOG).unlink()


def test_post_never_writes_into_a_directory(project):
    _refused(project, lambda log, _elsewhere: log.mkdir())
    (project / ".claude" / LOG).rmdir()


def test_post_in_managed_mode_writes_under_the_home_directory(tmp_path):
    script = tmp_path / "spellwarden_guard.py"
    script.write_bytes(hooks.guard_script(vector_pack(), mode="managed"))
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), CLAUDE_PROJECT_DIR=str(tmp_path / "checkout"))
    result = run_command([sys.executable, "-I", str(script), "post"], POST_EVENT, env=env)
    assert (result.returncode, result.stderr) == (0, b"")
    assert len((home / ".claude" / LOG).read_text(encoding="utf-8").splitlines()) == 1
    assert not (tmp_path / "checkout").exists()


def test_isolated_mode_keeps_planted_modules_out(project, tmp_path):
    planted = 'import sys\nsys.stdout.write("PLANTED\\n")\nsys.exit(9)\n'
    (tmp_path / "json.py").write_text(planted, encoding="utf-8")
    beside = _guard(project).parent / "json.py"
    beside.write_text(planted, encoding="utf-8")
    try:
        vector = VECTORS["vectors"][0]
        result = _run(project, "pre", stdin_of(vector), cwd=tmp_path, env=dict(os.environ, PYTHONPATH=str(tmp_path)))
        assert b"PLANTED" not in result.stdout
        assert problems_of(vector, result, NAMES) == []
    finally:
        beside.unlink()
