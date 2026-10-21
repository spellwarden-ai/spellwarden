"""The guard's shared test support and the CI job `managed-guard` (Phase C spec 5.5.1's release gate, claim E7).

The tests import it (`vector_pack`, `run_command`, `problems_of`); the workflow runs it:

    python tests/guard_ci.py build OUT                  the managed export of the vector pack, written under OUT
    python tests/guard_ci.py sums SHA256SUMS SCRIPT     the installed script matches the export's SHA256SUMS
    python tests/guard_ci.py perms SCRIPT               (Linux, macOS) the script and its folder are root's, not writable
                                                        by group or others, and this unprivileged user cannot change them
    python tests/guard_ci.py run SETTINGS SHELL         every vector through the exact PreToolUse command of SETTINGS
    python tests/guard_ci.py isolation SETTINGS SHELL   a planted json.py in the current directory and on PYTHONPATH is
                                                        not imported

SHELL is `sh`, a path to `bash` (Git Bash on Windows), `powershell` or `cmd`: the shells Claude Code and the spec
name for hook commands. Nothing here opens the network."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS_PATH = ROOT / "fixtures" / "guard_vectors.json"
PACK_ID = "0123456789abcdef" * 2
PACK_NAME = "Guard vectors"
PACK_VERSION = "1.0"
BUILT_AT = "2026-10-21T00:00:00Z"
TIMEOUT_SECONDS = 30


def load_vectors() -> dict:
    """The vectors, with every `expand` vector's command built (`prefix + repeat * times + suffix`)."""
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    for item in vectors["vectors"]:
        if "expand" in item:
            spec = item["expand"]
            item["event"]["tool_input"]["command"] = spec["prefix"] + spec["repeat"] * spec["times"] + spec["suffix"]
    return vectors


def vector_pack(enabled=None, org_rules=None, name: str = PACK_NAME):
    """The pack of the vectors: every enforcement rule on (or only `enabled`) and the vectors' two org rules (or
    `org_rules`)."""
    from spellwarden_scan.packs import ENFORCEMENT_IDS, make_pack_document, validate_pack

    rules = {rule_id: enabled is None or rule_id in enabled for rule_id in ENFORCEMENT_IDS}
    specs = load_vectors()["org_rules"] if org_rules is None else list(org_rules)
    return validate_pack(make_pack_document(pack_id=PACK_ID, name=name, version=PACK_VERSION, description="",
                                            rules=rules, org_rules=specs))


def titles() -> dict[str, str]:
    from spellwarden_scan.packs import ENFORCEMENT_RULES

    found = {rule.id: rule.title for rule in ENFORCEMENT_RULES}
    found.update({spec["id"]: spec["title"] for spec in load_vectors()["org_rules"]})
    return found


def shell_argv(shell: str, command: str):
    """How a platform shell runs one hook command string, unchanged."""
    if shell == "powershell":
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
    if shell == "cmd":
        return 'cmd.exe /d /s /c "' + command + '"'  # a string: cmd /s keeps everything between the outer quotes
    return [shell, "-c", command]


def run_command(argv, stdin: bytes, *, cwd=None, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=stdin, capture_output=True, cwd=cwd, env=env, timeout=TIMEOUT_SECONDS, check=False)


def stdin_of(item: dict) -> bytes:
    if "event" in item:
        return json.dumps(item["event"]).encode("utf-8")
    if "stdin_hex" in item:
        return bytes.fromhex(item["stdin_hex"])
    return item["stdin"].encode("utf-8")


def problems_of(item: dict, result: subprocess.CompletedProcess, names: dict[str, str]) -> list[str]:
    """What is wrong with one run of the guard on one vector (an empty list when it decided as the vector says)."""
    name = item["name"]
    out = result.stdout.decode("utf-8", "replace").strip()
    err = result.stderr.decode("utf-8", "replace")
    if result.returncode != 0:
        return [f"{name}: exit {result.returncode}: {err.strip()}"]
    if "event" not in item:
        found = []
        if out:
            found.append(f"{name}: printed {out!r} for unexpected input")
        if len(err.splitlines()) != 1:
            found.append(f"{name}: wrote {err!r} to stderr, not one line")
        return found
    if item["decision"] is None:
        return [] if out == "" else [f"{name}: printed {out!r}, expected nothing"]
    try:
        decision = json.loads(out)["hookSpecificOutput"]
    except (ValueError, KeyError, TypeError):
        return [f"{name}: printed {out!r}, expected a decision"]
    reason = f"Spellwarden {item['rule_id']}: {names[item['rule_id']]} (pack {PACK_NAME} {PACK_VERSION})."
    expected = {"hookEventName": "PreToolUse", "permissionDecision": item["decision"], "permissionDecisionReason": reason}
    return [] if decision == expected else [f"{name}: got {decision}, expected {expected}"]


def _pre_command(settings: Path) -> str:
    document = json.loads(settings.read_text(encoding="utf-8"))
    if document.get("allowManagedHooksOnly") is not True:
        raise SystemExit(f"{settings}: allowManagedHooksOnly is not true")
    command = document["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    post = document["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    if not command.endswith(" pre") or post != command[: -len("pre")] + "post":
        raise SystemExit(f"{settings}: unexpected commands {command!r} {post!r}")
    if "$CLAUDE_PROJECT_DIR" in settings.read_text(encoding="utf-8"):
        raise SystemExit(f"{settings}: names $CLAUDE_PROJECT_DIR")
    return command


def cmd_build(out: str) -> int:
    from spellwarden_scan.exports import build

    for path, content in build(vector_pack(), "claude-code-hooks", built_at=BUILT_AT, mode="managed").items():
        target = Path(out) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        print(f"wrote {target}")
    return 0


def cmd_sums(sums: str, script: str) -> int:
    digest, _name = Path(sums).read_text(encoding="ascii").split()
    actual = hashlib.sha256(Path(script).read_bytes()).hexdigest()
    if actual != digest:
        print(f"{script}: sha256 {actual} is not {digest}")
        return 1
    print(f"{script}: matches SHA256SUMS")
    return 0


def cmd_perms(script: str) -> int:
    path = Path(script)
    problems = []
    if os.geteuid() == 0:
        problems.append("run this check as the unprivileged runner user, not as root")
    for target in (path, path.parent):
        info = target.stat()
        if info.st_uid != 0:
            problems.append(f"{target} is not owned by root")
        if info.st_mode & 0o022:
            problems.append(f"{target} is writable by group or others ({oct(info.st_mode & 0o777)})")
    try:
        with open(path, "ab"):
            problems.append(f"{path} can be opened for writing")
    except PermissionError:
        pass
    try:
        os.rename(path, path.with_name(path.name + ".moved"))
        problems.append(f"{path} can be moved away")
    except PermissionError:
        pass
    for problem in problems:
        print(problem)
    return 1 if problems else 0


def cmd_run(settings: str, shell: str) -> int:
    command = _pre_command(Path(settings))
    vectors = load_vectors()
    names = titles()
    problems: list[str] = []
    for item in vectors["vectors"] + vectors["invalid"]:
        problems += problems_of(item, run_command(shell_argv(shell, command), stdin_of(item)), names)
    big = {"name": "2 MiB of input", "stdin": ""}
    problems += problems_of(big, run_command(shell_argv(shell, command), b"a" * (2 * 1024 * 1024)), names)
    for problem in problems:
        print(problem)
    print(f"{shell}: {command}: {len(vectors['vectors']) + len(vectors['invalid']) + 1} vectors, {len(problems)} problems")
    return 1 if problems else 0


def cmd_isolation(settings: str, shell: str) -> int:
    command = _pre_command(Path(settings))
    vector = load_vectors()["vectors"][0]
    with tempfile.TemporaryDirectory() as planted:
        Path(planted, "json.py").write_text('import sys\nsys.stdout.write("PLANTED\\n")\nsys.exit(9)\n', encoding="utf-8")
        env = dict(os.environ, PYTHONPATH=planted)
        result = run_command(shell_argv(shell, command), stdin_of(vector), cwd=planted, env=env)
    problems = problems_of(vector, result, titles())
    if b"PLANTED" in result.stdout:
        problems.append("the planted json.py was imported")
    for problem in problems:
        print(problem)
    print(f"{shell}: isolation: {len(problems)} problems")
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    commands = {"build": cmd_build, "sums": cmd_sums, "perms": cmd_perms, "run": cmd_run, "isolation": cmd_isolation}
    if len(argv) < 2 or argv[1] not in commands:
        print(__doc__)
        return 2
    return commands[argv[1]](*argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
