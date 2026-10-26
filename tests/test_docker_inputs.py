"""Spec 7.2 and O4 spec 7: the image installs the runtime dependencies (PyYAML and, since 1.3.0, `cryptography` with the
distributions it needs) from `docker/requirements.deps.txt`, every published hash pinned, and each version is the one
`uv.lock` resolves; `.dockerignore` keeps the build context to the three install inputs."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _requirements() -> str:
    return (ROOT / "docker" / "requirements.deps.txt").read_text(encoding="utf-8")


def _locked() -> dict[str, dict]:
    return {p["name"]: p for p in tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]}


def _runtime_closure() -> set[str]:
    """The distributions `spellwarden` needs at run time: its own dependencies and theirs, whatever the markers say."""
    packages, seen, pending = _locked(), set(), ["spellwarden"]
    while pending:
        for dependency in packages[pending.pop()].get("dependencies", []):
            if dependency["name"] not in seen:
                seen.add(dependency["name"])
                pending.append(dependency["name"])
    return seen


def test_the_requirements_are_exactly_the_locks_runtime_set_at_the_locked_versions_with_hashes():
    text = _requirements()
    names = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\;]+)", text, re.M)
    assert {name.lower() for name, _ in names} == _runtime_closure() >= {"pyyaml", "cryptography", "cffi", "pycparser"}
    locked = _locked()
    for name, version in names:
        assert version == locked[name.lower()]["version"], name
    blocks = re.split(r"(?m)^(?=[A-Za-z0-9_.-]+==)", text)[1:]
    assert len(blocks) == len(names)
    for block in blocks:
        assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", block)) >= 1, block.splitlines()[0]
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", text)) >= 50, "every published file of every distribution is pinned"


def test_the_dockerfile_pins_its_base_by_digest_and_never_reaches_an_index():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.13-slim@sha256:[0-9a-f]{64} AS system$", dockerfile, re.M)
    assert "__PYTHON_SLIM_DIGEST__" not in dockerfile
    for line in re.findall(r"pip install[^;\n]*", dockerfile):
        assert "--no-index" in line, line
    assert "USER spellwarden" in dockerfile and "--uid 10001" in dockerfile
    assert 'ENTRYPOINT ["python", "-I", "-m", "spellwarden_cli"]' in dockerfile and 'CMD ["scan"]' in dockerfile


def test_the_final_stage_builds_on_a_prebuilt_system_image_so_that_no_run_needs_the_network():
    # `docker build --network none` forces that mode on every RUN, the system stage's apt-get included, and the
    # network mode is part of a RUN's cache key: a cached system stage does not carry over. So the final stage starts
    # from the image check.yml builds first (`--target system -t spellwarden-system`); release.yml builds with the
    # network and names the stage instead.
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    first_from = dockerfile.index("\nFROM ")
    assert "\nARG SYSTEM_BASE=spellwarden-system\n" in dockerfile[: first_from + 1], "a global ARG precedes the first FROM"
    assert re.search(r"^FROM \$\{SYSTEM_BASE\}$", dockerfile, re.M)
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "SYSTEM_BASE=system" in release
    check = (ROOT / ".github" / "workflows" / "check.yml").read_text(encoding="utf-8")
    assert "-t spellwarden-system" in check and "SYSTEM_BASE" not in check


def test_the_build_context_is_the_three_install_inputs():
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert lines == ["*", "!docker/requirements.deps.txt", "!docker/Dockerfile", "!dist/*.whl", "!wheelhouse/"]


def test_the_action_candidate_reference_is_one_commit():
    assert re.fullmatch(r"[0-9a-f]{40}\n", (ROOT / "wrappers" / "scan-action.ref").read_text(encoding="utf-8"))


def test_fixture_repositories_check_out_on_windows():
    bad = re.compile(r'[|<>:"*?\\]')
    for path in (ROOT / "fixtures" / "repos").rglob("*"):
        assert not bad.search(path.name), f"{path} cannot exist in a Windows checkout"
