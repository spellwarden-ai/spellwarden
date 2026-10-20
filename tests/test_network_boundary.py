"""Spec 2 invariant 2 and claim C16: of both packages, only `spellwarden_cli/net.py` (the probe), `ping.py` (the
usage ping) and `forge.py` (the comment) import `socket`, `ssl`, `http` or `urllib.request`; only `files.py` and
`ci.py` (git) import `subprocess`; nothing imports modules by name at run time to get around this."""
from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
PACKAGES = ("spellwarden_scan", "spellwarden_cli")
NETWORK = ("socket", "ssl", "http", "urllib.request")
NETWORK_MODULES = {"spellwarden_cli/net.py", "spellwarden_cli/ping.py", "spellwarden_cli/forge.py"}
SUBPROCESS_MODULES = {"spellwarden_cli/files.py", "spellwarden_cli/ci.py"}


def modules():
    for package in PACKAGES:
        for path in sorted((SRC / package).rglob("*.py")):
            yield path.relative_to(SRC).as_posix(), ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imported(tree: ast.AST) -> set[str]:
    """Every dotted name a module imports: `import a.b` gives `a.b`; `from a import b` gives `a` and `a.b`."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def reaches(names: set[str], roots: tuple[str, ...]) -> set[str]:
    return {name for name in names if any(name == root or name.startswith(root + ".") for root in roots)}


def test_only_three_modules_reach_the_network():
    offenders = {name: sorted(reaches(imported(tree), NETWORK)) for name, tree in modules()
                 if reaches(imported(tree), NETWORK) and name not in NETWORK_MODULES}
    assert offenders == {}


def test_the_network_modules_are_the_ones_that_exist_and_need_it():
    present = {name for name, _ in modules()}
    assert {"spellwarden_cli/ping.py", "spellwarden_cli/forge.py"} <= present  # net.py arrives in Task 11
    for name, tree in modules():
        if name in NETWORK_MODULES:
            assert reaches(imported(tree), NETWORK), f"{name} is allowed the network but does not use it"


def test_only_files_and_ci_run_subprocesses():
    offenders = sorted(name for name, tree in modules() if reaches(imported(tree), ("subprocess",)) and name not in SUBPROCESS_MODULES)
    assert offenders == []


def test_nothing_imports_by_name_at_run_time():
    for name, tree in modules():
        assert not reaches(imported(tree), ("importlib",)), f"{name} imports importlib"
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert node.id != "__import__", f"{name} calls __import__"
