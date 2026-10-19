"""Spec 2 invariant 1 and claim P1: the engine does no I/O."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "spellwarden_scan"
FORBIDDEN_MODULES = {"os", "subprocess", "socket", "urllib", "http", "requests", "boto3", "botocore", "spellwarden",
                     "importlib", "pathlib", "shutil", "tempfile", "glob"}
ALLOWED_THIRD_PARTY = {"yaml"}
# `zipfile.ZipFile.open` streams an entry from bytes; it is the one `.open(` the engine may call.
OPEN_ALLOWED_IN = {"archive.py"}


def modules():
    for path in sorted(SRC.rglob("*.py")):
        yield path.relative_to(SRC).as_posix(), ast.parse(path.read_text(), filename=str(path))


def imported_roots(tree) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_every_import_is_stdlib_yaml_or_the_package_itself():
    stdlib = set(sys.stdlib_module_names)
    for name, tree in modules():
        for root in imported_roots(tree):
            assert root == "spellwarden_scan" or root in ALLOWED_THIRD_PARTY or root in stdlib, f"{name} imports {root}"
            assert root not in FORBIDDEN_MODULES, f"{name} imports {root}"


def test_sys_is_used_only_for_version_info_and_nothing_reads_the_environment():
    for name, tree in modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "sys":
                assert node.attr == "version_info", f"{name} uses sys.{node.attr}"
            if isinstance(node, ast.Name):
                assert node.id not in ("environ", "getenv"), f"{name} reads the environment"


def test_nothing_opens_a_file():
    for name, tree in modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id == "open":
                raise AssertionError(f"{name} calls open()")
            if isinstance(func, ast.Attribute) and func.attr == "open" and name not in OPEN_ALLOWED_IN:
                raise AssertionError(f"{name} calls .open()")
