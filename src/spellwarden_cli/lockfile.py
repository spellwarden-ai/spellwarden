"""`.spellwarden/lock.json` (spec 6.6): every discovered configuration document, MCP server entry, marketplace
plugin, local plugin directory and skill, each pinned by hash or declared source. `spellwarden lock` writes it;
`--locked` and `lock --check` compare it with what the scan computed."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable, Mapping

from spellwarden_scan import canonical_sha256
from spellwarden_scan.agentconfig import has_declared_pin
from spellwarden_scan.model import PluginSource

from spellwarden_cli import commands, discover, escape, files, paths
from spellwarden_cli.baseline import BASELINE_PATH
from spellwarden_cli.discover import Discovery
from spellwarden_cli.report import LOCK_ITEM_KINDS, LockState
from spellwarden_cli.settings import CONFIG_PATH

LOCK_PATH = ".spellwarden/lock.json"
LOCK_VERSION = 1
# The item kinds `compute_lock` writes; a stored lock holding any other kind is unreadable (spec 6.6, 6.13).
KINDS = frozenset(LOCK_ITEM_KINDS)
# The scanner's own files, by exact scan-root path. Nothing else under `.spellwarden/` is left out of a hash: a root
# SKILL.md may run `.spellwarden/setup.sh`, and that script is skill content (r0:F5).
OWN_FILES = frozenset({LOCK_PATH, BASELINE_PATH, CONFIG_PATH})


class LockUnreadable(ValueError):
    """The lock file exists but cannot be used (spec 6.6: exit 2)."""


def _status(error: str | None) -> str:
    if error is None:
        return "ok"
    if error == "truncated":
        return "truncated"
    return f"error:{error}"


def _relative_to(directory: str, path: str) -> str:
    if directory in ("", "."):
        return path
    prefix = directory + "/"
    if not path.startswith(prefix):
        raise ValueError(f"{path} is not under {directory}")
    return path[len(prefix):]


def _own_file(path: str) -> bool:
    """The scanner's own files at the scan root (the lock, the baseline, the settings), by exact scan-root path. A
    package rooted at the scan root (a `SKILL.md` there, a plugin source `.`) holds them, and hashing the lock into
    itself would make every lock stale the moment it is written. A `--baseline FILE` elsewhere is not left out: the
    `lock` command, which writes the lock, does not know it, and the lock must not depend on a flag."""
    return path in OWN_FILES


def _package_hash(directory: str, package: Mapping[str, bytes]) -> str:
    """The lock's move-stable hash: `canonical_sha256` over the files with paths relative to the directory (D8),
    without the scanner's own files (`OWN_FILES`)."""
    return canonical_sha256({_relative_to(directory, path): content for path, content in package.items()
                             if not _own_file(path)})


def declared_pin(source: PluginSource) -> str | None:
    """The 40-hex commit the marketplace declares (5.6): `sha`, or a 40-hex `ref` when there is no `sha`."""
    if not has_declared_pin(source):
        return None
    return source.sha if source.sha is not None else source.ref


def _item_key(item: Mapping) -> tuple[str, str, str]:
    return item["kind"], item["path"], json.dumps(item, sort_keys=True, ensure_ascii=False)


def compute_lock(found: Discovery) -> dict:
    items: list[dict] = []
    for document in found.documents:
        items.append({"kind": "document", "path": document.path, "doc_kind": document.kind,
                      "status": _status(document.error), "sha256": document.sha256})
        for server in document.servers:
            items.append({"kind": "mcp-server", "path": f"{document.path}#{server.name}", "sha256": server.raw_sha256})
        for plugin in document.plugins:
            items.append({"kind": "plugin", "path": f"{document.path}#{plugin.name}", "source": plugin.source.canonical,
                          "pin": declared_pin(plugin.source), "ref": plugin.source.ref})
    for directory in found.plugin_dirs:
        items.append({"kind": "plugin-dir", "path": directory.path, "sha256": _package_hash(directory.path, directory.files)})
    for skill in found.skills:
        items.append({"kind": "skill", "path": skill.path, "name": skill.name,
                      "sha256": _package_hash(skill.path, skill.files)})
    items.sort(key=_item_key)
    return {"lock_version": LOCK_VERSION, "items": items}


def render_lock(lock: Mapping) -> bytes:
    return (json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _read(root: str) -> dict | None:
    """The stored lock, or None when the file is absent. The file comes from the scanned revision: it is read
    contained and bounded, and anything but a lock of version 1 is refused."""
    try:
        data, _mode = paths.read_contained(root, LOCK_PATH, max_bytes=files.FILE_MAX)
    except FileNotFoundError:
        return None
    except (OSError, paths.UnsafePath, paths.TooLarge) as exc:
        raise LockUnreadable(f"{LOCK_PATH} cannot be read: {exc}") from exc
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise LockUnreadable(f"{LOCK_PATH} is not valid JSON") from exc
    version = document.get("lock_version") if isinstance(document, dict) else None
    if type(version) is not int or version != LOCK_VERSION or not isinstance(document.get("items"), list):
        raise LockUnreadable(f"{LOCK_PATH} is not a lock file of version {LOCK_VERSION}")
    for item in document["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("kind"), str) or not isinstance(item.get("path"), str):
            raise LockUnreadable(f"{LOCK_PATH} holds an item without a kind and a path")
        if item["kind"] not in KINDS:
            raise LockUnreadable(f"{LOCK_PATH} holds an item of an unknown kind; the kinds are {', '.join(sorted(KINDS))}")
    return document


def _grouped(items: Iterable[Mapping]) -> dict[tuple[str, str], list[str]]:
    """Items by (kind, path); a key may hold several items (two plugins of one name), compared as a sorted list."""
    groups: dict[tuple[str, str], list[str]] = {}
    for item in items:
        groups.setdefault((item["kind"], item["path"]), []).append(json.dumps(item, sort_keys=True, ensure_ascii=False))
    return {key: sorted(values) for key, values in groups.items()}


def _changes(keys: Iterable[tuple[str, str]]) -> tuple[dict, ...]:
    return tuple({"kind": kind, "path": path} for kind, path in sorted(keys))


def compare_lock(root: str, computed: Mapping) -> LockState:
    stored = _read(root)
    if stored is None:
        return LockState(status="absent")
    old, new = _grouped(stored["items"]), _grouped(computed["items"])
    added = _changes(new.keys() - old.keys())
    removed = _changes(old.keys() - new.keys())
    changed = _changes(key for key in old.keys() & new.keys() if old[key] != new[key])
    return LockState(status="stale" if added or removed or changed else "ok", added=added, removed=removed, changed=changed)


def describe(state: LockState) -> list[str]:
    if state.status == "absent":
        return [f"{LOCK_PATH} is absent. Run `spellwarden lock` and commit the file."]
    if state.status == "ok":
        return [f"{LOCK_PATH} is up to date."]
    lines = [f"{LOCK_PATH} is out of date:"]
    for label, changes in (("added", state.added), ("removed", state.removed), ("changed", state.changed)):
        lines.extend(f"  {label} {escape.terminal(change['kind'])} {escape.terminal(change['path'])}" for change in changes)
    return lines


def add_parser(commands_: argparse._SubParsersAction) -> None:
    parser = commands_.add_parser("lock", help="Write .spellwarden/lock.json, or compare it with --check.")
    parser.add_argument("path", nargs="?", default=".", help="The scan root (default: the current directory).")
    parser.add_argument("--check", action="store_true", help="Compare without writing; exit 3 when absent or stale.")
    parser.set_defaults(handler=cmd_lock)


def cmd_lock(args: argparse.Namespace) -> int:
    try:
        root = commands.scan_root(args.path)
        fileset = files.list_files(root, commands.settings_for(root, os.environ))
    except commands.CommandError as exc:
        return commands.fail(str(exc))
    found = discover.discover(fileset)
    for problem in (*fileset.errors, *found.errors):
        print(f"spellwarden: warning: {problem.code} {escape.terminal(problem.path)}: {escape.terminal(problem.message)}",
              file=sys.stderr)
    computed = compute_lock(found)
    if args.check:
        try:
            state = compare_lock(root, computed)
        except LockUnreadable as exc:
            return commands.fail(str(exc))
        print("\n".join(describe(state)))
        return 0 if state.status == "ok" else 3
    try:
        commands.write_in_root(root, LOCK_PATH, render_lock(computed))
    except (commands.CommandError, OSError) as exc:
        return commands.fail(str(exc))
    print(f"Wrote {LOCK_PATH} with {len(computed['items'])} items.")
    return 0
