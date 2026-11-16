"""`.spellwarden/lock.json` (spec 6.6): every discovered configuration document, MCP server entry, marketplace
plugin, local plugin directory, skill and instruction file, each pinned by hash or declared source. `spellwarden lock` writes it;
`--locked` and `lock --check` compare it with what the scan computed.

1.15.0 (owner decision O2): `spellwarden lock --probe` also pins the probed tool hashes of each remote server whose tools it
read, as an `mcp-tools` item (`{"kind": "mcp-tools", "path": "<document>#<server>", "format": 1, "kinds": {kind: hash}}`,
`toolhash` kind hashes of the kinds read in full; never the endpoint or a credential). Only a run that probes compares them:
`scan --probe --locked` makes the lock stale when a kind read in full both then and now has another hash, and says
`tools_not_compared` for a pinned server or kind it could not read; `scan --probe` without `--locked` says `tools_changed`.
Every comparison without a probe, `lock --check` included, leaves the pins out on both sides, and `lock` without `--probe`
keeps the stored pin of every server it locks again.

1.16.1 (review High 3): "read in full" means every entry was read (`KindListing.entries_whole`), whether or not the probe cut
a text or dropped a schema in it, as the hosted product compares; such a kind is pinned and compared over the texts as the
probe keeps them, with the notice `probe_list_incomplete` (a change past the cut is not seen)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime

from spellwarden_scan import RuleSet, canonical_sha256, toolhash
from spellwarden_scan.agentconfig import has_declared_pin
from spellwarden_scan.model import PluginSource

from spellwarden_cli import commands, discover, escape, files, paths
from spellwarden_cli.baseline import BASELINE_PATH
from spellwarden_cli.discover import Discovery
from spellwarden_cli.report import LOCK_ITEM_KINDS, LockState, Notice, ProbeReport
from spellwarden_cli.settings import CONFIG_PATH

LOCK_PATH = ".spellwarden/lock.json"
LOCK_VERSION = 1
# The item kinds `compute_lock` writes; a stored lock holding any other kind is unreadable (spec 6.6, 6.13).
KINDS = frozenset(LOCK_ITEM_KINDS)
# The scanner's own files, by exact scan-root path. Nothing else under `.spellwarden/` is left out of a hash: a root
# SKILL.md may run `.spellwarden/setup.sh`, and that script is skill content (r0:F5).
OWN_FILES = frozenset({LOCK_PATH, BASELINE_PATH, CONFIG_PATH})
PIN_KIND = "mcp-tools"
PIN_FORMAT = 1


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


def _package_hash(directory: str, package: Mapping[str, bytes], links: Mapping[str, bytes] | None = None,
                  own: frozenset[str] = frozenset()) -> str:
    """The lock's move-stable hash: `canonical_sha256` over the files with paths relative to the directory (D8),
    without the scanner's own files (`OWN_FILES`) and without the member links `own` that discovery followed to the
    lock (r3 nit: a link to the lock would hash the lock into itself, stale the moment it is written; a link to the
    settings or the baseline is hashed, r4:R4-3). A package with
    member links that discovery could not follow (r2:F6) also hashes each link's target text, so pointing such a link
    elsewhere makes the lock stale: SHA-256 of
    `spellwarden-package-links` NUL, then the compact sorted JSON `{"files": <that hash>, "links": {<relative link
    path>: <target text in hex>}}`. That input ends with `}`; every `canonical_sha256` input is empty or ends with
    NUL, so no package without such links (whose hash is unchanged) shares an input with one that has them."""
    files_hash = canonical_sha256({_relative_to(directory, path): content for path, content in package.items()
                                   if not _own_file(path) and path not in own})
    kept = {_relative_to(directory, path): text.hex() for path, text in (links or {}).items() if not _own_file(path)}
    if not kept:
        return files_hash
    text = json.dumps({"files": files_hash, "links": kept}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(b"spellwarden-package-links\x00" + text.encode("ascii")).hexdigest()


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
        items.append({"kind": "plugin-dir", "path": directory.path, "sha256": _package_hash(directory.path, directory.files,
                                                                                     directory.links, directory.own)})
    for skill in found.skills:
        items.append({"kind": "skill", "path": skill.path, "name": skill.name,
                      "sha256": _package_hash(skill.path, skill.files, skill.links, skill.own)})
    for instruction in found.instruction_files:  # 1.13.0 (Phase 3 batch 1 spec 10.4): each file pinned by its name and bytes
        items.append({"kind": "instructions", "path": instruction.path, "format": instruction.format,
                      "sha256": canonical_sha256({instruction.name: instruction.content})})
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
        if item["kind"] == PIN_KIND and not _valid_pin(item):
            raise LockUnreadable(f"{LOCK_PATH} holds an mcp-tools item that is not of format {PIN_FORMAT}")
    return document


def _valid_pin(item: Mapping) -> bool:
    kinds = item.get("kinds")
    return (type(item.get("format")) is int and item["format"] == PIN_FORMAT and isinstance(kinds, dict) and bool(kinds)
            and all(kind in toolhash.KINDS and isinstance(value, str) for kind, value in kinds.items()))


def _grouped(items: Iterable[Mapping]) -> dict[tuple[str, str], list[str]]:
    """Items by (kind, path); a key may hold several items (two plugins of one name), compared as a sorted list."""
    groups: dict[tuple[str, str], list[str]] = {}
    for item in items:
        groups.setdefault((item["kind"], item["path"]), []).append(json.dumps(item, sort_keys=True, ensure_ascii=False))
    return {key: sorted(values) for key, values in groups.items()}


def _changes(keys: Iterable[tuple[str, str]]) -> tuple[dict, ...]:
    return tuple({"kind": kind, "path": path} for kind, path in sorted(keys))


def pin_of(path: str, listing: toolhash.ToolListing | None) -> tuple[dict | None, tuple[str, ...]]:
    """The `mcp-tools` item of a probed server and the kinds its probe read only in part (never pinned: a list with missing
    entries cannot be compared for additions and removals). A kind whose entries were all read is pinned even when the probe
    cut a text in it (1.16.1, review High 3): the hash over the texts as the probe keeps them is deterministic, so padding one
    description past the cut changes the hash instead of taking the list out of the comparison (`cut_kinds` names these).
    No item when the probe did not read `tools` or read no kind's entries whole."""
    if listing is None or "tools" not in listing.kinds:
        return None, ()
    whole = {kind: listed.hash for kind, listed in listing.kinds.items() if listed.entries_whole}
    partial = tuple(kind for kind, listed in listing.kinds.items() if not listed.entries_whole)
    if not whole:
        return None, partial
    return {"kind": PIN_KIND, "path": path, "format": PIN_FORMAT, "kinds": whole}, partial


def cut_kinds(listing: toolhash.ToolListing, kinds: Iterable[str]) -> list[str]:
    """Those of `kinds` whose entries were all read but in which the probe cut a text or dropped a schema: pinned and
    compared as the probe keeps them, so a change past the cut is not seen."""
    return [kind for kind in kinds if (listed := listing.kinds.get(kind)) is not None and listed.entries_whole
            and not listed.complete]


def _cut_notice(path: str, kinds: list[str]) -> Notice:
    return Notice("probe_list_incomplete", path, f"a text in these lists pinned in {LOCK_PATH} is longer than the probe reads "
                  "(a description 1,000 characters, a schema 16 KiB; README \"Limits\"): they were compared as the probe keeps "
                  f"them, so a change past the cut is not seen: {', '.join(kinds)}")


def _pins(document: Mapping) -> list[dict]:
    return [item for item in document["items"] if item["kind"] == PIN_KIND]


def _kinds_against(pin: Mapping, listing: toolhash.ToolListing) -> tuple[list[str], list[str]]:
    """The pinned kinds whose hash differs now, and the pinned kinds this probe did not read or read with entries missing.
    A kind whose entries were all read is compared even when a text in it was cut (1.16.1): pins written by 1.15.0 and
    1.16.0 hold the same hash of a list read whole, so a list padded past a cut now differs from them."""
    differ: list[str] = []
    unread: list[str] = []
    for kind in toolhash.KINDS:
        if kind not in pin["kinds"]:
            continue
        now = listing.kinds.get(kind)
        if now is None or not now.entries_whole:
            unread.append(kind)
        elif now.hash != pin["kinds"][kind]:
            differ.append(kind)
    return differ, unread


def _not_read_reason(report: ProbeReport | None) -> str:
    if report is None:
        return "the server was not probed"
    if report.status != "probed":
        return f"the server was not probed ({report.skip_reason})"
    return "its tools were not read (the server could not be reached or asks for credentials)"


def compare_pins(pins: Iterable[Mapping], probes: Iterable[ProbeReport], servers: frozenset[str]
                 ) -> tuple[set[tuple[str, str]], set[tuple[str, str]], list[Notice]]:
    """`scan --probe --locked` (owner O2): the pins whose server is no longer locked (removed), the pins a kind of which
    differs (changed), and a `tools_not_compared` notice for each pinned server or kind the run could not read. A server
    that cannot be read never makes the lock stale: a remote party must not fail a build by not answering."""
    by_item = {report.item: report for report in probes}
    changed: set[tuple[str, str]] = set()
    removed: set[tuple[str, str]] = set()
    notices: list[Notice] = []
    for pin in pins:
        path = pin["path"]
        if path not in servers:
            removed.add((PIN_KIND, path))
            continue
        report = by_item.get(path)
        listing = report.listing if report is not None and report.status == "probed" else None
        if listing is None or "tools" not in listing.kinds:
            notices.append(Notice("tools_not_compared", path,
                                  f"the tools pinned in {LOCK_PATH} were not compared: {_not_read_reason(report)}"))
            continue
        differ, unread = _kinds_against(pin, listing)
        if differ:
            changed.add((PIN_KIND, path))
        if unread:
            notices.append(Notice("tools_not_compared", path, f"these lists pinned in {LOCK_PATH} were not read in full and "
                                  f"were not compared: {', '.join(unread)}"))
        cut = cut_kinds(listing, (kind for kind in toolhash.KINDS if kind in pin["kinds"]))
        if cut:
            notices.append(_cut_notice(path, cut))
    return changed, removed, notices


def compare_lock(root: str, computed: Mapping, *, probes: Iterable[ProbeReport] | None = None,
                 notices: list[Notice] | None = None) -> LockState:
    """The stored lock against `computed` (which never holds pins). The `mcp-tools` pins take part only when the run probed
    (`probes` is not None); their notices are appended to `notices`."""
    stored = _read(root)
    if stored is None:
        return LockState(status="absent")
    old = _grouped(item for item in stored["items"] if item["kind"] != PIN_KIND)
    new = _grouped(computed["items"])
    added_keys = set(new.keys() - old.keys())
    removed_keys = set(old.keys() - new.keys())
    changed_keys = {key for key in old.keys() & new.keys() if old[key] != new[key]}
    if probes is not None:
        servers = frozenset(path for kind, path in new if kind == "mcp-server")
        pin_changed, pin_removed, pin_notices = compare_pins(_pins(stored), probes, servers)
        changed_keys |= pin_changed
        removed_keys |= pin_removed
        if notices is not None:
            notices.extend(pin_notices)
    added, removed, changed = _changes(added_keys), _changes(removed_keys), _changes(changed_keys)
    return LockState(status="stale" if added or removed or changed else "ok", added=added, removed=removed, changed=changed)


def changed_pin_notices(root: str, probes: Iterable[ProbeReport]) -> list[Notice]:
    """`scan --probe` without `--locked`: a `tools_changed` notice for each pinned server whose kinds read in full differ now.
    The exit code does not change, and a lock file that is absent or cannot be read gives no notice here."""
    try:
        stored = _read(root)
    except LockUnreadable:
        return []
    if stored is None:
        return []
    by_item = {report.item: report for report in probes}
    notices: list[Notice] = []
    for pin in _pins(stored):
        report = by_item.get(pin["path"])
        listing = report.listing if report is not None and report.status == "probed" else None
        if listing is None or "tools" not in listing.kinds:
            continue
        differ, _unread = _kinds_against(pin, listing)
        if differ:
            notices.append(Notice("tools_changed", pin["path"], f"the server's {', '.join(differ)} differ from the pins in "
                                  f"{LOCK_PATH}; a run with --locked fails on this, and `spellwarden lock --probe` pins the "
                                  "lists the server sends now"))
    return notices


def with_pins(computed: Mapping, pins: Iterable[Mapping]) -> dict:
    """`computed` plus each pin whose `mcp-server` item it holds (the same path), every item sorted as `compute_lock` sorts."""
    servers = {item["path"] for item in computed["items"] if item["kind"] == "mcp-server"}
    items = [*computed["items"], *(dict(pin) for pin in pins if pin["path"] in servers)]
    items.sort(key=_item_key)
    return {"lock_version": LOCK_VERSION, "items": items}


def _warn(message: str) -> None:
    print(f"spellwarden: warning: {escape.terminal(message)}", file=sys.stderr)


def _remote_servers(found: Discovery) -> list[tuple[str, str]]:
    """`(item, url)` of every remote server entry of a judged configuration document."""
    servers: list[tuple[str, str]] = []
    for document in found.documents:
        if document.error not in (None, "truncated"):
            continue
        for server in document.servers:
            if server.transport in ("http", "sse") and server.url:
                servers.append((f"{document.path}#{server.name}", server.url))
    return sorted(servers)


def probe_pins(found: Discovery, stored: Mapping[str, dict], *, now_iso: str,
               fetcher_factory: Callable[[], object] | None = None) -> dict[str, dict]:
    """`lock --probe`: the pins to write, by item. Each configured remote server is probed with the scan's probe rules,
    public `https` only (`--probe-private` is not offered); a server whose tools were read is pinned with the kinds read in
    full; a server that could not be read keeps the pin already stored for it (a server that does not answer never removes
    its own pin). Every server or kind not pinned is a warning on stderr; nothing here changes the exit code."""
    from spellwarden_cli import net, probing  # here, not at the top: the probe phase is needed only with --probe

    targets, skipped = probing.probe_targets(found)
    phase = probing.run_combined(targets, RuleSet.baseline(), fetcher_factory=fetcher_factory or net.Fetcher, now_iso=now_iso)
    reports = {report.item: report for report in [*skipped, *phase.reports]}
    pins = dict(stored)
    for item, url in _remote_servers(found):
        report = reports.get(item)
        if report is None:
            reason = "only https:// servers are probed" if not url.startswith("https://") else "the server was not probed"
        else:
            pin, partial = pin_of(item, report.listing if report.status == "probed" else None)
            for kind in partial:
                _warn(f"{item}: the server sent part of its {kind}; that list is not pinned")
            if pin is not None and report.listing is not None:
                for kind in cut_kinds(report.listing, pin["kinds"]):
                    _warn(f"{item}: a text in its {kind} is longer than the probe reads; the list is pinned as the probe "
                          "keeps it, so a change past the cut is not seen")
            if pin is not None:
                pins[item] = pin
                continue
            reason = _not_read_reason(report)
        kept = " (the pin already stored is kept)" if item in stored else ""
        _warn(f"{item}: not pinned{kept}: {reason}")
    return pins


def _stored_pins(root: str) -> dict[str, dict]:
    try:
        stored = _read(root)
    except LockUnreadable as exc:
        _warn(f"{exc}; no stored mcp-tools pin is kept")
        return {}
    return {} if stored is None else {pin["path"]: pin for pin in _pins(stored)}


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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Compare without writing; exit 3 when absent or stale.")
    mode.add_argument("--probe", action="store_true", help="Also probe the configured remote servers (public https only) "
                      "and pin the hashes of the tool lists they send.")
    parser.set_defaults(handler=cmd_lock)


def cmd_lock(args: argparse.Namespace) -> int:
    try:
        root = commands.scan_root(args.path)
        settings = commands.settings_for(root, os.environ)
        fileset = files.list_files(root, settings)
    except commands.CommandError as exc:
        return commands.fail(str(exc))
    found = discover.discover(fileset, instructions=settings.instructions)
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
    pins = _stored_pins(root)
    if args.probe:
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        pins = probe_pins(found, pins, now_iso=now_iso)
    computed = with_pins(computed, pins.values())
    try:
        commands.write_in_root(root, LOCK_PATH, render_lock(computed))
    except (commands.CommandError, OSError) as exc:
        return commands.fail(str(exc))
    print(f"Wrote {LOCK_PATH} with {len(computed['items'])} items.")
    return 0
