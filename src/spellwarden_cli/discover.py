"""Items from the file set (spec 6.5). Every document and skill is keyed by
its scan-root-relative path, so a file reached both by the global filename
rules and through a plugin is parsed once and listed once (one owner per
file). Only skill packages and configuration documents are read (plan P12)."""
from __future__ import annotations

import posixpath
from dataclasses import dataclass, field, replace

from spellwarden_scan.agentconfig import ConfigDocument, parse_document, reference_kind
from spellwarden_scan.archive import DEFAULT_LIMITS
from spellwarden_scan.relpath import UnsafePath, contain

from spellwarden_cli import paths
from spellwarden_cli.files import FileEntry, FileSet
from spellwarden_cli.report import Notice

SKILL_FILE = "SKILL.md"
_ITEM_KIND = {"mcp": "mcp-config", "settings": "settings", "marketplace": "marketplace", "hooks": "hooks",
              "plugin": "plugin-manifest"}


@dataclass(frozen=True)
class Item:
    kind: str
    path: str
    name: str
    plugin: str | None = None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "path": self.path, "name": self.name, "plugin": self.plugin}


@dataclass(frozen=True)
class SkillPackage:
    path: str  # the skill directory, "." for a SKILL.md at the scan root (plan P13)
    name: str
    files: dict[str, bytes] = field(hash=False)
    executable: frozenset[str] = frozenset()
    plugin: str | None = None


@dataclass(frozen=True)
class PluginDir:
    path: str  # the plugin directory; files keyed by scan-root-relative paths, like SkillPackage.files
    files: dict[str, bytes] = field(hash=False)


@dataclass(frozen=True)
class Discovery:
    items: tuple[Item, ...]
    skills: tuple[SkillPackage, ...]
    documents: tuple[ConfigDocument, ...]
    plugin_dirs: tuple[PluginDir, ...]
    notices: tuple[Notice, ...]
    errors: tuple[Notice, ...]


def _named(path: str, suffix: str) -> bool:
    return path == suffix or path.endswith("/" + suffix)


def _global_kind(path: str) -> str | None:
    """The document kind a file has by its name alone, wherever it sits (spec 6.5)."""
    if posixpath.basename(path) == ".mcp.json" or _named(path, ".vscode/mcp.json") or _named(path, ".cursor/mcp.json"):
        return "mcp"
    if _named(path, ".claude/settings.json") or _named(path, ".claude/settings.local.json"):
        return "settings"
    if _named(path, ".claude-plugin/marketplace.json"):
        return "marketplace"
    return None


def _under(path: str, directory: str) -> bool:
    return directory == "." or path.startswith(directory + "/")


class _Builder:
    def __init__(self, fileset: FileSet) -> None:
        self.fileset = fileset
        self.paths = set(fileset.paths())  # grows by the symbolic links followed (`follow`)
        self.entries = {entry.path: entry for entry in fileset.entries}
        self.links = {link.path: link for link in fileset.links}
        self.followed: set[str] = set()
        self.documents: dict[str, ConfigDocument] = {}
        self.owners: dict[str, str] = {}  # document path -> plugin name
        self.roles: dict[str, set[str]] = {}  # document path -> every kind it was parsed as
        self.notices: list[Notice] = []
        self.errors: list[Notice] = []
        self.contents: dict[str, bytes] = {}  # each file is read at most once, whoever asks

    def read(self, path: str) -> bytes | None:
        if path in self.contents:
            return self.contents[path]
        try:
            content = self.fileset.read(path)
        except UnsafePath as exc:
            self.errors.append(Notice("unsafe_path", path, str(exc)))
            return None
        except paths.TooLarge:
            self.errors.append(Notice("unreadable", path, "grew past the size limit while it was read"))
            return None
        except OSError as exc:
            self.errors.append(Notice("unreadable", path, f"cannot be read ({exc.strerror or type(exc).__name__})"))
            return None
        self.contents[path] = content
        return content

    def follow(self, path: str) -> bool:
        """Whether `path` is a file of the set, following it first when it is a listed symbolic link at an
        agent-content path (owner decision, 2026-10-20). A link is followed when its target, resolved against the
        link's directory by the containment rule (6.13), is a regular file of the set; the target's bytes are then
        the link path's content, and findings, items and the lock name the link. An absolute or escaping target, a
        target that is itself a link and a target outside the file set are `unsafe_path`."""
        if path not in self.links:
            return path in self.paths
        if path in self.followed:
            return path in self.paths
        self.followed.add(path)
        try:
            text = self.fileset.link_target(path).decode("utf-8")
            target = contain(posixpath.dirname(path), text)
        except (UnsafePath, UnicodeDecodeError, paths.TooLarge) as exc:
            reason = "target is not UTF-8" if isinstance(exc, UnicodeDecodeError) else str(exc)
            self.errors.append(Notice("unsafe_path", path, f"symbolic link: {reason}"))
            return False
        except OSError as exc:
            self.errors.append(Notice("unreadable", path, f"symbolic link cannot be read ({exc.strerror or type(exc).__name__})"))
            return False
        if target in self.links:
            self.errors.append(Notice("unsafe_path", path, f"symbolic link to {target!r}, itself a symbolic link"))
            return False
        if target not in self.entries:
            self.errors.append(Notice("unsafe_path", path, f"symbolic link to {target!r}, not a file of the file set"))
            return False
        content = self.read(target)
        if content is None:
            return False
        entry = self.entries[target]
        self.entries[path] = FileEntry(path, entry.size, entry.executable, self.links[path].tracked)
        self.contents[path] = content
        self.paths.add(path)
        return True

    def document(self, kind: str, path: str, plugin: str | None = None, *,
                 drop_references: bool = False) -> ConfigDocument | None:
        """The one document of `path`. A file reached in a second role (a global name, a plugin's conventional
        path, a manifest reference read by its JSON shape) stays one document of its first kind, but is also
        parsed in the new role and keeps what that role finds (r1:F1): what an agent loads in either role is
        judged, listed and locked."""
        if path in self.documents:
            if plugin is not None:
                self.owners.setdefault(path, plugin)
            if kind not in self.roles[path]:
                self.roles[path].add(kind)
                content = self.contents.get(path)
                if content is not None:
                    self.documents[path] = self._merge(self.documents[path], parse_document(kind, path, content))
            return self.documents[path]
        if not self.follow(path):
            return None
        content = self.read(path)
        if content is None:
            return None
        parsed = parse_document(kind, path, content)
        if drop_references:
            parsed = replace(parsed, references=())
        self.documents[path] = parsed
        self.roles[path] = {kind}
        if plugin is not None:
            self.owners[path] = plugin
        self._report(parsed.error, path)
        return parsed

    def _report(self, error: str | None, path: str) -> None:
        if error is not None:
            self.errors.append(Notice(error, path, _DOCUMENT_MESSAGES.get(error, error)))

    def _merge(self, document: ConfigDocument, role: ConfigDocument) -> ConfigDocument:
        """`document` plus the servers and hooks `role` (the same bytes read by another parser) adds. Its kind,
        path and hash stay (both parses hash the same canonical JSON). A document that is already an error stays
        as it is; a role that refuses the bytes (a server name under both `mcpServers` and `servers`, which the
        settings parser does not read) makes the document that error, as one parser alone would."""
        if document.error not in (None, "truncated") or role.error is None and not role.servers and not role.hooks:
            return document
        if role.error not in (None, "truncated"):
            self._report(role.error, document.path)
            return replace(document, error=role.error, servers=(), hooks=(), settings=(), plugins=(), references=(),
                           truncated=False, sha256=role.sha256)
        names = {server.name for server in document.servers}
        seen = {(hook.event, hook.matcher, hook.command, hook.line) for hook in document.hooks}
        added = [hook for hook in role.hooks if (hook.event, hook.matcher, hook.command, hook.line) not in seen]
        hooks = document.hooks + tuple(replace(hook, index=len(document.hooks) + offset) for offset, hook in enumerate(added))
        truncated = document.truncated or role.truncated
        if truncated and not document.truncated:
            self._report("truncated", document.path)
        return replace(document, servers=document.servers + tuple(s for s in role.servers if s.name not in names),
                       hooks=hooks, truncated=truncated, error="truncated" if truncated else None)


_DOCUMENT_MESSAGES = {
    "too_large": "configuration document over 1 MiB; not judged",
    "not_utf8": "configuration document is not UTF-8; not judged",
    "not_json": "configuration document is not valid JSON (comments and trailing commas are accepted); not judged",
    "duplicate_key": "a key repeats in one object, and agents disagree on which value wins; not judged",
    "too_deep": "configuration document nests deeper than 32 levels; not judged",
    "not_an_object": "configuration document is not a JSON object; not judged",
    "truncated": "more entries than the scanner reads; the first entries were judged, the rest were not",
}


def _follow_references(builder: _Builder, manifest: ConfigDocument, directory: str, plugin: str) -> None:
    """Every reference of a plugin manifest that the containment rule accepts and that names a file of the set is
    followed, whatever its name; the JSON shape picks the parser (`reference_kind`). A referenced manifest's own
    references are not followed (one level). A file that is no configuration gets a notice and stays covered by
    the plugin directory's hash in the lock. A file that is already a document (a global name such as
    `.claude/settings.json`, a plugin's conventional path, an earlier reference) stays one document of its kind and
    is also judged in the role its shape gives it here (`_Builder.document`, r1:F1)."""
    for reference in manifest.references:
        try:
            target = contain(directory, reference)
        except UnsafePath as exc:
            builder.errors.append(Notice("unsafe_path", manifest.path, f"reference {reference!r}: {exc}"))
            continue
        if not builder.follow(target):
            if target not in builder.links:  # a link that could not be followed is already an error
                builder.notices.append(Notice("file_missing", target, f"referenced by {manifest.path} but not in the file set"))
            continue
        content = builder.read(target)
        if content is None:
            continue
        kind = reference_kind(content)
        if kind is not None:
            builder.document(kind, target, plugin, drop_references=kind == "plugin")
        elif target in builder.documents:  # one owner per file: the plugin is recorded, the document is unchanged
            builder.document(builder.documents[target].kind, target, plugin)
        else:
            builder.notices.append(Notice("reference_not_config", target,
                                          f"referenced by {manifest.path} but holds no hooks or MCP servers; not parsed"))


def discover(fileset: FileSet) -> Discovery:
    builder = _Builder(fileset)
    plugin_dirs: dict[str, str] = {}  # directory -> plugin name
    plugin_items: list[Item] = []
    for path in sorted(builder.links):  # links at a global name; plugin paths and references follow theirs below
        if _global_kind(path) is not None or posixpath.basename(path) == SKILL_FILE:
            builder.follow(path)
    for path in sorted(p for p in builder.paths if _global_kind(p) == "marketplace"):
        marketplace = builder.document("marketplace", path)
        if marketplace is None or marketplace.error not in (None, "truncated"):
            continue
        for plugin in marketplace.plugins:
            plugin_items.append(Item("plugin", f"{path}#{plugin.name}", plugin.name))
            source = plugin.source
            if source.kind != "local" or source.error is not None or source.local_path is None:
                continue  # remote plugins are inventory only: listed, locked, judged by SW-CFG-009, never fetched
            directory = source.local_path
            plugin_dirs.setdefault(directory, plugin.name)
    # A file's kind is the first role that reaches it: its global name, then a plugin's conventional path, then a
    # manifest reference; every later role adds what it finds to that one document (r1:F1).
    for path in sorted(builder.paths):
        kind = _global_kind(path)
        if kind is not None and kind != "marketplace":
            builder.document(kind, path)
    for directory, name in plugin_dirs.items():
        builder.document("mcp", f"{directory}/.mcp.json", name)
        builder.document("hooks", f"{directory}/hooks/hooks.json", name)
        builder.document("plugin", f"{directory}/.claude-plugin/plugin.json", name)
    for directory, name in plugin_dirs.items():
        manifest = builder.documents.get(f"{directory}/.claude-plugin/plugin.json")
        if manifest is not None:
            _follow_references(builder, manifest, directory, name)
    skills = _skills(builder, plugin_dirs)
    # A local plugin whose directory holds no file of the set is listed and locked by its source only; one over the
    # package limits is an item error and is not read whole, like a skill (r0:F8).
    members = {d: sorted(p for p in builder.paths if _under(p, d)) for d in plugin_dirs}
    dirs = tuple(PluginDir(d, _read_all(builder, members[d])) for d in sorted(plugin_dirs)
                 if members[d] and not _too_large(builder, d, members[d], "plugin directory"))
    builder.notices.extend(Notice("symlink_skipped", path, "symbolic link; skipped")
                           for path in sorted(builder.links) if path not in builder.followed)
    items = _items(builder, skills, plugin_items)
    if not items:
        builder.notices.append(Notice("no_agent_content", "", "No agent content found"))
    return Discovery(tuple(items), tuple(skills), tuple(builder.documents[p] for p in sorted(builder.documents)),
                     dirs, tuple(builder.notices), tuple(builder.errors))


def _too_large(builder: _Builder, directory: str, members: list[str], what: str) -> bool:
    """A package over the `ArchiveLimits` totals (spec 6.5) is the item error `package_too_large`, judged from
    the listing's sizes before any member is read."""
    entries = builder.entries
    size = sum(entries[p].size for p in members)
    if len(members) <= DEFAULT_LIMITS.max_files and size <= DEFAULT_LIMITS.max_uncompressed:
        return False
    builder.errors.append(Notice("package_too_large", directory,
                                 f"{what} of {len(members)} files and {size} bytes is over the limits "
                                 f"({DEFAULT_LIMITS.max_files} files, {DEFAULT_LIMITS.max_uncompressed // 2**20} MiB)"))
    return True


def _read_all(builder: _Builder, files: list[str]) -> dict[str, bytes]:
    read: dict[str, bytes] = {}
    for path in files:
        content = builder.read(path)
        if content is not None:
            read[path] = content
    return read


def _skills(builder: _Builder, plugin_of_dir: dict[str, str]) -> list[SkillPackage]:
    entries = builder.entries
    directories = sorted({posixpath.dirname(p) or "." for p in builder.paths if posixpath.basename(p) == SKILL_FILE})
    packages: list[SkillPackage] = []
    for directory in directories:
        nested = [d for d in directories if d != directory and _under(d, directory)]
        members = sorted(p for p in builder.paths
                         if _under(p, directory) and not any(_under(p, inner) for inner in nested))
        if _too_large(builder, directory, members, "skill package"):
            continue
        before = len(builder.errors)
        files = _read_all(builder, members)
        if len(builder.errors) != before:
            continue  # an unreadable member makes the skill an item error, not a partial scan
        owners = [d for d in plugin_of_dir if _under(directory, d) and d != "."]
        plugin = plugin_of_dir[max(owners, key=len)] if owners else None
        # the root skill is "." and never the checkout directory's name: a lock and a report must not depend on where
        # the repository sits on disk (r0:F4)
        name = posixpath.basename(directory) if directory != "." else "."
        packages.append(SkillPackage(directory, name, files, frozenset(p for p in members if entries[p].executable), plugin))
    return packages


def _items(builder: _Builder, skills: list[SkillPackage], plugin_items: list[Item]) -> list[Item]:
    items = [Item("skill", skill.path, skill.name, skill.plugin) for skill in skills]
    items.extend(plugin_items)
    for path, document in builder.documents.items():
        owner = builder.owners.get(path)
        items.append(Item(_ITEM_KIND[document.kind], path, posixpath.basename(path), owner))
        for server in document.servers:
            items.append(Item("mcp-server", f"{path}#{server.name}", server.name, owner))
    return sorted(items, key=lambda item: (item.kind, item.path))


__all__ = ["Discovery", "Item", "PluginDir", "SkillPackage", "discover"]
