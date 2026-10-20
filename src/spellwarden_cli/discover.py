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
from spellwarden_cli.files import FileSet
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
        self.paths = fileset.paths()
        self.documents: dict[str, ConfigDocument] = {}
        self.owners: dict[str, str] = {}  # document path -> plugin name
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

    def document(self, kind: str, path: str, plugin: str | None = None, *,
                 drop_references: bool = False) -> ConfigDocument | None:
        if path in self.documents:
            if plugin is not None:
                self.owners.setdefault(path, plugin)
            return self.documents[path]
        if path not in self.paths:
            return None
        content = self.read(path)
        if content is None:
            return None
        parsed = parse_document(kind, path, content)
        if drop_references:
            parsed = replace(parsed, references=())
        self.documents[path] = parsed
        if plugin is not None:
            self.owners[path] = plugin
        if parsed.error is not None:
            self.errors.append(Notice(parsed.error, path, _DOCUMENT_MESSAGES.get(parsed.error, parsed.error)))
        return parsed


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
    the plugin directory's hash in the lock."""
    for reference in manifest.references:
        try:
            target = contain(directory, reference)
        except UnsafePath as exc:
            builder.errors.append(Notice("unsafe_path", manifest.path, f"reference {reference!r}: {exc}"))
            continue
        if target not in builder.paths:
            builder.notices.append(Notice("file_missing", target, f"referenced by {manifest.path} but not in the file set"))
            continue
        if target in builder.documents:  # one owner per file: already parsed globally or by another reference
            builder.document(builder.documents[target].kind, target, plugin)
            continue
        content = builder.read(target)
        if content is None:
            continue
        kind = _global_kind(target) or reference_kind(content)  # a global name fixes the kind, as in the global pass
        if kind is None:
            builder.notices.append(Notice("reference_not_config", target,
                                          f"referenced by {manifest.path} but holds no hooks or MCP servers; not parsed"))
            continue
        builder.document(kind, target, plugin, drop_references=kind == "plugin")


def discover(fileset: FileSet) -> Discovery:
    builder = _Builder(fileset)
    plugin_dirs: dict[str, tuple[str, list[str]]] = {}  # directory -> (plugin name, member paths)
    plugin_items: list[Item] = []
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
            if directory in plugin_dirs:
                continue
            members = sorted(p for p in builder.paths if _under(p, directory))
            plugin_dirs[directory] = (plugin.name, members)
            builder.document("mcp", f"{directory}/.mcp.json", plugin.name)
            builder.document("hooks", f"{directory}/hooks/hooks.json", plugin.name)
            manifest = builder.document("plugin", f"{directory}/.claude-plugin/plugin.json", plugin.name)
            if manifest is not None:
                _follow_references(builder, manifest, directory, plugin.name)
    for path in sorted(builder.paths):
        kind = _global_kind(path)
        if kind is not None and kind != "marketplace":
            builder.document(kind, path)
    skills = _skills(builder, {d: name for d, (name, _) in plugin_dirs.items()})
    # A local plugin whose directory holds no file of the set is listed and locked by its source only.
    dirs = tuple(PluginDir(d, _read_all(builder, members)) for d, (_, members) in sorted(plugin_dirs.items()) if members)
    items = _items(builder, skills, plugin_items)
    if not items:
        builder.notices.append(Notice("no_agent_content", "", "No agent content found"))
    return Discovery(tuple(items), tuple(skills), tuple(builder.documents[p] for p in sorted(builder.documents)),
                     dirs, tuple(builder.notices), tuple(builder.errors))


def _read_all(builder: _Builder, files: list[str]) -> dict[str, bytes]:
    read: dict[str, bytes] = {}
    for path in files:
        content = builder.read(path)
        if content is not None:
            read[path] = content
    return read


def _skills(builder: _Builder, plugin_of_dir: dict[str, str]) -> list[SkillPackage]:
    entries = {entry.path: entry for entry in builder.fileset.entries}
    directories = sorted({posixpath.dirname(p) or "." for p in builder.paths if posixpath.basename(p) == SKILL_FILE})
    packages: list[SkillPackage] = []
    for directory in directories:
        nested = [d for d in directories if d != directory and _under(d, directory)]
        members = sorted(p for p in builder.paths
                         if _under(p, directory) and not any(_under(p, inner) for inner in nested))
        size = sum(entries[p].size for p in members)
        if len(members) > DEFAULT_LIMITS.max_files or size > DEFAULT_LIMITS.max_uncompressed:
            builder.errors.append(Notice("package_too_large", directory,
                                         f"skill package of {len(members)} files and {size} bytes is over the limits "
                                         f"({DEFAULT_LIMITS.max_files} files, {DEFAULT_LIMITS.max_uncompressed // 2**20} MiB)"))
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
