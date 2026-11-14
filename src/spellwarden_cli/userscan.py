"""`spellwarden scan --user` (phase 3 batch 2a spec 11.2, 11.3): discovery over the client table of `clients` in a user's home,
then the existing rules. The home, the operating system and the environment are parameters, so the tests read a fixture home
for each system without touching the real one.

What is read: each row of the table for the system, at its base (`clients.resolve_base`). Every file is opened read-only and
nothing is ever written, started or fetched (a remote server is probed only under `--probe`, by `run.run_probes`). A symbolic
link at a table path, at a directory the table lists entries of, or inside a skill is followed when its target is a regular
file or a directory inside the home (11.3, D39); the item keeps the path it was reached by. Each real file and directory is
read once: a second row that reaches it adds its client to the items it gave. A link that is not followed is the notice
`symlink_skipped`.

A client is found when a path that only it reads exists. The items of a directory that several clients read (a `shared` row)
name the clients found that way, or every client that reads the directory when none of them was found: a shared directory
alone does not show which client is installed (11.2).

Paths are shown `~/...` inside the home and under a base token outside it, never absolute (`clients.display`). A project-scoped
server of Claude Code is `<document>#<scope>#<name>` with its project directory as its scope: `~/...` inside the home,
`outside-home:<8 hex>/<last segment>` outside it (D38).

Limits (README "Limits"; the home is content the user controls, so each one reached is an error and an incomplete scan): 300
instruction files per client (`user_instructions_limit`), 1,000 skills per skills directory (`user_skills_limit`), 200 plugins
or marketplaces per listing and 200 extensions (`truncated`), a skill's archive limits (`package_too_large`), 10 MiB a file
(`unreadable`)."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import posixpath
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import date

from spellwarden_scan import RULES_VERSION, RuleSet, __version__
from spellwarden_scan.agentconfig import MAX_PLUGINS
from spellwarden_scan.archive import DEFAULT_LIMITS
from spellwarden_scan.model import ConfigDocument
from spellwarden_scan.relpath import UnsafePath, contain

from spellwarden_cli import clients, details, instruction_files, userdocs
from spellwarden_cli.discover import _DOCUMENT_MESSAGES, Discovery, InstructionFile, Item, SkillPackage
from spellwarden_cli.files import FILE_MAX, SKIP_DIRS
from spellwarden_cli.report import LockState, Notice, Report, ReportFinding
from spellwarden_cli.settings import Settings

MAX_INSTRUCTIONS = 300  # instruction files read per client; more is the error `user_instructions_limit`
MAX_SKILLS = 1000  # skills read per skills directory; more is the error `user_skills_limit`
SKILL_FILE = "SKILL.md"
_ITEM_KIND = {"mcp": "mcp-config", "settings": "settings", "marketplace": "marketplace", "hooks": "hooks",
              "plugin": "plugin-manifest"}
_OPEN = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)  # read-only; a FIFO must not block
_WAY_OUT = "remove what is not used, or scan without --user"


def _silent(_line: str) -> None:
    return None


@dataclass(frozen=True)
class UserDiscovery:
    found: Discovery
    clients: tuple[dict, ...]  # `[{"client", "found", "roots"}]` in the order of `clients.CLIENTS`
    details: dict  # `details.item_details` plus the facts of the plugins and marketplaces of state files
    not_found: tuple[str, ...]  # the clients with no file of the table (the notice `client_not_found`, verbose text only)


class _Home:
    def __init__(self, home: str, system: str, env: Mapping[str, str]) -> None:
        self.home = os.path.abspath(home)
        self.real_home = os.path.realpath(self.home)
        self.system = system
        self.env = env
        self.entries: dict[str, dict] = {}
        self.documents: dict[str, ConfigDocument] = {}
        self.skills: dict[str, SkillPackage] = {}
        self.instructions: dict[str, InstructionFile] = {}
        self.facts: dict[str, dict] = {}
        self.notices: list[Notice] = []
        self.errors: list[Notice] = []
        self.done: dict[str, list[str]] = {}  # each real path read -> the item paths it gave
        self.current: list[str] | None = None
        self.roots: dict[str, set[str]] = {client: set() for client in clients.CLIENTS}
        self.own: set[str] = set()  # the clients for which a path that only they read exists
        self.instruction_counts: dict[str, int] = {}
        self.instruction_left: dict[str, int] = {}

    # -- paths ----------------------------------------------------------------------------------------------------------

    def show(self, path: str) -> str:
        shown = clients.display(path, self.home, self.system, self.env)
        return shown if shown is not None else posixpath.basename(path.replace("\\", "/"))

    def step(self, real: str, name: str, shown: str) -> str | None:
        """The real path of `name` inside the real directory `real`: None when it does not exist, or when it is a link that is
        not followed (its target missing, a loop, or outside the home: the notice `symlink_skipped`)."""
        candidate = os.path.join(real, name)
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            return None
        except OSError as exc:
            self.errors.append(Notice("unreadable", shown, f"cannot be read ({exc.strerror or type(exc).__name__})"))
            return None
        if not stat.S_ISLNK(info.st_mode):
            return candidate
        try:
            target = os.path.realpath(candidate, strict=True)
        except OSError:
            self.notices.append(Notice("symlink_skipped", shown, "symbolic link whose target is missing or a loop; not followed"))
            return None
        if clients.relative_to(target, self.real_home) is None:
            self.notices.append(Notice("symlink_skipped", shown, "symbolic link to a place outside the home directory; not "
                                                                 "followed"))
            return None
        return target

    def resolve(self, real: str, relative: str, shown_base: str) -> str | None:
        """`relative` (`/`-separated) below the real directory `real`, each component by `step`."""
        current, shown = real, shown_base
        for part in relative.split("/"):
            shown = f"{shown}/{part}"
            found = self.step(current, part, shown)
            if found is None:
                return None
            current = found
        return current

    def names(self, real: str, shown: str) -> list[str]:
        try:
            return sorted(os.listdir(real))
        except OSError as exc:
            self.errors.append(Notice("unreadable", shown, f"cannot be listed ({exc.strerror or type(exc).__name__})"))
            return []

    def read(self, real: str, shown: str, limit: int = FILE_MAX) -> bytes | None:
        """The bytes of the regular file at `real`, opened read-only; None, with the error `unreadable`, when it cannot be."""
        try:
            fd = os.open(real, _OPEN)
        except OSError as exc:
            self.errors.append(Notice("unreadable", shown, f"cannot be read ({exc.strerror or type(exc).__name__})"))
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                self.errors.append(Notice("unreadable", shown, "not a regular file; not read"))
                return None
            if info.st_size > limit:
                self.errors.append(Notice("unreadable", shown, f"larger than {limit // 2**20} MiB; not read"))
                return None
            chunks, total = [], 0
            while chunk := os.read(fd, 65536):
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    self.errors.append(Notice("unreadable", shown, f"grew past {limit // 2**20} MiB while it was read"))
                    return None
            return b"".join(chunks)
        except OSError as exc:
            self.errors.append(Notice("unreadable", shown, f"cannot be read ({exc.strerror or type(exc).__name__})"))
            return None
        finally:
            os.close(fd)

    def inside_home(self, text: str | None) -> tuple[str, str] | None:
        """The real path and the shown path of a directory a state file names by its absolute path, when it lies inside the
        home; None otherwise."""
        if not isinstance(text, str) or not os.path.isabs(text):
            return None
        try:
            real = os.path.realpath(text, strict=True)
        except OSError:
            return None
        if clients.relative_to(real, self.real_home) is None or clients.relative_to(text, self.home) is None:
            return None
        return real, self.show(text)

    def scope_of(self, directory: str) -> str:
        """A project directory as the upload and every output carry it (11.2, D38)."""
        inside = clients.relative_to(directory, self.home) if os.path.isabs(directory) else None
        if inside is not None:
            return "~/" + inside  # the home itself is `~/`: the upload accepts a scope that starts with `~/` (spec 6.3)
        digest = hashlib.sha256(directory.encode("utf-8", "surrogatepass")).hexdigest()[:8]
        parts = [part for part in directory.replace("\\", "/").split("/") if part]
        return f"outside-home:{digest}/{parts[-1] if parts else ''}"

    # -- items ----------------------------------------------------------------------------------------------------------

    def item(self, kind: str, path: str, name: str, client: str, *, plugin: str | None = None, format: str | None = None,
             front_matter: dict | None = None, scope: str | None = None) -> None:
        entry = self.entries.setdefault(path, {"kind": kind, "name": name, "plugin": plugin, "format": format,
                                               "front_matter": front_matter, "scope": scope, "clients": set()})
        entry["clients"].add(client)
        if self.current is not None:
            self.current.append(path)

    def once(self, real: str, client: str) -> bool:
        """True the first time `real` is read; afterwards False, after adding `client` to the items it gave."""
        key = os.path.normcase(real)
        if key in self.done:
            for path in self.done[key]:
                self.entries[path]["clients"].add(client)
            return False
        self.done[key] = []
        return True

    def gave(self, real: str, paths: list[str]) -> None:
        self.done[os.path.normcase(real)].extend(paths)

    def document(self, document: ConfigDocument, client: str, *, plugin: str | None = None, scope: str | None = None) -> None:
        self.documents[document.path] = document
        if document.error is not None:
            self.errors.append(Notice(document.error, document.path, _DOCUMENT_MESSAGES.get(document.error, document.error)))
        name = posixpath.basename(document.path.split("#", 1)[0])
        self.item(_ITEM_KIND[document.kind], document.path, name, client, plugin=plugin, scope=scope)
        for server in document.servers:
            self.item("mcp-server", f"{document.path}#{server.name}", server.name, client, plugin=plugin, scope=scope)

    # -- the table ------------------------------------------------------------------------------------------------------

    def run(self) -> None:
        for row in clients.rows_for(self.system):
            base = clients.resolve_base(row, self.home, self.system, self.env)
            if base is None:
                continue
            for pattern in row.paths:
                for real, shown in self.expand(base, pattern):
                    self.roots[row.client].add(shown)
                    if not row.shared:
                        self.own.add(row.client)
                    self.read_row(row, real, shown)
        for client, left in self.instruction_left.items():
            if left:
                self.errors.append(Notice("user_instructions_limit", "", f"{left} more instruction files of "
                                          f"{clients.CLIENT_NAMES[client]} were not read: the scanner reads at most "
                                          f"{MAX_INSTRUCTIONS} per client, so the scan is incomplete; {_WAY_OUT}"))

    def expand(self, base: str, pattern: str) -> list[tuple[str, str]]:
        """`(real path, shown path)` of each existing path the pattern names below `base` (`*` matches one name)."""
        found: list[tuple[str, str]] = []

        def walk(real: str, shown: str, rest: list[str]) -> None:
            if not rest:
                found.append((real, shown))
                return
            segment, more = rest[0], rest[1:]
            if "*" in segment:
                if not os.path.isdir(real):
                    return
                names = [name for name in self.names(real, shown) if fnmatch.fnmatchcase(name, segment)]
            else:
                names = [segment]
            for name in names:
                target = self.step(real, name, f"{shown}/{name}")
                if target is not None:
                    walk(target, f"{shown}/{name}", more)

        start = self.start(base)
        if start is not None:
            walk(start, self.show(base), pattern.split("/"))
        return found

    def start(self, base: str) -> str | None:
        """The real directory a row's walk starts at. A base inside the home (the default of a client, or a variable that
        names a place there) is walked from the real home by `step`, so a link on it that leaves the home is skipped with the
        notice `symlink_skipped`; a base outside the home was named by an absolute variable and is trusted as it is."""
        inside = clients.relative_to(base, self.home)
        if inside is None:
            return os.path.realpath(base)
        return self.resolve(self.real_home, inside, "~") if inside else self.real_home

    def read_row(self, row: clients.Row, real: str, shown: str) -> None:
        if not self.once(real, row.client):
            return
        self.current = []
        try:
            getattr(self, "_" + row.reader.replace("-", "_"))(row, real, shown)
        finally:
            self.gave(real, self.current)
            self.current = None

    def _document_reader(self, read: Callable[[str, bytes], ConfigDocument], row: clients.Row, real: str, shown: str) -> None:
        content = self.read(real, shown)
        if content is not None:
            self.document(read(shown, content), row.client)

    def _mcp(self, row, real, shown):
        self._document_reader(userdocs.read_mcp, row, real, shown)

    def _windsurf_mcp(self, row, real, shown):
        self._document_reader(userdocs.read_windsurf_mcp, row, real, shown)

    def _gemini_settings(self, row, real, shown):
        self._document_reader(userdocs.read_gemini_settings, row, real, shown)

    def _settings(self, row, real, shown):
        self._document_reader(userdocs.read_settings, row, real, shown)

    def _hooks(self, row, real, shown):
        self._document_reader(userdocs.read_hooks, row, real, shown)

    def _cursor_hooks(self, row, real, shown):
        self._document_reader(userdocs.read_cursor_hooks, row, real, shown)

    def _claude_json(self, row, real, shown):
        content = self.read(real, shown, userdocs.STATE_MAX_BYTES)
        if content is not None:
            for document, scope in userdocs.read_claude_json(shown, content, self.scope_of):
                self.document(document, row.client, scope=scope)

    def _codex_config(self, row, real, shown):
        content = self.read(real, shown)
        if content is None:
            return
        config = userdocs.read_codex_config(shown, content)
        if config.document is None:
            self.errors.append(Notice("unreadable", shown, f"{config.error}; not judged"))
            return
        self.document(config.document, row.client)
        self.listing(config.listing, shown, row.client, marketplaces=shown)

    def _claude_marketplaces(self, row, real, shown):
        content = self.read(real, shown)
        if content is not None:
            self.listing(userdocs.read_claude_marketplaces(shown, content), shown, row.client, marketplaces=shown)

    def _claude_plugins(self, row, real, shown):
        content = self.read(real, shown)
        if content is None:
            return
        listing = userdocs.read_claude_plugins(shown, content)
        self.listing(listing, shown, row.client, marketplaces=posixpath.dirname(shown) + "/known_marketplaces.json")
        for entry in listing.entries:
            install = entry.facts.get("install_path")
            if install is None:
                continue
            place = self.inside_home(install)
            if place is None:
                self.errors.append(Notice("unsafe_path", entry.path, "the installed plugin's directory is not a directory inside "
                                          "the home directory; not read"))
                continue
            self.plugin_directory(place[0], place[1], row.client, entry.name)

    def listing(self, listing: userdocs.Listing, shown: str, client: str, *, marketplaces: str) -> None:
        """The plugins and marketplaces of a state file as items; a plugin names its marketplace's item when the marketplace
        listing of the same client holds it (resolved in `finish`)."""
        if listing.error is not None:
            self.errors.append(Notice(listing.error[0], shown, listing.error[1]))
        if listing.cut:
            self.errors.append(Notice("truncated", shown, f"{listing.cut} more entries were not read: the scanner reads at most "
                                      f"{MAX_PLUGINS} plugins and {MAX_PLUGINS} marketplaces per file, so the scan is "
                                      f"incomplete; {_WAY_OUT}"))
        for entry in listing.entries:
            self.item(entry.kind, entry.path, entry.name, client)
            if entry.kind == "marketplace":
                source = entry.facts.get("source_url")
                local = entry.facts.get("source_path")
                if source is None and isinstance(local, str) and os.path.isabs(local):
                    source = clients.display(local, self.home, self.system, self.env)
                self.facts[entry.path] = {"source": source} if source else {}
            elif entry.facts.get("marketplace"):
                self.facts[entry.path] = {"marketplace_item": f"{marketplaces}#{entry.facts['marketplace']}"}

    def plugin_directory(self, real: str, shown: str, client: str, plugin: str) -> None:
        """An installed Claude Code plugin's standard layout: its manifest, `.mcp.json`, `hooks/hooks.json` and `skills/` (a
        plugin with a root `SKILL.md` and no `skills/` is one skill)."""
        if not self.once(real, client):
            return
        before = self.current
        self.current = []
        try:
            for relative, read in ((".claude-plugin/plugin.json", lambda path, content: _plugin_manifest(path, content)),
                                   (".mcp.json", userdocs.read_mcp), ("hooks/hooks.json", userdocs.read_hooks)):
                target = self.resolve(real, relative, shown)
                if target is not None:
                    content = self.read(target, f"{shown}/{relative}")
                    if content is not None:
                        self.document(read(f"{shown}/{relative}", content), client, plugin=plugin)
            skills = self.resolve(real, "skills", shown)
            if skills is not None and os.path.isdir(skills):
                self.skill_directory(skills, f"{shown}/skills", client, plugin)
            elif self.resolve(real, SKILL_FILE, shown) is not None:
                self.skill(real, shown, client, plugin)
        finally:
            self.gave(real, self.current)
            self.current = before + self.current if before is not None else None

    def _gemini_extensions(self, row, real, shown):
        if not os.path.isdir(real):
            return
        directories = []
        for name in self.names(real, shown):
            target = self.step(real, name, f"{shown}/{name}")
            if target is None or not os.path.isdir(target):
                continue
            manifest = self.step(target, "gemini-extension.json", f"{shown}/{name}/gemini-extension.json")
            if manifest is not None:
                directories.append((name, target, manifest))
        if len(directories) > MAX_PLUGINS:
            self.errors.append(Notice("truncated", shown, f"{len(directories) - MAX_PLUGINS} more extensions were not read: the "
                                      f"scanner reads at most {MAX_PLUGINS} per client, so the scan is incomplete; {_WAY_OUT}"))
        for name, target, manifest_path in directories[:MAX_PLUGINS]:
            here = f"{shown}/{name}"
            self.item("plugin", here, name, row.client)
            manifest = self.read(manifest_path, f"{here}/gemini-extension.json")
            if manifest is None:
                continue
            extension = userdocs.read_gemini_extension(f"{here}/gemini-extension.json", manifest)
            self.document(extension.document, row.client, plugin=name)
            hooks = self.resolve(target, "hooks/hooks.json", here)
            if hooks is not None:
                content = self.read(hooks, f"{here}/hooks/hooks.json")
                if content is not None:
                    self.document(userdocs.read_hooks(f"{here}/hooks/hooks.json", content), row.client, plugin=name)
            for context in extension.context_files:
                try:
                    relative = contain("", context)
                except UnsafePath:
                    self.errors.append(Notice("unsafe_path", f"{here}/gemini-extension.json", f"context file {context!r} is not "
                                              "a path inside the extension; not read"))
                    continue
                file = self.resolve(target, relative, here)
                if file is not None:
                    self.instruction(file, f"{here}/{relative}", row.client, "gemini-md", plugin=name)

    def _skills(self, row, real, shown):
        if os.path.isdir(real):
            self.skill_directory(real, shown, row.client, None)

    def _instructions(self, row, real, shown):
        self.instruction(real, shown, row.client, row.format)

    def instruction(self, real: str, shown: str, client: str, format: str | None, *, plugin: str | None = None) -> None:
        count = self.instruction_counts.get(client, 0)
        if count >= MAX_INSTRUCTIONS:
            self.instruction_left[client] = self.instruction_left.get(client, 0) + 1
            return
        self.instruction_counts[client] = count + 1
        content = self.read(real, shown)
        if content is None or format is None:
            return
        front_matter, readable = instruction_files.front_matter_of(format, content)
        if not readable:
            self.notices.append(Notice("instructions_front_matter", shown, "the front matter of this rule file could not be "
                                       "read, so its scope is not shown; the file is still scanned"))
        name = posixpath.basename(shown)
        self.instructions[shown] = InstructionFile(shown, name, format, front_matter, content)
        self.item("instructions", shown, name, client, plugin=plugin, format=format, front_matter=front_matter)

    def skill_directory(self, real: str, shown: str, client: str, plugin: str | None) -> None:
        """Each `<name>/SKILL.md` below a skills directory, in name order, at most `MAX_SKILLS`."""
        found = []
        for name in self.names(real, shown):
            target = self.step(real, name, f"{shown}/{name}")
            if target is not None and os.path.isdir(target) and os.path.isfile(os.path.join(target, SKILL_FILE)):
                found.append((name, target))
        if len(found) > MAX_SKILLS:
            self.errors.append(Notice("user_skills_limit", shown, f"{len(found) - MAX_SKILLS} more skills were not read: the "
                                      f"scanner reads at most {MAX_SKILLS} per skills directory, so the scan is incomplete; "
                                      f"{_WAY_OUT}"))
        for name, target in found[:MAX_SKILLS]:
            self.skill(target, f"{shown}/{name}", client, plugin)

    def skill(self, real: str, shown: str, client: str, plugin: str | None) -> None:
        """One skill package: every file below its directory (`SKIP_DIRS` left out, as a repository walk does), each link to a
        regular file inside the home read under the link's path, every other link the notice `symlink_skipped`. A member
        over 10 MiB and a directory that cannot be listed are the error `unreadable`: the scan is then incomplete."""
        if not self.once(real, client):
            return
        members: list[tuple[str, str, bool]] = []  # (shown path, real path, executable)
        size = 0
        def unlisted(exc: OSError) -> None:  # `os.walk` would skip it silently: unread content is an error (README "Limits")
            self.errors.append(Notice("unreadable", shown, "a directory of the skill cannot be listed "
                                      f"({exc.strerror or type(exc).__name__}); not read, so the scan is incomplete"))

        for directory, directories, names in os.walk(real, followlinks=False, onerror=unlisted):
            below = clients.relative_to(directory, real) or ""
            prefix = f"{shown}/{below}/" if below else f"{shown}/"
            kept = []
            for name in sorted(directories):
                if name in SKIP_DIRS:
                    continue
                if os.path.islink(os.path.join(directory, name)):
                    self.notices.append(Notice("symlink_skipped", prefix + name, "symbolic link to a directory inside a skill; "
                                                                                 "not followed"))
                    continue
                kept.append(name)
            directories[:] = kept
            for name in sorted(names):
                target = self.step(directory, name, prefix + name)
                if target is None:
                    continue
                try:
                    info = os.stat(target)
                except OSError as exc:
                    self.errors.append(Notice("unreadable", prefix + name, f"cannot be read ({exc.strerror})"))
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                if info.st_size > FILE_MAX:  # the user's own content left unread: an error, never a skip (README "Limits")
                    self.errors.append(Notice("unreadable", prefix + name, f"larger than {FILE_MAX // 2**20} MiB; not read, so "
                                              f"the scan is incomplete; {_WAY_OUT}"))
                    continue
                size += info.st_size
                members.append((prefix + name, target, os.name != "nt" and bool(info.st_mode & 0o111)))
        if len(members) > DEFAULT_LIMITS.max_files or size > DEFAULT_LIMITS.max_uncompressed:
            self.errors.append(Notice("package_too_large", shown, f"skill package of {len(members)} files and {size} bytes is "
                                      f"over the limits ({DEFAULT_LIMITS.max_files} files, "
                                      f"{DEFAULT_LIMITS.max_uncompressed // 2**20} MiB)"))
            return
        before = len(self.errors)
        files = {path: content for path, target, _ in members if (content := self.read(target, path)) is not None}
        if len(self.errors) != before:
            return  # an unreadable member makes the skill an error, not a partial scan
        self.skills[shown] = SkillPackage(shown, posixpath.basename(shown), files,
                                          frozenset(path for path, _, executable in members if executable), plugin)
        self.item("skill", shown, posixpath.basename(shown), client, plugin=plugin)
        if self.current is not None:
            self.gave(real, [shown])

    # -- the result -----------------------------------------------------------------------------------------------------

    def finish(self) -> UserDiscovery:
        # A directory that several clients read (`~/.agents/skills`; `~/.claude/skills`, which VS Code reads too) does not show
        # which of them is installed (spec 11.2): its items name the clients found by a path of their own, or every client
        # that reads it when none of them was found. A client is found when a path of its own exists or an item names it.
        for entry in self.entries.values():
            entry["clients"] = (entry["clients"] & self.own) or entry["clients"]
        present = self.own | {client for entry in self.entries.values() for client in entry["clients"]}
        items = sorted((Item(entry["kind"], path, entry["name"], entry["plugin"], entry["format"], entry["front_matter"],
                             tuple(client for client in clients.CLIENTS if client in entry["clients"]), entry["scope"])
                        for path, entry in self.entries.items()), key=lambda item: (item.kind, item.path))
        if not items:
            self.notices.append(Notice("no_agent_content", "", "No agent content found in the home directory"))
        found = Discovery(tuple(items), tuple(self.skills[path] for path in sorted(self.skills)),
                          tuple(self.documents[path] for path in sorted(self.documents)), (), tuple(self.notices),
                          tuple(self.errors), None, (), tuple(self.instructions[path] for path in sorted(self.instructions)))
        facts = details.item_details(found)
        for path, extra in self.facts.items():
            kept = {key: value for key, value in extra.items() if key != "marketplace_item" or value in self.entries}
            facts[path] = {**facts.get(path, {}), **kept}
        listed = tuple({"client": client, "found": client in present,
                        "roots": sorted(self.roots[client]) if client in present else []} for client in clients.CLIENTS)
        return UserDiscovery(found, listed, facts, tuple(client for client in clients.CLIENTS if client not in present))


def _plugin_manifest(path: str, content: bytes) -> ConfigDocument:
    from spellwarden_scan.agentconfig import parse_document

    return parse_document("plugin", path, content)


def discover_home(home: str, system: str, env: Mapping[str, str]) -> UserDiscovery:
    """Every row of the table for `system` (`clients.SYSTEMS`) under the home `home`, with the variables of `env`."""
    reader = _Home(home, system, env)
    reader.run()
    return reader.finish()


def _without_evidence(finding: ReportFinding, rules: RuleSet) -> ReportFinding:
    """D22: a finding on a configuration document keeps its location and drops the matched text, which can hold an environment
    value, a header or a token."""
    rule = rules.get(finding.finding.rule_id)
    if rule is None or rule.area != "config":
        return finding
    return replace(finding, finding=replace(finding.finding, evidence=""))


def scan(home: str, sys_platform: str, env: Mapping[str, str], *, settings: Settings, as_of: date, inventory: bool,
         log: Callable[[str], None] = _silent) -> tuple[Report, tuple[str, ...]]:
    """The report of `scan --user` (with `inventory`, `--inventory`: discovery only, no rule and no probe) and the clients that
    were not found. No baseline, lock, settings file, organisation rule or connected mode applies (11.3, D13)."""
    from spellwarden_cli import run  # here, not at the top, like the other seams of `run`

    system = clients.platform_of(sys_platform)
    discovered = discover_home(home, system, env)
    found = discovered.found
    rules = RuleSet.baseline()
    notices, errors = list(found.notices), list(found.errors)
    findings: list[ReportFinding] = []
    probes: list = []
    if not inventory:
        findings = [_without_evidence(finding, rules) for finding in run.engine_findings(found, rules, notices, errors)]
        options = run.ScanOptions(root=os.path.abspath(home), settings=settings, as_of=as_of, env=dict(env), log=log)
        probes = run.run_probes(options, found, rules, findings, notices)
    report = Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of=as_of.isoformat(), fail_on=settings.fail_on,
                    items=found.items, findings=tuple(findings), probes=tuple(probes), lock=LockState(),
                    notices=tuple(notices), errors=tuple(errors), repo_prefix=None, rules=rules, clients=discovered.clients,
                    user="inventory" if inventory else "scan", details=discovered.details)
    return report.sorted(), discovered.not_found


__all__ = ["MAX_INSTRUCTIONS", "MAX_SKILLS", "UserDiscovery", "discover_home", "scan"]
