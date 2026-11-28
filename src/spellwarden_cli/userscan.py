"""`spellwarden scan --user` (phase 3 batch 2a spec 11.2, 11.3): discovery over the client table of `clients` in a user's home,
then the existing rules. The home, the operating system and the environment are parameters, so the tests read a fixture home
for each system without touching the real one.

What is read: each row of the table for the system, at its base (`clients.resolve_base`). Every file is opened read-only and
nothing is ever written, started or fetched (a remote server is probed only under `--probe`, by `run.run_probes`). A symbolic
link at a table path, at a directory the table lists entries of, or inside a skill is followed when its target is a regular
file or a directory inside the home (11.3, D39); the item keeps the path it was reached by. Each real file and directory is
read once: a second row that reaches it adds its client to the items it gave. A link to a place outside the home is not followed
(D39); it is the error `unreadable` (one per link) when what the scan looks for below it exists below its target, checked by
`os.stat` only, since that is content an agent loads and the scan did not judge, so the scan is incomplete (1.16.1, README
"Limits"): the rest of the row's path, `SKILL.md` for an entry of a skills directory, `gemini-extension.json` for one of the
Gemini CLI extensions directory, the target itself inside a skill. A link to a directory inside a skill is not followed either
and is the same error when its target exists. Every other link that is not followed (a target missing, a loop, or out of the
home holding nothing the scan reads) is the notice `symlink_skipped`.

A client is found when a path that only it reads exists. The items of a directory that several clients read (a `shared` row)
name the clients found that way, or every client that reads the directory when none of them was found: a shared directory
alone does not show which client is installed (11.2).

Paths are shown `~/...` inside the home and under a base token outside it, never absolute (`clients.display`). A project-scoped
server of Claude Code is `<document>#<scope>#<name>` with its project directory as its scope: `~/...` inside the home,
`outside-home:<8 hex>/<last segment>` outside it (D38).

Limits (README "Limits"; the home is content the user controls, so each one reached is an error and an incomplete scan): 300
instruction files per client (`user_instructions_limit`), 1,000 skills per skills directory (`user_skills_limit`), 200 plugins
or marketplaces per listing, 200 extensions and, since 1.20.0, 200 plugin directories of one Codex, Copilot or Cursor row
(`truncated`), a skill's archive limits (`package_too_large`), 10 MiB a file (`unreadable`)."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import posixpath
import stat
from collections.abc import Callable, Mapping, Sequence
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


@dataclass(frozen=True)
class _Layout:
    """What an installed plugin directory of one client holds (Engine 1.20.0: scan selection, 7.11, D18), as paths below the
    directory: every manifest that exists is a `plugin` document (two that both exist are two documents), every MCP file an `mcp`
    document, every hooks file a document of `read_hooks`; `skills/` is a skills directory; each `(pattern, format)` of
    `instructions` names instruction files (`**` matches zero or more directory names)."""
    manifests: tuple[str, ...]
    mcp: tuple[str, ...]
    hooks: tuple[str, ...]
    read_hooks: Callable[[str, bytes], ConfigDocument]
    instructions: tuple[tuple[str, str], ...]


_LAYOUTS = {
    "claude-code": _Layout((".claude-plugin/plugin.json",), (".mcp.json",), ("hooks/hooks.json",), userdocs.read_hooks,
                           (("commands/**/*.md", "claude-command"), ("agents/**/*.md", "claude-agent"))),
    "codex": _Layout(("plugin.json", ".codex-plugin/plugin.json"), ("mcp.json", ".mcp.json"), ("hooks/hooks.json",),
                     userdocs.read_hooks, ()),
    "copilot": _Layout(("plugin.json", ".plugin/plugin.json", ".github/plugin/plugin.json", ".claude-plugin/plugin.json"),
                       (".mcp.json",), ("hooks.json", "hooks/hooks.json"), userdocs.read_copilot_hooks,
                       (("agents/**/*.md", "github-agent"),)),
    "cursor": _Layout((".cursor-plugin/plugin.json", "plugin.json"), ("mcp.json",), ("hooks/hooks.json",),
                      userdocs.read_cursor_hooks, (("rules/**/*.mdc", "cursor-mdc"), ("agents/**/*.md", "cursor-agent"),
                                                   ("commands/**/*.md", "cursor-command"))),
}


def _executable(real: str) -> bool:
    """1.28.0 (spec 4.4): the executable bit of the file at `real`, read as a skill's members are read (`os.stat`, any of the
    three bits); False on Windows, which records none, and when the mode cannot be read."""
    if os.name == "nt":
        return False
    try:
        return bool(os.stat(real).st_mode & 0o111)
    except OSError:
        return False


def _silent(_line: str) -> None:
    return None


def _holds(target: str, rest: Sequence[str]) -> bool:
    """Whether the path `rest` exists below the real path `target`, by `os.stat` only (D39: nothing out of the home is read or
    listed). Where `rest` holds a `*`, only the directory it would be matched in can be checked without listing it."""
    fixed: list[str] = []
    for part in rest:
        if "*" in part:
            return os.path.isdir(os.path.join(target, *fixed))
        fixed.append(part)
    return os.path.exists(os.path.join(target, *fixed))


def _linked_out_message(variables: set[str | None]) -> str:
    """The error `unreadable` of a link out of the home that leads to content the scan looks for (1.16.1). A variable is named
    as a way out only when every row that reached the link starts at a base it moves: `start` reads a base outside the home
    that an absolute variable names as it is, but a row whose base is the home itself is not moved by any."""
    text = ("symbolic link to a place outside the home directory that holds files the scan reads; not followed, so they were "
            "not judged and the scan is incomplete: remove the link, or replace it with a copy of what it leads to")
    if variables and None not in variables:
        text += (f", or set {' or '.join(sorted(v for v in variables if v))} to the real path of the directory it stands for "
                 "(a directory outside the home that the variable names is read as it is)")
    return text


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
        self.plugin_counts: dict[str, int] = {}  # plugin directories read per row of the table (`_plugin_row`)
        self.plugins_left: dict[str, int] = {}  # plugin directories past MAX_PLUGINS per row, not read
        # each link out of the home that leads to content the scan looks for -> the variable that moves the base it is on, for
        # each row that reached it (None: none does)
        self.linked_out: dict[str, set[str | None]] = {}

    # -- paths ----------------------------------------------------------------------------------------------------------

    def show(self, path: str) -> str:
        shown = clients.display(path, self.home, self.system, self.env)
        return shown if shown is not None else posixpath.basename(path.replace("\\", "/"))

    def step(self, real: str, name: str, shown: str, rest: Sequence[str] = (), variable: str | None = None) -> str | None:
        """The real path of `name` inside the real directory `real`: None when it does not exist, or when it is a link that is
        not followed: its target missing or a loop (the notice `symlink_skipped`), or outside the home (D39). A link out of the
        home is the error `unreadable` (once per link, `run`) when `rest`, what the scan looks for below `name`, exists below
        the link's target (`_holds`, stat only: nothing out of the home is read or listed): that is content the client loads
        and the scan did not judge (1.16.1). Otherwise it leads to nothing the scan reads and stays the notice
        `symlink_skipped`. `variable`: the absolute variable that moves the base the link is on, named as a way out."""
        candidate = os.path.join(real, name)
        try:
            info = os.lstat(candidate)
        except (FileNotFoundError, NotADirectoryError):  # a name below a regular file does not exist (`agents/*/AGENT.md`)
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
            if _holds(target, rest):
                self.linked_out.setdefault(shown, set()).add(variable)
            else:
                self.notices.append(Notice("symlink_skipped", shown, "symbolic link to a place outside the home directory; not "
                                                                     "followed"))
            return None
        return target

    def resolve(self, real: str, relative: str, shown_base: str, tail: Sequence[str] = (),
                variable: str | None = None) -> str | None:
        """`relative` (`/`-separated) below the real directory `real`, each component by `step`; `tail` is what the scan looks
        for below `relative` (a row's path below its base), `variable` as for `step`."""
        current, shown = real, shown_base
        parts = relative.split("/")
        for index, part in enumerate(parts):
            shown = f"{shown}/{part}"
            found = self.step(current, part, shown, (*parts[index + 1:], *tail), variable)
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
            bases = [(base, clients.base_variable(row, self.env))]
            default = clients.default_base(row, self.home, self.system, self.env)
            if default is not None:  # the default folder too, which no variable moves: a file there is not left unread
                bases.append((default, None))
            for start, variable in bases:
                for pattern in row.paths:
                    for real, shown in self.expand(start, pattern, variable):
                        self.roots[row.client].add(shown)
                        if not row.shared:
                            self.own.add(row.client)
                        self.read_row(row, real, shown)
        for shown, variables in self.linked_out.items():  # one error per link, however many rows reached it
            self.errors.append(Notice("unreadable", shown, _linked_out_message(variables)))
        for client, left in self.instruction_left.items():
            if left:
                self.errors.append(Notice("user_instructions_limit", "", f"{left} more instruction files of "
                                          f"{clients.CLIENT_NAMES[client]} were not read: the scanner reads at most "
                                          f"{MAX_INSTRUCTIONS} per client, so the scan is incomplete; {_WAY_OUT}"))
        rows = {row.id: row for row in clients.ROWS}
        for row_id, left in self.plugins_left.items():
            row = rows[row_id]
            self.errors.append(Notice("truncated", "", f"{left} more plugin directories of {clients.CLIENT_NAMES[row.client]} "
                                      f"({row.base}/{row.paths[0]}) were not read: the scanner reads at most {MAX_PLUGINS} "
                                      f"there, so the scan is incomplete; {_WAY_OUT}"))

    def expand(self, base: str, pattern: str, variable: str | None = None) -> list[tuple[str, str]]:
        """`(real path, shown path)` of each existing path the pattern names below `base` (`glob`); `variable` is the absolute
        variable that moves `base`, if any."""
        start = self.start(base, pattern.split("/"), variable)
        if start is None:
            return []
        return self.glob(start, self.show(base), pattern)

    def glob(self, real: str, shown: str, pattern: str) -> list[tuple[str, str]]:
        """`(real path, shown path)` of each existing path `pattern` names below the real directory `real`, shown as `shown`:
        `*` matches one name, case-sensitively (`fnmatch.fnmatchcase`); a segment `**` matches zero or more directory names
        (Engine 1.20.0: scan selection, 7.10), its matches shallowest first, then by name. Every name is entered through
        `step`, so the link rules of the workstation scan hold."""
        found: list[tuple[str, str]] = []

        def walk(real: str, shown: str, rest: list[str]) -> None:
            if not rest:
                found.append((real, shown))
                return
            segment, more = rest[0], rest[1:]
            if segment == "**":
                for directory, directory_shown in self.directories_below(real, shown, more):
                    walk(directory, directory_shown, more)
                return
            if "*" in segment:
                if not os.path.isdir(real):
                    return
                names = [name for name in self.names(real, shown) if fnmatch.fnmatchcase(name, segment)]
            else:
                names = [segment]
            for name in names:
                target = self.step(real, name, f"{shown}/{name}", more)
                if target is not None:
                    walk(target, f"{shown}/{name}", more)

        walk(real, shown, pattern.split("/"))
        return found

    def directories_below(self, real: str, shown: str, more: Sequence[str]) -> list[tuple[str, str]]:
        """`real` and every directory below it, breadth first and each level by shown path (D17). A name is tried as a directory
        only when it is one (`os.path.isdir`, which follows a link): a name that is no directory is left to the pattern's next
        segment, as on 1.19.0, so a link that leads nowhere or to a file gives no notice here. Each directory is entered through
        `step` (a link inside the home is followed; one out of the home to a directory is the error `unreadable`, since `_holds`
        sees the `**` of the rest of the pattern), once per real path (a loop is entered once), never into `SKIP_DIRS`; a
        directory that cannot be listed is the error `unreadable` (`names`)."""
        if not os.path.isdir(real):
            return []
        seen = {os.path.normcase(os.path.realpath(real))}
        level, result = [(real, shown)], []
        while level:
            result.extend(level)
            below: list[tuple[str, str]] = []
            for directory, directory_shown in level:
                for name in self.names(directory, directory_shown):
                    if name in SKIP_DIRS or not os.path.isdir(os.path.join(directory, name)):
                        continue
                    target = self.step(directory, name, f"{directory_shown}/{name}", ("**", *more))
                    if target is None:
                        continue
                    key = os.path.normcase(os.path.realpath(target))
                    if key in seen:
                        continue
                    seen.add(key)
                    below.append((target, f"{directory_shown}/{name}"))
            level = sorted(below, key=lambda pair: pair[1])
        return result

    def start(self, base: str, tail: Sequence[str] = (), variable: str | None = None) -> str | None:
        """The real directory a row's walk starts at. A base inside the home (the default of a client, or a variable that
        names a place there) is walked from the real home by `step`, so a link on it that leaves the home is not followed: the
        error `unreadable` when the row's path `tail` exists below the link's target, else the notice `symlink_skipped`. A base
        outside the home was named by an absolute variable and is trusted as it is, which is why setting `variable` to the
        real path is a way out of that error."""
        inside = clients.relative_to(base, self.home)
        if inside is None:
            return os.path.realpath(base)
        return self.resolve(self.real_home, inside, "~", tail, variable) if inside else self.real_home

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

    def _copilot_hooks(self, row, real, shown):
        self._document_reader(userdocs.read_copilot_hooks, row, real, shown)

    def _copilot_settings(self, row, real, shown):
        self._document_reader(userdocs.read_copilot_settings, row, real, shown)

    def _devin_config(self, row, real, shown):
        self._document_reader(userdocs.read_devin_config, row, real, shown)

    def _codex_plugins(self, row, real, shown):
        # `plugins/cache/<marketplace>/<plugin>/<version>`: the plugin is named by its plugin segment
        self._plugin_row(_LAYOUTS["codex"], row, real, shown, posixpath.basename(posixpath.dirname(shown)))

    def _copilot_plugins(self, row, real, shown):
        # `installed-plugins/<marketplace>/<plugin>` and `installed-plugins/_direct/<source id>`
        self._plugin_row(_LAYOUTS["copilot"], row, real, shown, posixpath.basename(shown))

    def _cursor_plugins(self, row, real, shown):
        self._plugin_row(_LAYOUTS["cursor"], row, real, shown, posixpath.basename(shown))

    def _plugin_row(self, layout: _Layout, row: clients.Row, real: str, shown: str, name: str) -> None:
        """One plugin directory a row's pattern names (Engine 1.20.0: scan selection, 7.11): an item of kind `plugin` at its shown
        path, named by its plugin segment, as a Gemini CLI extension is, and its files by `layout`, carrying the name. At most
        `MAX_PLUGINS` per row; the rest are counted for the error `truncated` (`run`)."""
        if not os.path.isdir(real):
            return
        count = self.plugin_counts.get(row.id, 0)
        if count >= MAX_PLUGINS:
            self.plugins_left[row.id] = self.plugins_left.get(row.id, 0) + 1
            return
        self.plugin_counts[row.id] = count + 1
        self.item("plugin", shown, name, row.client)
        self.layout(layout, real, shown, row.client, name)

    def layout(self, layout: _Layout, real: str, shown: str, client: str, plugin: str, *, root_skill: bool = False) -> None:
        """The files of one installed plugin directory by its client's layout (7.11): its manifests, MCP and hooks files, its
        `skills/` and its instruction folders, each carrying the plugin's name. With `root_skill` (Claude Code), a plugin with a
        root `SKILL.md` and no `skills/` is one skill, which keeps its `commands/` and `agents/` as its own files (one owner per
        file). The caller has claimed `real` with `once` (`plugin_directory`), so that skill is read with `claimed=True`."""
        for relative in layout.manifests:
            self._plugin_file(real, shown, relative, client, plugin, _plugin_manifest)
        for relative in layout.mcp:
            self._plugin_file(real, shown, relative, client, plugin, userdocs.read_mcp)
        for relative in layout.hooks:
            self._plugin_file(real, shown, relative, client, plugin, layout.read_hooks)
        skills = self.resolve(real, "skills", shown)
        if skills is not None and os.path.isdir(skills):
            self.skill_directory(skills, f"{shown}/skills", client, plugin)
        elif root_skill and self.resolve(real, SKILL_FILE, shown) is not None:
            self.skill(real, shown, client, plugin, claimed=True)
            return
        for pattern, format in layout.instructions:
            for file, file_shown in self.glob(real, shown, pattern):
                self.instruction(file, file_shown, client, format, plugin=plugin)

    def _plugin_file(self, real: str, shown: str, relative: str, client: str, plugin: str,
                     read: Callable[[str, bytes], ConfigDocument]) -> None:
        target = self.resolve(real, relative, shown)
        if target is not None:
            content = self.read(target, f"{shown}/{relative}")
            if content is not None:
                self.document(read(f"{shown}/{relative}", content), client, plugin=plugin)

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
        self.listing(config.listing, shown, row.client, marketplaces=f"{shown}#marketplaces.")
        if config.error is not None:  # entries left unread (review r1:F2): an incomplete scan, never a pass
            self.errors.append(Notice("unreadable", shown, f"{config.error}; not judged"))

    def _claude_marketplaces(self, row, real, shown):
        content = self.read(real, shown)
        if content is not None:
            self.listing(userdocs.read_claude_marketplaces(shown, content), shown, row.client, marketplaces=f"{shown}#")

    def _claude_plugins(self, row, real, shown):
        content = self.read(real, shown)
        if content is None:
            return
        listing = userdocs.read_claude_plugins(shown, content)
        self.listing(listing, shown, row.client, marketplaces=posixpath.dirname(shown) + "/known_marketplaces.json#")
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
        listing of the same client holds it (resolved in `finish`); `marketplaces` is a marketplace item path up to its name."""
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
                self.facts[entry.path] = {"marketplace_item": f"{marketplaces}{entry.facts['marketplace']}"}

    def plugin_directory(self, real: str, shown: str, client: str, plugin: str) -> None:
        """An installed Claude Code plugin's standard layout (`_LAYOUTS["claude-code"]`): its manifest, `.mcp.json`,
        `hooks/hooks.json`, `skills/` (a plugin with a root `SKILL.md` and no `skills/` is one skill) and, since 1.20.0, its
        `commands/` and `agents/` (Engine 1.20.0: scan selection, 7.11)."""
        if not self.once(real, client):
            return
        before = self.current
        self.current = []
        try:
            self.layout(_LAYOUTS["claude-code"], real, shown, client, plugin, root_skill=True)
        finally:
            self.gave(real, self.current)
            self.current = before + self.current if before is not None else None

    def _gemini_extensions(self, row, real, shown):
        if not os.path.isdir(real):
            return
        directories = []
        for name in self.names(real, shown):
            # a link out of the home is an error only when it leads to an extension (its manifest exists, by `os.stat`)
            target = self.step(real, name, f"{shown}/{name}", ("gemini-extension.json",))
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
            # Engine 1.20.0 (scan selection, 7.11): the extension's skills and subagents, with its name
            skills = self.resolve(target, "skills", here)
            if skills is not None and os.path.isdir(skills):
                self.skill_directory(skills, f"{here}/skills", row.client, name)
            for file, file_shown in self.glob(target, here, "agents/*.md"):
                self.instruction(file, file_shown, row.client, "gemini-agent", plugin=name)
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
        self.instructions[shown] = InstructionFile(shown, name, format, front_matter, content, executable=_executable(real))
        self.item("instructions", shown, name, client, plugin=plugin, format=format, front_matter=front_matter)

    def skill_directory(self, real: str, shown: str, client: str, plugin: str | None) -> None:
        """Each `<name>/SKILL.md` below a skills directory, in name order, at most `MAX_SKILLS`."""
        found = []
        for name in self.names(real, shown):
            # a link out of the home is an error only when it leads to a skill (`SKILL.md`, by `os.stat`, so in each case form
            # the file system matches it, as for a skill inside the home); any other is the notice `symlink_skipped`
            target = self.step(real, name, f"{shown}/{name}", (SKILL_FILE,))
            if target is not None and os.path.isdir(target) and os.path.isfile(os.path.join(target, SKILL_FILE)):
                found.append((name, target))
        if len(found) > MAX_SKILLS:
            self.errors.append(Notice("user_skills_limit", shown, f"{len(found) - MAX_SKILLS} more skills were not read: the "
                                      f"scanner reads at most {MAX_SKILLS} per skills directory, so the scan is incomplete; "
                                      f"{_WAY_OUT}"))
        for name, target in found[:MAX_SKILLS]:
            self.skill(target, f"{shown}/{name}", client, plugin)

    def skill(self, real: str, shown: str, client: str, plugin: str | None, *, claimed: bool = False) -> None:
        """One skill package: every file below its directory (`SKIP_DIRS` left out, as a repository walk does), each link to a
        regular file inside the home read under the link's path. A link out of the home or to a directory, a member over 10 MiB
        and a directory that cannot be listed are the error `unreadable`: the scan is then incomplete. A link whose target is
        missing or a loop is the notice `symlink_skipped`. `claimed` (Engine 1.20.0: scan selection, 7.11): the caller has
        already claimed `real` with `once` (an installed plugin that is one skill, `layout`), so it is not asked again; until
        1.20.0 that second question was answered no and such a plugin's skill was never read."""
        if not claimed and not self.once(real, client):
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
                    if os.path.exists(os.path.join(directory, name)):  # files an agent loads with the skill, not judged
                        self.errors.append(Notice("unreadable", prefix + name, "symbolic link to a directory inside a skill; "
                                                  "not followed, so not judged, and the scan is incomplete: remove the link, "
                                                  "or replace it with a copy of the directory"))
                    else:  # its target is missing or a loop: nothing an agent could load
                        self.notices.append(Notice("symlink_skipped", prefix + name, "symbolic link whose target is missing "
                                                   "or a loop; not followed"))
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
        # A link several rows start at or walk through (`~/.claude` is the base of seven rows) is one notice, not one per
        # row: the first notice of each code and path is kept, in the order found (review r1:F1).
        # A link out of the home that one row found leading to content and another to nothing is the error alone.
        seen: set[tuple[str, str]] = {("symlink_skipped", path) for path in self.linked_out}
        self.notices = [notice for notice in self.notices
                        if (notice.code, notice.path) not in seen and not seen.add((notice.code, notice.path))]
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
        # 1.19.0: a front matter past a limit names the way out of a user scan, which reads no settings file (no `exclude`)
        way_out = "make the front matter smaller, or remove the skill if it is not used"
        findings = [_without_evidence(finding, rules)
                    for finding in run.engine_findings(found, rules, notices, errors, way_out=way_out)]
        options = run.ScanOptions(root=os.path.abspath(home), settings=settings, as_of=as_of, env=dict(env), log=log)
        probes = run.run_probes(options, found, rules, findings, notices)
    report = Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of=as_of.isoformat(), fail_on=settings.fail_on,
                    items=found.items, findings=tuple(findings), probes=tuple(probes), lock=LockState(),
                    notices=tuple(notices), errors=tuple(errors), repo_prefix=None, rules=rules, clients=discovered.clients,
                    user="inventory" if inventory else "scan", details=discovered.details)
    return report.sorted(), discovered.not_found


__all__ = ["MAX_INSTRUCTIONS", "MAX_SKILLS", "UserDiscovery", "discover_home", "scan"]
