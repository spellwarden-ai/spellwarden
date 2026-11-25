"""SW-CFG-015: MCP server given the whole home directory or the filesystem root.

Read over the servers of MCP client configurations (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` and the other `mcp`
documents, at any depth), of plugin manifests and of settings documents (Codex's `config.toml` and Gemini CLI's
`settings.json`); hooks and marketplace documents are not read. From `McpServerEntry.args` and `command`, which the entry
parser keeps whole (`options` is not read, so no cut mark applies). An argument fires, once per server and argument and at the
server's line, when it is the whole home directory or the filesystem root and it is

* a path after the package of a filesystem-class server (not of `docker` or `podman`, whose arguments after the image are the
  container's, and not the value of a flag other than the flags below): a server whose name, command or an argument that is not a path holds
  the name token `filesystem`, `fs` or `files`, or the adjacent tokens `file` and `system` (the arguments after the package, or
  every argument when no argument names it);
* the value of `--allowed-directories`, `--allowed-dir`, `--allowed-dirs`, `--root`, `--roots`, `--workspace`, `--directory`,
  `--dir`, `--base-dir` or `--path`, in `--flag value` and `--flag=value` form, for any server; or
* the host side of a bind mount of `docker` or `podman`: the value of `-v` or `--volume` up to the first colon that ends the
  host path, or the `src=` or `source=` part of the value of `--mount`.

The whole home directory is `~`, `$HOME`, `${HOME}`, `$USERPROFILE`, `$env:USERPROFILE`, `${userHome}`, `%USERPROFILE%`, `/home/<name>`, `/Users/<name>` or
`C:\\Users\\<name>`; the root is `/`, a drive root such as `C:\\`, `/home`, `/Users` or `/root`; a trailing separator is
allowed. A deeper path, `.`, a project variable such as `${workspaceFolder}` and a relative path are quiet, and so is the
container side of a mount. Matching is textual and the same on every platform. The evidence names the form, never the path
(a home path carries a user name). A server yields at most `_PER_SERVER` findings and the last one counts the rest. Every
environment variable cannot be expressed in the fields the scanner reads and is not checked. The module is registered by the
rule set, not here."""
from __future__ import annotations

import re
from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.model import Finding, Location, McpServerEntry
from spellwarden_scan.rules.patterns import name_tokens

RULE_ID = "SW-CFG-015"
TITLE = "MCP server given the whole home directory or the filesystem root"
SEVERITY = "medium"
OWASP = ("MCP02", "ASI03")
NIST = ("AC-6",)
ATLAS = ("AML.T0053",)
MALICIOUS = False

_PER_SERVER = 20
_I = re.IGNORECASE
_HOME = re.compile(
    r"^(?:~|\$HOME|\$\{HOME\}|\$USERPROFILE|\$env:USERPROFILE|\$\{userHome\}|%USERPROFILE%|/home/[^/\\]+|/Users/[^/\\]+|[A-Za-z]:[\\/]Users[\\/][^/\\]+)[/\\]?$", _I)
_ROOT = re.compile(r"^(?:[/\\]|[A-Za-z]:[\\/]?|/(?:home|Users|root)[/\\]?)$", _I)
_FLAGS = frozenset({"--allowed-directories", "--allowed-dir", "--allowed-dirs", "--root", "--roots", "--workspace", "--directory",
                    "--dir", "--base-dir", "--path"})
_LAUNCHERS = frozenset({"docker", "podman"})
_FILESYSTEM_TOKENS = frozenset({"filesystem", "fs", "files"})
_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_HOST_OF_MOUNT = re.compile(r"^(?:[A-Za-z]:[\\/][^:]*|\$env:[^:]*|[^:]*)", _I)
_MOUNT_SOURCE = re.compile(r"(?:^|,)(?:src|source)=([^,]*)", _I)


def _form_of(path: str) -> str | None:
    """`home_directory`, `filesystem_root` or None for the text of one path."""
    if _HOME.match(path):
        return "home_directory"
    if _ROOT.match(path):
        return "filesystem_root"
    return None


def _filesystem_named(text: str) -> bool:
    tokens = name_tokens(text)
    return bool(_FILESYSTEM_TOKENS & set(tokens)) or ("file", "system") in zip(tokens, tokens[1:], strict=False)


def _looks_like_a_path(argument: str) -> bool:
    return argument.startswith(("/", "~", ".", "$", "%", "\\", "-")) or _DRIVE_PATH.match(argument) is not None


def _program(entry: McpServerEntry) -> str:
    command = (entry.command or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return command[:-4] if command.endswith(".exe") else command


def _mount_host(value: str) -> str:
    """The host side of a `-v` value: everything before the colon that ends the host path (a drive letter's colon stays)."""
    return _HOST_OF_MOUNT.match(value).group(0)


def _flag_value(args: tuple[str, ...], index: int, flags: frozenset[str]) -> tuple[int, str] | None:
    """`(index of the value, value)` when `args[index]` is one of `flags` followed by its value, or `flag=value`."""
    argument = args[index]
    name, equals, value = argument.partition("=")
    if name not in flags:
        return None
    if equals:
        return index, value
    return (index + 1, args[index + 1]) if index + 1 < len(args) else None


def _grants(entry: McpServerEntry) -> dict[int, str]:
    """`{argument index: form}` of the arguments that give the server the whole home directory or the root."""
    args = tuple(entry.args)
    found: dict[int, str] = {}
    if _program(entry) not in _LAUNCHERS and (_filesystem_named(entry.name) or _filesystem_named(entry.command or "") or any(
            _filesystem_named(argument) for argument in args if not _looks_like_a_path(argument))):
        package = next((i for i, argument in enumerate(args) if not _looks_like_a_path(argument) and _filesystem_named(argument)), -1)
        for index in range(package + 1, len(args)):
            before = args[index - 1] if index else ""
            if before.startswith("-") and "=" not in before and before not in _FLAGS:
                continue  # the value of a flag that is not a path flag (`--log-dir /`)
            form = _form_of(args[index])
            if form is not None:
                found[index] = form
    for index in range(len(args)):
        hit = _flag_value(args, index, _FLAGS)
        if hit is not None and (form := _form_of(hit[1])) is not None:
            found.setdefault(hit[0], form)
    if _program(entry) in _LAUNCHERS:
        for index in range(len(args)):
            for flags, host in ((frozenset({"-v", "--volume"}), _mount_host), (frozenset({"--mount"}), _mount_source)):
                hit = _flag_value(args, index, flags)
                if hit is None:
                    continue
                form = _form_of(host(hit[1]))
                if form is not None:
                    found[hit[0]] = "bind_mount_" + ("home" if form == "home_directory" else "root")
    return dict(sorted(found.items()))


def _mount_source(value: str) -> str:
    found = _MOUNT_SOURCE.search(value)
    return found.group(1) if found else ""


_SAYS = {"home_directory": "is the whole home directory", "filesystem_root": "is the filesystem root",
         "bind_mount_home": "is a bind mount of the home directory", "bind_mount_root": "is a bind mount of the filesystem root"}


def detect(config) -> Iterator[Finding]:
    # Imported here, not at the top: rules/config.py will import this module to register it (import cycle).
    from spellwarden_scan.rules.config import config_matched

    for doc, entry in config.servers():
        if doc.kind not in ("mcp", "plugin", "settings"):
            continue
        grants = list(_grants(entry).items())
        for count, (index, form) in enumerate(grants[:_PER_SERVER], start=1):
            shown = f"{entry.name}: args[{index}] {_SAYS[form]}"
            if count == _PER_SERVER and len(grants) > _PER_SERVER:
                shown += f" and {len(grants) - _PER_SERVER} more arguments"
            yield Finding(RULE_ID, SEVERITY, TITLE, Location(doc.path, entry.line), bounded_evidence(shown),
                          fingerprint(RULE_ID, doc.path, config_matched("server", entry.name, form, str(index))), MALICIOUS)
