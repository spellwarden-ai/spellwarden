"""SW-CFG-013: database or cluster MCP server with write access although a read-only mode exists.

Read over the servers of MCP client configurations (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, at any
depth; no other document kind). A small registry names the write-capable servers and the switch that restricts each:

* the hosted Supabase endpoint (`mcp.supabase.com`, in the server's `url` or in a launcher argument) without
  `read_only=true` in its query;
* the `@supabase/mcp-server-supabase` package (run directly or through `npx`, `bunx`, `pnpm dlx`) without `--read-only`;
* a Kubernetes server (`kubernetes-mcp-server`, `mcp-server-kubernetes`) with neither `--read-only` nor
  `--disable-destructive`, and without `ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS=true` in its environment;
* any other server whose environment sets an `...ACCESS_MODE` to `unrestricted` (or whose arguments pass
  `--access-mode unrestricted`) or an insert, update, delete or DDL enable flag to `true`.

A restricting switch (`--read-only`, or a `read_only` / `readOnly` key of the server object), a disabled entry
(`disabled: true` or `enabled: false`) and a documentation-only Supabase server (`features` naming only `docs`) are quiet.
A server yields at most one finding, at its line, and its evidence names the missing switch. Every scan is a plain
string scan, linear in the size of the entry. The module is registered by the rule set, not here."""
from __future__ import annotations

from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.model import Finding, Location, McpServerEntry

RULE_ID = "SW-CFG-013"
TITLE = "Database or cluster MCP server with write access although a read-only mode exists"
SEVERITY = "high"
OWASP = ("MCP02", "ASI03")
NIST = ("AC-3", "AC-6")
MALICIOUS = False

_HOSTED = "mcp.supabase.com"
_SUPABASE_PACKAGE = ("@supabase", "mcp-server-supabase")
_KUBERNETES_PACKAGES = frozenset({"kubernetes-mcp-server", "mcp-server-kubernetes"})
_KUBERNETES_SAFE_ENV = "ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS"
_WRITE_FLAGS = frozenset(f"{verb}_{operation}{suffix}" for verb in ("ALLOW", "ENABLE")
                         for operation in ("INSERT", "UPDATE", "DELETE", "DDL")
                         for suffix in ("", "_OPERATION", "_OPERATIONS"))
_READ_ONLY_ENV = frozenset({"READ_ONLY", "READONLY"})


def _is_true(value: object) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _option(entry: McpServerEntry, key: str) -> object:
    option = entry.options.get(key)
    return option["value"] if option else None


def _disabled(entry: McpServerEntry) -> bool:
    return _is_true(_option(entry, "disabled")) or _option(entry, "enabled") is False or _option(entry, "enabled") == "false"


def _switch_on(arg: str, switch: str) -> bool:
    """`arg` is `switch` or `switch=<value>` with a value other than a false one."""
    if arg == switch:
        return True
    return arg.startswith(switch + "=") and arg[len(switch) + 1:].lower() not in ("false", "0", "no", "off", "")


def _read_only(entry: McpServerEntry) -> bool:
    if _is_true(_option(entry, "read_only")) or _is_true(_option(entry, "readOnly")):
        return True
    return any(_switch_on(arg, "--read-only") for arg in entry.args)


def _package(arg: str) -> tuple[str, str] | None:
    """`(scope, name)` of an npm package argument (version cut off; scope is empty for an unscoped one). A path keeps
    only its last segment, so a binary named like the package matches too."""
    if not arg or arg.startswith("-"):
        return None
    text = arg.replace("\\", "/")
    scope = ""
    if text.startswith("@"):
        slash = text.find("/")
        if slash < 0:
            return None
        scope, text = text[:slash], text[slash + 1:]
    else:
        text = text[text.rfind("/") + 1:]
    name = text.partition("@")[0]
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return scope, name


def _mentions(entry: McpServerEntry, wanted) -> bool:
    candidates = list(entry.args)
    if entry.command:
        candidates.append(entry.command)
    for candidate in candidates:
        package = _package(candidate)
        if package is not None and wanted(*package):
            return True
    return False


def _hosted_queries(text: str) -> Iterator[str]:
    """The query string after the first `mcp.supabase.com` host occurrence in `text` (host boundaries checked): a URL
    names its host once, and reading only the first occurrence keeps the work linear in the text (review r1:F2)."""
    lowered = text.lower()
    start = lowered.find(_HOSTED)
    while start >= 0:
        end = start + len(_HOSTED)
        before_ok = start == 0 or lowered[start - 1] in "/@"
        after_ok = end == len(lowered) or lowered[end] in "/?#:"
        if before_ok and after_ok:
            fragment = text.find("#", end)
            stop = len(text) if fragment < 0 else fragment
            mark = text.find("?", end, stop)
            yield "" if mark < 0 else text[mark + 1:stop]
            return
        start = lowered.find(_HOSTED, end)


def _params(query: str) -> Iterator[tuple[str, str]]:
    for part in query.split("&"):
        key, _, value = part.partition("=")
        yield key.lower(), value.lower()


def _docs_only(features: list[str]) -> bool:
    tokens = [token for value in features for token in value.split(",") if token]
    return bool(tokens) and all(token == "docs" for token in tokens)


def _hosted_supabase(entry: McpServerEntry) -> str | None | bool:
    """False when the entry is not the hosted endpoint, None when it is and is restricted, else the missing switch."""
    seen = False
    for text in ([entry.url] if entry.url else []) + list(entry.args):
        for query in _hosted_queries(text):
            seen = True
            params = list(_params(query))
            if any(key == "read_only" and value == "true" for key, value in params):
                return None
            if _docs_only([value for key, value in params if key == "features"]):
                return None
    if not seen:
        return False
    return None if _read_only(entry) else "hosted endpoint without read_only=true"


def _supabase_package(entry: McpServerEntry) -> str | None | bool:
    if not _mentions(entry, lambda scope, name: (scope, name) == _SUPABASE_PACKAGE):
        return False
    features = [arg.partition("=")[2].lower() for arg in entry.args if arg.startswith("--features=")]
    features += [entry.args[i + 1].lower() for i, arg in enumerate(entry.args[:-1]) if arg == "--features"]
    if _docs_only(features) or _read_only(entry):
        return None
    return "package without --read-only"


def _kubernetes(entry: McpServerEntry) -> str | None | bool:
    if not _mentions(entry, lambda _scope, name: name in _KUBERNETES_PACKAGES):
        return False
    if _read_only(entry) or any(_switch_on(arg, "--disable-destructive") for arg in entry.args):
        return None
    if _is_true(entry.env.get(_KUBERNETES_SAFE_ENV)):
        return None
    return f"neither --read-only nor --disable-destructive nor {_KUBERNETES_SAFE_ENV}=true"


def _unrestricted(entry: McpServerEntry) -> str | None | bool:
    """Environment or arguments that switch a database server's write access on; None when nothing does."""
    unlocked = None
    for key, value in entry.env.items():
        upper = key.upper()
        if upper.endswith("ACCESS_MODE") and value.lower() == "unrestricted":
            unlocked = f"{key}=unrestricted"
            break
        if upper in _WRITE_FLAGS and _is_true(value):
            unlocked = f"{key}=true"
            break
    if unlocked is None:
        for index, arg in enumerate(entry.args):
            if arg.lower() == "--access-mode=unrestricted" or (
                    arg.lower() == "--access-mode" and index + 1 < len(entry.args)
                    and entry.args[index + 1].lower() == "unrestricted"):
                unlocked = "--access-mode unrestricted"
                break
    if unlocked is None:
        return False
    if _read_only(entry) or any(key.upper() in _READ_ONLY_ENV and _is_true(value) for key, value in entry.env.items()):
        return None
    return f"{unlocked} with no read-only switch"


_CHECKS = (_hosted_supabase, _supabase_package, _kubernetes, _unrestricted)


def _missing(entry: McpServerEntry) -> str | None:
    """The missing switch of a write-capable server, or None when the entry is not one or is restricted. The first
    registry entry that recognises the server decides."""
    for check in _CHECKS:
        outcome = check(entry)
        if outcome is not False:
            return outcome
    return None


def detect(config) -> Iterator[Finding]:
    # Imported here, not at the top: rules/config.py will import this module to register it (import cycle).
    from spellwarden_scan.rules.config import config_matched

    for doc, entry in config.servers():
        if doc.kind != "mcp" or _disabled(entry):
            continue
        missing = _missing(entry)
        if missing is None:
            continue
        matched = config_matched("server", entry.name, "write_access", missing)
        yield Finding(RULE_ID, SEVERITY, TITLE, Location(doc.path, entry.line),
                      bounded_evidence(f"{entry.name}: {missing}"), fingerprint(RULE_ID, doc.path, matched), MALICIOUS)
