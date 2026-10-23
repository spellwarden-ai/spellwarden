"""Connected mode, the command's side (O3 spec 6.2 to 6.5, 6.8): when it is on, how the session is established, what
the `required` setting decides when it cannot be, and the organisation's policy and rules once it is.

`activation` is the one owner of "is this run connected". `establish` takes a run from credentials to a
`ConnectedState` (the session, the policy answer validated field by field, the compiled org rules). It raises
`ConnectedStop` for everything before the first authenticated answer (invariant 4: `required` decides, after
discovery, in `decide_stop`) and `ConnectedFail` for everything after it (exit 2, whatever `required` says). It never
decides and never writes: the report block and the notices are built from its result.

`run_gate` is the registry gate of 6.6: the candidates of the run, which of them the request changes, the one check,
and the SW-REG findings. Imports `api` and `ci`, the engine and nothing else network-shaped
(`tests/test_network_boundary.py`; `urllib.parse` is no network module, P21); a credential is a `Secret` from start
to end and no message built here holds one."""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import quote

from spellwarden_scan import (RULES_VERSION, OrgRuleBudget, OrgRuleError, PackDocument, PackError, Rule, __version__,
                              compile_org_rule, validate_pack)
from spellwarden_scan import SEVERITY_RANK
from spellwarden_scan import gate as gates
from spellwarden_scan import identity as ident
from spellwarden_scan.evidence import mask_credentials

from spellwarden_cli import api, ci, discover, escape, paths
from spellwarden_cli.api import ApiClient, ApiError, Session
from spellwarden_cli.ci import ORG_RE
from spellwarden_cli.report import Notice, ProbeReport, Report, ReportFinding, to_json_dict
from spellwarden_cli.secret import Credentials
from spellwarden_cli.settings import Settings

if TYPE_CHECKING:
    from spellwarden_cli.ci import CiContext
    from spellwarden_cli.discover import Discovery, SkillPackage
    from spellwarden_cli.files import FileSet
    from spellwarden_cli.run import ScanOptions

ORG_RULE_SECONDS = 10.0
CLOCK: Callable[[], float] = time.monotonic  # the clock of the org-rule budget; tests replace it
# Test seams of the transport (`opener`, `resolver`, `clock`), applied to the client and to the GitHub token request.
TRANSPORT: dict[str, object] = {}
# The names of the files that redirect package resolution (`spellwarden_scan.identity._RESOLVER_FILES`; a test keeps
# the two equal).
RESOLVER_NAMES = frozenset((".npmrc", ".yarnrc.yml", "bunfig.toml", "uv.toml", "pip.conf", "pyproject.toml"))
GATE_SCOPES = ("changed", "all")
NO_OIDC = ("This job has no OIDC token. Grant `permissions: id-token: write` on GitHub, add the `id_tokens` entry on "
           "GitLab, or use a CI key.")
NO_CREDENTIAL = ("No Spellwarden credential reached this job. Set SPELLWARDEN_ORG with an OIDC token, or "
                 "SPELLWARDEN_API_KEY with a CI key.")
FALLBACK = ("Connected mode was not available ({code}); this run applied the baseline rules only and uploaded "
            "nothing.")
REQUIRED = "This repository requires connected mode (.spellwarden/config.yml) and the run could not connect: {detail}."


class ConnectedStop(Exception):
    """A failure before the first authenticated answer. `code` is the report code of what stopped the run, `message`
    its text (the fix), `detail` the server's own words when it sent any. `run.scan` keeps it until `decide_stop`."""

    def __init__(self, code: str, message: str, detail: str | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.detail = code, message, detail


class ConnectedFail(Exception):
    """A failure after the session was established: the run exits 2 whatever `connected.required` says."""

    def __init__(self, code: str, message: str, detail: str | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.detail = code, message, detail


@dataclass
class ConnectedState:
    session: Session
    policy: dict            # the answer's `policy` object, as received
    document: PackDocument  # its validated pack document
    compiled: tuple[Rule, ...]
    skipped: list[dict]     # the rules the server left out for this scanner: {"id", "why", "version"?}
    ci_policy: dict         # {"gate": {"enabled", "scope", "stdio", "plugins"}}
    registry_name: str | None
    dashboard_url: str
    limits: dict
    client: ApiClient
    scope: str


def activation(settings: Settings, ctx: CiContext, credentials: Credentials) -> str | None:
    """Spec 6.2: `"org"` (`SPELLWARDEN_ORG`), `"key"` (`SPELLWARDEN_API_KEY`), `"required"` (in CI, the settings in
    force say `connected.required: true` and neither variable is set), else None. Both credentials set is
    `connected_config`, decided by `run.connected_config_problem` before this is asked."""
    if credentials.org:
        return "org"
    if credentials.key is not None:
        return "key"
    if settings.connected.required and ctx.provider is not None:
        return "required"
    return None


def org_rule_budget() -> OrgRuleBudget:
    return OrgRuleBudget(CLOCK, ORG_RULE_SECONDS)


def make_client(base_url: str, credential, **kwargs) -> ApiClient:
    """The client factory `run.scan` hands `establish`: the production client plus the test seams of `TRANSPORT`."""
    return ApiClient(base_url, credential, **{**TRANSPORT, **kwargs})


def _explain(error: ApiError) -> str:
    """The text of 6.9 for a failed call: what to fix, the server's words where the text asks for them."""
    server = error.message.rstrip(".")
    if error.code == "connected_auth":
        return (f"The organisation did not accept this pipeline's identity: {server}. Check the CI connection under "
                "Settings, CI connections, or the SPELLWARDEN_API_KEY secret.")
    if error.code == "connected_subscription":
        return ("The organisation's subscription is not active. Machine access is paused until billing is restored; "
                "people can still sign in.")
    if error.code == "connected_ci_key_required":
        return "Connected mode needs a CI key. Create one under Settings, API keys, with access CI."
    if error.code == "connected_rate_limited":
        return f"A Spellwarden limit, not an outage, stopped this call: {server}."
    if error.code == "policy_not_found":
        return f"The pack named in .spellwarden/config.yml is not one this organisation allows for CI: {server}."
    if error.code == "connected_forbidden":
        return f"The credential is not allowed to do this: {server}."
    return error.message if error.message.startswith("Connected mode is not available") else \
        f"Connected mode is not available: {server}."


def _events(log: Callable[[str], None]) -> Callable[[str, dict], None]:
    def on_event(name: str, fields: dict) -> None:
        if name == "api_request":
            log(escape.terminal(f"api: {fields.get('method')} {fields.get('host')}{fields.get('path', '')} "
                                f"{fields.get('status')} ({fields.get('ms')} ms)"))
    return on_event


def _client_fields(ctx: CiContext, scope: str) -> dict:
    """The unsigned display fields of 8.2.2; a field the CI does not give is left out."""
    fields: dict = {"scope": scope}
    for name, value in (("request_number", ctx.request_number), ("head_sha", ctx.head_sha),
                        ("default_branch", ctx.default_branch)):
        if value is not None:
            fields[name] = value
    return fields


def _provider_token(options: ScanOptions, ctx: CiContext, credentials: Credentials, org: str, proxy, loopback: bool):
    if credentials.id_token is not None:
        return credentials.id_token
    if ctx.provider == "github" and credentials.request_url is not None and credentials.request_token is not None:
        try:
            return api.github_id_token(options.env, credentials.request_url, credentials.request_token,
                                       api.audience_for(org), proxy=proxy, loopback=loopback, **TRANSPORT)
        except ApiError as error:
            raise ConnectedStop(error.code, _explain(error), error.message) from None
    raise ConnectedStop("connected_no_credential", NO_OIDC)


def _key_session(client: ApiClient, key) -> Session:
    """Spec 6.5: `GET /orgs` must list exactly one organisation and the caller must hold the CI access."""
    try:
        answer = client.get("/v1/orgs")
    except ApiError as error:
        raise ConnectedStop(error.code, _explain(error), error.message) from None
    caller = answer.get("caller")
    access = caller.get("access") if isinstance(caller, dict) else None
    if access in ("read", "write"):
        raise ConnectedStop("connected_ci_key_required", _explain(ApiError("connected_ci_key_required")))
    listed = answer.get("orgs")
    if access != "ci" or not isinstance(listed, list) or len(listed) != 1 or not isinstance(listed[0], dict):
        raise ConnectedStop("connected_auth", _explain(ApiError(
            "connected_auth", "the key must belong to exactly one organisation and hold the CI access")))
    entry = listed[0]
    slug, name, plan = entry.get("slug"), entry.get("name"), entry.get("plan")
    if not (isinstance(slug, str) and ORG_RE.fullmatch(slug) and isinstance(name, str) and isinstance(plan, str)):
        raise ConnectedStop("connected_auth", _explain(ApiError("connected_auth", "the organisation listing was malformed")))
    if entry.get("reachable") is False:
        if entry.get("billing_state") == "read_only":  # P45: day 15 of a lapsed trial is pre-session
            raise ConnectedStop("connected_subscription", _explain(ApiError("connected_subscription")))
        raise ConnectedStop("connected_auth", _explain(ApiError("connected_auth", "this key cannot reach the organisation")))
    return Session(key, "", {"slug": slug, "name": name, "plan": plan}, None, "key")


def _bad_answer(what: str) -> ConnectedFail:
    return ConnectedFail("connected_unavailable", f"Connected mode is not available: the policy answer {what}.")


def _strict_bool(value: object, what: str) -> bool:
    if not isinstance(value, bool):
        raise _bad_answer(f"has no boolean {what}")
    return value


def _ci_policy(value: object) -> dict:
    gate = value.get("gate") if isinstance(value, dict) else None
    if not isinstance(gate, dict) or gate.get("scope") not in GATE_SCOPES:
        raise _bad_answer("has no gate posture")
    return {"gate": {"enabled": _strict_bool(gate.get("enabled"), "gate.enabled"), "scope": gate["scope"],
                     "stdio": _strict_bool(gate.get("stdio"), "gate.stdio"),
                     "plugins": _strict_bool(gate.get("plugins"), "gate.plugins")}}


def _skipped(value: object) -> list[dict]:
    if not isinstance(value, list):
        raise _bad_answer("has no list of skipped rules")
    out = []
    for entry in value:
        if not (isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry.get("why") in
                ("needs_scanner", "compile_error")):
            raise _bad_answer("lists a skipped rule that is not understood")
        item = {"id": entry["id"], "why": entry["why"]}
        if isinstance(entry.get("version"), str):
            item["version"] = entry["version"]
        out.append(item)
    return out


def _limits(value: object) -> dict:
    keys = ("upload_max_bytes", "upload_max_findings", "upload_max_items", "upload_max_probes")
    if not isinstance(value, dict) or not all(isinstance(value.get(key), int) and not isinstance(value.get(key), bool)
                                              and value[key] >= 0 for key in keys):
        raise _bad_answer("has no limits")
    check = value.get("check_max")
    if not isinstance(check, dict) or not all(isinstance(check.get(key), int) and not isinstance(check.get(key), bool)
                                              for key in ("skills", "servers", "stdio", "plugins", "marketplaces")):
        raise _bad_answer("has no check limits")
    return {**{key: value[key] for key in keys}, "check_max": {key: int(check[key]) for key in check}}


def _policy(answer: dict) -> tuple[dict, PackDocument, tuple[Rule, ...]]:
    policy = answer.get("policy")
    if not isinstance(policy, dict) or policy.get("source") not in ("org_rules", "pack") or \
            policy.get("chosen_by") not in ("organisation", "repository"):
        raise _bad_answer("has no policy")
    try:
        document = validate_pack(policy.get("document"))
    except PackError as error:
        raise ConnectedFail("policy_invalid", f"The organisation's rules are not a valid pack: {error}") from None
    compiled = []
    for spec in document.org_rules:
        try:
            compiled.append(compile_org_rule(spec))
        except OrgRuleError as error:  # after the server's filtering this is a hosted defect (6.5)
            raise ConnectedFail("policy_invalid", f"Organisation rule {spec.get('id', '?')} cannot be compiled: "
                                f"{error.message}") from None
    return policy, document, tuple(compiled)


def establish(options: ScanOptions, ctx: CiContext, credentials: Credentials, scope: str | None,
              client_factory: Callable[..., ApiClient]) -> ConnectedState:
    """Credentials to a session and the organisation's policy. Raises `ConnectedStop` before the session (the caller
    decides with `required`), `ConnectedFail` after it, and never returns without both."""
    if scope is None:
        raise ConnectedFail("connected_config", "The scan root's path cannot be a scan root in connected mode.")
    base_url = options.api_url or api.DEFAULT_API_URL
    loopback = options.api_url is not None
    host = base_url.split("//", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    proxy = api.proxy_for(options.env, host)
    on_event = _events(options.log)

    def client_with(credential) -> ApiClient:
        return client_factory(base_url, credential, release=__version__, proxy=proxy, loopback=loopback,
                              on_event=on_event)

    org, key = credentials.org, credentials.key
    if org:
        token = _provider_token(options, ctx, credentials, org, None, loopback)
        client = client_with(None)
        try:
            session = client.exchange(org, token, _client_fields(ctx, scope))
        except ApiError as error:
            raise ConnectedStop(error.code, _explain(error), error.message) from None
    elif key is not None:
        if ctx.provider == "github" and ctx.event == "pull_request" and ctx.fork:
            raise ConnectedStop("fork_free_mode", "A pull request from a fork gets no secrets from GitHub; the "
                                "SPELLWARDEN_API_KEY that reached this job is ignored.")
        client = client_with(key)
        session = _key_session(client, key)
    else:
        raise ConnectedStop("connected_no_credential", NO_CREDENTIAL)
    slug = session.org.get("slug")
    if not (isinstance(slug, str) and ORG_RE.fullmatch(slug)):
        raise ConnectedFail("connected_unavailable", "Connected mode is not available: the session names no organisation.")
    params = {"scanner": __version__}
    if options.settings.connected.pack:
        params["pack"] = options.settings.connected.pack
    try:
        answer = client.get(f"/v1/orgs/{slug}/ci/policy", params)
    except ApiError as error:
        raise ConnectedFail(error.code, _explain(error), error.message) from None
    organisation = answer.get("org")
    dashboard = answer.get("dashboard_url")
    registry = answer.get("registry")
    if not (isinstance(organisation, dict) and isinstance(organisation.get("name"), str)
            and isinstance(dashboard, str) and dashboard.startswith(("https://", "http://127.0.0.1", "http://[::1]"))
            and (registry is None or (isinstance(registry, dict) and isinstance(registry.get("name"), str)))):
        raise _bad_answer("is not understood")
    ci_policy = _ci_policy(answer.get("ci_policy"))
    limits = _limits(answer.get("limits"))
    policy, document, compiled = _policy(answer)
    skipped = _skipped(policy.get("skipped"))
    merged = {**session.org, "slug": slug, "name": organisation["name"]}
    if isinstance(organisation.get("plan"), str):
        merged["plan"] = organisation["plan"]
    return ConnectedState(session=Session(session.token, session.expires_at, merged, session.run, session.credential),
                          policy=policy, document=document, compiled=compiled, skipped=skipped, ci_policy=ci_policy,
                          registry_name=registry["name"] if registry else None, dashboard_url=dashboard, limits=limits,
                          client=client, scope=scope)


# --- the decision before the session (6.4) ---------------------------------------------------------------------------

def dependabot_candidates_in_scope(found: Discovery, changed: list[str] | None) -> bool:
    """The fixed posture of P35 (every kind, scope `changed`, a registry assumed to exist): True when a path the
    request changes is under a skill directory or is a file a followed link of a skill names, is a configuration
    document holding a server, plugin or marketplace entry, or is a resolver file while a stdio server exists.
    `changed is None` (the base is unavailable) puts every candidate in scope."""
    if changed is None:
        return True
    paths = set(changed)
    if not paths:
        return False
    for skill in found.skills:
        if skill.path == "." or any(path == skill.path or path.startswith(skill.path + "/") for path in paths):
            return True
        if paths & (skill.targets | set(skill.links)):
            return True
    documents = {doc.path for doc in found.documents if doc.servers or doc.plugins or doc.marketplaces or doc.enabled_plugins}
    if paths & documents:
        return True
    stdio = any(server.transport == "stdio" for doc in found.documents for server in doc.servers)
    return stdio and any(path.rpartition("/")[2] in RESOLVER_NAMES for path in paths)


def decide_stop(stop: ConnectedStop, settings: Settings, ctx: CiContext, found: Discovery,
                changed: list[str] | None) -> tuple[Notice | None, Notice | None]:
    """`(error, notice)` for a failure before the session (6.4): a Dependabot request with no candidate in scope is
    `dependabot_free_mode` whatever `required` says; otherwise `required` makes it the error `connected_required` and
    its absence a notice, `fork_free_mode` or `connected_fallback`, after which the run continues in free mode."""
    said = FALLBACK.format(code=stop.code)
    if ctx.dependabot and ctx.is_request and not dependabot_candidates_in_scope(found, changed):
        return None, Notice("dependabot_free_mode", "", f"{said} This Dependabot pull request changes nothing the "
                            "private registry gate would judge.")
    if settings.connected.required:
        detail = f"{stop.code} ({stop.message.rstrip('.')})"
        return Notice("connected_required", "", REQUIRED.format(detail=detail), stop.code), None
    if stop.code == "fork_free_mode":
        return None, Notice("fork_free_mode", "", f"{said} {stop.message}")
    return None, Notice("connected_fallback", "", said)



# --- the registry gate (6.6) -----------------------------------------------------------------------------------------

# The check body's list for each gate kind, in the order the answer is read.
LISTS = {"skill": "skills", "server": "servers", "stdio": "stdio", "plugin": "plugins", "marketplace": "marketplaces"}
ITEMS_MAX = 3600  # the report's `registry.items` (8.4): the sum of the check caps
_EXPORT_ATTRIBUTE = re.compile(r"(?<![\w-])-?export-(?:ignore|subst)\b")
_LAUNCHER_FAMILY = {**ident.LAUNCHER_FAMILY, "pnpm": "npm", "pipx": "python", "docker": "docker"}


@dataclass
class _Candidate:
    """One thing the gate judges. `identity` is None when it cannot be judged (`reason` says why, `binding` ties an
    acceptance to the entry as it stands, P48). `url` is a server's own URL: it completes a request link and never
    leaves the runner."""
    kind: str
    path: str
    line: int | None
    name: str
    item: str
    identity: str | None = None
    reason: str | None = None
    binding: str | None = None
    label: str | None = None                 # the name the evidence of an SW-REG-003 finding carries (first offending path)
    raw: str | None = None                   # the entry's raw_sha256 (configuration entries)
    links: bool = False                      # skills: the package followed a member link
    source_url: str | None = None            # plugins and marketplaces
    pin: str | None = None
    url: str | None = None                   # servers
    family: str | None = None                # stdio: the launcher family (5.1)
    skill: SkillPackage | None = None
    enabled: tuple[str, ...] = ()            # marketplaces: the enabledPlugins entries naming it, from every document
    enabled_in: dict[str, tuple[str, ...]] = field(default_factory=dict)  # marketplaces: those entries per document path
    in_scope: bool = True
    admitted: bool | None = None
    request_url: str | None = None

    def body(self) -> dict:
        entry: dict = {"path": self.path, "name": self.name, "identity": self.identity}
        if self.kind == "skill":
            entry["links"] = self.links
            return entry
        if self.line is not None:
            entry["line"] = self.line
        if self.kind in ("plugin", "marketplace"):
            entry["source_url"], entry["pin"] = self.source_url, self.pin
        return entry

    def report_item(self) -> dict:
        item: dict = {"kind": self.kind, "path": self.path, "name": self.name, "identity": self.identity,
                      "in_scope": self.in_scope, "admitted": self.admitted, "request_url": self.request_url}
        if self.identity is None and self.reason is not None:
            item["reason"] = self.reason
        if self.kind == "marketplace" and self.enabled:
            item["enabled_plugins"] = list(self.enabled)
        return item


def _under(path: str, directory: str, nested: tuple[str, ...] = ()) -> bool:
    """`path` is in the package at `directory` ("." is the scan root) and not in a skill nested in it."""
    inside = directory == "." or path == directory or path.startswith(directory + "/")
    return inside and not any(path == inner or path.startswith(inner + "/") for inner in nested)


def _resolver_bytes(fileset: FileSet | None, path: str) -> bytes:
    """What a `resolver_override` acceptance binds for one resolver file (P48: a changed resolver file is a new finding):
    its bytes; for a link, its target; for a file over `FILE_MAX`, the digest of all of it; and for a file nobody can
    read, a value no stored fingerprint matches, so the acceptance fails closed."""
    if fileset is None:
        return b""
    try:
        return fileset.read(path)
    except paths.TooLarge:
        try:
            digest = hashlib.sha256()
            with open(os.path.join(fileset.root, path), "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            return b"\0large\0" + digest.hexdigest().encode("ascii")
        except OSError:
            return b"\0unreadable\0" + os.urandom(16)
    except (paths.UnsafePath, OSError):
        try:  # a link: its text and the bytes of the file it reaches inside the scan root, which is what the tool reads
            target = fileset.link_target(path)
            text = target.decode("utf-8", "replace")
            segments = text.split("/")
            climbs_back = any(segment == ".." and any(earlier not in ("..", ".", "") for earlier in segments[:index])
                              for index, segment in enumerate(segments))  # `a/../x`: what `a` is decides what is read
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), text))
            if climbs_back or resolved.startswith("../") or resolved == ".." or posixpath.isabs(resolved) or "\\" in resolved:
                return b"\0unreadable\0" + os.urandom(16)
            return b"\0link\0" + target + b"\0" + _resolver_bytes(fileset, resolved)
        except (paths.UnsafePath, paths.TooLarge, OSError, RecursionError):
            return b"\0unreadable\0" + os.urandom(16)


def _reader(fileset: FileSet) -> Callable[[str], bytes]:
    def read(path: str) -> bytes:
        try:
            return fileset.read(path)
        except (OSError, ValueError) as exc:  # too large, a link: `resolver_files` counts what it cannot read
            raise OSError(str(exc)) from exc
    return read


def _gitattributes_hits(fileset: FileSet, read: Callable[[str], bytes]) -> list[str]:
    """Outside a work tree (or where git cannot answer): the `.gitattributes` files under the scan root whose text names
    `export-ignore` or `export-subst` (P55). A file that cannot be read counts: a gate that cannot look says no."""
    hits = []
    for path in sorted(fileset.paths()):
        if path.rpartition("/")[2] != ".gitattributes":
            continue
        try:
            text = read(path).decode("utf-8", errors="replace")
        except OSError:
            hits.append(path)
            continue
        if any(_EXPORT_ATTRIBUTE.search(line) for line in text.splitlines() if not line.lstrip().startswith("#")):
            hits.append(path)
    return hits


def _skill_candidates(found: Discovery, options: ScanOptions, read: Callable[[str], bytes] | None) -> list[_Candidate]:
    fileset = found.fileset
    members = sorted({path for skill in found.skills for path in skill.files})
    attributed = ci.export_attribute_paths(options.root, members, git=None, env=options.env) if members else []
    fallback = ([] if attributed is not None or fileset is None or read is None else _gitattributes_hits(fileset, read))
    candidates = []
    for skill in found.skills:
        root = "" if skill.path == "." else skill.path
        package = ident.package_files(skill.files, root, skill.nested)
        offending = set(package.unhashable)
        if fileset is not None:
            offending |= {path for path in fileset.skipped_dirs if _under(path, skill.path, skill.nested)}
            offending |= {path for path in fileset.deselected if _under(path, skill.path, skill.nested)}
        offending |= set(skill.links)  # member links that could not be followed
        offending |= {path for path in (attributed or ()) if path in skill.files}
        offending |= set(fallback)
        candidate = _Candidate("skill", skill.path, None, skill.name, skill.path, links=bool(skill.targets), skill=skill)
        if offending:
            candidate.reason = "unhashable"
            candidate.binding = gates.unhashable_binding(package.files, offending)
            candidate.label = f"{skill.name} ({sorted(offending)[0]})"
        else:
            candidate.identity = ident.package_sha256(package.files)
        candidates.append(candidate)
    return sorted(candidates, key=lambda candidate: candidate.path)


def _family_of(command: str, parsed_launcher: str | None) -> str | None:
    if parsed_launcher is not None:
        return ident.LAUNCHER_FAMILY.get(parsed_launcher)
    name = posixpath.basename(command.replace("\\", "/")).lower()
    for suffix in (".cmd", ".exe", ".bat"):
        name = name.removesuffix(suffix)
    return _LAUNCHER_FAMILY.get(name)


def _config_candidates(found: Discovery, gate: dict, resolvers: dict[str, tuple[str, ...]],
                       notices: list[Notice]) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    readable = [doc for doc in found.documents if doc.error in (None, "truncated")]
    declared = {decl.name for doc in readable for decl in doc.marketplaces}
    # 6.6: the enabledPlugins entries naming a marketplace are listed under it, whichever settings document holds them
    enabled_in: dict[str, dict[str, tuple[str, ...]]] = {}
    for doc in readable:
        for name in {entry.marketplace for entry in doc.enabled_plugins if entry.enabled}:
            plugins = tuple(sorted(entry.plugin for entry in doc.enabled_plugins if entry.marketplace == name and entry.enabled))
            enabled_in.setdefault(name, {})[doc.path] = plugins
    for doc in found.documents:
        if doc.error not in (None, "truncated"):
            continue
        for server in doc.servers:
            item = f"{doc.path}#{server.name}"
            if server.transport in ("http", "sse") and server.url is not None:
                candidate = _Candidate("server", doc.path, server.line, server.name, item, raw=server.raw_sha256, url=server.url)
                if "${" in server.url:
                    candidate.reason = "unresolved"
                elif server.url.lower().startswith("http://"):
                    candidate.reason = "insecure"
                else:
                    candidate.identity = ident.server_identity(server.url)
                    candidate.reason = None if candidate.identity is not None else "unresolved"
            elif server.transport == "stdio" and gate["stdio"] and server.command is not None:
                candidate = _Candidate("stdio", doc.path, server.line, server.name, item, raw=server.raw_sha256)
                result = ident.command_identity(server.command, server.args, server.env)
                launcher = ident.parse_command_identity(result.identity).launcher if result.identity else None
                candidate.family = _family_of(server.command, launcher)
                candidate.identity, candidate.reason = result.identity, result.reason
                if result.identity is not None and candidate.family in resolvers:
                    bound = {path: _resolver_bytes(found.fileset, path) for path in resolvers[candidate.family]}
                    candidate.identity, candidate.reason = None, "resolver_override"
                    candidate.binding = gates.resolver_binding(server.raw_sha256, bound)
            else:
                continue
            if candidate.identity is None and candidate.binding is None:
                candidate.binding = server.raw_sha256
            candidates.append(candidate)
        if not gate["plugins"]:
            continue
        for plugin in doc.plugins:
            if plugin.source.kind == "local":
                continue
            candidate = _Candidate("plugin", doc.path, plugin.line, plugin.name, f"{doc.path}#{plugin.name}",
                                   raw=plugin.raw_sha256)
            _remote_identity(candidate, plugin.source, plugin.raw_sha256)
            candidates.append(candidate)
        for decl in doc.marketplaces:
            if decl.source.kind == "local":
                continue
            per_document = enabled_in.get(decl.name, {})
            candidate = _Candidate("marketplace", doc.path, decl.line, decl.name, f"{doc.path}#{decl.name}", raw=decl.raw_sha256,
                                   enabled=tuple(sorted({plugin for plugins in per_document.values() for plugin in plugins})),
                                   enabled_in=per_document)
            _remote_identity(candidate, decl.source, decl.raw_sha256)
            candidates.append(candidate)
        for entry in doc.enabled_plugins:
            if entry.marketplace not in declared:
                notices.append(Notice("plugin_marketplace_unknown", doc.path, f"{entry.plugin}@{entry.marketplace} is enabled, "
                                      "but its marketplace is not declared in this repository: it lives in the user's own "
                                      "settings, which no repository scan sees."))
    return candidates


def _remote_identity(candidate: _Candidate, source, raw: str) -> None:
    identity = ident.plugin_identity(source)
    if identity is None:
        candidate.reason, candidate.binding = "unpinned", raw
        return
    candidate.identity = identity
    candidate.source_url = ident.canonical_repo_url(source)
    candidate.pin = identity.rsplit("@", 1)[1]


@dataclass
class _Base:
    """What the base revision's version of one configuration document holds."""
    identities: set[str] = field(default_factory=set)
    raws: set[str] = field(default_factory=set)
    enabled: set[tuple[str, str]] = field(default_factory=set)


def _base_view(options: ScanOptions, ctx: CiContext, doc_path: str, kind: str) -> _Base:
    content = ci.read_at_base(options.root, ctx, doc_path, env=options.env)
    view = _Base()
    if content is None:  # a new document: every entry of it is new
        return view
    for parse_as in dict.fromkeys((kind, "mcp")):  # the settings parser and the MCP parser both read a file, 5.2
        parsed = discover._parse(parse_as, doc_path, content)
        if parsed.error not in (None, "truncated"):
            continue
        for server in parsed.servers:
            if server.transport in ("http", "sse") and server.url is not None:
                view.identities.add(f"server:{ident.server_identity(server.url)}")
            elif server.transport == "stdio" and server.command is not None:
                view.identities.add(f"stdio:{ident.command_identity(server.command, server.args, server.env).identity}")
            view.raws.add(server.raw_sha256)
        for plugin in parsed.plugins:
            view.identities.add(f"plugin:{ident.plugin_identity(plugin.source)}")
            view.raws.add(plugin.raw_sha256)
        for decl in parsed.marketplaces:
            view.identities.add(f"marketplace:{ident.marketplace_identity(decl.source)}")
            view.raws.add(decl.raw_sha256)
        view.enabled |= {(entry.plugin, entry.marketplace) for entry in parsed.enabled_plugins if entry.enabled}
    return view


def _scope(candidates: list[_Candidate], changed: set[str], resolvers: dict[str, tuple[str, ...]], options: ScanOptions,
           ctx: CiContext, kinds: dict[str, str]) -> None:
    """Spec 6.6 "Scope": a candidate is in scope when this request added or changed it."""
    views: dict[str, _Base] = {}
    for candidate in candidates:
        if candidate.kind == "skill":
            skill = candidate.skill
            candidate.in_scope = skill is not None and (
                any(_under(path, skill.path, skill.nested) for path in changed) or bool(skill.targets & changed))
            continue
        candidate.in_scope = False
        if candidate.path in changed:
            if candidate.path not in views:
                views[candidate.path] = _base_view(options, ctx, candidate.path, kinds[candidate.path])
            view = views[candidate.path]
            if candidate.identity is not None:
                new = f"{candidate.kind}:{candidate.identity}" not in view.identities
            else:
                new = candidate.raw not in view.raws
            if candidate.kind == "marketplace":
                new = new or any((plugin, candidate.name) not in view.enabled
                                 for plugin in candidate.enabled_in.get(candidate.path, ()))
            candidate.in_scope = new
        if not candidate.in_scope and candidate.kind == "marketplace":
            # a changed document elsewhere newly enabling one of its plugins puts the marketplace in scope (6.6)
            for path, plugins in candidate.enabled_in.items():
                if path == candidate.path or path not in changed:
                    continue
                if path not in views:
                    views[path] = _base_view(options, ctx, path, kinds[path])
                if any((plugin, candidate.name) not in views[path].enabled for plugin in plugins):
                    candidate.in_scope = True
                    break
        if not candidate.in_scope and candidate.kind == "stdio" and candidate.family is not None:
            candidate.in_scope = any(path in changed for path in resolvers.get(candidate.family, ()))


def _check_failed(error: ApiError) -> ConnectedFail:
    if error.code == "connected_rate_limited":
        return ConnectedFail(error.code, _explain(error), error.message)
    return ConnectedFail("registry_check_failed", f"The private registry could not be checked ({error.code}). The scan is "
                         "incomplete.", error.message)


def _malformed(what: str) -> ConnectedFail:
    return ConnectedFail("registry_check_failed", "The private registry could not be checked (malformed_answer). The scan "
                         "is incomplete.", what)


def _verdicts(answer: dict, sent: dict[str, list[_Candidate]], dashboard_url: str) -> None:
    prefix = dashboard_url.rstrip("/") + "/"
    for kind, candidates in sent.items():
        entries = answer.get(LISTS[kind], [])
        if not isinstance(entries, list) or len(entries) != len(candidates):
            raise _malformed(f"the answer holds {len(entries) if isinstance(entries, list) else 'no list of'} "
                             f"{LISTS[kind]} for {len(candidates)} sent")
        for candidate, entry in zip(candidates, entries, strict=True):
            if not isinstance(entry, dict) or not isinstance(entry.get("admitted"), bool):
                raise _malformed(f"an item of {LISTS[kind]} has no admitted verdict")
            candidate.admitted = entry["admitted"]
            if candidate.admitted:
                continue
            if kind == "server":
                template = entry.get("request_url_template")
                complete = quote(ident.request_link_url(candidate.url or ""), safe="")
                link = template + complete if isinstance(template, str) else None
            else:
                link = entry.get("request_url")
            # a request link is printed only when it is under the dashboard address of the policy answer (6.10)
            if isinstance(link, str) and link.startswith(prefix) and link.isascii() and " " not in link:
                candidate.request_url = link


def run_gate(state: ConnectedState, found: Discovery, probes: list[ProbeReport],  # noqa: ARG001 -- the registry's signature
             ctx: CiContext, options: ScanOptions, notices: list[Notice]) -> tuple[list[ReportFinding], dict | None]:
    """O3 spec 6.6: `(the SW-REG findings, the report's registry block)`, the block None when the gate did not run (no
    registry in the plan, or the organisation turned the gate off). Raises `ConnectedFail` when the check cannot be made
    or answered: the run then exits 2 and writes no SW-REG finding."""
    if state.registry_name is None:
        return [], None
    gate = state.ci_policy["gate"]
    if not gate["enabled"]:
        notices.append(Notice("registry_gate_off", "", "The organisation turned the registry gate off for CI runs: nothing "
                              "was checked against the private registry."))
        return [], None
    fileset = found.fileset
    read = _reader(fileset) if fileset is not None else None
    resolvers = ident.resolver_files(fileset.paths(), read) if fileset is not None and read is not None else {}
    candidates = [*_skill_candidates(found, options, read), *_config_candidates(found, gate, resolvers, notices)]
    applied = "all"
    if gate["scope"] == "changed" and ctx.run_kind() == "request":
        changed = ci.changed_paths(options.root, ctx, env=options.env)
        if changed is None:
            notices.append(Notice("gate_scope_all", "", "The base revision of this request could not be read, so the registry "
                                  "gate judged every item, not only the ones this request changes."))
        else:
            applied = "changed"
            kinds = {doc.path: doc.kind for doc in found.documents}
            _scope(candidates, set(changed), resolvers, options, ctx, kinds)
    in_scope = [candidate for candidate in candidates if candidate.in_scope]
    sent: dict[str, list[_Candidate]] = {
        kind: [c for c in in_scope if c.kind == kind and c.identity is not None] for kind in LISTS}
    caps = state.limits["check_max"]
    over = [f"{len(sent[kind])} {LISTS[kind]} (at most {caps[LISTS[kind]]})" for kind in LISTS
            if len(sent[kind]) > caps[LISTS[kind]]]
    if over:
        raise ConnectedFail("registry_check_too_large", "This run has more items to check against the private registry than "
                            f"one call may carry: {', '.join(over)}. Narrow the scan with include or exclude, or split the "
                            "repository into scan roots. The scan is incomplete.")
    checked = sum(len(items) for items in sent.values())
    if checked:
        slug = state.session.org["slug"]
        identity = (state.session.run or {}).get("identity") or ctx.repository_identity
        body = {"schema": 1, "repository": {"identity": identity, "scope": state.scope, "head_sha": ctx.head_sha or ctx.sha,
                                            "visibility": ctx.visibility or "private"},
                **{LISTS[kind]: [candidate.body() for candidate in items] for kind, items in sent.items()}}
        try:
            answer = state.client.post(f"/v1/orgs/{slug}/ci/registry-check", body)
        except ApiError as error:
            raise _check_failed(error) from None
        _verdicts(answer, sent, state.dashboard_url)
    findings = []
    for candidate in in_scope:
        if candidate.identity is None:
            finding = gates.gate_finding(candidate.kind, candidate.path, candidate.line, candidate.label or candidate.name, None,
                                         candidate.reason or "unpinned", candidate.binding)
        elif candidate.admitted is False:
            finding = gates.gate_finding(candidate.kind, candidate.path, candidate.line, candidate.name, candidate.identity,
                                         gates.NOT_ADMITTED)
        else:
            continue
        findings.append(ReportFinding(finding, candidate.item))
    registry = {"gate": True, "scope": gate["scope"], "scope_applied": applied, "stdio": gate["stdio"],
                "plugins": gate["plugins"], "checked": checked,
                "not_admitted": sum(1 for c in in_scope if c.admitted is False),
                "unidentified": sum(1 for c in in_scope if c.identity is None),
                "out_of_scope": len(candidates) - len(in_scope),
                "items": [candidate.report_item() for candidate in candidates[:ITEMS_MAX]]}
    return findings, registry



# --- the upload (6.7) ------------------------------------------------------------------------------------------------

UPLOAD_SKIPS = ("branch", "event_not_reportable", "default_branch_unconfirmed")  # what the server may answer 202 with
STRING_MAX = 1024            # every string of the report's connected block (8.4)
MESSAGE_MAX = 300            # a notice or error message in the body
LIST_MAX = 50                # notices and errors in the body
PROBE_FIELDS = ("item", "status", "skip_reason", "transport", "spec_version", "auth_mode", "migration_status")
_KEY_UNSAFE = re.compile(r"[^A-Za-z0-9._:#/-]")


def idempotency_key(ctx: CiContext, env: dict[str, str] | dict) -> str | None:
    """Spec 6.7: the key of one run's upload, `^[A-Za-z0-9._:#/-]{16,128}$`: the run URL, the job and the attempt; in
    `other` CI without a run URL, `SPELLWARDEN_RUN_ID`. None when there is no run id."""
    job = ctx.job or "job"
    if ctx.run_url:
        raw = f"{ctx.run_url}#{job}#{ctx.attempt}"
    else:
        run_id = str(env.get("SPELLWARDEN_RUN_ID", "")).strip()
        if not run_id:
            return None
        raw = f"{ctx.provider or 'other'}:{run_id}#{job}#{ctx.attempt}"
    key = _KEY_UNSAFE.sub("_", raw)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if len(key) > 128:
        return f"{ctx.provider or 'other'}:{digest[:64]}#{ctx.attempt}"
    return key if len(key) >= 16 else f"{key}#{digest[:16]}"


def _clip(value: object) -> object:
    if isinstance(value, str):
        return value if len(value) <= STRING_MAX else value[:STRING_MAX - 3] + "..."
    if isinstance(value, list):
        return [_clip(item) for item in value]
    if isinstance(value, dict):
        return {key: _clip(item) for key, item in value.items()}
    return value


def _message(text: object) -> str:
    masked = mask_credentials(str(text))
    return masked if len(masked) <= MESSAGE_MAX else masked[:MESSAGE_MAX - 3] + "..."


def _entries(entries: list[dict]) -> list[dict]:
    cut = []
    for entry in entries:
        reduced = {**entry, "message": _message(entry.get("message", ""))}
        if entry.get("detail") is not None:
            reduced["detail"] = _message(entry["detail"])  # 8.4: at most 300, masked, like the message
        cut.append(reduced)
    return cut


def _cap(report: dict, name: str, limit: int, cut: list[str]) -> None:
    if len(report[name]) > limit:
        report[name] = report[name][:limit]
        cut.append(name)


def reduce_report(report_dict: dict, limits: dict, envelope: dict | None = None) -> tuple[dict, int, list[str]]:
    """O3 spec 6.7, invariant 3: the report as the body carries it, `(body report, findings dropped, lists cut)`. No
    `connected.upload`; probes keep the seven fields of 8.4 (no findings, no checklist); at most 50 notices and 50 errors
    with messages masked and cut to 300 characters; the caps of the policy answer for items, probes and findings
    (highest severity first, suppressed ones included with their baseline). Over `upload_max_bytes` the items, then the
    probes, then the lowest findings are dropped. Every cut is in `upload_truncated` and `upload_truncated_fields`.
    `envelope` is the rest of the body (`schema`, `run`): the server caps the whole body, so the size is measured with
    it. `report_dict` is not changed."""
    report = {**report_dict}
    cut: list[str] = []
    report["findings"] = sorted(report_dict["findings"], key=lambda f: SEVERITY_RANK[f["severity"]])  # stable: report order
    report["items"] = list(report_dict["items"])
    report["probes"] = [{name: probe.get(name) for name in PROBE_FIELDS} for probe in report_dict["probes"]]
    report["notices"] = _entries(report_dict["notices"])
    report["errors"] = _entries(report_dict["errors"])
    if report_dict.get("connected") is not None:
        block = {key: _clip(value) for key, value in report_dict["connected"].items() if key != "upload"}
        registry = block.get("registry")
        if isinstance(registry, dict) and len(registry.get("items", [])) > 3600:
            block["registry"] = {**registry, "items": registry["items"][:3600]}
        report["connected"] = block
    before = len(report["findings"])
    _cap(report, "findings", limits["upload_max_findings"], cut)
    _cap(report, "items", limits["upload_max_items"], cut)
    _cap(report, "probes", limits["upload_max_probes"], cut)
    _cap(report, "notices", LIST_MAX, cut)
    _cap(report, "errors", LIST_MAX, cut)

    def size() -> int:
        body = report if envelope is None else {**envelope, "report": report}
        return len(json.dumps(body, separators=(",", ":")).encode("utf-8"))

    for name in ("items", "probes"):  # still over the limit: these two go whole, in this order
        if size() > limits["upload_max_bytes"] and report[name]:
            report[name] = []
            cut.append(name)
    while size() > limits["upload_max_bytes"] and len(report["findings"]) > 1:  # last: the lowest findings, in halves
        report["findings"] = report["findings"][:max(1, len(report["findings"]) // 2)]
        cut.append("findings")
    dropped = before - len(report["findings"])
    cut = [name for name in ("findings", "items", "probes", "notices", "errors") if name in cut]
    if cut:
        report["upload_truncated"] = dropped
        report["upload_truncated_fields"] = cut
    return report, dropped, cut


def _upload_failure(error: ApiError) -> dict:
    code = error.body.get("error") if isinstance(error.body, dict) and isinstance(error.body.get("error"), str) else error.code
    block: dict = {"status": "failed", "error": code}
    if error.request_id:
        block["request_id"] = error.request_id
    return block


def upload(state: ConnectedState, report: Report, ctx: CiContext, options: ScanOptions) -> dict:
    """O3 spec 6.7: the report's `upload` block. Posts the run and the reduced report to `/ci/scans` once the exit code is
    known; never raises and never changes the exit code. `skipped` carries a `reason`, `failed` an `error` (and the
    `request_id` when the server sent one), `uploaded` the repository page `url` (only when it is under the dashboard
    address) and whether the scan is `attested` (a CI token's run; a key's is a key report)."""
    try:
        return _upload(state, report, ctx, options)
    except Exception as exc:  # noqa: BLE001 -- an upload failure is a notice, whatever it was
        return {"status": "failed", "error": type(exc).__name__}


def _upload(state: ConnectedState, report: Report, ctx: CiContext, options: ScanOptions) -> dict:
    if not options.settings.connected.upload:
        return {"status": "skipped", "reason": "disabled"}
    if ctx.provider is None:
        return {"status": "skipped", "reason": "local"}
    kind = ctx.run_kind()
    if kind == "branch":
        return {"status": "skipped", "reason": "branch"}
    key = idempotency_key(ctx, options.env)
    if key is None and state.session.credential == "key":
        return {"status": "skipped", "reason": "no_run_id"}
    identity = (state.session.run or {}).get("identity") or ctx.repository_identity
    if not isinstance(identity, str):
        return {"status": "failed", "error": "repository_unknown"}
    run_block = {"provider": ctx.provider,
                 "repository": {"identity": identity, "url": ctx.repository_url, "visibility": ctx.visibility or "private",
                                "scope": state.scope},
                 "kind": kind, "event": ctx.event or "unknown", "request_number": ctx.request_number,
                 "head_sha": ctx.head_sha, "head_ref": ctx.head_ref, "sha": ctx.sha, "ref_name": ctx.ref_name,
                 "default_branch": ctx.default_branch, "run_url": ctx.run_url, "idempotency_key": key}
    body_report, _dropped, _cut = reduce_report(to_json_dict(report), state.limits, envelope={"schema": 1, "run": run_block})
    body = {"schema": 1, "run": run_block, "report": body_report}
    try:
        answer = state.client.post(f"/v1/orgs/{state.session.org['slug']}/ci/scans", body, retry=False)
    except ApiError as error:
        return _upload_failure(error)
    if "skipped" in answer:
        reason = answer["skipped"]
        if reason in UPLOAD_SKIPS:
            return {"status": "skipped", "reason": reason}
        return {"status": "failed", "error": "unknown_skip"}
    result: dict = {"status": "uploaded", "attested": state.session.credential == "oidc"}
    link = answer.get("url")
    if isinstance(link, str) and link.startswith(state.dashboard_url.rstrip("/") + "/") and link.isascii() and " " not in link:
        result["url"] = link
    return result


_SKIPPED_BECAUSE = {
    "branch": "this run is on a branch that is neither the default branch nor a pull or merge request",
    "event_not_reportable": "the server does not take results from this kind of event",
    "default_branch_unconfirmed": "the default branch of this repository is not confirmed; ask someone who can edit the "
                                  "repository in the dashboard to confirm it",
    "no_run_id": "there is no run id to make the upload idempotent; set SPELLWARDEN_RUN_ID",
}


def upload_notice(block: dict) -> Notice:
    """The notice of an upload outcome (6.7): `uploaded`, `upload_failed`, `upload_skipped`, `upload_ci_only` or
    `upload_disabled`. It never changes the exit code."""
    if block["status"] == "uploaded":
        where = f" to {block['url']}" if block.get("url") else ""
        return Notice("uploaded", "", f"Results were uploaded{where}.")
    if block["status"] == "failed":
        request = f" Request id {block['request_id']}." if block.get("request_id") else ""
        return Notice("upload_failed", "", f"The results could not be uploaded ({block.get('error')}); the scan and its exit "
                      f"code are unaffected.{request}")
    reason = block.get("reason")
    if reason == "local":
        return Notice("upload_ci_only", "", "Results are uploaded from CI runs only; this local run uploaded nothing.")
    if reason == "disabled":
        return Notice("upload_disabled", "", "Uploading is turned off (--no-upload, SPELLWARDEN_UPLOAD or connected.upload); "
                      "nothing was uploaded.")
    return Notice("upload_skipped", "", f"The results were not uploaded: {_SKIPPED_BECAUSE.get(reason, reason)}.")


# --- notices and the report block ------------------------------------------------------------------------------------

def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) if part.isdigit() else 0 for part in text.split("."))


def state_notices(state: ConnectedState, settings: Settings) -> list[Notice]:
    """The notices of 6.5: rules the server left out, a pack made for newer rules, MCP rules that need `--probe`."""
    notices = []
    if state.skipped:
        ids = ", ".join(entry["id"] for entry in state.skipped)
        why = "; ".join(f"{entry['id']} needs scanner {entry.get('version', 'a newer version')}"
                        if entry["why"] == "needs_scanner" else f"{entry['id']} did not compile on the server"
                        for entry in state.skipped)
        notices.append(Notice("org_rules_skipped", "", f"{len(state.skipped)} organisation rules were not applied "
                              f"({ids}): {why}. The dashboard marks this scan incomplete."))
    if _version(state.document.rules_version) > _version(RULES_VERSION):
        notices.append(Notice("policy_newer_than_scanner", "", f"The pack was made for rules version "
                              f"{state.document.rules_version}, newer than this scanner's {RULES_VERSION}; it validates "
                              "and compiles, so it was applied. Update the scanner to match."))
    if not settings.probe and any(rule.area == "mcp" for rule in state.compiled):
        notices.append(Notice("mcp_rules_need_probe", "", "Organisation rules for MCP servers run on probed servers only; "
                              "this run does not probe (--probe)."))
    return notices


def report_block(state: ConnectedState, ctx: CiContext) -> dict:
    """The report's `connected` object (6.9). `registry` and `upload` are placeholders the gate and the upload fill."""
    run: dict = {"identity": ctx.repository_identity, "scope": state.scope, "kind": ctx.run_kind(), "event": ctx.event,
                 "sha": ctx.sha, "head_sha": ctx.head_sha, "ref_name": ctx.ref_name}
    server = state.session.run or {}
    for name in ("identity", "event", "sha", "head_sha", "ref_name"):  # the server derived these from the signed token
        if isinstance(server.get(name), str):
            run[name] = server[name]
    policy = state.policy
    return {
        "credential": state.session.credential,
        "org": {"slug": state.session.org["slug"], "name": state.session.org["name"]},
        "run": run,
        "policy": {
            "source": policy["source"], "chosen_by": policy["chosen_by"], "pack_id": state.document.pack_id,
            "version": state.document.version, "sha256": policy.get("sha256") if isinstance(policy.get("sha256"), str) else None,
            "org_rule_ids": sorted(rule.id for rule in state.compiled), "skipped": list(state.skipped),
            "pack_name": state.document.name, "gate": dict(state.ci_policy["gate"]), "registry_name": state.registry_name,
        },
        "registry": None, "upload": None,
    }


def org_rules_incomplete_error(ids: tuple[str, ...], path: str) -> Notice:
    return Notice("org_rules_incomplete", path, f"Organisation rule(s) {', '.join(ids)} did not finish on {path or '.'} "
                  f"within {int(ORG_RULE_SECONDS)} seconds. The scan is incomplete.")


__all__ = ["ConnectedFail", "ConnectedState", "ConnectedStop", "activation", "decide_stop",
           "dependabot_candidates_in_scope", "establish", "make_client", "org_rule_budget", "reduce_report", "report_block",
           "run_gate", "state_notices", "upload", "upload_notice"]
