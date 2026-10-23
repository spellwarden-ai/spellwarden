"""Connected mode, the command's side (O3 spec 6.2 to 6.5, 6.8): when it is on, how the session is established, what
the `required` setting decides when it cannot be, and the organisation's policy and rules once it is.

`activation` is the one owner of "is this run connected". `establish` takes a run from credentials to a
`ConnectedState` (the session, the policy answer validated field by field, the compiled org rules). It raises
`ConnectedStop` for everything before the first authenticated answer (invariant 4: `required` decides, after
discovery, in `decide_stop`) and `ConnectedFail` for everything after it (exit 2, whatever `required` says). It never
decides and never writes: the report block and the notices are built from its result.

Imports `api` and `ci`, the engine and nothing else network-shaped (`tests/test_network_boundary.py`); a credential
is a `Secret` from start to end and no message built here holds one."""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from spellwarden_scan import (RULES_VERSION, OrgRuleBudget, OrgRuleError, PackDocument, PackError, Rule, __version__,
                              compile_org_rule, validate_pack)

from spellwarden_cli import api, escape
from spellwarden_cli.api import ApiClient, ApiError, Session
from spellwarden_cli.ci import ORG_RE
from spellwarden_cli.report import Notice
from spellwarden_cli.secret import Credentials
from spellwarden_cli.settings import Settings

if TYPE_CHECKING:
    from spellwarden_cli.ci import CiContext
    from spellwarden_cli.discover import Discovery
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
        return Notice("connected_required", "", REQUIRED.format(detail=detail)), None
    if stop.code == "fork_free_mode":
        return None, Notice("fork_free_mode", "", f"{said} {stop.message}")
    return None, Notice("connected_fallback", "", said)


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
           "dependabot_candidates_in_scope", "establish", "make_client", "org_rule_budget", "report_block", "state_notices"]
