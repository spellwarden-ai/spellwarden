"""`spellwarden scan --user` from the command line, and the workstation upload (phase 3 batch 2a spec 11.3, 11.4).

The run: the usage checks are `main`'s; then, with `--upload`, the organisation and the key (`SPELLWARDEN_WORKSTATION_ORG`,
`SPELLWARDEN_WORKSTATION_KEY`, never the repository variables, D33) and the device label are checked before any client file is
read; the scan (`userscan.scan`); with `--upload` the upload; and last every requested output, which carries the upload's
outcome (phase 3 batch 2c spec 11.2, F1). A `--user` run sends no usage ping and starts no connected mode, whatever
`SPELLWARDEN_ORG` and `SPELLWARDEN_API_KEY` say.

The upload is one `POST {api}/v1/orgs/{slug}/workstations/inventory` through `api.ApiClient` (HTTPS, public addresses, no
redirect, 10 s, one retry on a 429 or a 5xx). Its body is the closed shape of 6.3, built from the report: the item facts of
`Report.details` (already reduced, D40), no message, no evidence, no environment value, header or argument. Over the caps
(1 MiB, 2,000 items, 1,000 findings) nothing is sent. The outcome is a notice (`workstation_uploaded`) or an error
(`workstation_upload_too_large`, `workstation_upload_failed`) of the report, so each output carries it as it carries any notice
or error, and a failure exits 2 (D12, batch 2c spec 11.2); a crash while uploading is `workstation_upload_failed` with the detail
`crash` and still writes every output. The report's notice holds no time (a report holds no timestamp); the stderr line,
printed after the outputs are written, keeps the server's time of the upload.

The state file `workstation.json` in the user configuration directory holds the random install id and the label, written with
mode 0600 where modes exist, by an upload run only, before its request, so a failed request keeps the device's identity."""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import secrets
import sys
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from urllib.parse import urlsplit

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

from spellwarden_cli import api, clients
from spellwarden_cli.report import LockState, Notice, Report
from spellwarden_cli.secret import Credentials
from spellwarden_cli.settings import Settings

STATE_FILE = "workstation.json"
LABEL_MAX = 64
ITEMS_MAX = 2000
FINDINGS_MAX = 1000
BODY_MAX = 1_048_576
LISTED_MAX = 50  # errors and notices listed in the body; the totals count all (4.8: an output cap)
# client roots sent per client: an output cap, since every report on the workstation lists them all (README "Limits"); the
# server reduces the body to a closed table of fields and has no field for the count left out
ROOTS_MAX = 8
ORG_RE = re.compile(r"[a-z0-9-]{2,64}")
KEY_RE = re.compile(r"swk_[A-Za-z0-9_-]{40}")
_INSTALL_ID = re.compile(r"[0-9a-f]{32}")
_CUTS = {"name": 256, "path": 512, "scope": 512, "endpoint": 2048, "command_identity": 512, "command_reason": 32,
         "plugin": 256, "marketplace": 2048, "format": 32}


def _stderr(line: str) -> None:
    print(f"spellwarden: {line}", file=sys.stderr)


def _silent(_line: str) -> None:
    return None


def _platform() -> str:
    """`sys.platform`; the tests replace it to run the command as on another system."""
    return sys.platform


# --- the device ----------------------------------------------------------------------------------------------------------

def clean(text: str) -> str:
    """The server's cleaning rule (6.3), applied before sending: NFC, control and format (zero-width) characters removed,
    surrounding space removed, cut to 64 characters."""
    normal = unicodedata.normalize("NFC", text)
    kept = "".join(char for char in normal if unicodedata.category(char) not in ("Cc", "Cf"))
    return kept.strip()[:LABEL_MAX]


def state_directory(sys_platform: str, env: Mapping[str, str], home: str) -> str:
    """`$XDG_CONFIG_HOME/spellwarden` on Linux, `~/Library/Application Support/spellwarden` on macOS, `%APPDATA%\\spellwarden`
    on Windows (11.4); an unset or relative variable is its default."""
    system = clients.platform_of(sys_platform)
    if system == "macos":
        return os.path.join(home, "Library", "Application Support", "spellwarden")
    variable, default = ("APPDATA", ("AppData", "Roaming")) if system == "windows" else ("XDG_CONFIG_HOME", (".config",))
    value = env.get(variable, "")
    base = value if value and os.path.isabs(value) else os.path.join(home, *default)
    return os.path.join(base, "spellwarden")


def load_state(directory: str) -> dict:
    """The state file's `install_id` and `device_label`, each only when valid; `{}` when the file is absent or unreadable."""
    try:
        with open(os.path.join(directory, STATE_FILE), "rb") as handle:
            data = json.loads(handle.read(65536).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    state = {}
    if isinstance(data.get("install_id"), str) and _INSTALL_ID.fullmatch(data["install_id"]):
        state["install_id"] = data["install_id"]
    if isinstance(data.get("device_label"), str) and clean(data["device_label"]):
        state["device_label"] = clean(data["device_label"])
    return state


def save_state(directory: str, install_id: str, label: str) -> None:
    """Written to a new file of mode 0600 beside the old one, then renamed over it."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, STATE_FILE)
    temporary = f"{path}.{secrets.token_hex(4)}.tmp"
    data = json.dumps({"schema": 1, "install_id": install_id, "device_label": label}, ensure_ascii=False).encode("utf-8")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)


# --- the body --------------------------------------------------------------------------------------------------------

def _cut(entry: dict) -> dict:
    return {key: (value[:_CUTS[key]] if isinstance(value, str) and key in _CUTS else value) for key, value in entry.items()}


def _listed(notices: tuple[Notice, ...]) -> list[dict]:
    ordered = sorted(notices, key=lambda notice: (notice.code, notice.path))
    return [{"code": notice.code[:64], "path": notice.path[:512]} for notice in ordered[:LISTED_MAX]]


def body(report: Report, *, install_id: str, label: str, system: str) -> dict:
    """The upload body of 6.3, from a `--user` report."""
    numbers = {item.path: index for index, item in enumerate(report.items, start=1)}
    items = []
    for item in report.items:
        facts = report.details.get(item.path, {})
        if item.kind == "marketplace":
            marketplace = facts.get("source")
        elif item.kind == "plugin":
            marketplace = report.details.get(facts.get("marketplace_item", ""), {}).get("source")
        else:
            marketplace = None
        items.append(_cut({"n": numbers[item.path], "clients": list(item.clients), "kind": item.kind, "name": item.name,
                           "path": item.path, "scope": item.scope, "transport": facts.get("transport"),
                           "endpoint": facts.get("endpoint"), "command_identity": facts.get("command_identity"),
                           "command_reason": facts.get("command_reason"), "plugin": item.plugin, "marketplace": marketplace,
                           "format": item.format}))
    findings = [{"item": numbers[rf.item], "rule_id": rf.finding.rule_id, "severity": rf.finding.severity,
                 "line": rf.finding.location.line, "suppressed": rf.suppressed}
                for rf in report.findings if rf.item in numbers]
    return {
        "schema": 1, "install_id": install_id, "device_label": label, "os": system,
        "scanner": {"version": report.scanner_version, "rules_version": report.rules_version},
        "mode": report.user or "scan", "complete": not report.errors,
        "clients": [{"client": entry["client"], "found": entry["found"], "roots": list(entry["roots"])[:ROOTS_MAX]}
                    for entry in report.clients or ()],
        "items": items, "findings": findings,
        "errors": _listed(report.errors), "notices": _listed(report.notices),
        "errors_total": len(report.errors), "notices_total": len(report.notices),
    }


def encoded(document: dict) -> bytes:
    """The bytes `api.ApiClient.post` sends for `document`."""
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def too_large(document: dict) -> str | None:
    """Why the body is over the caps of 4.8, or None."""
    if len(document["items"]) > ITEMS_MAX:
        return f"{len(document['items'])} items, more than the {ITEMS_MAX} an upload carries"
    if len(document["findings"]) > FINDINGS_MAX:
        return f"{len(document['findings'])} findings, more than the {FINDINGS_MAX} an upload carries"
    size = len(encoded(document))
    if size > BODY_MAX:
        return f"{size} bytes, more than the {BODY_MAX} an upload carries"
    return None


# --- the upload ------------------------------------------------------------------------------------------------------

def upload(document: dict, *, org: str, key, env: Mapping[str, str], log=_silent) -> Notice:
    """One request; the notice `workstation_uploaded` or the error `workstation_upload_failed` with the server's code in
    `detail`. Never raises."""
    from spellwarden_cli.connected import TRANSPORT  # the transport seams the tests replace, shared with connected mode

    base, overridden = api.api_url(env, log)
    host = urlsplit(base).hostname or ""
    proxy = api.proxy_for(env, host) if base.startswith("https://") else None
    client = api.ApiClient(base, key, release=__version__, proxy=proxy, loopback=overridden, **TRANSPORT)
    try:
        answer = client.post(f"/v1/orgs/{org}/workstations/inventory", document)
    except api.ApiError as error:
        given = error.body.get("error") if isinstance(error.body, dict) else None
        code = given if isinstance(given, str) and given else error.code
        return Notice("workstation_upload_failed", "", f"the workstation inventory was not uploaded: {error.message}",
                      detail=code)
    device = answer.get("device") if isinstance(answer.get("device"), dict) else {}
    when = device.get("uploaded_at") if isinstance(device.get("uploaded_at"), str) else "now"
    return Notice("workstation_uploaded", "", f"uploaded the inventory of {document['device_label']} ({when})")


# --- the outcome ------------------------------------------------------------------------------------------------------

def upload_outcome(report: Report, *, install_id: str, label: str, org: str, key, env: Mapping[str, str], home: str,
                   log=_silent) -> Notice:
    """Phase 3 batch 2c spec 11.2 (F1): the body from the report, then the caps, the state file and the request. The notice
    `workstation_uploaded`, or the error `workstation_upload_too_large` (nothing sent) or `workstation_upload_failed` (the
    server's code in `detail`, or `crash` with the exception's class when anything here raised). Never raises."""
    try:
        document = body(report, install_id=install_id, label=label, system=clients.platform_of(_platform()))
        reason = too_large(document)
        if reason is not None:
            return Notice("workstation_upload_too_large", "",
                          f"nothing was uploaded: the inventory has {reason}. Report this as a bug.")
        save_state(state_directory(_platform(), env, home), install_id, label)
        return upload(document, org=org, key=key, env=env, log=log)
    except Exception as exc:  # a crash in the upload still writes every report (11.2); the class only, never its text
        return Notice("workstation_upload_failed", "",
                      f"the workstation inventory was not uploaded: internal error: {type(exc).__name__}", detail="crash")


def with_outcome(report: Report, outcome: Notice, *, label: str) -> Report:
    """The report with the upload's outcome among its notices (success) or its errors (exit 2), in the order of spec 6.9.
    The notice of a success names the device and not the server's time of the upload, which `upload` puts in its message
    for the stderr line: a report holds no timestamp (README "Reports")."""
    if outcome.code == "workstation_uploaded":
        listed = Notice("workstation_uploaded", "", f"uploaded the inventory of {label}")
        return dataclasses.replace(report, notices=(*report.notices, listed)).sorted()
    return dataclasses.replace(report, errors=(*report.errors, outcome)).sorted()


def _print_outcome(outcome: Notice, *, quiet: bool) -> None:
    """The stderr line of 1.14.0, after the outputs are written."""
    if outcome.code == "workstation_uploaded":
        if not quiet:
            _stderr(f"notice workstation_uploaded: {outcome.message}")
    elif outcome.detail is None:
        _stderr(f"error {outcome.code}: {outcome.message}")
    else:
        _stderr(f"error {outcome.code} ({outcome.detail}): {outcome.message}")


# --- the command -----------------------------------------------------------------------------------------------------

def _error_report(as_of: str, fail_on: str, code: str, message: str) -> Report:
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of=as_of, fail_on=fail_on, items=(),
                  findings=(), probes=(), lock=LockState(), notices=(), errors=(Notice(code, "", message),), repo_prefix=None,
                  rules=RuleSet.baseline(), user="scan")


def credential_problem(credentials: Credentials) -> str | None:
    org, key = credentials.workstation_org, credentials.workstation_key
    if org is None:
        return "SPELLWARDEN_WORKSTATION_ORG is not set: set it to your organisation's slug (the part of the dashboard address " \
               "after dash.spellwarden.ai/) to upload the inventory."
    if ORG_RE.fullmatch(org) is None:
        return "SPELLWARDEN_WORKSTATION_ORG is not an organisation slug (2 to 64 lower-case letters, digits and hyphens)."
    if key is None:
        return "SPELLWARDEN_WORKSTATION_KEY is not set: create a key with access Workstation under Settings, API keys."
    if KEY_RE.fullmatch(key.value) is None:
        return "SPELLWARDEN_WORKSTATION_KEY is not a Spellwarden key (swk_ and 40 characters)."
    return None


def cmd_user(args: argparse.Namespace, outputs: list[tuple[str, str | None]], credentials: Credentials) -> int:
    from spellwarden_cli import userscan
    from spellwarden_cli.main import write_outputs

    as_of = args.as_of or datetime.now(UTC).date()
    fail_on = args.fail_on or "high"
    log = _stderr if args.verbose else _silent
    env = dict(os.environ)
    home = os.path.expanduser("~")
    install_id = label = None
    if args.upload:
        problem = credential_problem(credentials)
        state_dir = state_directory(_platform(), env, home)
        state = load_state(state_dir)
        label = clean(args.device_label) if args.device_label is not None else state.get("device_label", "")
        if problem is None and not label:
            problem_code, problem = "workstation_label_missing", ("The first upload of a device needs --device-label TEXT "
                                                                  "(1 to 64 characters): the name your organisation sees for "
                                                                  "this device.")
        else:
            problem_code = "workstation_no_credential"
        if problem is not None:
            report = _error_report(as_of.isoformat(), fail_on, problem_code, problem)
            write_outputs(report, outputs, stdout=sys.stdout)
            return 2
        install_id = state.get("install_id") or secrets.token_hex(16)
    settings = Settings(fail_on=fail_on, probe=bool(args.probe), probe_private=bool(args.probe_private), telemetry=False)
    try:
        report, not_found = userscan.scan(home, _platform(), env, settings=settings, as_of=as_of, inventory=args.inventory,
                                          log=log)
    except Exception as exc:  # a scanner crash still writes every output (spec 6.2)
        report, not_found = _error_report(as_of.isoformat(), fail_on, "crash", f"internal error: {type(exc).__name__}: {exc}"), ()
    for client in not_found:
        log(f"notice client_not_found: {clients.CLIENT_NAMES[client]}: no file of the client table was found")
    outcome = None
    if args.upload:  # before the outputs, so that every output carries the outcome (batch 2c spec 11.2, F1)
        outcome = upload_outcome(report, install_id=install_id, label=label, org=credentials.workstation_org,
                                 key=credentials.workstation_key, env=env, home=home, log=log)
        report = with_outcome(report, outcome, label=label)
    write_outputs(report, outputs, stdout=sys.stdout)
    if not args.quiet:
        for fmt, path in outputs:
            if path is not None:
                _stderr(f"wrote the {fmt} report to {path}")
    if outcome is not None:
        _print_outcome(outcome, quiet=args.quiet)
    return report.exit_code()  # no usage ping from --user, whatever `telemetry` says (11.3)


__all__ = ["BODY_MAX", "FINDINGS_MAX", "ITEMS_MAX", "LISTED_MAX", "STATE_FILE", "body", "clean", "cmd_user", "load_state",
           "save_state", "state_directory", "too_large", "upload", "upload_outcome", "with_outcome"]
