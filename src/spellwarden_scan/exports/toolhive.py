"""The ToolHive export (1.15.0): a Cedar authorization file for `thv run --authz-config`, checked against Stacklok ToolHive
v0.65.0 (`docs/authz.md` and `pkg/authz/authorizers/cedar/entity.go` at that tag). The file is
`{"version": "1.0", "type": "cedarv1", "cedar": {"policies": [...], "entities_json": "[]"}}`. ToolHive's Cedar authorizer sees a
`tools/call` request as the action `call_tool` on a `Tool` entity whose `name` attribute is the tool's name; a `forbid` that
matches denies the request whatever the `permit`s say, and `tools/list` is filtered by the same policies.

The file permits every request, then forbids, while SW-GW-006 is on in the pack, every tool whose name `mcp_verb` reads as
destructive (`hooks.MCP_VERBS`: the name starts with a verb or holds it as a `_`- or `-`-separated word). Cedar's `like` is
case-sensitive and has no lower-case function, so each verb is matched in its lower case, Capitalised and UPPER spellings; a
mixed-case spelling is a stated limit. Pure: the files are returned as `{path: bytes}`; nothing from the pack reaches the
authorization file, and the README gets the pack's text only through `readme_text`."""
from __future__ import annotations

import hashlib
import json

from spellwarden_scan.exports import README_NAME, coverage, readme_text
from spellwarden_scan.exports.hooks import MCP_VERBS
from spellwarden_scan.packs import PackDocument

TARGET = "toolhive"
GATEWAY = "ToolHive"
GATEWAY_VERSION = "v0.65.0"
AUTHZ_PATH = "toolhive/spellwarden-authz.json"
SUMS_NAME = "SHA256SUMS"
# ToolHive refuses an inline policy above 8 KiB on an MCPRemoteProxy (docs/authz.md); every policy here stays below it.
MAX_POLICY_BYTES = 8192
ALLOW_REST = '@id("spellwarden-allow-rest") permit(principal, action, resource);'
# `resource.name like` forms that match exactly what `mcp_verb` matches for one spelling of a verb.
NAME_FORMS = ("{verb}*", "*_{verb}", "*-{verb}", "*_{verb}_*", "*_{verb}-*", "*-{verb}_*", "*-{verb}-*")
GUIDE = "https://spellwarden.ai/docs/export-toolhive?utm_source=export&utm_medium=toolhive&utm_campaign=policy-export"


def spellings(verb: str) -> tuple[str, str, str]:
    return verb, verb.capitalize(), verb.upper()


def verb_policy(verb: str) -> str:
    """The `forbid` of one verb of SW-GW-006, on `call_tool` requests only."""
    tests = " || ".join(f'resource.name like "{form.format(verb=spelling)}"'
                        for spelling in spellings(verb) for form in NAME_FORMS)
    return f'@id("SW-GW-006:{verb}") forbid(principal, action == Action::"call_tool", resource) when {{ {tests} }};'


def policies(doc: PackDocument) -> list[str]:
    """The permit, then one `forbid` per verb while SW-GW-006 is on in the pack."""
    found = [ALLOW_REST]
    if "SW-GW-006" in doc.enabled():
        found += [verb_policy(verb) for verb in MCP_VERBS]
    return found


def authz_json(doc: PackDocument) -> bytes:
    document = {"version": "1.0", "type": "cedarv1", "cedar": {"policies": policies(doc), "entities_json": "[]"}}
    return (json.dumps(document, indent=2) + "\n").encode("ascii")


INSTALL = [
    "Check the files against SHA256SUMS.",
    f"Start the server with the authorization file: thv run --authz-config <absolute path of {AUTHZ_PATH}> <server>.",
    "If the server already has an authorization file, do not replace it with this one: copy the forbid policies of this file "
    "(their ids start with SW-GW-006) into the cedar.policies list of yours. A forbid policy wins over every permit, so they "
    "hold next to the permits you already have.",
    "ToolHive filters tools/list by the call_tool policies, so clients no longer see the denied tools, and a call to one is "
    "answered with HTTP 403.",
]
LIMITS_COMMON = [
    f"Checked against {GATEWAY} {GATEWAY_VERSION}: Cedar policies of type cedarv1, the tool's name as resource.name. A later "
    f"{GATEWAY} release may change this; a later Spellwarden engine release checks the export against it again.",
    "Only tools/call is restricted (the call_tool action). Prompts, resources and every other request pass.",
    "vMCP composite tools are authorised by their own name, not by the names of the tools they call.",
]
LIMITS_ON = [
    "SW-GW-006 asks a person to approve destructive tools. The gateway cannot ask, so this export denies them.",
    "Cedar's like operator is case-sensitive: the lower case, Capitalised and UPPER spellings of each verb are denied, a "
    "mixed-case spelling such as dElete_row is not.",
]
LIMITS_OFF = ["Nothing is enforced: SW-GW-006 is off in this pack, so the file holds only the permit for every request."]


def _sums(files: dict[str, bytes]) -> bytes:
    return "".join(f"{hashlib.sha256(files[path]).hexdigest()}  {path}\n" for path in sorted(files)).encode("ascii")


def toolhive_files(doc: PackDocument, *, built_at: str) -> dict[str, bytes]:
    """The three files of the export of `doc` to ToolHive, by archive path."""
    enforced, cannot, not_included = coverage(doc, TARGET)
    limits = LIMITS_COMMON + (LIMITS_ON if "SW-GW-006" in doc.enabled() else LIMITS_OFF)
    readme = readme_text(doc, target=TARGET, mode=None, built_at=built_at, enforced=enforced, cannot_enforce=cannot,
                         not_included=not_included, install=INSTALL, limits=limits, guide=GUIDE)
    files = {AUTHZ_PATH: authz_json(doc), README_NAME: readme}
    files[SUMS_NAME] = _sums(files)
    return files


__all__ = ["ALLOW_REST", "AUTHZ_PATH", "GATEWAY", "GATEWAY_VERSION", "GUIDE", "MAX_POLICY_BYTES", "NAME_FORMS", "SUMS_NAME",
           "TARGET", "authz_json", "policies", "spellings", "toolhive_files", "verb_policy"]
