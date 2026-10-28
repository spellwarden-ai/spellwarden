"""The files the Node tests of the Zuplo export run against, written from the engine's own output (Zuplo export spec 4.7):

    uv run --locked python tests/zuplo_ci.py write DIR

writes under DIR `guard/` (the guard and the check script, as the export holds them), `packs/<fixture>/` (the policies file
of the export of every valid fixture pack and of the baseline) and `projects/<case>/` (small Zuplo projects for the check
script, each with an `expect.json`: the exit code and the exact lines it prints). A project is the template of
`fixtures/zuplo_projects/template/` with one change; `pack-<fixture>` is the template wired with that pack's own policy
entry, which proves the script's canonical options hash equals Python's for every fixture pack (claim K8). The Node tests
read DIR from the environment variable SPELLWARDEN_ZUPLO_DIR. Nothing here opens the network."""
from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

from spellwarden_scan.exports import build
from spellwarden_scan.exports.zuplo import CHECK_PATH, GUARD_PATH, POLICIES_PATH
from spellwarden_scan.packs import baseline_pack, validate_pack

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "fixtures" / "zuplo_projects" / "template"
PACKS = ROOT / "fixtures" / "packs" / "valid"
BUILT = "2026-12-01T10:00:00Z"
GUARD_FILE = "modules/spellwarden-mcp-guard.ts"
NAME = "spellwarden-mcp-guard"


def documents() -> dict:
    found = {"baseline": baseline_pack()}
    for path in sorted(PACKS.glob("*.json")):
        found[path.stem] = validate_pack(json.loads(path.read_text(encoding="utf-8")))
    return found


class Project:
    """One project in memory: the template's files, the export's guard and policy entry, and what a case changes."""

    def __init__(self, doc) -> None:
        files = build(doc, "zuplo", built_at=BUILT)
        self.guard = files[GUARD_PATH]
        self.entry = json.loads(files[POLICIES_PATH])["policies"][0]
        self.extra = json.loads((TEMPLATE / "config" / "policies.extra.json").read_text(encoding="utf-8"))["policies"]
        self.routes = json.loads((TEMPLATE / "config" / "routes.oas.json").read_text(encoding="utf-8"))
        self.settings = (TEMPLATE / "zuplo.jsonc").read_text(encoding="utf-8")
        self.entries = [self.entry]
        self.policies_text: str | None = None
        self.expect: dict = {"exit": 0, "lines": []}

    def route(self, path: str) -> dict:
        return self.routes["paths"][path]["post"]["x-zuplo-route"]

    def write(self, out: Path) -> None:
        shutil.rmtree(out, ignore_errors=True)
        (out / "config").mkdir(parents=True)
        (out / "zuplo.jsonc").write_text(self.settings, encoding="utf-8")
        (out / "config" / "routes.oas.json").write_text(json.dumps(self.routes, indent=2), encoding="utf-8")
        text = self.policies_text if self.policies_text is not None else json.dumps({"policies": self.extra + self.entries}, indent=2)
        (out / "config" / "policies.json").write_text(text, encoding="utf-8")
        if self.guard is not None:
            (out / "modules").mkdir()
            (out / GUARD_FILE).write_bytes(self.guard)
        (out / "expect.json").write_text(json.dumps(self.expect), encoding="utf-8")


def summary(project: Project, routes: int, failures: int) -> str:
    block = project.entry["handler"]["options"]["spellwarden"]
    return f'spellwarden-zuplo-check: {routes} MCP routes, {failures} failures, pack {json.dumps(block["pack"], ensure_ascii=False)} {block["version"]}'


def expect(project: Project, exit_code: int, lines: list[str], *, routes: int = 2, failures: int | None = None) -> None:
    count = len(lines) if failures is None else failures
    project.expect = {"exit": exit_code, "lines": lines + [summary(project, routes, count)]}


# --- the cases (each takes a project built from the baseline pack and changes it) ----------------------------------

def wired(p: Project) -> None:
    expect(p, 0, [])


def guard_missing_on_one_route(p: Project) -> None:
    p.route("/mcp/orders")["policies"]["outbound"] = []
    expect(p, 1, [f"route POST /mcp/orders: {NAME} is not in policies.outbound"])


def guard_not_last(p: Project) -> None:
    p.route("/mcp/search")["policies"]["outbound"] = [NAME, "another-outbound"]
    expect(p, 1, [f"route POST /mcp/search: {NAME} is not the last of policies.outbound"])


def two_entries(p: Project) -> None:
    p.entries = [p.entry, p.entry]
    expect(p, 1, [f"policy {NAME}: 2 entries in config/policies.json, expected one"])


def no_entry(p: Project) -> None:
    p.entries = []
    p.entry = {"handler": {"options": {"spellwarden": {"pack": None, "version": None}}}}
    p.expect = {"exit": 1, "lines": [f"policy {NAME}: missing from config/policies.json",
                                     "spellwarden-zuplo-check: 2 MCP routes, 1 failures, pack null unknown"]}


def edited_guard(p: Project) -> None:
    p.guard = p.guard + b"// edited\n"
    expect(p, 1, [f"{GUARD_FILE}: the file differs from the guard of the export (guard_sha256)"])


def missing_guard(p: Project) -> None:
    p.guard = None
    expect(p, 1, [f"{GUARD_FILE}: missing"])


def edited_options(p: Project) -> None:
    p.entry["handler"]["options"]["maxBodyBytes"] = 16777216
    expect(p, 1, [f"policy {NAME}: the options differ from those of the export (options_sha256)"])


def edited_checks(p: Project) -> None:
    p.entry["handler"]["options"]["checks"][0]["parts"] = ["a^"]
    expect(p, 1, [f"policy {NAME}: the options differ from those of the export (options_sha256)"])


def wrong_module(p: Project) -> None:
    p.entry["handler"]["module"] = "$import(./modules/other)"
    expect(p, 1, [f"policy {NAME}: handler.module is not $import(./modules/spellwarden-mcp-guard)"])


def wrong_policy_type(p: Project) -> None:
    p.entry["policyType"] = "custom-code-inbound"
    expect(p, 1, [f"policy {NAME}: policyType is not custom-code-outbound"])


def upstream_api_key(p: Project) -> None:
    p.extra.append({"name": "upstream-key", "policyType": "set-upstream-api-key-inbound", "handler": {"export": "X", "module": "$import(@zuplo/runtime)", "options": {}}})
    p.route("/mcp/search")["policies"]["inbound"] = ["mcp-oauth", "upstream-key"]
    expect(p, 1, ["route POST /mcp/search: SW-GW-003 needs a mcp-token-exchange-inbound policy with authMode user-oauth, shared-oauth, id-jag in policies.inbound"])


def no_token_exchange(p: Project) -> None:
    p.route("/mcp/orders")["policies"]["inbound"] = ["mcp-oauth"]
    expect(p, 1, ["route POST /mcp/orders: SW-GW-003 needs a mcp-token-exchange-inbound policy with authMode user-oauth, shared-oauth, id-jag in policies.inbound"])


def other_auth_mode(p: Project) -> None:
    for policy in p.extra:
        if policy["name"] == "token-exchange":
            policy["handler"]["options"]["authMode"] = "static-key"
    expect(p, 1, [f"route POST {path}: SW-GW-003 needs a mcp-token-exchange-inbound policy with authMode user-oauth, shared-oauth, id-jag in policies.inbound"
                  for path in ("/mcp/search", "/mcp/orders")])


def auth_mode(mode: str) -> Callable[[Project], None]:
    def change(p: Project) -> None:
        for policy in p.extra:
            if policy["name"] == "token-exchange":
                policy["handler"]["options"]["authMode"] = mode
        expect(p, 0, [])
    return change


def composite_inbound(p: Project) -> None:
    p.extra.append({"name": "both", "policyType": "composite-inbound", "handler": {"export": "X", "module": "$import(@zuplo/runtime)", "options": {"policies": ["token-exchange"]}}})
    p.route("/mcp/search")["policies"]["inbound"] = ["mcp-oauth", "both"]
    expect(p, 0, [])


def old_compatibility_date(p: Project) -> None:
    p.settings = p.settings.replace("2026-03-01", "2026-02-01")
    expect(p, 1, ['zuplo.jsonc: compatibilityDate must be 2026-03-01 or later (found "2026-02-01")'])


def later_compatibility_date(p: Project) -> None:
    p.settings = p.settings.replace("2026-03-01", "2027-01-15")
    expect(p, 0, [])


def no_compatibility_date(p: Project) -> None:
    p.settings = '{"version": 1}'
    expect(p, 1, ["zuplo.jsonc: compatibilityDate must be 2026-03-01 or later (found null)"])


def mcp_server_handler(p: Project) -> None:
    p.routes["paths"]["/api/tools"] = {"post": {"x-zuplo-route": {"handler": {"export": "mcpServerHandler", "module": "$import(@zuplo/runtime)", "options": {}}, "policies": {"inbound": [], "outbound": []}}}}
    p.expect = {"exit": 0, "lines": ["note: 1 mcpServerHandler routes are not required to carry the guard (the README recommends it there too)", summary(p, 2, 0)]}


def unparseable_policies(p: Project) -> None:
    p.policies_text = '{"policies": [ not json'
    p.expect = {"exit": 2, "prefix": "spellwarden-zuplo-check: config/policies.json: not valid JSON"}


def route_with_two_methods(p: Project) -> None:
    p.routes["paths"]["/mcp/search"]["get"] = {"x-zuplo-route": {"handler": {"export": "McpProxyHandler", "module": "$import(@zuplo/runtime/mcp-gateway)", "options": {}}, "policies": {"inbound": ["mcp-oauth", "token-exchange"], "outbound": []}}}
    expect(p, 1, [f"route GET /mcp/search: {NAME} is not in policies.outbound"], routes=3)


def null_policies(p: Project) -> None:
    p.policies_text = "null"
    p.expect = {"exit": 2, "prefix": "spellwarden-zuplo-check: config/policies.json: expected a JSON object"}


def null_settings(p: Project) -> None:
    p.settings = "null"
    p.expect = {"exit": 2, "prefix": "spellwarden-zuplo-check: zuplo.jsonc: expected a JSON object"}


def null_routes(p: Project) -> None:
    p.routes = None
    p.expect = {"exit": 2, "prefix": "spellwarden-zuplo-check: config/routes.oas.json: expected a JSON object"}


def null_spellwarden_block(p: Project) -> None:
    entry = json.loads(json.dumps(p.entry))
    entry["handler"]["options"]["spellwarden"] = None
    p.entries = [entry]
    p.expect = {"exit": 1, "lines": [f"policy {NAME}: options.spellwarden.format is not 1",
                                     f"{GUARD_FILE}: the file differs from the guard of the export (guard_sha256)",
                                     "spellwarden-zuplo-check: 2 MCP routes, 2 failures, pack null unknown"]}


def malformed_route(p: Project) -> None:
    p.route("/mcp/search")["policies"] = {"inbound": {}, "outbound": {}}
    p.routes["paths"]["/other"] = {"post": {"x-zuplo-route": None}}
    expect(p, 1, [f"route POST /mcp/search: {NAME} is not in policies.outbound",
                  "route POST /mcp/search: SW-GW-003 needs a mcp-token-exchange-inbound policy with authMode user-oauth, shared-oauth, id-jag in policies.inbound"])


CASES: dict[str, Callable[[Project], None]] = {
    "wired": wired, "guard-missing-on-one-route": guard_missing_on_one_route, "guard-not-last": guard_not_last,
    "two-entries": two_entries, "no-entry": no_entry, "edited-guard": edited_guard, "missing-guard": missing_guard,
    "edited-options": edited_options, "edited-checks": edited_checks, "wrong-module": wrong_module,
    "wrong-policy-type": wrong_policy_type, "upstream-api-key": upstream_api_key, "no-token-exchange": no_token_exchange,
    "other-auth-mode": other_auth_mode, "auth-mode-shared-oauth": auth_mode("shared-oauth"),
    "auth-mode-id-jag": auth_mode("id-jag"), "composite-inbound": composite_inbound,
    "old-compatibility-date": old_compatibility_date, "later-compatibility-date": later_compatibility_date,
    "no-compatibility-date": no_compatibility_date, "mcp-server-handler": mcp_server_handler,
    "unparseable-policies": unparseable_policies, "route-with-two-methods": route_with_two_methods,
    "null-policies": null_policies, "null-settings": null_settings, "null-routes": null_routes,
    "null-spellwarden-block": null_spellwarden_block, "malformed-route": malformed_route,
}


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    docs = documents()
    files = build(docs["baseline"], "zuplo", built_at=BUILT)
    (out / "guard").mkdir(exist_ok=True)
    (out / "guard" / "spellwarden-mcp-guard.ts").write_bytes(files[GUARD_PATH])
    (out / "guard" / "spellwarden-zuplo-check.mjs").write_bytes(files[CHECK_PATH])
    for name, doc in docs.items():
        (out / "packs" / name).mkdir(parents=True, exist_ok=True)
        (out / "packs" / name / "spellwarden-policies.json").write_bytes(build(doc, "zuplo", built_at=BUILT)[POLICIES_PATH])
        project = Project(doc)
        wired(project)
        project.write(out / "projects" / f"pack-{name}")
    for name, change in CASES.items():
        project = Project(docs["baseline"])
        change(project)
        project.write(out / "projects" / name)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "write":
        raise SystemExit("usage: python tests/zuplo_ci.py write DIR")
    write(Path(sys.argv[2]))
    print("wrote", sys.argv[2])
