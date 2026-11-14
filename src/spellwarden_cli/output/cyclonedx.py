"""`--format cyclonedx` (phase 3 batch 2a spec 7.3 scanner column, 11.5): a CycloneDX 1.7 JSON document of one scan, written
with `spellwarden_scan.cyclonedx`. Skills, plugins, marketplaces, instruction files and configuration documents are
components, MCP servers and A2A agent cards are services, findings are vulnerabilities naming the component or service of
their item. A pure function of the report: the timestamp is the scan's date (`as_of`, midnight UTC), so the same files, settings
and date give the same bytes, and the facts of each item come from `Report.details`, already free of secrets."""
from __future__ import annotations

import json

from spellwarden_scan import cyclonedx as cdx

from spellwarden_cli.report import Report, ReportFinding

TAGS = "utm_source=scanner&utm_medium=cyclonedx&utm_campaign=ai-bom"  # spec 4.6
HOME_URL = f"https://spellwarden.ai/?{TAGS}"
RULE_URL = "https://spellwarden.ai/docs/rules/{}?" + TAGS
DOCUMENT_KINDS = ("mcp-config", "settings", "hooks", "plugin-manifest")
AUTHENTICATED = {"none": False, "static-key": True, "oauth-dcr": True, "oauth-cimd": True, "xaa": True}
_PREFIX = {"skill": "skill", "plugin": "plugin", "marketplace": "marketplace", "mcp-server": "mcp-server",
           "instructions": "instructions", **{kind: "document" for kind in DOCUMENT_KINDS}}


def _agent_ref(item: str) -> str:
    if item.startswith("a2a-agent:"):
        return "agent:a2a-agent:" + (cdx.reduce_url(item[len("a2a-agent:"):]) or "")
    return "agent:" + item


def _common(item) -> list[dict]:
    """The properties every component and service of an item carries: its kind, and in a `--user` report its clients and the
    project directory of a project-scoped server."""
    found = [cdx.prop("kind", item.kind)]
    if item.plugin is not None:
        found.append(cdx.prop("plugin", item.plugin))
    found += [cdx.prop("client", client) for client in item.clients]
    if item.scope is not None:
        found.append(cdx.prop("scope", item.scope))
    return found


def _component(report: Report, item, ref: str) -> dict:
    facts = report.details.get(item.path, {})
    hashes = [facts["sha256"]] if "sha256" in facts else []
    properties = _common(item)
    external: list[tuple[str, str]] = []
    if item.kind == "skill":
        return cdx.component(ref=ref, type="library", name=item.name, hashes=hashes,
                             properties=[*properties, cdx.prop("path", item.path)])
    if item.kind == "instructions":
        return cdx.component(ref=ref, type="file", name=item.path, hashes=hashes,
                             properties=[*properties, cdx.prop("format", item.format)])
    if item.kind in ("plugin", "marketplace"):
        source = facts.get("source")
        if isinstance(source, str) and source.startswith("https://"):
            external.append(("vcs" if item.kind == "plugin" else "distribution", source))
        elif isinstance(source, str):
            properties.append(cdx.prop("source", source))
        if "commit" in facts:
            properties.append(cdx.prop("commit", facts["commit"]))
        return cdx.component(ref=ref, type="library" if item.kind == "plugin" else "data", name=item.name,
                             hashes=hashes if item.kind == "marketplace" else [], external=external, properties=properties)
    return cdx.component(ref=ref, type="file", name=item.path, hashes=hashes, properties=properties)  # a configuration document


def _server(report: Report, item, ref: str, probes: dict) -> dict:
    facts = report.details.get(item.path, {})
    properties = _common(item)
    if "transport" in facts:
        properties.append(cdx.prop("transport", facts["transport"]))
    if "command_identity" in facts:
        properties.append(cdx.prop("command", facts["command_identity"]))
    elif "command_reason" in facts:
        properties.append(cdx.prop("command_reason", facts["command_reason"]))
    probe = probes.get(item.path)
    authenticated = None
    if probe is not None and probe.result is not None:
        authenticated = AUTHENTICATED.get(probe.result.auth_mode)
        properties += [cdx.prop("auth_mode", probe.result.auth_mode),
                       cdx.prop("migration_status", probe.result.migration_status)]
        properties += [cdx.prop("tool", name) for name in probe.tools]
    endpoints = [facts["endpoint"]] if "endpoint" in facts else []
    return cdx.service(ref=ref, name=item.name, endpoints=endpoints, authenticated=authenticated, properties=properties)


def _agent(agent) -> dict:
    remote = agent.item.startswith("a2a-agent:")
    url = cdx.reduce_url(agent.item[len("a2a-agent:"):]) if remote else None
    name = (url or "") if remote else agent.item[len("a2a-card:"):]
    result = agent.result
    properties = [cdx.prop("kind", "a2a-agent"), cdx.prop("source", agent.source), cdx.prop("status", agent.status)]
    if result is not None:
        properties.append(cdx.prop("card_format", result.card_format))
        properties += [cdx.prop("protocol_version", version) for version in result.protocol_versions]
        properties += [cdx.prop("migration_status", result.migration_status),
                       cdx.prop("signature_status", result.signature_status)]
    return cdx.service(ref=_agent_ref(agent.item), name=name, endpoints=[url] if url else [], properties=properties)


def _vulnerability(report: Report, finding: ReportFinding, ref: str, target: str | None) -> dict:
    f = finding.finding
    rule = report.rules.get(f.rule_id)
    public = rule is not None and not f.rule_id.startswith("SW-ORG-")
    status = "accepted" if finding.suppressed else "open"
    state, response = cdx.ANALYSIS[status]
    location = f"{f.location.path}:{f.location.line}" if f.location.line else f.location.path
    properties = [cdx.prop("location", location), cdx.prop("origin", "rule"), cdx.prop("status", status)]
    baseline = finding.baseline or {}
    if finding.suppressed and baseline.get("expires"):
        properties.append(cdx.prop("expires", baseline["expires"]))
    return cdx.vulnerability(ref=ref, title=f.title, severity=f.severity, affects=[target] if target else [], state=state,
                             response=response, rule_id=f.rule_id, url=RULE_URL.format(f.rule_id) if public else None,
                             detail=baseline.get("reason") if finding.suppressed else None, properties=properties)


def build(report: Report) -> dict:
    refs: dict[str, str] = {}
    components: list[dict] = []
    services: list[dict] = []
    probes = {probe.item: probe for probe in report.probes}
    for item in report.items:
        ref = f"{_PREFIX[item.kind]}:{item.path}"
        refs[item.path] = ref
        if item.kind == "mcp-server":
            services.append(_server(report, item, ref, probes))
        else:
            components.append(_component(report, item, ref))
    for agent in report.agents:
        refs[agent.item] = _agent_ref(agent.item)
        services.append(_agent(agent))
    dependencies: dict[str, list[str]] = {}
    for item in report.items:
        facts = report.details.get(item.path, {})
        owner = facts.get("marketplace_item") if item.kind == "plugin" else facts.get("document")
        if item.kind in ("plugin", "mcp-server") and owner in refs:
            dependencies.setdefault(refs[owner], []).append(refs[item.path])
        if item.kind == "skill" and item.plugin is not None:
            for plugin in report.items:
                if plugin.kind == "plugin" and plugin.name == item.plugin and set(plugin.clients) >= set(item.clients):
                    dependencies.setdefault(refs[plugin.path], []).append(refs[item.path])
    vulnerabilities: list[dict] = []
    seen: dict[str, int] = {}
    for finding in report.findings:
        base = f"finding:{finding.finding.fingerprint}"
        seen[base] = seen.get(base, 0) + 1
        ref = base if seen[base] == 1 else f"{base}:{seen[base]}"
        vulnerabilities.append(_vulnerability(report, finding, ref, refs.get(finding.item)))
    if report.user is not None:
        subject = cdx.component(ref=None, type="device", name="workstation")
        mode = report.user
    else:
        subject = cdx.component(ref=None, type="application", name=report.root_name or ".")
        mode = "repository"
    properties = [cdx.prop("mode", mode), cdx.prop("rules_version", report.rules_version),
                  cdx.prop("as_of", report.as_of), cdx.prop("exit_code", report.exit_code()),
                  cdx.prop("complete", not report.errors), cdx.prop("errors", len(report.errors))]
    for entry in report.clients or ():
        properties.append(cdx.prop(f"client:{entry['client']}", "found" if entry["found"] else "not_found"))
    return cdx.document(subject=subject, tool_version=report.scanner_version, tool_url=HOME_URL,
                        timestamp=f"{report.as_of}T00:00:00Z", components=components, services=services,
                        vulnerabilities=vulnerabilities,
                        dependencies=[cdx.dependency(ref, sorted(set(depends))) for ref, depends in sorted(dependencies.items())],
                        properties=properties)


def render(report: Report) -> str:
    """`ensure_ascii` writes every non-ASCII character as `\\uXXXX`, as the JSON report does, so a bidirectional or invisible
    character from a scanned file is inert wherever the document is shown."""
    return json.dumps(build(report), indent=2, ensure_ascii=True) + "\n"
