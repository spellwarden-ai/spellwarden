"""Phase 3 batch 2a spec 7.1, 7.2 and T-8 (the module's half): `spellwarden_scan.cyclonedx` writes documents that validate
against the vendored CycloneDX 1.7.2 schema, for every case of the hosted column of 7.3, with a reproducible serial number."""
from __future__ import annotations

import hashlib

import pytest
from conftest import CYCLONEDX_FILES, CYCLONEDX_SCHEMAS, cyclonedx_problems, cyclonedx_schema_bytes

from spellwarden_scan import cyclonedx as cdx

RECORDED = {
    "bom-1.7.schema.json": "73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce",
    "spdx.schema.json": "4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "cryptography-defs.schema.json": "027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44",
}
RULE_PAGE = "https://spellwarden.ai/docs/rules/SW-SKL-007?utm_source=ai-bom&utm_medium=export&utm_campaign=ai-bom"
HOME = "https://spellwarden.ai/?utm_source=ai-bom&utm_medium=export&utm_campaign=ai-bom"


@pytest.mark.parametrize("name", CYCLONEDX_FILES)
def test_the_vendored_schema_files_are_the_recorded_bytes_of_the_1_7_2_tag(name):
    assert hashlib.sha256(cyclonedx_schema_bytes(name)).hexdigest() == RECORDED[name]
    assert RECORDED[name] in (CYCLONEDX_SCHEMAS / "SOURCE.md").read_text(encoding="utf-8")


def hosted_document(*, timestamp: str = "2026-11-14T10:00:00Z") -> dict:
    """Every hosted case of 7.3 at once: a git skill, a plugin with its marketplace and skill, a stdio and a remote server, a
    repository with an agent, a runtime-only server and skill, a rule finding, an accepted finding, an org rule's finding, a
    manual finding, and the service the tool component names."""
    marketplace = cdx.component(ref="marketplace:3f2a", type="data", name="tools",
                                external=[("distribution", "https://github.com/example/tools")],
                                properties=[cdx.prop("kind", "marketplace")])
    plugin = cdx.component(ref="plugin:0123456789abcdef", type="library", name="lint", properties=[cdx.prop("kind", "plugin")])
    skill = cdx.component(ref="skill:s1", type="library", name="deploy", version="1.0.0", hashes=["a" * 64],
                          external=[("vcs", "https://github.com/example/skills")],
                          properties=[cdx.prop("kind", "skill"), cdx.prop("source", "git"), cdx.prop("curated", True)])
    repository = cdx.component(ref="repository:r1", type="application", name="github.com/example/app",
                               properties=[cdx.prop("kind", "repository"), cdx.prop("items:skill", 3), cdx.prop("agent_cards", 51),
                                           cdx.prop("agent_cards_omitted", 1)])
    runtime_skill = cdx.component(ref="runtime-skill:k1", type="library", name="unknown-skill",
                                  properties=[cdx.prop("kind", "skill"), cdx.prop("runtime_only", True)])
    stdio = cdx.service(ref="mcp-server:m1", name="files", properties=[
        cdx.prop("kind", "mcp-server"), cdx.prop("transport", "stdio"), cdx.prop("command", "cmd:npx pkg@1.0.0")])
    remote = cdx.service(ref="mcp-server:m2", name="remote", endpoints=["https://mcp.example.com/mcp"], authenticated=True,
                         properties=[cdx.prop("kind", "mcp-server"), cdx.prop("tool", "search"), cdx.prop("tool", "fetch")])
    agent = cdx.service(ref="agent:r1:0", name=".well-known/agent-card.json", properties=[
        cdx.prop("kind", "a2a-agent"), cdx.prop("source", "repository"), cdx.prop("protocol_version", "1.0")])
    runtime_server = cdx.service(ref="runtime-server:k2", name="mystery", properties=[
        cdx.prop("kind", "mcp-server"), cdx.prop("runtime_only", True), cdx.prop("first_seen", "2026-10-01")])
    state, response = cdx.ANALYSIS["open"]
    accepted_state, accepted_response = cdx.ANALYSIS["accepted"]
    vulnerabilities = [
        cdx.vulnerability(ref="finding:f1", title="Remote script piped to a shell", severity="high", affects=["skill:s1"],
                          state=state, response=response, rule_id="SW-SKL-007", url=RULE_PAGE, created="2026-11-01T08:00:00Z",
                          properties=[cdx.prop("status", "open"), cdx.prop("origin", "rule")]),
        cdx.vulnerability(ref="finding:f2", title="Unpinned package", severity="medium", affects=["mcp-server:m1"],
                          state=accepted_state, response=accepted_response, rule_id="SW-CFG-003", url=RULE_PAGE,
                          detail="Reviewed by the platform team.", properties=[cdx.prop("status", "accepted")]),
        cdx.vulnerability(ref="finding:f3", title="Staging host in a skill", severity="low", affects=["repository:r1"],
                          state=state, rule_id="SW-ORG-010"),
        cdx.vulnerability(ref="finding:f4", title="Reported by a reviewer", severity="critical", affects=["agent:r1:0"],
                          state=state, properties=[cdx.prop("origin", "manual")]),
    ]
    dependencies = [cdx.dependency("marketplace:3f2a", ["plugin:0123456789abcdef"]),
                    cdx.dependency("plugin:0123456789abcdef", ["skill:s1"]), cdx.dependency("repository:r1", ["agent:r1:0"])]
    return cdx.document(
        subject=cdx.component(ref="org:acme", type="application", name="Acme"), tool_version="1.14.0", tool_url=HOME,
        timestamp=timestamp, components=[marketplace, plugin, skill, repository, runtime_skill],
        services=[stdio, remote, agent, runtime_server], vulnerabilities=vulnerabilities, dependencies=dependencies,
        properties=[cdx.prop("count:skills", 1), cdx.prop("runtime_partial", False), cdx.prop("vulnerabilities_omitted", 0)],
        tool_properties=[cdx.prop("service", "dash.spellwarden.ai")])


def test_every_hosted_case_of_the_mapping_validates_and_every_reference_resolves():
    document = hosted_document()
    assert cyclonedx_problems(document) == []
    assert list(document)[:5] == ["$schema", "bomFormat", "specVersion", "serialNumber", "version"]
    assert (document["specVersion"], document["$schema"]) == ("1.7", "http://cyclonedx.org/schema/bom-1.7.schema.json")
    tool = document["metadata"]["tools"]["components"][0]  # 7.3: the hosted export names its service on the tool component
    assert (tool["name"], tool["version"]) == ("Spellwarden", "1.14.0")
    assert tool["properties"] == [{"name": "spellwarden:service", "value": "dash.spellwarden.ai"}]


def test_a_manual_finding_has_no_id_and_no_link_and_an_org_rule_finding_has_its_id_and_no_link():
    by_ref = {entry["bom-ref"]: entry for entry in hosted_document()["vulnerabilities"]}
    assert "id" not in by_ref["finding:f4"] and by_ref["finding:f4"]["source"] == {"name": "Spellwarden"}
    assert by_ref["finding:f3"]["id"] == "SW-ORG-010" and by_ref["finding:f3"]["source"] == {"name": "Spellwarden"}
    assert by_ref["finding:f1"]["source"] == {"name": "Spellwarden", "url": RULE_PAGE}
    assert by_ref["finding:f2"]["analysis"] == {"state": "exploitable", "response": ["will_not_fix"],
                                                "detail": "Reviewed by the platform team."}
    assert by_ref["finding:f1"]["analysis"] == {"state": "in_triage"}
    assert by_ref["finding:f1"]["ratings"] == [{"source": {"name": "Spellwarden", "url": RULE_PAGE}, "severity": "high",
                                                "method": "other"}]


def test_the_serial_number_depends_on_the_content_and_not_on_the_timestamp():
    first, second = hosted_document(), hosted_document(timestamp="2027-01-01T00:00:00Z")
    assert first["serialNumber"] == second["serialNumber"]
    assert first["serialNumber"].startswith("urn:uuid:") and first["serialNumber"][23] == "5"  # UUID version 5
    changed = cdx.document(subject=cdx.component(ref="org:other", type="application", name="Other"), tool_version="1.14.0",
                           tool_url=HOME, timestamp="2026-11-14T10:00:00Z", components=[], services=[], vulnerabilities=[],
                           dependencies=[], properties=[])
    assert changed["serialNumber"] != first["serialNumber"]
    assert cyclonedx_problems(changed) == []
    assert "properties" not in changed["metadata"]["tools"]["components"][0]  # no `tool_properties`, as the scanner writes it


def test_properties_are_prefixed_strings():
    assert cdx.prop("runtime_only", True) == {"name": "spellwarden:runtime_only", "value": "true"}
    assert cdx.prop("spellwarden:calls", 12) == {"name": "spellwarden:calls", "value": "12"}


@pytest.mark.parametrize("given, reduced", [
    ("https://user:secret@Mcp.Example.com:8443/mcp?token=abc#frag", "https://mcp.example.com:8443/mcp"),
    ("http://[::1]:9000/sse", "http://[::1]:9000/sse"),
    ("https://github.com/example/tools.git", "https://github.com/example/tools.git"),
    ("example/tools", None), ("/srv/data", None), ("https://a.example/ b", None), (None, None),
])
def test_reduce_url_keeps_scheme_host_port_and_path_only(given, reduced):
    assert cdx.reduce_url(given) == reduced


def test_a_workstation_subject_carries_no_identifier():
    subject = cdx.component(ref=None, type="device", name="workstation")
    assert subject == {"type": "device", "name": "workstation"}
