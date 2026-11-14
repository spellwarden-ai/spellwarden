"""The facts of each item that a CycloneDX document and the workstation upload may carry (phase 3 batch 2a spec 7.3, 11.4,
11.5), computed once from the discovery and already free of secrets: an endpoint or a source URL is reduced to
`scheme://host[:port]/path` (`cyclonedx.reduce_url`), a stdio launch is its `command_identity` or the reason it has none, and
no argument, environment value or header is ever copied. Keys are item paths; every value is a dict of the keys below that
apply, each left out when it does not:

- a configuration document: `sha256` (the lock's), `hooks` (how many hook commands it holds);
- an MCP server: `document` (its document's path), `transport` (`stdio`, `http` or `sse`), `endpoint`, `command_identity`,
  `command_reason`;
- a plugin of a marketplace: `marketplace_item` (the marketplace's item path), `source` (a reduced repository URL or a local
  directory), `commit` (the declared pin);
- a skill and an instruction file: `sha256` (the lock's).

`scan --user` adds the facts of the items only it finds (`userscan`)."""
from __future__ import annotations

from spellwarden_scan.agentconfig import has_declared_pin
from spellwarden_scan.cyclonedx import reduce_url
from spellwarden_scan.identity import canonical_repo_url, command_identity
from spellwarden_scan.model import McpServerEntry, PluginSource

from spellwarden_cli.discover import Discovery

TRANSPORTS = ("stdio", "http", "sse")


def server_facts(server: McpServerEntry, document: str) -> dict:
    facts: dict = {"document": document}
    if server.transport in TRANSPORTS:
        facts["transport"] = server.transport
    if server.url:
        endpoint = reduce_url(server.url)
        if endpoint is not None:
            facts["endpoint"] = endpoint
    if server.command:
        identity = command_identity(server.command, server.args, server.env)
        if identity.identity is not None:
            facts["command_identity"] = identity.identity
        else:
            facts["command_reason"] = identity.reason
    return facts


def source_facts(source: PluginSource) -> dict:
    """A plugin's or marketplace's declared source: a repository URL in its canonical form (already without user name, query
    and fragment), or a local directory; a source the parser could keep only raw is left out, since it may hold anything."""
    facts: dict = {}
    repository = canonical_repo_url(source)
    if repository is not None:
        facts["source"] = repository
    elif source.kind == "local" and source.local_path is not None:
        facts["source"] = source.local_path
    if has_declared_pin(source):
        facts["commit"] = (source.sha if source.sha is not None else source.ref).lower()  # type: ignore[union-attr]
    return facts


def item_details(found: Discovery) -> dict[str, dict]:
    from spellwarden_cli import lockfile  # here, not at the top: lockfile's command imports `run`, which imports this module

    hashes = {(entry["kind"], entry["path"]): entry["sha256"] for entry in lockfile.compute_lock(found)["items"]
              if "sha256" in entry}
    details: dict[str, dict] = {}
    for document in found.documents:
        details[document.path] = {"sha256": document.sha256, "hooks": len(document.hooks)}
        for server in document.servers:
            details[f"{document.path}#{server.name}"] = server_facts(server, document.path)
        for plugin in document.plugins:
            details[f"{document.path}#{plugin.name}"] = {"marketplace_item": document.path, **source_facts(plugin.source)}
    for skill in found.skills:
        details[skill.path] = {"sha256": hashes[("skill", skill.path)]}
    for instruction in found.instruction_files:
        details[instruction.path] = {"sha256": hashes[("instructions", instruction.path)]}
    return details


__all__ = ["TRANSPORTS", "item_details", "server_facts", "source_facts"]
