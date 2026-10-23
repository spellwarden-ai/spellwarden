"""The data classes of the public interface (spec 5.2). Every class is a
frozen dataclass with `to_dict()` (JSON types only) and `from_dict()`; the
hosted product stores exactly these dicts, a CLI prints them."""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low"]
Area = Literal["skill", "mcp", "config"]
SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _plain(value: Any) -> Any:
    """A JSON value for `value`: data classes become dicts, tuples lists, frozensets sorted lists."""
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_plain(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    return value


class _Model:
    """Mixin: `to_dict` and `from_dict` driven by the dataclass fields."""

    def to_dict(self) -> dict:
        return {f.name: _plain(getattr(self, f.name)) for f in fields(self)}  # type: ignore[arg-type]

    @classmethod
    def from_dict(cls, data: dict):
        known = {f.name: f for f in fields(cls)}  # type: ignore[arg-type]
        values: dict[str, Any] = {}
        for name in known:
            if name not in data:
                continue
            values[name] = _convert(cls, name, data[name])
        return cls(**values)


def _without_empty_incomplete(data: dict) -> dict:
    if not data.get("org_rules_incomplete"):
        data.pop("org_rules_incomplete", None)
    return data


def _convert(cls, name: str, value: Any) -> Any:
    """Rebuilds nested classes and tuples from JSON by field name."""
    nested = _NESTED.get((cls.__name__, name))
    if nested is not None and value is not None:
        kind, inner = nested
        if kind == "one":
            return inner.from_dict(value)
        # A string item stays a string (severity-only `CurationInputs`).
        return tuple(inner.from_dict(item) if isinstance(item, dict) else item for item in value)
    if name in _TUPLE_FIELDS and value is not None:
        return tuple(value)
    if name == "present" and value is not None:
        return frozenset(value)
    return value


@dataclass(frozen=True, slots=True)
class Location(_Model):
    path: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class Finding(_Model):
    rule_id: str
    severity: str
    title: str
    location: Location
    evidence: str
    fingerprint: str
    malicious_indicator: bool = False


@dataclass(frozen=True, slots=True)
class Metadata(_Model):
    name: str | None
    description: str | None
    version: str | None
    license: str | None
    publisher: str | None
    present: frozenset[str]
    frontmatter_ok: bool
    problems: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SkillScanResult(_Model):
    findings: tuple[Finding, ...]
    truncated: int
    sha256: str
    metadata: Metadata
    files_scanned: int
    rules_version: str
    scanner_version: str
    # O3 spec 5.1: `identity.package_sha256` of the package as a forge archive of its directory holds it, None when the
    # package is unhashable (a `node_modules`-like directory). Written by `to_dict` always.
    package_sha256: str | None = None
    # Phase C spec 5.2.2: the org rules the time budget stopped; written by `to_dict` only when non-empty, so every
    # 1.0.0 output stays byte-identical (plan decision P-ORG-3).
    org_rules_incomplete: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return _without_empty_incomplete(_Model.to_dict(self))


@dataclass(frozen=True, slots=True)
class ToolInfo(_Model):
    name: str
    description: str = ""
    annotations: dict = field(default_factory=dict)
    # Phase C spec 5.6: the tool's `inputSchema` as the prober recorded it (a JSON object of at most 16 KiB of
    # canonical JSON), else None. Additive: a 1.0.0 dict without it loads; no rule reads it in 1.1.0.
    input_schema: dict | None = None


@dataclass(frozen=True, slots=True)
class AuthServerMetadata(_Model):
    issuer: str | None = None
    metadata_url: str | None = None
    registration_endpoint: str | None = None
    client_id_metadata_document_supported: bool = False
    grant_types_supported: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProbeResult(_Model):
    """What a prober records (spec 5.2); every field has a default so a partial probe is valid."""

    endpoint: str | None = None
    repository: str | None = None
    reachable: bool = False
    error: str | None = None
    discover: dict | None = None
    initialize: dict | None = None
    negotiated_version: str | None = None
    session_id_seen: bool = False
    post_status: int | None = None
    post_content_type: str | None = None
    get_content_type: str | None = None
    sse_endpoint_event: bool = False
    unauthenticated_status: int | None = None
    www_authenticate: str | None = None
    resource_metadata: dict | None = None
    auth_server_metadata: AuthServerMetadata | None = None
    tools: tuple[ToolInfo, ...] = ()
    tools_source: str | None = None
    list_result_meta: dict | None = None
    capabilities: dict = field(default_factory=dict)
    probed_at: str | None = None


@dataclass(frozen=True, slots=True)
class ChecklistItem(_Model):
    order: int
    key: str
    text: str


@dataclass(frozen=True, slots=True)
class McpScanResult(_Model):
    findings: tuple[Finding, ...]
    truncated: int
    spec_version: str | None
    transport: str
    auth_mode: str
    deprecated_features: tuple[str, ...]
    migration_status: str
    checklist: tuple[ChecklistItem, ...]
    rules_version: str
    scanner_version: str
    # What the checklist generator reads (computed by `evaluate_probe`; defaults keep older dicts loadable).
    list_meta_missing: bool = False
    long_running_tools: tuple[str, ...] = ()
    tasks_supported: bool = False
    issuer_problem: bool = False
    org_rules_incomplete: tuple[str, ...] = ()  # as on `SkillScanResult`

    def to_dict(self) -> dict:
        return _without_empty_incomplete(_Model.to_dict(self))


@dataclass(frozen=True, slots=True)
class CurationInputs(_Model):
    """`open_findings` and `accepted_findings` hold `Finding`s or severity strings (spec 5.2);
    `curation.severities_of` normalises either."""
    open_findings: tuple[Finding | str, ...]
    accepted_findings: tuple[Finding | str, ...]
    metadata_present: int
    eval_component: float = 0.5
    sha256_matches: bool = True
    quarantined: bool = False


@dataclass(frozen=True, slots=True)
class McpServerEntry(_Model):
    """One server of an MCP client configuration (spec 5.2). `transport` is `stdio`, `http`, `sse` or `unknown`
    (neither `command` nor `url`: listed and locked, judged by no rule; plan decision P4). `args`, `env` and
    `headers` keep string values only; `raw_sha256` hashes the entry's canonical JSON."""
    name: str
    line: int
    transport: str
    url: str | None
    command: str | None
    args: tuple[str, ...]
    env: dict
    headers: dict
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class HookCommand(_Model):
    """One `{"type": "command", "command": ...}` hook; `index` is its position in the document's flattened hook
    list and serves ordering only (its identity is event, matcher and command; spec 5.3)."""
    event: str
    matcher: str | None
    index: int
    command: str
    line: int


@dataclass(frozen=True, slots=True)
class SettingFlag(_Model):
    """A Claude Code settings flag SW-CFG-008 reads (plan decision P5): `permissions.defaultMode`, one
    `permissions.allow` item, or `enableAllProjectMcpServers`."""
    key: str
    value: str | bool
    line: int


@dataclass(frozen=True, slots=True)
class PluginSource(_Model):
    """A marketplace plugin's source (spec 5.6). `kind` is `local`, `github`, `url` or `other`; `canonical` is its
    one deterministic string; `error` is `unsafe_path` for a local source that leaves the marketplace root."""
    kind: str
    local_path: str | None
    repo: str | None
    url: str | None
    ref: str | None
    sha: str | None
    canonical: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class MarketplacePlugin(_Model):
    name: str
    line: int
    source: PluginSource
    # O3 spec 5.1: sha256 of the canonical JSON of the entry as parsed; the binding of an SW-REG-003 acceptance (P48).
    # Not a lock input.
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class MarketplaceDecl(_Model):
    """One `extraKnownMarketplaces` entry of a Claude Code settings file (O3 spec 5.1): the marketplace's name, its
    source and the hash of the entry as parsed."""
    name: str
    source: PluginSource
    line: int
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class EnabledPlugin(_Model):
    """One `enabledPlugins` entry, `"<plugin>@<marketplace>": bool` (O3 spec 5.1)."""
    plugin: str
    marketplace: str
    enabled: bool
    line: int


@dataclass(frozen=True, slots=True)
class ConfigDocument(_Model):
    """One parsed agent-configuration file (spec 5.2). `kind` is `mcp`, `hooks`, `settings`, `marketplace` or
    `plugin`; `error` is None or one of `agentconfig.DOCUMENT_ERRORS`, and only `truncated` keeps entries.
    `sha256` hashes the canonical JSON of the whole document when it parsed, else its raw bytes."""
    path: str
    kind: str
    error: str | None
    servers: tuple[McpServerEntry, ...]
    hooks: tuple[HookCommand, ...]
    settings: tuple[SettingFlag, ...]
    plugins: tuple[MarketplacePlugin, ...]
    references: tuple[str, ...]
    truncated: bool
    sha256: str
    # O3 spec 5.1: settings documents only; written by `to_dict` only when non-empty, so every 1.0.0 output stays
    # byte-identical.
    marketplaces: tuple[MarketplaceDecl, ...] = ()
    enabled_plugins: tuple[EnabledPlugin, ...] = ()

    def to_dict(self) -> dict:
        data = _Model.to_dict(self)
        for name in ("marketplaces", "enabled_plugins"):
            if not data.get(name):
                data.pop(name, None)
        return data


@dataclass(frozen=True, slots=True)
class ConfigScanResult(_Model):
    """`scan_agent_config`'s result (spec 5.5); `documents` are the judged documents' paths, sorted (plan P6)."""
    findings: tuple[Finding, ...]
    truncated: int
    documents: tuple[str, ...]
    rules_version: str
    scanner_version: str


# (class, field) -> ("one" | "many", nested class)
_NESTED: dict[tuple[str, str], tuple[str, type]] = {
    ("Finding", "location"): ("one", Location),
    ("SkillScanResult", "findings"): ("many", Finding),
    ("SkillScanResult", "metadata"): ("one", Metadata),
    ("ProbeResult", "auth_server_metadata"): ("one", AuthServerMetadata),
    ("ProbeResult", "tools"): ("many", ToolInfo),
    ("McpScanResult", "findings"): ("many", Finding),
    ("McpScanResult", "checklist"): ("many", ChecklistItem),
    ("CurationInputs", "open_findings"): ("many", Finding),
    ("CurationInputs", "accepted_findings"): ("many", Finding),
    ("MarketplacePlugin", "source"): ("one", PluginSource),
    ("MarketplaceDecl", "source"): ("one", PluginSource),
    ("ConfigDocument", "marketplaces"): ("many", MarketplaceDecl),
    ("ConfigDocument", "enabled_plugins"): ("many", EnabledPlugin),
    ("ConfigDocument", "servers"): ("many", McpServerEntry),
    ("ConfigDocument", "hooks"): ("many", HookCommand),
    ("ConfigDocument", "settings"): ("many", SettingFlag),
    ("ConfigDocument", "plugins"): ("many", MarketplacePlugin),
    ("ConfigScanResult", "findings"): ("many", Finding),
}
_TUPLE_FIELDS = frozenset({"problems", "grant_types_supported", "deprecated_features", "long_running_tools", "args",
                           "references", "documents", "org_rules_incomplete"})
