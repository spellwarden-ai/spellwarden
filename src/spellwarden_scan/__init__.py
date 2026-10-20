"""spellwarden_scan: the Spellwarden scan engine (spec 5). Pure code: it
takes bytes and recorded probe results and returns findings: skill packages
(`scan_skill_package`), probed MCP servers (`evaluate_probe`) and agent
configuration documents (`parse_*`, `scan_agent_config`)."""
from __future__ import annotations

from spellwarden_scan.agentconfig import (
    parse_document, parse_hooks, parse_marketplace, parse_mcp_config, parse_plugin_manifest, parse_settings,
    reference_kind,
)
from spellwarden_scan.archive import ArchiveError, ArchiveLimits, unpack_zip
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.evidence import mask_credentials
from spellwarden_scan.frontmatter import FrontmatterError, parse_frontmatter
from spellwarden_scan.model import (
    SEVERITY_RANK, Area, AuthServerMetadata, ChecklistItem, ConfigDocument, ConfigScanResult, CurationInputs, Finding,
    HookCommand, Location, MarketplacePlugin, McpScanResult, McpServerEntry, Metadata, PluginSource, ProbeResult,
    SettingFlag, Severity, SkillScanResult, ToolInfo,
)
from spellwarden_scan.checklist import migration_checklist
from spellwarden_scan.curation import curation_score, is_curated, is_quarantined
from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import Rule, RuleSet
from spellwarden_scan.rules.skill import logical_commands
from spellwarden_scan.scan import scan_agent_config, scan_skill_package
from spellwarden_scan.version import RULES_VERSION, __version__

__all__ = [
    "RULES_VERSION", "SEVERITY_RANK", "Area", "ArchiveError", "ArchiveLimits", "AuthServerMetadata", "ChecklistItem",
    "ConfigDocument", "ConfigScanResult", "CurationInputs", "Finding", "FrontmatterError", "HookCommand", "Location",
    "MarketplacePlugin", "McpScanResult", "McpServerEntry", "Metadata", "PluginSource", "ProbeResult", "Rule", "RuleSet",
    "SettingFlag", "Severity", "SkillScanResult", "ToolInfo", "__version__", "canonical_sha256", "curation_score",
    "evaluate_probe", "is_curated", "is_quarantined", "logical_commands", "mask_credentials", "migration_checklist",
    "parse_document", "parse_frontmatter", "parse_hooks", "parse_marketplace", "parse_mcp_config",
    "parse_plugin_manifest", "parse_settings", "reference_kind", "scan_agent_config", "scan_skill_package", "unpack_zip",
]
