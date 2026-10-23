"""spellwarden_scan: the Spellwarden scan engine (spec 5). Pure code: it
takes bytes and recorded probe results and returns findings: skill packages
(`scan_skill_package`), probed MCP servers (`evaluate_probe`) and agent
configuration documents (`parse_*`, `scan_agent_config`). Since 1.2.0 `identity` and `gate` hold the identities
and findings of the connected command's registry gate. Since 1.1.0 it also
compiles organisation rules (`compile_org_rule`), validates policy pack
documents (`validate_pack`) and builds their exports (`build_export`)."""
from __future__ import annotations

from spellwarden_scan.agentconfig import (
    parse_document, parse_hooks, parse_marketplace, parse_mcp_config, parse_plugin_manifest, parse_settings,
    reference_kind,
)
from spellwarden_scan import gate, identity  # noqa: F401 (O3 spec 5.4: `spellwarden_scan.gate`, `spellwarden_scan.identity`)
from spellwarden_scan.archive import ArchiveError, ArchiveLimits, unpack_zip
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.evidence import mask_credentials
from spellwarden_scan.exports import EXPORT_MODES, EXPORT_TARGETS, PLANNED_TARGETS
from spellwarden_scan.exports import build as build_export
from spellwarden_scan.frontmatter import FrontmatterError, parse_frontmatter
from spellwarden_scan.model import (
    SEVERITY_RANK, Area, AuthServerMetadata, ChecklistItem, ConfigDocument, ConfigScanResult, CurationInputs,
    EnabledPlugin, Finding, HookCommand, Location, MarketplaceDecl, MarketplacePlugin, McpScanResult, McpServerEntry, Metadata,
    PluginSource, ProbeResult, SettingFlag, Severity, SkillScanResult, ToolInfo,
)
from spellwarden_scan.checklist import migration_checklist
from spellwarden_scan.curation import curation_score, is_curated, is_quarantined
from spellwarden_scan.orgrules import PATTERN_LIMITS, OrgRuleBudget, OrgRuleError, compile_org_rule, validate_org_rule
from spellwarden_scan.packs import (
    ENFORCEMENT_RULES, EnforcementRule, PackDocument, PackError, baseline_pack, canonical_json, pack_sha256,
    validate_pack,
)
from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import Rule, RuleSet
from spellwarden_scan.rules.skill import logical_commands
from spellwarden_scan.scan import scan_agent_config, scan_skill_package
from spellwarden_scan.text import comment_safe, valid_block, valid_line
from spellwarden_scan.version import RULES_VERSION, __version__

__all__ = [
    "RULES_VERSION", "SEVERITY_RANK", "Area", "ArchiveError", "ArchiveLimits", "AuthServerMetadata", "ChecklistItem",
    "ConfigDocument", "ConfigScanResult", "CurationInputs", "Finding", "FrontmatterError", "HookCommand", "Location",
    "MarketplacePlugin", "McpScanResult", "McpServerEntry", "Metadata", "PluginSource", "ProbeResult", "Rule", "RuleSet",
    "SettingFlag", "Severity", "SkillScanResult", "ToolInfo", "__version__", "canonical_sha256", "curation_score",
    "evaluate_probe", "is_curated", "is_quarantined", "logical_commands", "mask_credentials", "migration_checklist",
    "parse_document", "parse_frontmatter", "parse_hooks", "parse_marketplace", "parse_mcp_config",
    "parse_plugin_manifest", "parse_settings", "reference_kind", "scan_agent_config", "scan_skill_package", "unpack_zip",
    # Phase C spec 5.8: added in 1.1.0
    "OrgRuleError", "OrgRuleBudget", "validate_org_rule", "compile_org_rule", "PATTERN_LIMITS",
    "EnforcementRule", "ENFORCEMENT_RULES", "PackDocument", "PackError", "baseline_pack", "validate_pack",
    "canonical_json", "pack_sha256", "EXPORT_TARGETS", "PLANNED_TARGETS", "EXPORT_MODES", "build_export",
    "valid_line", "valid_block", "comment_safe",
    # O3 spec 5.4: added in 1.2.0 (the rest of 5.4 lives in `identity`, `gate` and `packs`)
    "MarketplaceDecl", "EnabledPlugin",
]
