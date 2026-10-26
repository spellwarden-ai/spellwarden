"""Spec 5.8 and invariant 2: 1.1.0 adds exactly these names to the package and removes or renames none of 1.0.0's."""
from __future__ import annotations

import spellwarden_scan
from spellwarden_scan import exports

NAMES_1_0_0 = (
    "RULES_VERSION", "SEVERITY_RANK", "Area", "ArchiveError", "ArchiveLimits", "AuthServerMetadata", "ChecklistItem",
    "ConfigDocument", "ConfigScanResult", "CurationInputs", "Finding", "FrontmatterError", "HookCommand", "Location",
    "MarketplacePlugin", "McpScanResult", "McpServerEntry", "Metadata", "PluginSource", "ProbeResult", "Rule", "RuleSet",
    "SettingFlag", "Severity", "SkillScanResult", "ToolInfo", "__version__", "canonical_sha256", "curation_score",
    "evaluate_probe", "is_curated", "is_quarantined", "logical_commands", "mask_credentials", "migration_checklist",
    "parse_document", "parse_frontmatter", "parse_hooks", "parse_marketplace", "parse_mcp_config",
    "parse_plugin_manifest", "parse_settings", "reference_kind", "scan_agent_config", "scan_skill_package", "unpack_zip",
)
NAMES_1_1_0 = (
    "OrgRuleError", "OrgRuleBudget", "validate_org_rule", "compile_org_rule", "PATTERN_LIMITS",
    "EnforcementRule", "ENFORCEMENT_RULES", "PackDocument", "PackError", "baseline_pack", "validate_pack", "canonical_json",
    "pack_sha256", "EXPORT_TARGETS", "PLANNED_TARGETS", "EXPORT_MODES", "build_export", "valid_line", "valid_block",
    "comment_safe",
)
NAMES_1_2_0 = ("MarketplaceDecl", "EnabledPlugin")
# O4 spec 5.9
NAMES_1_3_0 = (
    "parse_agent_card", "evaluate_agent_card", "AgentCardDocument", "CardOrigin", "SignatureOutcome", "SignatureInput",
    "A2aScanResult", "signature_inputs", "a2a_checklist", "jcs_canonicalize", "JcsError", "A2A_CARD_FORMATS",
    "A2A_MIGRATION_STATUSES", "A2A_SIGNATURE_STATUSES",
)
# O3 spec 5.4: the names that live in a submodule of the engine, which the package imports so that they are reachable.
IDENTITY_NAMES = (
    "package_files", "PackageFiles", "package_sha256", "nested_skill_roots", "is_skill_file", "fold_skill_name",
    "normalise_url", "server_identity", "request_link_url", "command_identity", "CommandIdentity",
    "parse_command_identity", "format_command_identity", "ParsedCommandIdentity", "LAUNCH_OVERRIDE_ENV", "QUIET_FLAGS",
    "LAUNCHER_FAMILY", "resolver_files", "canonical_repo_url", "plugin_identity", "marketplace_identity", "SKIP_DIRS",
)
GATE_NAMES = ("gate_finding", "resolver_binding", "unhashable_binding", "GATE_RULE_IDS", "GATE_REASONS", "GATE_KINDS")


def test_the_1_0_0_names_are_all_still_exported():
    for name in NAMES_1_0_0:
        assert name in spellwarden_scan.__all__ and hasattr(spellwarden_scan, name), name


def test_1_1_0_adds_exactly_the_names_of_spec_5_8():
    for name in NAMES_1_1_0:
        assert name in spellwarden_scan.__all__ and hasattr(spellwarden_scan, name), name
    assert sorted(spellwarden_scan.__all__) == sorted(NAMES_1_0_0 + NAMES_1_1_0 + NAMES_1_2_0 + NAMES_1_3_0)
    assert len(spellwarden_scan.__all__) == len(set(spellwarden_scan.__all__))


def test_1_2_0_adds_the_names_of_o3_spec_5_4():
    from spellwarden_scan import packs
    from spellwarden_scan.model import ConfigDocument, SkillScanResult

    for name in NAMES_1_2_0:
        assert name in spellwarden_scan.__all__ and hasattr(spellwarden_scan, name), name
    for name in IDENTITY_NAMES:
        assert hasattr(spellwarden_scan.identity, name), name
    for name in GATE_NAMES:
        assert hasattr(spellwarden_scan.gate, name), name
    assert hasattr(packs, "org_rule_min_version") and hasattr(packs, "PREDICATE_SINCE")
    assert "package_sha256" in SkillScanResult.__dataclass_fields__
    assert {"marketplaces", "enabled_plugins"} <= set(ConfigDocument.__dataclass_fields__)
    assert "registry" in {rule.area for rule in spellwarden_scan.RuleSet.baseline()}


def test_build_export_is_exports_build_and_the_target_lists_are_the_spec_s():
    assert spellwarden_scan.build_export is exports.build
    assert spellwarden_scan.EXPORT_TARGETS == ("claude-code-hooks", "kong")
    assert spellwarden_scan.PLANNED_TARGETS == ("zuplo", "agentcore-policy", "cloudflare-egress")
    assert spellwarden_scan.EXPORT_MODES == ("project", "managed")


def test_pattern_limits_are_the_numbers_of_spec_5_2_2_and_read_only():
    assert dict(spellwarden_scan.PATTERN_LIMITS) == {
        "max_length": 300, "max_parts": 4, "max_groups": 4, "max_alternatives": 16, "max_class_members": 64,
        "max_repeat": 100, "max_repeat_range": 400, "window": 4096, "overlap": 512,
    }
    try:
        spellwarden_scan.PATTERN_LIMITS["window"] = 1  # type: ignore[index]
    except TypeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("PATTERN_LIMITS must be a read-only mapping")
