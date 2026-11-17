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
# Phase 3 batch 1 spec 11.2
NAMES_1_13_0 = ("PromptArgument", "PromptInfo", "ResourceInfo", "ResourceTemplateInfo")
# O3 spec 5.4: the names that live in a submodule of the engine, which the package imports so that they are reachable.
IDENTITY_NAMES = (
    "package_files", "PackageFiles", "package_sha256", "nested_skill_roots", "is_skill_file", "fold_skill_name",
    "normalise_url", "server_identity", "request_link_url", "command_identity", "CommandIdentity",
    "parse_command_identity", "format_command_identity", "ParsedCommandIdentity", "LAUNCH_OVERRIDE_ENV", "QUIET_FLAGS",
    "LAUNCHER_FAMILY", "resolver_files", "canonical_repo_url", "plugin_identity", "marketplace_identity", "SKIP_DIRS",
)
# Phase 3 batch 2a spec 7.2: the public module `spellwarden_scan.cyclonedx` (1.14.0); `__all__` of the package is unchanged.
CYCLONEDX_NAMES = ("SPEC_VERSION", "SCHEMA_URL", "PROPERTY_PREFIX", "SEVERITY", "ANALYSIS", "document", "component", "service",
                   "vulnerability", "dependency", "prop", "reduce_url")
GATE_NAMES = ("gate_finding", "resolver_binding", "unhashable_binding", "GATE_RULE_IDS", "GATE_REASONS", "GATE_KINDS")


def test_the_1_0_0_names_are_all_still_exported():
    for name in NAMES_1_0_0:
        assert name in spellwarden_scan.__all__ and hasattr(spellwarden_scan, name), name


def test_1_1_0_adds_exactly_the_names_of_spec_5_8():
    for name in NAMES_1_1_0:
        assert name in spellwarden_scan.__all__ and hasattr(spellwarden_scan, name), name
    assert sorted(spellwarden_scan.__all__) == sorted(NAMES_1_0_0 + NAMES_1_1_0 + NAMES_1_2_0 + NAMES_1_3_0 + NAMES_1_13_0)
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
    assert spellwarden_scan.EXPORT_TARGETS == ("claude-code-hooks", "kong", "zuplo", "toolhive", "docker-mcp-gateway")
    assert spellwarden_scan.PLANNED_TARGETS == ("agentcore-policy", "cloudflare-egress")
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


# Runtime traces spec 4.7: the names of the subpackage `spellwarden_scan.otel` (1.7.0). The package does not import it,
# and its `__all__` does not change (checked above).
OTEL_NAMES = (
    "CONTENT_KINDS", "ContentItem", "DEFAULT_LIMITS", "DIALECTS", "Normalised", "OtlpError", "OtlpLimits", "OtlpRequest",
    "RECORD_KINDS", "Record", "ResourceInfo", "Stats", "count_records", "decode", "decompress", "encode_status",
    "encode_success", "normalise",
)


def test_1_7_0_adds_the_otel_subpackage_and_pins_its_limits():
    from spellwarden_scan import otel

    assert otel.OTEL_NAMES == OTEL_NAMES
    assert sorted(otel.__all__) == sorted(("OTEL_NAMES", *OTEL_NAMES))
    for name in OTEL_NAMES:
        assert hasattr(otel, name), name
        if name in NAMES_1_13_0:  # 1.13.0 added an MCP `ResourceInfo` to the package; the OTLP one stays in `otel` and is another class
            assert getattr(spellwarden_scan, name) is not getattr(otel, name), name
            continue
        assert name not in spellwarden_scan.__all__, name
    limits = otel.DEFAULT_LIMITS
    assert (limits.max_records, limits.max_depth, limits.max_attributes, limits.max_events, limits.max_value_bytes) == (
        20_000, 16, 512, 256, 1_048_576)
    try:
        limits.max_records = 1  # type: ignore[misc]
    except AttributeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("DEFAULT_LIMITS must be frozen")
    assert otel.DIALECTS == ("claude_code", "claude_platform", "openinference", "genai_legacy", "genai", "mcp")
    assert otel.RECORD_KINDS == ("agent", "model", "tool", "mcp", "decision", "connection", "skill", "content", "other")
    assert otel.CONTENT_KINDS == ("system", "input", "output", "tool_arguments", "tool_result", "prompt", "response")


def test_1_14_0_adds_the_cyclonedx_module_and_no_package_name():
    from spellwarden_scan import cyclonedx

    assert spellwarden_scan.cyclonedx is cyclonedx
    for name in CYCLONEDX_NAMES:
        assert hasattr(cyclonedx, name), name
    assert (cyclonedx.SPEC_VERSION, cyclonedx.PROPERTY_PREFIX) == ("1.7", "spellwarden:")
    assert "cyclonedx" not in spellwarden_scan.__all__


# Phase 3 batch 2b spec 10.2: the public module `spellwarden_scan.toolhash` (1.15.0), which the hosted product imports; `__all__`
# of the package is unchanged.
TOOLHASH_NAMES = ("KINDS", "FORMAT", "ITEM_PREFIX", "ToolListing", "KindListing", "ListedItem", "Baseline", "ToolDiff", "ItemChange",
                  "listing_of", "diff", "change_details", "adopt", "carry", "kinds_digest", "normalise_text")


def test_1_15_0_adds_the_toolhash_module_and_no_package_name():
    from spellwarden_scan import toolhash

    assert spellwarden_scan.toolhash is toolhash
    for name in TOOLHASH_NAMES:
        assert hasattr(toolhash, name) and name in toolhash.__all__, name
    assert "toolhash" not in spellwarden_scan.__all__


# Phase 4 batch B spec 11.4: the public module `spellwarden_scan.lint` (1.17.0), which the hosted product imports, and the two
# models `SkillMeta` and `LintNote` of `spellwarden_scan.model`; `__all__` of the package is unchanged.
LINT_NAMES = ("LINT_IDS", "TITLES", "DESCRIPTION_MIN", "OVERLAP_MIN", "MAX_NOTES_PER_SKILL", "STOP_WORDS", "USE_WHEN", "check",
              "counted", "single", "words", "similarity")


def test_1_17_0_adds_the_lint_module_and_no_package_name():
    from spellwarden_scan import lint, model

    assert spellwarden_scan.lint is lint
    for name in LINT_NAMES:
        assert hasattr(lint, name) and name in lint.__all__, name
    assert hasattr(model, "SkillMeta") and hasattr(model, "LintNote")
    for name in ("lint", "LintNote", "SkillMeta"):
        assert name not in spellwarden_scan.__all__, name
