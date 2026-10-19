"""spellwarden_scan: the Spellwarden scan engine (spec 5). Pure code: it
takes bytes and recorded probe results and returns findings. Tasks 2 to 4
add `scan_skill_package`, `evaluate_probe`, `migration_checklist` and the
curation functions to this list."""
from __future__ import annotations

from spellwarden_scan.archive import ArchiveError, ArchiveLimits, unpack_zip
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.evidence import mask_credentials
from spellwarden_scan.frontmatter import FrontmatterError, parse_frontmatter
from spellwarden_scan.model import (
    SEVERITY_RANK, Area, AuthServerMetadata, ChecklistItem, CurationInputs, Finding, Location, McpScanResult, Metadata,
    ProbeResult, Severity, SkillScanResult, ToolInfo,
)
from spellwarden_scan.rules import Rule, RuleSet
from spellwarden_scan.scan import scan_skill_package
from spellwarden_scan.version import RULES_VERSION, __version__

__all__ = [
    "RULES_VERSION", "SEVERITY_RANK", "Area", "ArchiveError", "ArchiveLimits", "AuthServerMetadata", "ChecklistItem",
    "CurationInputs", "Finding", "FrontmatterError", "Location", "McpScanResult", "Metadata", "ProbeResult", "Rule",
    "RuleSet", "Severity", "SkillScanResult", "ToolInfo", "__version__", "canonical_sha256", "mask_credentials",
    "parse_frontmatter", "scan_skill_package", "unpack_zip",
]
