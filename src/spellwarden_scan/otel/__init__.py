"""Agent telemetry, read the way the hosted receiver reads it (runtime traces spec 4): OTLP over HTTP decoded by hand
(`otlp`, `wire`) and normalised to an allow-list of fields (`normalise`, `dialects`). Pure: it takes bytes and returns
values, so `spellwarden otel normalise` shows anyone exactly what Spellwarden would keep from their own telemetry."""
from __future__ import annotations

from spellwarden_scan.otel.dialects import CONTENT_KINDS, DIALECTS, RECORD_KINDS
from spellwarden_scan.otel.normalise import ContentItem, Normalised, Record, ResourceInfo, Stats, normalise
from spellwarden_scan.otel.otlp import (
    DEFAULT_LIMITS, OtlpError, OtlpLimits, OtlpRequest, count_records, decode, decompress, encode_status, encode_success,
)

OTEL_NAMES = (
    "CONTENT_KINDS", "ContentItem", "DEFAULT_LIMITS", "DIALECTS", "Normalised", "OtlpError", "OtlpLimits", "OtlpRequest",
    "RECORD_KINDS", "Record", "ResourceInfo", "Stats", "count_records", "decode", "decompress", "encode_status",
    "encode_success", "normalise",
)
__all__ = [
    "OTEL_NAMES", "CONTENT_KINDS", "ContentItem", "DEFAULT_LIMITS", "DIALECTS", "Normalised", "OtlpError", "OtlpLimits",
    "OtlpRequest", "RECORD_KINDS", "Record", "ResourceInfo", "Stats", "count_records", "decode", "decompress",
    "encode_status", "encode_success", "normalise",
]
