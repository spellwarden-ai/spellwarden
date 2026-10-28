"""Agent telemetry, read the way the hosted receiver reads it (runtime traces spec 4): OTLP over HTTP decoded by hand
(`otlp`, `wire`). Pure: it takes bytes and returns values. Task 2 adds the normaliser and the full public names."""
from __future__ import annotations

from spellwarden_scan.otel.otlp import (
    DEFAULT_LIMITS, OtlpError, OtlpLimits, OtlpRequest, count_records, decode, decompress, encode_status, encode_success,
)

__all__ = [
    "DEFAULT_LIMITS", "OtlpError", "OtlpLimits", "OtlpRequest", "count_records", "decode", "decompress", "encode_status",
    "encode_success",
]
