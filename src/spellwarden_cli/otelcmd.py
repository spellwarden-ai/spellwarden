"""`spellwarden otel normalise` (runtime traces spec 4.8, P13): what Spellwarden would keep from a file of your own
telemetry. It reads one file, inflates it when it is gzip, decodes and normalises it with the engine the hosted
receiver runs, and prints `{"stats", "resources", "records"}`. It sends nothing and needs no key."""
from __future__ import annotations

import argparse
import json
import sys

from spellwarden_scan.otel import OtlpError, OtlpLimits, decode, decompress, normalise
from spellwarden_scan.otel.otlp import parse_json

from spellwarden_cli.output import write_stdout

DEFAULT_MAX_BYTES = 64 << 20
DEFAULT_MAX_RECORDS = 20_000
_GZIP_MAGIC = b"\x1f\x8b"


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def add_parser(commands_: argparse._SubParsersAction) -> None:
    otel = commands_.add_parser("otel", help="Read OpenTelemetry files as Spellwarden's receiver reads them.")
    actions = otel.add_subparsers(dest="otel_command", required=True, metavar="ACTION")
    parser = actions.add_parser("normalise", help="Print what Spellwarden would keep from an OTLP traces or logs file.")
    parser.add_argument("path", metavar="PATH", help="an OTLP/HTTP request body: protobuf or JSON, gzip or not")
    parser.add_argument("--signal", choices=("traces", "logs"), help="required for protobuf; read from the JSON otherwise")
    parser.add_argument("--encoding", choices=("auto", "protobuf", "json"), default="auto",
                        help="auto (default) reads JSON when the first non-blank byte is {")
    parser.add_argument("--content", action="store_true", help="also build and print the content Spellwarden keeps "
                                                               "only when an owner turns content storage on")
    parser.add_argument("--max-records", type=_positive, default=DEFAULT_MAX_RECORDS, metavar="N",
                        help=f"refuse more spans or log records than N (default {DEFAULT_MAX_RECORDS})")
    parser.add_argument("--max-bytes", type=_positive, default=DEFAULT_MAX_BYTES, metavar="N",
                        help=f"refuse more than N bytes of decompressed data (default {DEFAULT_MAX_BYTES})")
    parser.set_defaults(handler=cmd_normalise)


def _error(message: str) -> int:
    print(f"spellwarden: otel normalise: {message}", file=sys.stderr)
    return 2


def _json_signal(body: bytes, limits: OtlpLimits) -> str | None:
    document = parse_json(body, limits)
    if isinstance(document, dict):
        if "resourceSpans" in document or "resource_spans" in document:
            return "traces"
        if "resourceLogs" in document or "resource_logs" in document:
            return "logs"
    return None


def _looks_like_json(body: bytes) -> bool:
    """`--encoding auto` (spec 4.8): JSON when the first non-blank byte is `{`. A body that starts with blank bytes must
    also be UTF-8 text: 0x0a (a newline) is the tag byte every protobuf request starts with, so a first `ResourceSpans`
    of 123 bytes (0x7b, `{`) would otherwise read as JSON."""
    if body[:1] == b"{":
        return True
    if body.lstrip(b" \t\r\n")[:1] != b"{":
        return False
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def cmd_normalise(args: argparse.Namespace) -> int:
    try:
        with open(args.path, "rb") as handle:
            raw = handle.read(args.max_bytes + 1)
    except OSError as exc:
        return _error(f"cannot read {args.path}: {exc.strerror or exc}")
    limits = OtlpLimits(max_records=args.max_records)
    encoding = None
    try:
        # More than --max-bytes as read is too large in either form: gzip never inflates to less than it holds here.
        if len(raw) > args.max_bytes:
            raise OtlpError("too_large", f"more than {args.max_bytes} bytes")
        body = decompress(raw, "gzip", max_bytes=args.max_bytes) if raw.startswith(_GZIP_MAGIC) else raw
        encoding = args.encoding
        if encoding == "auto":
            encoding = "json" if _looks_like_json(body) else "protobuf"
        signal = args.signal
        if signal is None:
            if encoding == "protobuf":
                return _error("--signal traces or --signal logs is required for protobuf: the two request messages "
                              "cannot be told apart on the wire")
            signal = _json_signal(body, limits)
            if signal is None:
                return _error("the JSON has neither resourceSpans nor resourceLogs; give --signal")
        result = normalise(decode(body, signal=signal, encoding=encoding, limits=limits), content=args.content)
    except OtlpError as exc:
        hint = " (check --signal: a traces body read as logs, or the other way round, is malformed)" if (
            exc.reason == "malformed" and encoding == "protobuf") else ""
        return _error(f"{exc}{hint}")
    write_stdout(json.dumps(result.to_dict(content=args.content), indent=2, ensure_ascii=False) + "\n", sys.stdout)
    return 0
