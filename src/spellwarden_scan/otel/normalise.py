"""From a decoded OTLP request to the records Spellwarden keeps (runtime traces spec 4.4 to 4.6, invariants 1 and 2):
each span and log record becomes at most one `Record` of an allow-listed set of fields, or is ignored. Content is a
closed set of named attributes and events, returned apart from the record's fields and built only when asked for.
Identifiers are never passed through `mask_credentials` (spec 4.5, review item 1); the backend masks content."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field, fields

from spellwarden_scan.agentconfig import url_parts
from spellwarden_scan.identity import server_identity
from spellwarden_scan.otel.dialects import (
    CLAUDE_CODE_CONTENT_ATTRIBUTES, CLAUDE_CODE_CONTENT_EVENTS, CLAUDE_CODE_EVENT_KINDS, CLAUDE_CODE_PLACEHOLDERS,
    CLAUDE_CODE_SERVICES, CLAUDE_CODE_SPAN_KINDS, CLAUDE_PLATFORM_SERVICE, CONTENT_ITEM_BYTES, CONTENT_RECORD_BYTES,
    COUNTED_KINDS, GENAI_CONTENT_ATTRIBUTES, GENAI_CONTENT_EVENTS, GENAI_CONTENT_PREFIXES, GENAI_OPERATION_KINDS,
    LEGACY_PROVIDERS, OPENINFERENCE_CONTENT_SPANS, OPENINFERENCE_KINDS, OPERATION_DETAILS_PARTS, OTHER_FLOOR,
    SPAN_SAFE_PLACEHOLDERS, UNKNOWN_SERVICE,
)
from spellwarden_scan.otel.otlp import DEFAULT_LIMITS, CutBytes, CutText, LogRecord, OtlpError, OtlpRequest, Span, parse_json


@dataclass(frozen=True, slots=True)
class ContentItem:
    kind: str
    text: str
    cut: bool = False

    def to_dict(self) -> dict:
        return {"kind": self.kind, "text": self.text, "cut": self.cut}


@dataclass(frozen=True, slots=True)
class ResourceInfo:
    service_name: str = UNKNOWN_SERVICE
    service_version: str | None = None
    environment: str | None = None
    sdk_language: str | None = None

    def to_dict(self) -> dict:
        return {name.name: getattr(self, name.name) for name in fields(self) if getattr(self, name.name) is not None}


@dataclass(frozen=True, slots=True)
class Record:
    """Spec 4.5. Every field but the first five is optional (None when absent)."""
    signal: str
    dialect: str
    kind: str
    counted: bool
    resource: int
    scope: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    name: str | None = None
    start_ns: int | None = None
    end_ns: int | None = None
    duration_ms: int | None = None
    side: str | None = None
    status: str | None = None
    error_type: str | None = None
    rpc_status_code: int | None = None
    session_source: str | None = None
    session_value: str | None = None
    operation: str | None = None
    agent_name: str | None = None
    provider: str | None = None
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None
    tool_type: str | None = None
    names_redacted: bool = False
    mcp_method: str | None = None
    mcp_server_name: str | None = None
    server_address: str | None = None
    server_port: int | None = None
    url: str | None = None
    server_identity: str | None = None
    skill_name: str | None = None
    skill_source_uri: str | None = None
    decision_kind: str | None = None
    decision_outcome: str | None = None
    decision_source: str | None = None
    decision_category: str | None = None
    decision_reason_code: str | None = None
    decision_rule_source: str | None = None
    content: tuple[ContentItem, ...] = ()

    def to_dict(self, *, content: bool = False) -> dict:
        """The record as JSON-ready data: absent fields, `names_redacted` when false and `content` unless asked for
        are left out."""
        out: dict = {}
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name == "content":
                if content and value:
                    out["content"] = [entry.to_dict() for entry in value]
            elif item.name == "names_redacted":
                if value:
                    out["names_redacted"] = True
            elif value is not None:
                out[item.name] = value
        return out


@dataclass(frozen=True, slots=True)
class Stats:
    spans: int = 0
    log_records: int = 0
    kept: int = 0
    ignored: int = 0
    counted: int = 0
    by_dialect: dict = field(default_factory=dict)
    attributes_skipped: int = 0
    events_skipped: int = 0
    content_items: int = 0
    content_cut: int = 0

    def to_dict(self) -> dict:
        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True, slots=True)
class Normalised:
    stats: Stats
    resources: tuple[ResourceInfo, ...]
    records: tuple[Record, ...]

    def to_dict(self, *, content: bool = False) -> dict:
        return {"stats": self.stats.to_dict(), "resources": [resource.to_dict() for resource in self.resources],
                "records": [record.to_dict(content=content) for record in self.records]}


# --- values ---------------------------------------------------------------------------------------------------------

_CONTROL = re.compile("[\x00-\x1f\x80-\x9f]")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_DECIMAL = re.compile(r"-?[0-9]{1,19}")
_TOKEN_SEGMENT = re.compile(r"(?=[^/]*[A-Za-z])(?=[^/]*[0-9])[^/]{20,}")
_SCHEME_TEXT = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*:)(///[^?#]*|(?![/\\])[^?#/@]*(?:/[^?#]*)?)")
_DEFAULT_PORTS = {"https": 443, "http": 80}
_MAX_TOKENS = 10**9


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _plain_text(value: object) -> str | None:
    """C0 and C1 controls removed, NFC; None for a non-string or an empty result."""
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFC", _CONTROL.sub("", value))
    return text or None


def ident(value: object, limit: int) -> str | None:
    """An identifier or name (spec 4.5, first class): controls removed, NFC, cut to `limit` characters ending in `…`."""
    text = _plain_text(value)
    return None if text is None else _cut(text, limit)


def session_text(value: object) -> str | None:
    """A session id as kept: `ident(value, 128)`, except that an email-shaped id becomes `sha256:` and the first 32
    hex digits of the SHA-256 of its cleaned text (the backend replaces that with a keyed hash, P23)."""
    text = _plain_text(value)
    if text is None:
        return None
    if _EMAIL.fullmatch(text):
        return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]
    return _cut(text, 128)


def _integer(value: object, lenient: bool, low: int, high: int) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif lenient and isinstance(value, str) and _DECIMAL.fullmatch(value.strip()):
        number = int(value.strip())
    else:
        return None
    return number if low <= number <= high else None


def _boolean(value: object, lenient: bool) -> bool | None:
    if isinstance(value, bool):
        return value
    if lenient and value in ("true", "false"):
        return value == "true"
    return None


def kept_url(value: object) -> str | None:
    """`url.full` as kept (spec 4.5, URLs): one `url_parts` parse; scheme and host lower-cased, the host bracketed when
    it holds `:`, the port unless it is the scheme's default, the path without trailing slashes and with every
    segment of 20 or more characters that mixes letters and digits replaced by `***`; no userinfo, query or fragment.
    None when the splitter refuses the value or the port is over 65535."""
    if not isinstance(value, str) or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    parts = url_parts(value.strip())
    if parts is None:
        return None
    port = ""
    if parts.port is not None:
        number = int(parts.port)
        if number > 65535:
            return None
        if number != _DEFAULT_PORTS.get(parts.scheme):
            port = f":{number}"
    host = f"[{parts.host}]" if ":" in parts.host else parts.host
    path = "/".join("***" if _TOKEN_SEGMENT.fullmatch(segment) else segment for segment in parts.path.rstrip("/").split("/"))
    return _cut(f"{parts.scheme}://{host}{port}{path}", 2048)


def kept_skill_uri(value: object) -> str | None:
    """`gen_ai.skill.source.uri`: as `kept_url`, else, only for a value with no authority (`file:///opt/skills/x`,
    `scheme:` and a path), the scheme and path text without query or fragment, token-like segments replaced by `***`,
    cut to 2048. A value with an authority or userinfo that `kept_url` refuses leaves the field absent."""
    url = kept_url(value)
    if url is not None:
        return url
    text = _plain_text(value)
    if text is None:
        return None
    match = _SCHEME_TEXT.fullmatch(text.strip().split("?", 1)[0].split("#", 1)[0])
    if match is None:
        return None
    path = "/".join("***" if _TOKEN_SEGMENT.fullmatch(segment) else segment for segment in match.group(2).split("/"))
    return _cut(match.group(1) + path, 2048)


def _first(attributes: dict, names: tuple[str, ...], limit: int) -> str | None:
    for name in names:
        text = ident(attributes.get(name), limit)
        if text is not None:
            return text
    return None


def _first_int(attributes: dict, names: tuple[str, ...], lenient: bool) -> int | None:
    for name in names:
        number = _integer(attributes.get(name), lenient, 0, _MAX_TOKENS)
        if number is not None:
            return number
    return None


# --- content --------------------------------------------------------------------------------------------------------

def _plain(value: object, marks: list) -> object:
    if isinstance(value, (CutText, CutBytes)):
        marks.append(True)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, tuple):
        return [_plain(item, marks) for item in value]
    if isinstance(value, dict):
        return {str(key): _plain(item, marks) for key, item in value.items()}
    return value


def _render(value: object) -> tuple[str, bool]:
    """A content value as text: strings as they are, anything structured as compact JSON."""
    if isinstance(value, str):
        return value, isinstance(value, CutText)
    marks: list = []
    text = json.dumps(_plain(value, marks), separators=(",", ":"), ensure_ascii=False)
    return text, bool(marks)


class _Content:
    """One record's content items, cut to 32 KiB each and 128 KiB in all (spec 4.6)."""
    __slots__ = ("budget", "items", "cut")

    def __init__(self) -> None:
        self.budget = CONTENT_RECORD_BYTES
        self.items: list[ContentItem] = []
        self.cut = 0

    def add(self, kind: str, value: object) -> None:
        if value is None:
            return
        text, cut = _render(value)
        if not text:
            return
        if self.budget <= 0:
            self.cut += 1
            return
        raw = text.encode("utf-8", "replace")
        limit = min(CONTENT_ITEM_BYTES, self.budget)
        if len(raw) > limit:
            text, raw, cut = raw[:limit].decode("utf-8", "ignore"), raw[:limit], True
        self.budget -= len(raw)
        self.cut += cut
        self.items.append(ContentItem(kind, text, cut))

    def add_prefixed(self, attributes: dict, prefix: str, kind: str) -> None:
        family = {key[len(prefix):]: value for key, value in attributes.items() if key.startswith(prefix)}
        if family:
            self.add(kind, dict(sorted(family.items())))


def _span_content(span: Span, dialect: str, oi_kind: str | None) -> _Content:
    content = _Content()
    attributes = span.attributes
    if dialect == "claude_code":
        for name, kind in CLAUDE_CODE_CONTENT_ATTRIBUTES:
            content.add(kind, attributes.get(name))
        for event in span.events:
            kind = CLAUDE_CODE_CONTENT_EVENTS.get(event.name)
            if kind is not None and event.attributes:
                content.add(kind, event.attributes)
        return content
    for name, kind in GENAI_CONTENT_ATTRIBUTES:
        content.add(kind, attributes.get(name))
    for prefix, kind in GENAI_CONTENT_PREFIXES:
        content.add_prefixed(attributes, prefix, kind)
    if dialect == "openinference":
        if oi_kind == "TOOL":
            content.add("tool_arguments", attributes.get("input.value"))
            content.add("tool_result", attributes.get("output.value"))
        elif oi_kind in OPENINFERENCE_CONTENT_SPANS:
            content.add("input", attributes.get("input.value"))
            content.add("output", attributes.get("output.value"))
    for event in span.events:
        if event.name not in GENAI_CONTENT_EVENTS:
            continue
        kind = GENAI_CONTENT_EVENTS[event.name]
        if kind is None:
            for name, part in OPERATION_DETAILS_PARTS:
                content.add(part, event.attributes.get(name))
        elif event.attributes:
            content.add(kind, event.attributes)
    return content


def _log_content(log: LogRecord, dialect: str, event: str) -> _Content:
    content = _Content()
    if dialect == "claude_code":
        for name, kind in CLAUDE_CODE_CONTENT_ATTRIBUTES:
            content.add(kind, log.attributes.get(name))
        return content
    kind = GENAI_CONTENT_EVENTS[event]
    if kind is None:
        for name, part in OPERATION_DETAILS_PARTS:
            content.add(part, log.attributes.get(name))
    else:
        content.add(kind, log.body if log.body is not None else (log.attributes or None))
    return content


# --- dialects -------------------------------------------------------------------------------------------------------

def _span_dialect(span: Span, service: object) -> str | None:
    attributes = span.attributes
    if span.name.startswith("claude_code."):
        return "claude_code"
    if span.name.startswith("anthropic.") and service == CLAUDE_PLATFORM_SERVICE:
        return "claude_platform"
    if "openinference.span.kind" in attributes:
        return "openinference"
    if "gen_ai.system" in attributes and "gen_ai.provider.name" not in attributes:
        return "genai_legacy"
    if "gen_ai.operation.name" in attributes or "gen_ai.provider.name" in attributes:
        return "genai"
    if "mcp.method.name" in attributes:
        return "mcp"
    return None


def _log_dialect(log: LogRecord, service: object) -> tuple[str, str] | None:
    """`(dialect, event)`: Claude Code's events by `claude_code.<x>` in the event name field or a string body, or by
    the unprefixed `<x>` in the field or the attribute `event.name` from a `claude-code` resource; GenAI content
    events by name (field, else `event.name`)."""
    attribute = log.attributes.get("event.name")
    for candidate in (log.event_name, log.body):
        if isinstance(candidate, str) and candidate.startswith("claude_code."):
            event = candidate[len("claude_code."):]
            if event in CLAUDE_CODE_EVENT_KINDS:
                return "claude_code", event
    if service in CLAUDE_CODE_SERVICES:
        for candidate in (log.event_name, attribute):
            if isinstance(candidate, str) and candidate in CLAUDE_CODE_EVENT_KINDS:
                return "claude_code", candidate
    name = log.event_name or (attribute if isinstance(attribute, str) else "")
    if name in GENAI_CONTENT_EVENTS:
        return "genai", name
    return None


def _tool_parameters(value: object) -> dict:
    """Claude Code's `tool_parameters` JSON string, parsed under the depth bound of 4.3; {} when it is not an object."""
    if not isinstance(value, str):
        return {}
    try:
        parsed = parse_json(value.encode("utf-8", "replace"), depth_limit=DEFAULT_LIMITS.max_depth)
    except OtlpError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _decision(value: object) -> str | None:
    if value == "accept":
        return "accept"
    if value in ("reject", "cancelled"):
        return "reject"
    return None


def _fields(attributes: dict, cc: bool, service: object, span_kind: int | None) -> dict:
    """The fields every dialect reads the same way (spec 4.5): MCP and GenAI attributes are read on any span."""
    params = _tool_parameters(attributes.get("tool_parameters")) if cc else {}
    out: dict = {}
    conversation = session_text(attributes.get("gen_ai.conversation.id"))
    if conversation is not None:
        out["session_source"], out["session_value"] = "conversation", conversation
    else:
        session = session_text(attributes.get("session.id"))
        if session is not None:
            out["session_source"], out["session_value"] = "session", session
    out["operation"] = ident(attributes.get("gen_ai.operation.name"), 64)
    out["agent_name"] = _first(attributes, ("gen_ai.agent.name", "agent.name"), 128)
    provider = ident(attributes.get("gen_ai.provider.name"), 64)
    if provider is None:
        legacy = ident(attributes.get("gen_ai.system"), 64)
        provider = LEGACY_PROVIDERS.get(legacy, legacy) if legacy is not None else ident(attributes.get("llm.system"), 64)
    out["provider"] = "anthropic" if cc else provider
    out["model"] = _first(attributes, ("gen_ai.response.model", "gen_ai.request.model", "llm.model_name")
                          + (("model",) if cc else ()), 128)
    out["input_tokens"] = _first_int(attributes, ("gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens",
                                                  "llm.token_count.prompt"), False)
    out["output_tokens"] = _first_int(attributes, ("gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens",
                                                   "llm.token_count.completion"), False)
    if cc:
        if out["input_tokens"] is None:
            base = _integer(attributes.get("input_tokens"), True, 0, _MAX_TOKENS)
            if base is not None:
                total = base + sum(_integer(attributes.get(name), True, 0, _MAX_TOKENS) or 0
                                   for name in ("cache_read_tokens", "cache_creation_tokens"))
                out["input_tokens"] = total if total <= _MAX_TOKENS else None
        if out["output_tokens"] is None:
            out["output_tokens"] = _integer(attributes.get("output_tokens"), True, 0, _MAX_TOKENS)
    out["tool_name"] = (_first(attributes, ("gen_ai.tool.name", "tool.name"), 128)
                        or (ident(params.get("mcp_tool_name"), 128) or ident(attributes.get("tool_name"), 128) if cc else None))
    out["tool_call_id"] = (_first(attributes, ("gen_ai.tool.call.id", "tool_call.id"), 128)
                           or (ident(attributes.get("tool_use_id"), 128) if cc else None))
    out["tool_type"] = ident(attributes.get("gen_ai.tool.type"), 32) or (ident(attributes.get("tool_source"), 32) if cc else None)
    method = ident(attributes.get("mcp.method.name"), 64)
    out["mcp_method"] = method
    if method is not None and span_kind in (2, 3):
        out["side"] = "server" if span_kind == 2 else "client"
    server = _first(attributes, ("anthropic.mcp.server.name", "mcp.target"), 128)
    if server is None and cc:
        server = ident(params.get("mcp_server_name"), 128) or ident(attributes.get("server_name"), 128)
    redacted = False
    if server is None and method is not None and span_kind == 2:
        server = ident(service, 128)
        if isinstance(service, str) and (service == UNKNOWN_SERVICE or service.startswith(UNKNOWN_SERVICE + ":")):
            redacted = True
    out["mcp_server_name"] = server
    out["server_address"] = ident(attributes.get("server.address"), 253)
    out["server_port"] = _integer(attributes.get("server.port"), cc, 0, 65535)
    full = attributes.get("url.full")
    if isinstance(full, str):
        out["url"] = kept_url(full)
        out["server_identity"] = server_identity(full)
    out["skill_name"] = (ident(attributes.get("gen_ai.skill.name"), 128)
                         or (_first(params, ("skill_name",), 128) or _first(attributes, ("skill_name", "skill.name"), 128)
                             if cc else None))
    out["skill_source_uri"] = kept_skill_uri(attributes.get("gen_ai.skill.source.uri"))
    if cc:
        names = (out["tool_name"], out["skill_name"], out["mcp_server_name"])
        redacted = redacted or any(name in CLAUDE_CODE_PLACEHOLDERS for name in names)
        safe_name = attributes.get("tool_name_safe")  # a kvlist or array value is not hashable: never `in` a set
        redacted = redacted or (isinstance(safe_name, str) and safe_name in SPAN_SAFE_PLACEHOLDERS)
    out["names_redacted"] = redacted
    error = ident(attributes.get("error.type"), 64)
    rpc = attributes.get("rpc.response.status_code")
    out["rpc_status_code"] = _integer(rpc, True, -(2**31), 2**31 - 1) if isinstance(rpc, (int, str)) else None
    if error is None and method is not None and out["rpc_status_code"] is not None:
        error = str(out["rpc_status_code"])
    if cc:
        success = _boolean(attributes.get("success"), True)
        error = error or ident(attributes.get("error_type"), 64)
        if success is False and error is None:
            error = "tool_error"
        out["_success"] = success
    out["error_type"] = error
    return out


# --- the normaliser -------------------------------------------------------------------------------------------------

def _resource_info(attributes: dict) -> ResourceInfo:
    return ResourceInfo(
        service_name=ident(attributes.get("service.name"), 128) or UNKNOWN_SERVICE,
        service_version=ident(attributes.get("service.version"), 64),
        environment=_first(attributes, ("deployment.environment.name", "deployment.environment"), 64),
        sdk_language=ident(attributes.get("telemetry.sdk.language"), 32),
    )


def _times(start: int, end: int) -> tuple[int | None, int | None, int | None]:
    start_ns = start or None
    end_ns = end or None
    duration = (end - start) // 1_000_000 if start and end and end >= start else None
    return start_ns, end_ns, duration


def _hex_id(value: str) -> str | None:
    return value if value and value.strip("0") else None


def _status(code: int, error: str | None, success: bool | None, forced_error: bool) -> str:
    if forced_error or error is not None or success is False or code == 2:
        return "error"
    if code == 1 or success is True:
        return "ok"
    return "unset"


def _span_record(span: Span, resource: int, scope: str, service: object, content: bool, stats: dict) -> dict | None:
    dialect = _span_dialect(span, service)
    if dialect is None:
        return None
    attributes = span.attributes
    cc = dialect == "claude_code"
    out = _fields(attributes, cc, service, span.kind)
    oi_kind = attributes.get("openinference.span.kind") if dialect == "openinference" else None
    if cc:
        kind = CLAUDE_CODE_SPAN_KINDS.get(span.name, "other")
        if span.name == "claude_code.interaction":
            out["agent_name"] = "claude-code"
        if kind == "decision":
            out["decision_kind"] = "blocked_on_user"
            out["decision_outcome"] = _decision(attributes.get("decision"))
            out["decision_source"] = ident(attributes.get("source"), 32)
    elif dialect == "mcp":
        kind = "tool" if out["mcp_method"] == "tools/call" else "mcp"
    elif dialect == "openinference":
        kind = OPENINFERENCE_KINDS.get(oi_kind, "other") if isinstance(oi_kind, str) else "other"
    else:
        kind = GENAI_OPERATION_KINDS.get(out["operation"], "other")
    success = out.pop("_success", None)
    start_ns, end_ns, duration = _times(span.start_time_unix_nano, span.end_time_unix_nano)
    out.update(
        signal="span", dialect=dialect, kind=kind, counted=kind in COUNTED_KINDS and not cc, resource=resource,
        scope=ident(scope, 128), trace_id=_hex_id(span.trace_id), span_id=_hex_id(span.span_id),
        parent_span_id=_hex_id(span.parent_span_id), name=ident(span.name, 200), start_ns=start_ns, end_ns=end_ns,
        duration_ms=duration, status=_status(span.status.code, out["error_type"], success, False),
    )
    if content:
        items = _span_content(span, dialect, oi_kind if isinstance(oi_kind, str) else None)
        out["content"] = tuple(items.items)
        stats["content_cut"] += items.cut
    return out


def _log_record(log: LogRecord, resource: int, scope: str, service: object, content: bool, stats: dict) -> dict | None:
    found = _log_dialect(log, service)
    if found is None:
        return None
    dialect, event = found
    cc = dialect == "claude_code"
    kind = CLAUDE_CODE_EVENT_KINDS[event] if cc else "content"
    if kind == "content" and not content:
        return None
    attributes = log.attributes
    out = _fields(attributes, cc, service, None)
    success = out.pop("_success", None)
    if cc and kind == "decision":
        out["decision_kind"] = event
        out["decision_outcome"] = _decision(attributes.get("decision"))
        out["decision_source"] = ident(attributes.get("source" if event == "tool_decision" else "decision_source"), 32)
        if event == "safety_event":
            out["decision_category"] = ident(attributes.get("category"), 32)
            out["decision_reason_code"] = ident(attributes.get("reason_code"), 64)
            out["decision_rule_source"] = ident(attributes.get("rule_source"), 32)
    time = log.time_unix_nano or log.observed_time_unix_nano or None
    out.update(
        signal="log", dialect=dialect, kind=kind, counted=kind in COUNTED_KINDS, resource=resource,
        scope=ident(scope, 128), trace_id=_hex_id(log.trace_id), span_id=_hex_id(log.span_id),
        name=f"claude_code.{event}" if cc else ident(event, 200), start_ns=time, end_ns=time,
        duration_ms=_integer(attributes.get("duration_ms"), True, 0, 2**53) if cc else None,
        status=_status(0, out["error_type"], success, cc and event == "api_error"),
    )
    if content:
        items = _log_content(log, dialect, event)
        out["content"] = tuple(items.items)
        stats["content_cut"] += items.cut
        if kind == "content" and not items.items:
            return None
    return out


def _fold_safety_events(records: list[dict]) -> list[dict]:
    """Spec 4.4: a `safety_event` fills the absent category, reason code and rule source of the `tool_decision` with
    the same `tool_use_id` and the same decision in the request, and is not emitted; otherwise it is kept, uncounted."""
    decisions: dict[str, dict] = {}
    for record in records:
        if record.get("decision_kind") == "tool_decision" and record.get("tool_call_id"):
            decisions.setdefault(record["tool_call_id"], record)
    out: list[dict] = []
    for record in records:
        if record.get("decision_kind") != "safety_event":
            out.append(record)
            continue
        partner = decisions.get(record.get("tool_call_id")) if record.get("tool_call_id") else None
        if partner is not None and partner.get("decision_outcome") == record.get("decision_outcome"):
            for name in ("decision_category", "decision_reason_code", "decision_rule_source"):
                if partner.get(name) is None:
                    partner[name] = record.get(name)
            continue
        record["counted"] = False
        out.append(record)
    return out


def normalise(request: OtlpRequest, *, content: bool) -> Normalised:
    """Spec 4.4: one `Record` per kept span or log record, in request order, with its content only when `content`."""
    stats = {"content_cut": 0}
    resources: list[ResourceInfo] = []
    built: list[dict] = []
    total = 0
    for index, resource in enumerate(request.resources):
        resources.append(_resource_info(resource.attributes))
        service = resource.attributes.get("service.name")
        for scope in resource.scopes:
            for span in scope.spans:
                total += 1
                record = _span_record(span, index, scope.name, service, content, stats)
                if record is not None:
                    built.append(record)
            for log in scope.log_records:
                total += 1
                record = _log_record(log, index, scope.name, service, content, stats)
                if record is not None:
                    built.append(record)
    built = _fold_safety_events(built)
    counted = sum(1 for record in built if record["counted"])
    allowed_other = max(OTHER_FLOOR, 2 * counted)
    kept: list[Record] = []
    others = 0
    for record in built:
        if record["kind"] == "other":
            others += 1
            if others > allowed_other:
                continue
        kept.append(Record(**record))
    by_dialect: dict[str, int] = {}
    for record in kept:
        by_dialect[record.dialect] = by_dialect.get(record.dialect, 0) + 1
    spans = sum(len(scope.spans) for resource in request.resources for scope in resource.scopes)
    final = Stats(
        spans=spans, log_records=total - spans, kept=len(kept), ignored=total - len(kept), counted=counted,
        by_dialect=dict(sorted(by_dialect.items())), attributes_skipped=request.attributes_skipped,
        events_skipped=request.events_skipped, content_items=sum(len(record.content) for record in kept),
        content_cut=stats["content_cut"],
    )
    return Normalised(final, tuple(resources), tuple(kept))
