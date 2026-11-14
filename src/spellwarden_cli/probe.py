"""The MCP probe (spec 6.8; moved from the hosted backend's `spellwarden/mcpservers/probe.py`, Phase B spec 6.6,
behaviour unchanged): at most nine requests through the fetcher, no credential ever sent, a `ProbeResult` always
returned. `on_event` receives what the backend logged (`probe_failed`). Python 3.11 or newer."""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import replace
from urllib.parse import urlsplit

from spellwarden_scan import (
    AuthServerMetadata, ProbeResult, PromptArgument, PromptInfo, ResourceInfo, ResourceTemplateInfo, ToolInfo,
)

from spellwarden_cli import net

PROBE_NAME = "spellwarden-probe"
DISCOVER_VERSION = "2026-07-28"
INITIALIZE_VERSION = "2025-11-25"
MAX_REQUESTS = 9
MAX_TOOLS = 200
MAX_DESCRIPTION = 1000
MAX_SCHEMA_BYTES = 16 * 1024  # Phase C spec 5.6: the largest `inputSchema` recorded, as canonical JSON
# Phase 3 batch 1 spec 8.1, 8.2, 11.2: the wider reading. One page of each list, at most MAX_LISTED entries, every text cut.
MAX_LISTED = MAX_TOOLS
MAX_INSTRUCTIONS = 16000
MAX_NAME = 128
MAX_TITLE = 256
MAX_ARGUMENT_DESCRIPTION = 500
MAX_URI = 2048
MAX_ARGUMENTS = 20
# The only JSON-RPC methods the prober ever sends. `resources/read`, `prompts/get` and `tools/call` are not here and cannot be
# sent: `_Probe._post` refuses any other name before a byte leaves (spec 8.1, decision D16).
ALLOWED_METHODS = ("server/discover", "initialize", "notifications/initialized", "tools/list", "prompts/list", "resources/list",
                   "resources/templates/list")
_RESOURCE_METADATA_RE = re.compile(r'resource_metadata="([^"]+)"')


class MethodNotAllowed(ValueError):
    """`_Probe._post` was asked for a method outside `ALLOWED_METHODS`; the probe reports `probe_failed`."""


class _Probe:
    def __init__(self, fetcher, endpoint: str, release: str) -> None:
        self.fetcher, self.endpoint, self.release = fetcher, endpoint, release
        self.requests = 0
        self.session_id: str | None = None
        self.negotiated_version: str | None = None
        self.state: dict = {"endpoint": endpoint, "reachable": False}

    def _headers(self, method: str) -> dict[str, str]:
        # After `initialize`, every request carries the version the server negotiated (MCP 2025-06-18, "Protocol
        # Version Header"): a server that negotiated an older version refuses the probe's own with 400 (the AWS MCP
        # server, 2026-10-22, "Unsupported protocol version: 2025-11-25").
        version = DISCOVER_VERSION if method == "server/discover" else (self.negotiated_version or INITIALIZE_VERSION)
        headers = {"MCP-Protocol-Version": version,
                   "Mcp-Method": method, "Mcp-Name": PROBE_NAME, "Accept": "application/json, text/event-stream"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def _post(self, method: str, params: dict, *, notification: bool = False):
        if method not in ALLOWED_METHODS:
            raise MethodNotAllowed(f"the probe never sends {method}")
        if self.requests >= MAX_REQUESTS:
            return None
        self.requests += 1
        body: dict = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            body["id"] = self.requests
        try:
            response = self.fetcher.post_json(self.endpoint, body, self._headers(method), max_bytes=net.JSON_MAX)
        except net.FetchError as exc:
            self.state.setdefault("error", exc.code)
            return None
        self.state["reachable"] = True
        session = _header(response.headers, "Mcp-Session-Id")
        if session:
            self.state["session_id_seen"] = True
            self.session_id = session
        return response

    def _get(self, url: str, *, stream: bool = False):
        if self.requests >= MAX_REQUESTS:
            return None
        self.requests += 1
        try:
            if stream:
                return self.fetcher.get_stream_head(url)
            return self.fetcher.get(url, max_bytes=net.JSON_MAX, accept="application/json")
        except net.FetchError:
            return None

    def run(self) -> ProbeResult:
        if urlsplit(self.endpoint).scheme.lower() != "https":
            return ProbeResult(endpoint=self.endpoint, reachable=False, error="not_https")
        state = self.state
        discover = self._post("server/discover", {"_meta": {"io.modelcontextprotocol/protocolVersion": DISCOVER_VERSION}})
        result = _rpc_result(discover)
        statuses = []
        if discover is not None:
            statuses.append(discover.status)
            _note_post(state, discover)
            _note_auth(state, discover)
        if result is not None:
            state["discover"] = result
            state["capabilities"] = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
        elif discover is None or discover.status not in (401, 403):
            initialize = self._post("initialize", {"protocolVersion": INITIALIZE_VERSION, "capabilities": {},
                                                   "clientInfo": {"name": PROBE_NAME, "version": self.release}})
            init_result = _rpc_result(initialize)
            if initialize is not None:
                statuses.append(initialize.status)
                _note_post(state, initialize)
                _note_auth(state, initialize)
            if init_result is not None:
                state["initialize"] = init_result
                state["negotiated_version"] = init_result.get("protocolVersion")
                if isinstance(init_result.get("protocolVersion"), str) and init_result["protocolVersion"]:
                    self.negotiated_version = init_result["protocolVersion"]
                state["capabilities"] = init_result.get("capabilities") if isinstance(init_result.get("capabilities"), dict) else {}
                self._post("notifications/initialized", {}, notification=True)
        if statuses and all(status in (404, 405) for status in statuses):
            head = self._get(self.endpoint, stream=True)
            if head is not None:
                content_type = _content_type(head.headers)
                state["get_content_type"] = content_type
                state["sse_endpoint_event"] = content_type == "text/event-stream" and "event: endpoint" in head.body.decode("utf-8", "replace")
        listed = self._post("tools/list", {})
        list_result = _rpc_result(listed)
        if listed is not None:
            _note_post(state, listed)
            _note_auth(state, listed)
            state["unauthenticated_status"] = listed.status
        if list_result is not None:
            listed_tools = list_result.get("tools")
            tools = listed_tools if isinstance(listed_tools, list) else []
            state["tools"] = tuple(_tool_of(tool) for tool in tools[:MAX_TOOLS] if isinstance(tool, dict) and isinstance(tool.get("name"), str))
            state["tools_source"] = "probe"
            cursor = list_result.get("nextCursor")
            # 1.9.0: the whole list, or SW-MCP-001 stays high (a later page, an entry past the cap or a dropped entry may
            # be the dangerous one).
            state["tools_complete"] = (isinstance(listed_tools, list) and len(state["tools"]) == len(listed_tools)
                                       and not (isinstance(cursor, str) and cursor))
            meta = {key: list_result[key] for key in ("ttlMs", "cacheScope") if key in list_result}
            state["list_result_meta"] = meta or None
        self._note_instructions()
        if listed is not None and state.get("unauthenticated_status") not in (401, 403):
            self._read_listings()
        if state.get("unauthenticated_status") in (401, 403):
            self._auth_metadata()
        if not state.get("reachable"):
            state.setdefault("error", "unreachable")
        return ProbeResult(**state)

    def _note_instructions(self) -> None:
        """The server's own `instructions` (spec 8.1): the first non-empty string of the `server/discover` result, else the
        `initialize` result, cut at MAX_INSTRUCTIONS. No request is made for it; both results are already held."""
        for source in (self.state.get("discover"), self.state.get("initialize")):
            text = source.get("instructions") if isinstance(source, dict) else None
            if isinstance(text, str) and text:
                self.state["instructions"] = text[:MAX_INSTRUCTIONS]
                if len(text) > MAX_INSTRUCTIONS:
                    self.state["instructions_truncated"] = True
                return

    def _read_listings(self) -> None:
        """Spec 8.1: after `tools/list`, one request each of `prompts/list`, `resources/list` and `resources/templates/list`, in
        that order, one page, and only for a capability the server declared (a JSON object under `prompts` or `resources`).
        The caller has checked that `tools/list` was answered and not refused with 401 or 403, the sign that the server wants a
        credential the probe never sends. A list is recorded when the answer is a list; it is complete only when nothing was
        dropped (a cursor, the cap, an entry without a name or address)."""
        state = self.state
        capabilities = state.get("capabilities")
        if not isinstance(capabilities, dict):
            return
        read: list[str] = []
        for capability, method, key, field, complete_field, build in _LISTINGS:
            if not isinstance(capabilities.get(capability), dict):
                continue
            result = _rpc_result(self._post(method, {}))
            entries = result.get(key) if result is not None else None
            if result is None or not isinstance(entries, list):
                continue
            kept = tuple(item for item in (build(entry) for entry in entries[:MAX_LISTED]) if item is not None)
            cursor = result.get("nextCursor")
            state[field] = kept
            state[complete_field] = len(kept) == len(entries) and not (isinstance(cursor, str) and cursor)
            read.append(field)
        if read:
            state["lists_read"] = tuple(read)

    def _auth_metadata(self) -> None:
        state = self.state
        parts = urlsplit(self.endpoint)
        origin = f"{parts.scheme}://{parts.netloc}"
        candidates = []
        header = state.get("www_authenticate") or ""
        match = _RESOURCE_METADATA_RE.search(header)
        if match:
            candidates.append(match.group(1))
        candidates.append(f"{origin}/.well-known/oauth-protected-resource{parts.path}")
        candidates.append(f"{origin}/.well-known/oauth-protected-resource")
        document = None
        for url in dict.fromkeys(candidates):
            document = _json_of(self._get(url))
            if isinstance(document, dict):
                break
            document = None
        if document is None:
            return
        state["resource_metadata"] = document
        servers = document.get("authorization_servers")
        if not isinstance(servers, list) or not servers or not isinstance(servers[0], str):
            return
        issuer = servers[0].rstrip("/")
        for url in (f"{issuer}/.well-known/oauth-authorization-server", f"{issuer}/.well-known/openid-configuration"):
            metadata = _json_of(self._get(url))
            if isinstance(metadata, dict):
                grants = metadata.get("grant_types_supported")
                state["auth_server_metadata"] = AuthServerMetadata(
                    issuer=metadata.get("issuer") if isinstance(metadata.get("issuer"), str) else None, metadata_url=url,
                    registration_endpoint=metadata.get("registration_endpoint") if isinstance(metadata.get("registration_endpoint"), str) else None,
                    client_id_metadata_document_supported=metadata.get("client_id_metadata_document_supported") is True,
                    grant_types_supported=tuple(str(g) for g in grants) if isinstance(grants, list) else ())
                return


def _header(headers: dict, name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _content_type(headers: dict) -> str | None:
    value = _header(headers, "Content-Type")
    return value.split(";", 1)[0].strip().lower() if value else None


def _note_post(state: dict, response) -> None:
    if response.status == 200 or state.get("post_status") is None:
        state["post_status"] = response.status
        state["post_content_type"] = _content_type(response.headers)


def _note_auth(state: dict, response) -> None:
    if response.status in (401, 403):
        state["unauthenticated_status"] = response.status
        header = _header(response.headers, "WWW-Authenticate")
        if header:
            state["www_authenticate"] = header


def _json_of(response):
    if response is None or response.status != 200:
        return None
    try:
        return json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _rpc_result(response) -> dict | None:
    """The JSON-RPC `result` of a 200 answer, JSON or the first `data:` message of an event stream."""
    if response is None or response.status != 200:
        return None
    content_type = _content_type(response.headers)
    if content_type not in ("application/json", "text/event-stream"):
        return None  # spec 6.6, 6.8a: only these two carry an answer; anything else is the status alone
    text = response.body.decode("utf-8", "replace")
    message = None
    if content_type == "text/event-stream":
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    message = json.loads(line[5:].strip())
                except ValueError:
                    message = None
                break
    else:
        try:
            message = json.loads(text)
        except ValueError:
            message = None
    if isinstance(message, dict) and isinstance(message.get("result"), dict):
        return message["result"]
    return None


def _schema_of(value: object) -> dict | None:
    """Phase C spec 5.6: a tool's `inputSchema` when it is a JSON object whose canonical JSON (sorted keys, no
    whitespace, UTF-8) is at most 16 KiB; anything else, or a value that cannot be written as UTF-8 (a lone
    surrogate), is no schema."""
    if not isinstance(value, dict):
        return None
    try:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        size = len(canonical.encode("utf-8"))
    except (TypeError, ValueError, RecursionError):  # UnicodeEncodeError is a ValueError
        return None
    return value if size <= MAX_SCHEMA_BYTES else None


def _tool_of(tool: dict) -> ToolInfo:
    description = tool.get("description") if isinstance(tool.get("description"), str) else ""
    annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    return ToolInfo(name=tool["name"][:128], description=description[:MAX_DESCRIPTION], annotations=annotations,
                    input_schema=_schema_of(tool.get("inputSchema")))


def _text(value: object, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _title(entry: dict) -> str | None:
    title = entry.get("title")
    return title[:MAX_TITLE] if isinstance(title, str) and title else None


def _prompt_of(entry: object) -> PromptInfo | None:
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
        return None
    arguments = entry.get("arguments")
    kept = tuple(PromptArgument(name=argument["name"][:MAX_NAME], description=_text(argument.get("description"), MAX_ARGUMENT_DESCRIPTION))
                 for argument in (arguments[:MAX_ARGUMENTS] if isinstance(arguments, list) else ())
                 if isinstance(argument, dict) and isinstance(argument.get("name"), str))
    return PromptInfo(name=entry["name"][:MAX_NAME], title=_title(entry), description=_text(entry.get("description"), MAX_DESCRIPTION),
                      arguments=kept)


def _resource_of(entry: object) -> ResourceInfo | None:
    if not isinstance(entry, dict) or not isinstance(entry.get("uri"), str):
        return None
    return ResourceInfo(uri=entry["uri"][:MAX_URI], name=_text(entry.get("name"), MAX_NAME), title=_title(entry),
                        description=_text(entry.get("description"), MAX_DESCRIPTION))


def _template_of(entry: object) -> ResourceTemplateInfo | None:
    if not isinstance(entry, dict) or not isinstance(entry.get("uriTemplate"), str):
        return None
    return ResourceTemplateInfo(uri_template=entry["uriTemplate"][:MAX_URI], name=_text(entry.get("name"), MAX_NAME),
                                title=_title(entry), description=_text(entry.get("description"), MAX_DESCRIPTION))


# (capability the server must declare, method, key of the answer, `ProbeResult` field, its completeness field, entry builder),
# in the order the requests are sent.
_LISTINGS = (
    ("prompts", "prompts/list", "prompts", "prompts", "prompts_complete", _prompt_of),
    ("resources", "resources/list", "resources", "resources", "resources_complete", _resource_of),
    ("resources", "resources/templates/list", "resourceTemplates", "resource_templates", "resource_templates_complete", _template_of),
)


def probe(fetcher, endpoint: str, *, release: str, now_iso: str,
          on_event: Callable[[str, dict], None] | None = None) -> ProbeResult:
    """Phase B spec 6.6; never raises."""
    try:
        result = _Probe(fetcher, endpoint, release).run()
    except Exception as exc:  # noqa: BLE001 -- a probe failure is a result, never an exception (spec 6.6)
        if on_event is not None:
            on_event("probe_failed", {"error_class": type(exc).__name__})
        return ProbeResult(endpoint=endpoint, reachable=False, error="unreachable", probed_at=now_iso)
    return replace(result, probed_at=now_iso)
