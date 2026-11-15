"""The Docker MCP Gateway export (1.15.0; kept by the owner, phase 3 batch 2b spec's spec:Q1): an interceptor guard pinned to
Docker MCP Gateway v0.44.3. Docker documents only a positive tool list and on/off switches for the gateway; it can deny by
pattern only through `--interceptor` scripts, whose stdin contract is described by an examples README, not by its docs. The
export is therefore checked at that one release, in the release workflow's `gateway-exports` job, at each engine release.

Files: the guard (`docker_gateway_guard.TEMPLATE` with the pack's checks), a Dockerfile that adds Python 3 to the pinned
`docker/mcp-gateway` image and copies the guard read-only, an example `compose.yaml`, the two flags for a gateway on a host
with Python, the README and `SHA256SUMS`. The guard denies the destructive tool verbs of SW-GW-006 at call time and replaces a
tool result that holds one of SW-GW-004's nine injection patterns. Pure: the files are returned as `{path: bytes}`; the pack's
name and version reach the guard only as JSON string literals and the README only through `readme_text`."""
from __future__ import annotations

import hashlib
import re

from spellwarden_scan.exports import README_NAME, coverage, readme_text
from spellwarden_scan.exports.docker_gateway_guard import TEMPLATE
from spellwarden_scan.exports.hooks import MCP_VERBS
from spellwarden_scan.packs import PackDocument
from spellwarden_scan.rules.patterns import INJECTION
from spellwarden_scan.rules.skill import _INVISIBLE

TARGET = "docker-mcp-gateway"
GATEWAY = "Docker MCP Gateway"
GATEWAY_VERSION = "v0.44.3"
# The multi-platform image index of the release on Docker Hub (linux/amd64 and linux/arm64), read on 2026-11-15.
GATEWAY_IMAGE = "docker/mcp-gateway:v0.44.3@sha256:bae58d801fd4b73f6ad91e609b8ce5ec8868713825f33a2bb20a98f956d0bd46"
GUARD_NAME = "spellwarden_gateway_guard.py"
GUARD_PATH = "docker-mcp-gateway/" + GUARD_NAME
DOCKERFILE_PATH = "docker-mcp-gateway/Dockerfile"
COMPOSE_PATH = "docker-mcp-gateway/compose.yaml"
FLAGS_PATH = "docker-mcp-gateway/gateway-flags.txt"
SUMS_NAME = "SHA256SUMS"
IMAGE_GUARD = "/opt/spellwarden/" + GUARD_NAME
MAX_INPUT = 1024 * 1024
GUIDE = ("https://spellwarden.ai/docs/export-docker-mcp-gateway?utm_source=export&utm_medium=docker-mcp-gateway"
         "&utm_campaign=policy-export")
_PLACEHOLDER = re.compile(r"__(PACK|VERSION|VERBS|PATTERNS|INVISIBLE)__")


def interceptor_flags(guard: str) -> list[str]:
    return [f"--interceptor=before:exec:python3 -I {guard} before", f"--interceptor=after:exec:python3 -I {guard} after"]


def guard_script(doc: PackDocument) -> bytes:
    """The guard with the pack's checks: SW-GW-006's verbs and SW-GW-004's patterns, each empty while its rule is off. Every
    value is written with `ascii()`, an ASCII Python literal (a JSON string would spell an astral character as two lone
    surrogates)."""
    on = doc.enabled()
    values = {
        "__PACK__": ascii(doc.name), "__VERSION__": ascii(doc.version),
        "__VERBS__": ascii(list(MCP_VERBS) if "SW-GW-006" in on else []),
        "__PATTERNS__": ascii([["SW-GW-004", pattern.pattern] for pattern in INJECTION] if "SW-GW-004" in on else []),
        "__INVISIBLE__": ascii(_INVISIBLE.pattern),
    }
    # One pass over the template: a value that holds a placeholder (a pack named "__VERBS__") stays text.
    return _PLACEHOLDER.sub(lambda match: values[match.group(0)], TEMPLATE).encode("ascii")


DOCKERFILE = f"""# Spellwarden policy export for Docker MCP Gateway {GATEWAY_VERSION}: the pinned image, Python 3 and the guard.
FROM {GATEWAY_IMAGE}
RUN apk add --no-cache python3
COPY --chmod=0444 {GUARD_NAME} {IMAGE_GUARD}
"""

COMPOSE = f"""# Spellwarden policy export for Docker MCP Gateway {GATEWAY_VERSION}: an example service.
# Replace duckduckgo with your servers.
services:
  gateway:
    build: .
    command:
      - --transport=sse
      - --port=8811
      - --servers=duckduckgo
      - {interceptor_flags(IMAGE_GUARD)[0]}
      - {interceptor_flags(IMAGE_GUARD)[1]}
    ports:
      - "8811:8811"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""

FLAGS = "\n".join(interceptor_flags(f"/path/to/{GUARD_NAME}")) + "\n"

INSTALL = [
    "Check the files against SHA256SUMS.",
    f"Build the image from {DOCKERFILE_PATH}: it adds Python 3 to the pinned docker/mcp-gateway {GATEWAY_VERSION} image and "
    f"copies the guard to {IMAGE_GUARD}, read-only. To use your own gateway image instead, add python3 to it and copy the guard.",
    f"Run the gateway with the two --interceptor flags of {COMPOSE_PATH}, which shows a whole service. For docker mcp gateway "
    f"run on a host with Python 3, use the flags of {FLAGS_PATH} and replace /path/to with the directory of the guard.",
    "Keep --block-secrets on, as it is by default.",
    "Connect your clients over SSE (http://<host>:8811/sse) or run the gateway over stdio. Do not use --transport=streaming with "
    "this guard: see Limits.",
]
LIMITS = [
    f"Docker describes the interceptor contract only in an examples README, and this export was checked against "
    f"{GATEWAY} {GATEWAY_VERSION}. A later gateway release may change the contract; an export is checked against a newer "
    "gateway only by a later Spellwarden engine release.",
    f"With --transport=streaming, {GATEWAY} {GATEWAY_VERSION} cannot hand a tool call to a before interceptor and fails every "
    "tool call, so nothing passes. Run the gateway with --transport=sse or over stdio.",
    "The gateway image must carry Python 3. An interceptor that fails, including a missing python3, fails the tool call.",
    "The guard fails closed: a request or a result larger than 1 MiB, one that is not JSON, or a request without a tool "
    "name is answered with an error result instead of going on.",
    "SW-GW-006 asks a person to approve destructive tools. The gateway cannot ask, so the guard denies them; tool names are "
    "matched in any case.",
    "SW-GW-004 is checked on the text content and the structured content of tool results, after removing invisible "
    "characters and normalising to NFKC. Prompts are not checked.",
    "The guard writes one line on standard error when it blocks (the rule and the tool name), never an argument or a result.",
]

NOTHING_ENFORCED = "Nothing in this pack is enforced by the guard: SW-GW-006 and SW-GW-004 are off."


def _sums(files: dict[str, bytes]) -> bytes:
    return "".join(f"{hashlib.sha256(files[path]).hexdigest()}  {path}\n" for path in sorted(files)).encode("ascii")


def docker_gateway_files(doc: PackDocument, *, built_at: str) -> dict[str, bytes]:
    """The six files of the export of `doc` to Docker MCP Gateway, by archive path."""
    enforced, cannot, not_included = coverage(doc, TARGET)
    limits = LIMITS if enforced else [NOTHING_ENFORCED, *LIMITS]
    readme = readme_text(doc, target=TARGET, mode=None, built_at=built_at, enforced=enforced, cannot_enforce=cannot,
                         not_included=not_included, install=INSTALL, limits=limits, guide=GUIDE)
    files = {
        GUARD_PATH: guard_script(doc),
        DOCKERFILE_PATH: DOCKERFILE.encode("ascii"),
        COMPOSE_PATH: COMPOSE.encode("ascii"),
        FLAGS_PATH: FLAGS.encode("ascii"),
        README_NAME: readme,
    }
    files[SUMS_NAME] = _sums(files)
    return files


__all__ = ["COMPOSE_PATH", "DOCKERFILE_PATH", "FLAGS_PATH", "GATEWAY", "GATEWAY_IMAGE", "GATEWAY_VERSION", "GUARD_NAME",
           "GUARD_PATH", "GUIDE", "IMAGE_GUARD", "MAX_INPUT", "SUMS_NAME", "TARGET", "docker_gateway_files", "guard_script",
           "interceptor_flags"]
