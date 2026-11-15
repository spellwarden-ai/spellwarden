"""The gateway check of the release workflow's `gateway-exports` job (1.15.0, claims T-13 and T-15 of phase 3 batch 2b spec): each
gateway export of the baseline pack, run by the gateway itself in front of the fixture MCP server of
`tests/fixtures/gateways/server.py`, blocks `delete_order` and answers `read_order`. Linux with Docker; never run by pytest.

    uv run --locked python tests/gateway_ci.py toolhive DIR
    uv run --locked python tests/gateway_ci.py docker DIR [--capture OUT]

`toolhive` downloads ToolHive v0.65.0's `thv` for linux/amd64, checks it against the recorded SHA-256, runs the fixture server
over streamable HTTP and `thv run --authz-config` on the export in front of it, then checks that `tools/list` hides
`delete_order`, that `read_order` is answered and that `delete_order` is refused with HTTP 403.

`docker` builds an image of the fixture server and the export's Dockerfile (the pinned `docker/mcp-gateway` v0.44.3 image with
Python 3 and the guard), runs the gateway over SSE with a catalog that names the fixture server and the export's two
interceptors, then checks that `read_order` is answered, that `delete_order` is answered with the guard's error result and that
a result holding an injection phrase is replaced. With `--capture OUT` it first runs the gateway with interceptors that only
copy their stdin, and writes what v0.44.3 hands an interceptor to OUT (`tests/fixtures/gateways/docker-v0.44.3/` holds the
vendored copy that tests/test_export_docker_gateway.py feeds the guard).

DIR is a scratch directory (it must exist and be empty). Exit 0 when every check passes, 1 with the failed check otherwise."""
from __future__ import annotations

import hashlib
import json
import os
import queue
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from spellwarden_scan import baseline_pack, build_export
from spellwarden_scan.exports import docker_gateway, toolhive

ROOT = Path(__file__).resolve().parents[1]

SERVER = ROOT / "tests" / "fixtures" / "gateways" / "server.py"
BUILT = "2026-12-01T10:00:00Z"
THV_URL = "https://github.com/stacklok/toolhive/releases/download/v0.65.0/toolhive_0.65.0_linux_amd64.tar.gz"
THV_SHA256 = "4fb9ec83fd8172f2281accefc8d43af682ef096fa6b7e31db04b75b110f7a0f4"
# The fixture server's image: Python's official Alpine image, the multi-platform index read on 2026-11-15.
PYTHON_IMAGE = "python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e"
FIXTURE_IMAGE = "spellwarden-fixture-mcp:ci"
GUARD_IMAGE = "spellwarden-gateway-guard:ci"
CATALOG = """name: spellwarden-fixture
displayName: Spellwarden fixture
registry:
  fixture:
    description: "The fixture MCP server of the Spellwarden gateway export check"
    title: "Spellwarden fixture"
    type: "server"
    image: "spellwarden-fixture-mcp:ci"
    tools:
      - name: "read_order"
      - name: "delete_order"
"""
INJECTION_REPLACED = "replaced a tool result: SW-GW-004"
BLOCKED = "blocked the tool delete_order: SW-GW-006"


class CheckFailed(Exception):
    pass


def check(condition: bool, what: str) -> None:
    print(("ok: " if condition else "FAILED: ") + what)
    if not condition:
        raise CheckFailed(what)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_port(port: int, seconds: float = 60.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.5)
    raise CheckFailed(f"nothing listened on port {port} within {seconds:.0f} s")


def write_export(target: str, dest: Path) -> dict[str, bytes]:
    files = build_export(baseline_pack(), target, built_at=BUILT)
    for path, content in files.items():
        out = dest / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(content)
    return files


class StreamableClient:
    """A minimal MCP client over streamable HTTP: one POST per message, a JSON or event-stream answer, the session header kept."""

    def __init__(self, url: str) -> None:
        self.url, self.session, self.next_id = url, None, 1

    def send(self, method: str, params: dict | None = None, *, notify: bool = False) -> tuple[int, dict | None]:
        body: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            body["id"], self.next_id = self.next_id, self.next_id + 1
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": "2025-06-18"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(self.url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status, kind, data = response.status, response.headers.get("Content-Type", ""), response.read().decode("utf-8")
                self.session = response.headers.get("Mcp-Session-Id") or self.session
        except urllib.error.HTTPError as error:
            return error.code, None
        if notify or not data.strip():
            return status, None
        if kind.startswith("text/event-stream"):
            messages = [json.loads(line[5:]) for line in data.splitlines() if line.startswith("data:") and line[5:].strip()]
            return status, next(message for message in messages if message.get("id") == body["id"])
        return status, json.loads(data)


class SseClient:
    """A minimal MCP client over the SSE transport: one GET stream for answers, a POST to the endpoint it names per message."""

    def __init__(self, base: str) -> None:
        self.base, self.messages = base, queue.Queue()
        self.stream = urllib.request.urlopen(urllib.request.Request(base + "/sse", headers={"Accept": "text/event-stream"}),
                                             timeout=120)
        threading.Thread(target=self._read, daemon=True).start()
        endpoint = self.messages.get(timeout=30)
        self.endpoint = endpoint if endpoint.startswith("http") else base + endpoint

    def _read(self) -> None:
        for raw in self.stream:
            line = raw.decode("utf-8").rstrip("\r\n")
            if line.startswith("data:"):
                self.messages.put(line[5:].strip())

    def post(self, body: dict) -> None:
        request = urllib.request.Request(self.endpoint, data=json.dumps(body).encode("utf-8"),
                                         headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(request, timeout=30).read()

    def call(self, ident: int, method: str, params: dict) -> dict:
        self.post({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        while True:
            message = json.loads(self.messages.get(timeout=60))
            if message.get("id") == ident:
                return message


def initialize_params() -> dict:
    return {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "spellwarden-gateway-check", "version": "1"}}


def first_text(message: dict) -> str:
    content = (message.get("result") or {}).get("content") or [{}]
    return str(content[0].get("text", ""))


def run_toolhive(work: Path) -> None:
    archive = work / "thv.tar.gz"
    with urllib.request.urlopen(THV_URL, timeout=120) as response:
        archive.write_bytes(response.read())
    check(hashlib.sha256(archive.read_bytes()).hexdigest() == THV_SHA256, "thv v0.65.0 has the recorded SHA-256")
    with tarfile.open(archive) as bundle:
        bundle.extract("thv", work, filter="data")
    authz = work / "export" / toolhive.AUTHZ_PATH
    write_export("toolhive", work / "export")
    server_port, proxy_port = free_port(), free_port()
    home = work / "home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / "config"), XDG_STATE_HOME=str(home / "state"),
               XDG_DATA_HOME=str(home / "data"))
    server = subprocess.Popen([sys.executable, "-I", str(SERVER), "--port", str(server_port)], stdout=subprocess.DEVNULL)
    thv = None
    try:
        wait_for_port(server_port)
        thv = subprocess.Popen([str(work / "thv"), "run", f"http://127.0.0.1:{server_port}/mcp", "--name", "spellwarden-fixture",
                                "--proxy-port", str(proxy_port), "--authz-config", str(authz), "--foreground"], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        wait_for_port(proxy_port)
        client = StreamableClient(f"http://127.0.0.1:{proxy_port}/mcp")
        status, _ = client.send("initialize", initialize_params())
        check(status == 200, "ToolHive answers initialize")
        client.send("notifications/initialized", notify=True)
        _, listed = client.send("tools/list", {})
        names = [tool["name"] for tool in (listed or {}).get("result", {}).get("tools", [])]
        check(names == ["read_order"], f"tools/list hides delete_order (listed: {names})")
        status, read = client.send("tools/call", {"name": "read_order", "arguments": {"id": "7"}})
        check(status == 200 and first_text(read or {}) == "Order 7: shipped.", "read_order is answered")
        status, _ = client.send("tools/call", {"name": "delete_order", "arguments": {"id": "7"}})
        check(status == 403, f"delete_order is refused with HTTP 403 (got {status})")
    finally:
        for process in (thv, server):
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()


def docker(*args: str, capture: bool = True) -> str:
    done = subprocess.run(["docker", *args], check=True, capture_output=capture, text=True, timeout=600)
    return done.stdout if capture else ""


def gateway(name: str, port: int, catalogs: Path, interceptors: list[str], volumes: tuple[str, ...] = ()) -> None:
    mounts = ["-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{catalogs}:/root/.docker/mcp/catalogs:ro"]
    for volume in volumes:
        mounts += ["-v", volume]
    docker("run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:9011", *mounts, GUARD_IMAGE, "--transport=sse", "--port=9011",
           "--catalog=spellwarden-fixture.yaml", "--servers=fixture", "--verify-signatures=false", "--allow-unauthenticated",
           *interceptors)
    wait_for_port(port)
    time.sleep(3)  # the gateway lists the fixture's tools after it starts listening


def calls(port: int) -> list[dict]:
    client = SseClient(f"http://127.0.0.1:{port}")
    client.call(1, "initialize", initialize_params())
    client.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return [client.call(2, "tools/call", {"name": "read_order", "arguments": {"id": "7"}}),
            client.call(3, "tools/call", {"name": "delete_order", "arguments": {"id": "7"}}),
            client.call(4, "tools/call", {"name": "read_order", "arguments": {"id": "inject"}})]


def run_docker(work: Path, capture: Path | None) -> None:
    fixture = work / "fixture"
    fixture.mkdir()
    (fixture / "server.py").write_bytes(SERVER.read_bytes())
    (fixture / "Dockerfile").write_text(f'FROM {PYTHON_IMAGE}\nCOPY server.py /server.py\n'
                                        'ENTRYPOINT ["python3", "-I", "/server.py", "--stdio"]\n', encoding="utf-8")
    docker("build", "-q", "-t", FIXTURE_IMAGE, str(fixture))
    write_export("docker-mcp-gateway", work / "export")
    docker("build", "-q", "-t", GUARD_IMAGE, str(work / "export" / "docker-mcp-gateway"))
    catalogs = work / "catalogs"
    catalogs.mkdir()
    (catalogs / "spellwarden-fixture.yaml").write_text(CATALOG, encoding="utf-8")
    if capture is not None:
        copies = work / "copies"
        copies.mkdir(mode=0o777)
        port = free_port()
        try:
            gateway("spellwarden-gateway-capture", port, catalogs,
                    ["--interceptor=before:exec:cat > /copies/before-$$.json", "--interceptor=after:exec:cat > /copies/after-$$.json"],
                    (f"{copies}:/copies",))
            calls(port)
        finally:
            subprocess.run(["docker", "rm", "-f", "spellwarden-gateway-capture"], capture_output=True)
        write_captures(copies, capture)
    port = free_port()
    try:
        gateway("spellwarden-gateway-check", port, catalogs, docker_gateway.interceptor_flags(docker_gateway.IMAGE_GUARD))
        read, delete, injected = calls(port)
        check(first_text(read) == "Order 7: shipped.", "read_order is answered")
        check((delete.get("result") or {}).get("isError") is True and BLOCKED in first_text(delete),
              "delete_order is answered with the guard's error result")
        check(INJECTION_REPLACED in first_text(injected) and "Ignore all previous" not in json.dumps(injected),
              "a result holding an injection phrase is replaced")
        logs = docker("logs", "spellwarden-gateway-check")
        check("Order 7" not in "\n".join(line for line in logs.splitlines() if "spellwarden:" in line),
              "the guard's log lines hold no argument or result")
    finally:
        subprocess.run(["docker", "rm", "-f", "spellwarden-gateway-check"], capture_output=True)


def write_captures(copies: Path, out: Path) -> None:
    """The six copies, named by what they hold: `before-<tool>[-inject].json` and `after-<tool>[-inject].json`."""
    out.mkdir(parents=True, exist_ok=True)
    for path in sorted(copies.glob("*.json")):
        message = json.loads(path.read_text(encoding="utf-8"))
        phase = path.name.split("-", 1)[0]
        if phase == "before":
            params = message.get("Params") or message.get("params") or {}
            name = f"before-{params.get('name')}{'-inject' if params.get('arguments', {}).get('id') == 'inject' else ''}"
        else:
            text = first_text({"result": message})
            name = "after-" + ("inject" if "Ignore all previous" in text else "deleted" if "deleted" in text else "read_order")
        (out / f"{name}.json").write_bytes(path.read_bytes())
    print(f"wrote the captured interceptor input to {out}")


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 5) or argv[1] not in ("toolhive", "docker") or (len(argv) == 5 and argv[3] != "--capture"):
        print(__doc__, file=sys.stderr)
        return 2
    work = Path(argv[2]).resolve()
    if not work.is_dir() or any(work.iterdir()):
        print(f"{work} must be an existing, empty directory", file=sys.stderr)
        return 2
    try:
        if argv[1] == "toolhive":
            run_toolhive(work)
        else:
            run_docker(work, Path(argv[4]).resolve() if len(argv) == 5 else None)
    except CheckFailed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
