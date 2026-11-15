"""1.15.0: the pieces of the release workflow's gateway check that run anywhere (phase 3 batch 2b spec 10.9): the fixture MCP
server answers as the check expects, and `tests/gateway_ci.py` refuses bad arguments before it touches Docker or the network.
The gateways themselves run only in the `gateway-exports` job (Linux with Docker)."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = _module("gateway_fixture_server", ROOT / "tests" / "fixtures" / "gateways" / "server.py")
gateway_ci = _module("gateway_ci", ROOT / "tests" / "gateway_ci.py")


def call(name: str, order: str) -> str:
    reply = server.answer({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": name, "arguments": {"id": order}}})
    return reply["result"]["content"][0]["text"]


def test_the_fixture_server_lists_two_tools_and_answers_each():
    listed = server.answer({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert [tool["name"] for tool in listed["result"]["tools"]] == ["read_order", "delete_order"]
    assert call("read_order", "7") == "Order 7: shipped."
    assert call("delete_order", "7") == "Order 7 deleted."
    assert "Ignore all previous instructions" in call("read_order", "inject")
    assert server.answer({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.answer({"jsonrpc": "2.0", "id": 9, "method": "resources/read"})["error"]["code"] == -32601


def test_the_check_refuses_bad_arguments_and_a_directory_that_is_not_empty(tmp_path):
    assert gateway_ci.main(["gateway_ci.py"]) == 2
    assert gateway_ci.main(["gateway_ci.py", "kong", str(tmp_path)]) == 2
    assert gateway_ci.main(["gateway_ci.py", "docker", str(tmp_path), "--keep", "x"]) == 2
    (tmp_path / "left").write_text("x", encoding="utf-8")
    assert gateway_ci.main(["gateway_ci.py", "toolhive", str(tmp_path)]) == 2


def test_the_pinned_downloads_are_pinned_by_digest():
    assert re.fullmatch(r"[0-9a-f]{64}", gateway_ci.THV_SHA256)
    assert gateway_ci.THV_URL.endswith("/v0.65.0/toolhive_0.65.0_linux_amd64.tar.gz")
    assert re.fullmatch(r"python:3\.13-alpine@sha256:[0-9a-f]{64}", gateway_ci.PYTHON_IMAGE)
