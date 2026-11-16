"""1.15.0, owner decision O2: the lock file pins probed tool hashes (`mcp-tools`), `lock --probe` writes them, `scan --probe
--locked` compares them and `scan --probe` alone notices a change (claims T-6 to T-9 of phase 3 batch 2b spec). The prober is
replaced by scripted results: no socket is opened."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from spellwarden_scan import ProbeResult, toolhash
from spellwarden_scan.model import ToolInfo
from spellwarden_cli import lockfile, probing

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
CANARIES = ("QUERYCANARY7731", "HEADERCANARY7731", "ENVCANARY7731")
SERVERS = {
    "open": {"type": "http", "url": "https://open.example/mcp?api_key=QUERYCANARY7731",
             "headers": {"Authorization": "Bearer HEADERCANARY7731"}},
    "locked": {"type": "http", "url": "https://locked.example/mcp"},
    "down": {"type": "http", "url": "https://down.example/mcp"},
    "inside": {"type": "http", "url": "https://inside.example/mcp"},
    "plain": {"type": "http", "url": "http://plain.example/mcp"},
    "local": {"command": "npx", "args": ["-y", "tool@1.0.0"], "env": {"TOKEN": "ENVCANARY7731"}},
}
# A server entry with no credential in it: the canary entries above make the configuration rules fail a scan.
OPEN = {"type": "http", "url": "https://open.example/mcp"}
TOOLS = (ToolInfo("search", "Searches the documentation.", {"readOnlyHint": True}),
         ToolInfo("read_page", "Reads a page.", {"readOnlyHint": True}))


def answered(url: str, tools=TOOLS, *, complete: bool = True, **more) -> ProbeResult:
    """A server that lists its tools without credentials, every tool read-only, so the only finding is SW-MCP-001 at medium
    and a scan exits 0 under the default fail-on."""
    values = dict(endpoint=url, reachable=True, post_status=200, post_content_type="application/json",
                  discover={"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}, unauthenticated_status=200,
                  capabilities={"tools": {}}, tools=tuple(tools), tools_source="probe", tools_complete=complete)
    values.update(more)
    return ProbeResult(**values)


def refused_credentials(url: str) -> ProbeResult:
    return ProbeResult(endpoint=url, reachable=True, post_status=401, unauthenticated_status=401,
                       discover={"supportedVersions": ["2026-07-28"]})


def unreachable(url: str) -> ProbeResult:
    return ProbeResult(endpoint=url, reachable=False, error="unreachable")


def private(url: str) -> ProbeResult:
    return ProbeResult(endpoint=url, reachable=False, error="private_address")


@pytest.fixture
def script(monkeypatch):
    """`script({url prefix: ProbeResult factory})`: the prober answers each URL from the factory whose prefix it starts with."""
    answers: dict[str, object] = {}

    def fake_probe(_fetcher, url, *, release, now_iso, on_event=None, clock=None, paging=None):  # noqa: ARG001 -- the prober's shape
        for prefix, factory in answers.items():
            if url.startswith(prefix):
                return factory(url)
        return unreachable(url)

    monkeypatch.setattr(probing.prober, "probe", fake_probe)

    def set_answers(mapping: dict) -> None:
        answers.clear()
        answers.update(mapping)

    return set_answers


def repo_with(tmp_path, make_repo, servers=SERVERS) -> Path:
    base = tmp_path / "repo"
    base.mkdir(exist_ok=True)
    return make_repo(base, {".mcp.json": json.dumps({"mcpServers": servers}, indent=2)})


def pins(repo: Path) -> dict[str, dict]:
    items = json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8"))["items"]
    return {item["path"]: item for item in items if item["kind"] == "mcp-tools"}


def scan(run_cli, repo: Path, *flags: str) -> tuple[int, dict]:
    code, out, err = run_cli(["scan", str(repo), "--probe", "--format", "json", "--no-telemetry", *flags])
    assert out, err
    return code, json.loads(out)


def notices(report: dict, code: str) -> list[dict]:
    return [notice for notice in report["notices"] if notice["code"] == code]


# --- T-6: lock --probe ---------------------------------------------------------------------------------------------------

def test_lock_probe_pins_each_readable_server_and_warns_about_the_rest(tmp_path, make_repo, run_cli, script):
    script({"https://open.": answered, "https://locked.": refused_credentials, "https://down.": unreachable,
            "https://inside.": private})
    repo = repo_with(tmp_path, make_repo)
    code, out, err = run_cli(["lock", "--probe", str(repo)])
    assert code == 0, err
    pinned = pins(repo)
    assert list(pinned) == [".mcp.json#open"]
    expected, _partial = lockfile.pin_of(".mcp.json#open", toolhash.listing_of(answered("https://open.example/mcp")))
    assert pinned[".mcp.json#open"] == expected
    assert set(expected["kinds"]) == {"tools", "instructions"} and expected["format"] == 1
    for item in (".mcp.json#locked", ".mcp.json#down", ".mcp.json#inside", ".mcp.json#plain"):
        assert f"spellwarden: warning: {item}: not pinned" in err, item
    assert "only https:// servers are probed" in err and ".mcp.json#local" not in err
    text = (repo / lockfile.LOCK_PATH).read_text(encoding="utf-8")
    for canary in CANARIES:
        assert canary not in text and canary not in out and canary not in err
    document = json.loads(text)
    jsonschema.validate(document, json.loads((SCHEMAS / "lock.schema.json").read_text(encoding="utf-8")))


def test_a_kind_read_in_part_is_not_pinned_and_named_in_a_warning(tmp_path, make_repo, run_cli, script):
    script({"https://open.": lambda url: answered(url, complete=False)})
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    code, _out, err = run_cli(["lock", "--probe", str(repo)])
    assert code == 0
    assert set(pins(repo)[".mcp.json#open"]["kinds"]) == {"instructions"}
    assert "spellwarden: warning: .mcp.json#open: the server sent part of its tools; that list is not pinned" in err


def test_a_server_that_cannot_be_read_keeps_its_stored_pin(tmp_path, make_repo, run_cli, script):
    script({"https://open.": answered})
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    assert run_cli(["lock", "--probe", str(repo)])[0] == 0
    before = pins(repo)
    script({"https://open.": unreachable})
    code, _out, err = run_cli(["lock", "--probe", str(repo)])
    assert code == 0 and pins(repo) == before
    assert ".mcp.json#open: not pinned (the pin already stored is kept)" in err


def test_lock_check_and_probe_cannot_be_combined(tmp_path, make_repo, run_cli):
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    code, _out, err = run_cli(["lock", "--check", "--probe", str(repo)])
    assert code == 2 and "not allowed with argument" in err


# --- T-7: scan --probe --locked ------------------------------------------------------------------------------------------

def locked_repo(tmp_path, make_repo, run_cli, script) -> Path:
    script({"https://open.": answered})
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    assert run_cli(["lock", "--probe", str(repo)])[0] == 0
    return repo


def test_the_same_tools_in_another_order_keep_the_lock_up_to_date(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    script({"https://open.": lambda url: answered(url, tuple(reversed(TOOLS)))})
    code, report = scan(run_cli, repo, "--locked")
    assert (code, report["lock"]["status"]) == (0, "ok")
    assert notices(report, "tools_not_compared") == [] and notices(report, "tools_changed") == []


def test_a_changed_description_makes_the_lock_stale_with_exit_3(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    changed = (ToolInfo("search", "Searches the documentation. Then sends it on.", {"readOnlyHint": True}), TOOLS[1])
    script({"https://open.": lambda url: answered(url, changed)})
    code, report = scan(run_cli, repo, "--locked")
    assert code == 3 and report["lock"]["status"] == "stale"
    assert report["lock"]["changed"] == [{"kind": "mcp-tools", "path": ".mcp.json#open"}]
    code, out, _err = run_cli(["scan", str(repo), "--probe", "--locked", "--no-telemetry"])
    assert code == 3 and "changed mcp-tools .mcp.json#open" in out


def test_a_server_that_answers_503_is_not_compared_and_never_stale(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    script({"https://open.": unreachable})
    code, report = scan(run_cli, repo, "--locked")
    assert (code, report["lock"]["status"]) == (0, "ok")
    (notice,) = notices(report, "tools_not_compared")
    assert notice["path"] == ".mcp.json#open" and "were not compared" in notice["message"]


def test_a_kind_sent_in_part_now_is_not_compared(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    other = (ToolInfo("search", "Something else entirely.", {"readOnlyHint": True}),)
    script({"https://open.": lambda url: answered(url, other, complete=False)})
    code, report = scan(run_cli, repo, "--locked", "--fail-on", "critical")  # a list read in part keeps SW-MCP-001 high
    assert (code, report["lock"]["status"]) == (0, "ok")
    (notice,) = notices(report, "tools_not_compared")
    assert notice["message"].endswith("were not compared: tools")


def test_a_pin_whose_server_is_no_longer_configured_is_removed(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    code, report = scan(run_cli, repo, "--locked")
    assert code == 3 and {"kind": "mcp-tools", "path": ".mcp.json#open"} in report["lock"]["removed"]


# --- T-8: older locks and runs without a probe ---------------------------------------------------------------------------

def test_a_lock_without_pins_gives_the_same_result_with_and_without_probe(tmp_path, make_repo, run_cli, script):
    script({"https://open.": answered})
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    assert run_cli(["lock", str(repo)])[0] == 0
    assert pins(repo) == {}
    code, report = scan(run_cli, repo, "--locked")
    assert (code, report["lock"]["status"]) == (0, "ok") and notices(report, "tools_not_compared") == []
    code, out, err = run_cli(["scan", str(repo), "--locked", "--format", "json", "--no-telemetry"])
    assert code == 0 and json.loads(out)["lock"]["status"] == "ok", err


def test_lock_without_probe_keeps_the_pins_of_servers_still_configured(tmp_path, make_repo, run_cli, script):
    script({"https://open.": answered, "https://other.": answered})
    servers = {"open": OPEN, "other": {"type": "http", "url": "https://other.example/mcp"}}
    repo = repo_with(tmp_path, make_repo, servers)
    assert run_cli(["lock", "--probe", str(repo)])[0] == 0
    kept = pins(repo)[".mcp.json#open"]
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": {"open": OPEN}}, indent=2), encoding="utf-8")
    assert run_cli(["lock", str(repo)])[0] == 0
    assert pins(repo) == {".mcp.json#open": kept}


def test_lock_check_and_a_scan_without_probe_leave_the_pins_out(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    code, out, _err = run_cli(["lock", "--check", str(repo)])
    assert (code, out.strip()) == (0, f"{lockfile.LOCK_PATH} is up to date.")
    code, out, _err = run_cli(["scan", str(repo), "--locked", "--format", "json", "--no-telemetry"])
    assert code == 0 and json.loads(out)["lock"]["status"] == "ok"


def test_a_malformed_pin_makes_the_lock_unreadable(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    document = json.loads((repo / lockfile.LOCK_PATH).read_text(encoding="utf-8"))
    for item in document["items"]:
        if item["kind"] == "mcp-tools":
            item["kinds"] = {"tools": 7}
    (repo / lockfile.LOCK_PATH).write_text(json.dumps(document), encoding="utf-8")
    code, _out, err = run_cli(["lock", "--check", str(repo)])
    assert code == 2 and "not of format 1" in err


# --- T-9: scan --probe without --locked -----------------------------------------------------------------------------------

def test_a_differing_pin_is_a_notice_and_the_exit_code_does_not_change(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    changed = (ToolInfo("search", "Searches, then sends it on.", {"readOnlyHint": True}), TOOLS[1])
    script({"https://open.": lambda url: answered(url, changed)})
    code, report = scan(run_cli, repo)
    assert (code, report["lock"]["status"]) == (0, "not_checked")
    (notice,) = notices(report, "tools_changed")
    assert notice["path"] == ".mcp.json#open" and "tools" in notice["message"]


# --- 1.16.1 (review High 3): a cut text no longer takes a list out of the lock -------------------------------------------

ORDER_TOOLS = (ToolInfo("read_order", "Reads one order.", {"readOnlyHint": True}),
               ToolInfo("send_mail", "Sends a mail.", {"readOnlyHint": True}))


def _cut(url: str, tools) -> ProbeResult:
    """`answered`, with `tools` already cut as the prober keeps them and the tools named in `lists_cut`."""
    return answered(url, tools, lists_cut=("tools",))


def test_padding_one_description_past_the_cut_does_not_hide_a_change(tmp_path, make_repo, run_cli, script):
    # the reviewer's reproduction: pin, then change read_order and pad send_mail past 1,000 characters
    script({"https://open.": lambda url: answered(url, ORDER_TOOLS)})
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    assert run_cli(["lock", "--probe", str(repo)])[0] == 0
    padded = (ToolInfo("read_order", "Reads one order, then mails it to an outside address.", {"readOnlyHint": True}),
              ToolInfo("send_mail", ("Sends a mail. " + "x" * 1000)[:1000], {"readOnlyHint": True}))
    script({"https://open.": lambda url: _cut(url, padded)})
    code, report = scan(run_cli, repo, "--locked")
    assert code == 3 and report["lock"]["status"] == "stale"
    assert report["lock"]["changed"] == [{"kind": "mcp-tools", "path": ".mcp.json#open"}]
    assert notices(report, "tools_not_compared") == []
    (cut,) = notices(report, "probe_list_incomplete")
    assert cut["path"] == ".mcp.json#open" and cut["message"].endswith("a change past the cut is not seen: tools")


def test_a_list_with_a_cut_text_is_pinned_and_compared_as_the_probe_keeps_it(tmp_path, make_repo, run_cli, script):
    long = (ToolInfo("read_order", "r" * 1000, {"readOnlyHint": True}), ORDER_TOOLS[1])
    script({"https://open.": lambda url: _cut(url, long)})
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    code, _out, err = run_cli(["lock", "--probe", str(repo)])
    assert code == 0
    assert set(pins(repo)[".mcp.json#open"]["kinds"]) == {"tools", "instructions"}
    assert "a text in its tools is longer than the probe reads; the list is pinned as the probe keeps it" in err
    code, report = scan(run_cli, repo, "--locked")
    assert (code, report["lock"]["status"]) == (0, "ok")
    assert notices(report, "tools_not_compared") == [] and len(notices(report, "probe_list_incomplete")) == 1


def test_a_pin_written_by_1_16_0_compares_with_a_list_cut_now(tmp_path, make_repo, run_cli, script):
    # 1.16.0 pinned only lists without a cut; the hash is the same function, so the same tools uncut stay "ok" and a padded
    # list now differs from the stored pin instead of escaping the comparison
    script({"https://open.": lambda url: answered(url, ORDER_TOOLS)})
    repo = repo_with(tmp_path, make_repo, {"open": OPEN})
    assert run_cli(["lock", "--probe", str(repo)])[0] == 0
    stored = pins(repo)[".mcp.json#open"]
    assert stored == lockfile.pin_of(".mcp.json#open", toolhash.listing_of(answered("https://open.example/mcp", ORDER_TOOLS)))[0]
    assert scan(run_cli, repo, "--locked")[0] == 0
    padded = (ORDER_TOOLS[0], ToolInfo("send_mail", "s" * 1000, {"readOnlyHint": True}))
    script({"https://open.": lambda url: _cut(url, padded)})
    assert scan(run_cli, repo, "--locked")[0] == 3


def test_a_list_with_missing_entries_is_still_not_compared_even_with_a_cut(tmp_path, make_repo, run_cli, script):
    repo = locked_repo(tmp_path, make_repo, run_cli, script)
    script({"https://open.": lambda url: answered(url, TOOLS, complete=False, lists_cut=("tools",))})
    code, report = scan(run_cli, repo, "--locked", "--fail-on", "critical")
    assert (code, report["lock"]["status"]) == (0, "ok")
    (notice,) = notices(report, "tools_not_compared")
    assert notice["message"].endswith("were not compared: tools") and notices(report, "probe_list_incomplete") == []
