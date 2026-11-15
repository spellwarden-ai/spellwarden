"""Shared by the tests of the gateway exports (1.15.0): the hooks export's own rule for a destructive MCP tool name, read from
the generated `spellwarden_guard.py` itself, so the ToolHive policies and the Docker MCP Gateway guard are held to the very
function the Claude Code hooks export runs."""
from __future__ import annotations

from collections.abc import Callable

from spellwarden_scan import baseline_pack
from spellwarden_scan.exports import hooks


def destructive_rule() -> Callable[[str], bool]:
    """`name -> bool`: `mcp_verb` of the hooks guard for a bare tool name (as the tool part of `mcp__server__<name>`)."""
    script = hooks.guard_script(baseline_pack(), mode="project").decode("utf-8")
    namespace: dict = {}
    exec(compile(script.replace('if __name__ == "__main__":', "if False:"), "spellwarden_guard.py", "exec"), namespace)  # noqa: S102 -- our own export
    mcp_verb = namespace["mcp_verb"]
    return lambda name: mcp_verb("mcp__server__" + name, hooks.MCP_VERBS)


def corpus(spelling: Callable[[str], str]) -> list[str]:
    """Tool names around every verb of SW-GW-006 in one spelling, and names that only look close."""
    names = ["read_order", "list-orders", "undelete", "x.delete", "xdelete", "predestroy_cache", "get_reset_token"]
    for verb in hooks.MCP_VERBS:
        word = spelling(verb)
        names += [word, f"{word}_order", f"{word}er", f"x_{word}", f"x-{word}", f"x_{word}_y", f"x_{word}-y", f"x-{word}_y",
                  f"x-{word}-y", f"x__{word}", f"un{word}", f"x.{word}", f"x{word}", f"_{word}", f"{word}-"]
    return names
