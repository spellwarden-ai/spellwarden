"""The fixture homes of `scan --user` (phase 3 batch 2a spec 11.1, T-1): `tests/fixtures/homes/common` holds the files every
system shares and `linux`, `macos` and `windows` the ones whose place differs. `make_home` copies both into a new home and
writes the home's own path where a client's file names an absolute path (`{{HOME}}`), so the projects and plugin directories
inside the home are inside it on every system that runs the tests. Every secret place holds a canary (`CANARIES`)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

HOMES = Path(__file__).resolve().parents[1] / "fixtures" / "homes"
SYSTEMS = ("linux", "macos", "windows")
# One value per kind of secret place (T-4); `BEARER` is the value of the variable a Codex server names in `bearer_token_env_var`,
# which the scan's environment holds and the scanner never reads.
CANARIES = ("CANARY-ENV-VALUE", "CANARY-HEADER-VALUE", "CANARY-USERINFO", "CANARY-QUERY", "CANARY-FRAGMENT", "CANARY-ARGUMENT",
            "CANARY-HOOK-LINE", "CANARY-BEARER-VALUE")
BEARER = {"REMOTE_TOKEN": "CANARY-BEARER-VALUE"}


def make_home(base: Path, system: str) -> Path:
    home = base / "home"
    for layer in ("common", system):
        shutil.copytree(HOMES / layer, home, dirs_exist_ok=True)
    escaped = json.dumps(str(home))[1:-1]
    for path in home.rglob("*.json"):
        text = path.read_bytes().decode("utf-8")
        if "{{HOME}}" in text:
            path.write_bytes(text.replace("{{HOME}}", escaped).encode("utf-8"))
    return home
