"""The files the Node tests of the Zuplo export run against (Zuplo export spec 4.7):

    uv run --locked python tests/zuplo_ci.py write DIR

writes `DIR/guard/spellwarden-mcp-guard.ts` and `DIR/guard/spellwarden-zuplo-check.mjs`, the two files of the export that are
the same for every pack. The Node tests read DIR from the environment variable SPELLWARDEN_ZUPLO_DIR. Nothing here opens
the network."""
from __future__ import annotations

import sys
from pathlib import Path

from spellwarden_scan.exports.zuplo_guard import CHECK_MJS, GUARD_TS


def write(out: Path) -> None:
    (out / "guard").mkdir(parents=True, exist_ok=True)
    (out / "guard" / "spellwarden-mcp-guard.ts").write_bytes(GUARD_TS.encode("ascii"))
    (out / "guard" / "spellwarden-zuplo-check.mjs").write_bytes(CHECK_MJS.encode("ascii"))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "write":
        raise SystemExit("usage: python tests/zuplo_ci.py write DIR")
    write(Path(sys.argv[2]))
    print("wrote", sys.argv[2])
