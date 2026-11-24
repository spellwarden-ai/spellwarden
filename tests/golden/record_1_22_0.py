"""Records the golden files of what 1.22.0 changes (P6-4 spec 6.9): the seven reports of `fixtures/skills/SW-SKL-032/positive`, the
one fixture whose findings the normalised reading of the skill rules changes (it adds SW-SKL-007 at line 26, where a base64 text
decodes to a download piped to a shell). Run it from the repository root after a change, and review the diff:

    uv run --locked python tests/golden/record_1_22_0.py

Every file holds the scanner version 1.22.0 whatever version the tree carries (`fixture_reports.as_version`).
tests/test_golden_1_22_0.py imports `outputs` from here."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "1.22.0" / "disguised"
STORED_VERSION = "1.22.0"
FIXTURE = "fixtures/skills/SW-SKL-032/positive"


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reports = _module("fixture_reports", Path(__file__).resolve().parent / "fixture_reports.py")


def outputs(base: Path) -> tuple[int, dict[str, str]]:
    """The exit code and the seven reports of the fixture, by file name, with the scanner version set to 1.22.0."""
    from spellwarden_scan import __version__

    code, written = reports.render(reports.build_repo(FIXTURE, base / "repo"), base / "out", formats=reports.ALL_FORMATS)
    names = dict(reports.ALL_FORMATS)
    return code, {names[fmt]: reports.as_version(fmt, data, __version__, STORED_VERSION).decode("utf-8")
                  for fmt, data in written.items()}


def main() -> int:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        _, written = outputs(Path(tmp))
    for name, text in written.items():
        (GOLDEN / name).write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
