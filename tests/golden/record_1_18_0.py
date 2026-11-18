"""Records the golden files of what 1.18.0 adds. Run it from the repository root after a change, and review the diff:

    uv run --locked python tests/golden/record_1_18_0.py

tests/golden/1.18.0/html-escape.html is the HTML report of fixtures/html-escape, whose finding holds script and markup. Every
golden file holds the scanner version 1.18.0 whatever version the tree carries (`fixture_reports.as_version`). The tests import
the functions that make each one from here."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "1.18.0"
STORED_VERSION = "1.18.0"
HTML_FIXTURE = "fixtures/html-escape"


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reports = _module("fixture_reports", Path(__file__).resolve().parent / "fixture_reports.py")


def html_report(base: Path) -> str:
    from spellwarden_scan import __version__

    repo = reports.build_repo(HTML_FIXTURE, base / "repo")
    _, outputs = reports.render(repo, base / "out", formats=(("html", "report.html"),))
    return reports.as_version("html", outputs["html"], __version__, STORED_VERSION).decode("utf-8")


def record_html() -> None:
    GOLDEN.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        (GOLDEN / "html-escape.html").write_bytes(html_report(Path(tmp)).encode("utf-8"))


def main() -> int:
    record_html()
    return 0


if __name__ == "__main__":
    sys.exit(main())
