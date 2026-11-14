"""Records the 1.13.0 reports of the repository scan that 1.14.0 must keep byte for byte (phase 3 batch 2a spec 11.5, T-8).
Run it once, at version 1.13.0, from the repository root, before any 1.14.0 change:

    uv run --locked python tests/golden/record_1_13_0.py

It scans a committed copy of tests/golden/1.13.0/repo and writes the five reports under tests/golden/1.13.0/out/.
tests/test_golden_1_13_0.py imports `build_repo`, `scan` and `as_recorded` from here."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "1.13.0"
ROOT = GOLDEN.parents[2]
AS_OF = "2026-11-14"
RECORDED_VERSION = "1.13.0"
OUTPUTS = (("json", "report.json"), ("sarif", "report.sarif"), ("markdown", "report.md"),
           ("gitlab-codequality", "gl-code-quality-report.json"), ("text", "report.txt"))


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "user.name=golden", "-c", "user.email=golden@example.invalid",
                    "-c", "commit.gpgsign=false", *args], cwd=repo, check=True, capture_output=True)


def build_repo(dest: Path) -> Path:
    """A git repository holding a copy of tests/golden/1.13.0/repo, committed."""
    shutil.copytree(GOLDEN / "repo", dest)
    _git(dest, "init", "-q")
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m", "golden")
    return dest


def scan(repo: Path, out: Path) -> int:
    from spellwarden_cli.main import main

    argv = ["scan", str(repo), "--as-of", AS_OF, "--no-telemetry", "--quiet"]
    for fmt, name in OUTPUTS:
        argv += ["--format", fmt, "--output", str(out / name)]
    return main(argv)


def as_recorded(text: str, version: str) -> str:
    """`text` with the three places a report names the scanner version (the JSON field, the SARIF driver and the Markdown
    footer) set back to 1.13.0; the text and Code Quality reports name no version."""
    for template in ('"scanner_version": "{}"', '"semanticVersion": "{}"', "Spellwarden {}, rules"):
        text = text.replace(template.format(version), template.format(RECORDED_VERSION))
    return text


def record() -> None:
    from spellwarden_scan import __version__

    assert __version__ == RECORDED_VERSION, "record the goldens at 1.13.0, before any 1.14.0 change"
    recorded = GOLDEN / "out"
    shutil.rmtree(recorded, ignore_errors=True)
    recorded.mkdir()
    with tempfile.TemporaryDirectory() as tmp:
        code = scan(build_repo(Path(tmp) / "repo"), recorded)
    print(f"recorded the 1.13.0 reports; the scan exited {code}")


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "src"))
    record()
