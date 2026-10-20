"""Records the 1.0.0 golden files of spec 6.14. Run it once, at version 1.0.0, from the repository root:

    uv run --locked python tests/golden/record_1_0_0.py

It writes tests/golden/1.0.0/repo/.spellwarden/baseline.yml (accepting the SW-CFG-001 finding) and lock.json,
the five reports under tests/golden/1.0.0/out/, and frozen copies of the four schemas under
tests/golden/1.0.0/schemas/. tests/test_golden_1_0_0.py imports `build_repo` and `scan` from here."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "1.0.0"
ROOT = GOLDEN.parents[2]
AS_OF = "2027-01-15"
OUTPUTS = (("json", "report.json"), ("sarif", "report.sarif"), ("markdown", "report.md"),
           ("gitlab-codequality", "gl-code-quality-report.json"), ("text", "report.txt"))
SCHEMAS = ("settings", "baseline", "lock", "report")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "user.name=golden", "-c", "user.email=golden@example.invalid",
                    *args], cwd=repo, check=True, capture_output=True)


def build_repo(dest: Path) -> Path:
    """A git repository holding a copy of tests/golden/1.0.0/repo, committed."""
    shutil.copytree(GOLDEN / "repo", dest)
    _git(dest, "init", "-q")
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m", "golden")
    return dest


def scan(repo: Path, out: Path, *, locked: bool = True) -> int:
    from spellwarden_cli.main import main

    argv = ["scan", str(repo), "--as-of", AS_OF, "--no-telemetry"]
    if locked:
        argv.append("--locked")
    for fmt, name in OUTPUTS:
        argv += ["--format", fmt, "--output", str(out / name)]
    return main(argv)


def record() -> None:
    from spellwarden_cli.baseline import Entry, render_baseline
    from spellwarden_cli.main import main

    state = GOLDEN / "repo" / ".spellwarden"
    for name in ("baseline.yml", "lock.json"):
        (state / name).unlink(missing_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "first"
        out.mkdir()
        scan(build_repo(Path(tmp) / "a"), out, locked=False)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        target = [f for f in report["findings"] if f["rule_id"] == "SW-CFG-001"]
        assert len(target) == 1, target
        entry = Entry(fingerprint=target[0]["fingerprint"], rule="SW-CFG-001", path=".mcp.json",
                      reason="Internal test server on the private staging network.",
                      added=date(2027, 1, 10), expires=date(2027, 4, 10))
        (state / "baseline.yml").write_bytes(render_baseline([entry]))

        repo = build_repo(Path(tmp) / "b")
        assert main(["lock", str(repo)]) == 0
        shutil.copyfile(repo / ".spellwarden" / "lock.json", state / "lock.json")

        recorded = GOLDEN / "out"
        shutil.rmtree(recorded, ignore_errors=True)
        recorded.mkdir()
        code = scan(build_repo(Path(tmp) / "c"), recorded)
        print(f"recorded the golden reports; the scan exited {code}")

    frozen = GOLDEN / "schemas"
    frozen.mkdir(exist_ok=True)
    for name in SCHEMAS:
        shutil.copyfile(ROOT / "schemas" / f"{name}.schema.json", frozen / f"{name}.schema.json")


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "src"))
    record()
