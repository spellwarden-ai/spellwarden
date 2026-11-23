"""Records what the released 1.19.0 writes, so 1.20.0 can be held to it (Engine 1.20.0: scan selection, C40, C41). Run it from the
repository root of a clone that holds the tag v1.19.0 (`git fetch --tags` if it does not), once the fixture trees of 1.20.0 are
final:

    uv run --locked python tests/golden/record_release_1_19_0.py

It takes `src/` of the tag with `git archive` (the source the PyPI release was built from) and, for each root of
`record_1_17_0.scan_roots()` (this release's fixture trees), copies the fixture into a fresh git repository and runs that source in
a subprocess, once, in the seven formats. It writes tests/golden/1.19.0/outputs.json: per root the exit code, the SHA-256 of each
report (`fixture_reports.as_version`) and, from the JSON report, the items and findings (`summary`), which tests/test_golden_1_19_0.py
compares where 1.20.0 reads more. It also writes tests/golden/1.19.0/homes.json: for each system, the JSON report of `scan --user`
over the fixture home (common plus the system's, `tests/cli/homes.make_home`) by the released `userscan.scan` with that system's
`sys.platform`, without the two versions (`normalised_home_report`)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GOLDEN = HERE / "1.19.0"
RELEASE_TAG = "v1.19.0"
RECORDED_VERSION = "1.19.0"
# Fixture roots added after 1.19.0: not in the record, which was taken from 1.20.0's fixture trees at its release.
# `fixtures/repos/follow-links/repo` is the wrappers' case for their `follow-links` input, added with their 1.20.0 release.
ADDED_AFTER_1_19_0: tuple[str, ...] = ("fixtures/repos/follow-links/repo",)
HOME_AS_OF = "2026-11-23"
PLATFORMS = {"linux": "linux", "macos": "darwin", "windows": "win32"}
# The released `scan --user`, run with the released source first on the path; argv: the home, the platform and the date.
_USER_SCAN = ("import sys\n"
              "from datetime import date\n"
              "from spellwarden_cli import userscan\n"
              "from spellwarden_cli.output import json_out\n"
              "from spellwarden_cli.settings import Settings\n"
              "report, _ = userscan.scan(sys.argv[1], sys.argv[2], {}, settings=Settings(telemetry=False),\n"
              "                          as_of=date.fromisoformat(sys.argv[3]), inventory=False)\n"
              "sys.stdout.write(json_out.render(report))\n")


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous = _module("record_1_17_0", HERE / "record_1_17_0.py")
release_1_18_0 = _module("record_release_1_18_0", HERE / "record_release_1_18_0.py")
homes = _module("homes", HERE.parent / "cli" / "homes.py")
reports = previous.reports
scan_roots = previous.scan_roots
digest = previous.digest


def summary(json_report: bytes) -> dict:
    """The items (`[kind, path, plugin or ""]`) and findings (`[rule_id, fingerprint, item]`) of a JSON report, sorted."""
    document = json.loads(json_report.decode("utf-8"))
    return {"items": sorted([item["kind"], item["path"], item["plugin"] or ""] for item in document["items"]),
            "findings": sorted([finding["rule_id"], finding["fingerprint"], finding["item"]] for finding in document["findings"])}


def normalised_home_report(text: str) -> dict:
    """A `scan --user` JSON report without the scanner's version and the rules version, which the comparison leaves out."""
    document = json.loads(text)
    document.pop("scanner_version", None)
    document.pop("rules_version", None)
    return document


def home_report_released(source: Path, base: Path, system: str) -> dict:
    home = homes.make_home(base, system)
    done = subprocess.run([sys.executable, "-c", _USER_SCAN, str(home), PLATFORMS[system], HOME_AS_OF], capture_output=True,
                          check=True, env={**reports.clean_environment(), "PYTHONPATH": str(source)}, cwd=base)
    return normalised_home_report(done.stdout.decode("utf-8"))


def record(ref: str = RELEASE_TAG) -> None:
    roots: dict[str, dict] = {}
    home_reports: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = previous.extract_release(ref, base / "release")
        version = previous.released_version(source)
        if version != RECORDED_VERSION:
            raise SystemExit(f"{ref} holds scanner {version}, not {RECORDED_VERSION}")
        for index, root in enumerate(scan_roots()):
            if root in ADDED_AFTER_1_19_0:
                continue
            work = base / str(index)
            code, outputs = release_1_18_0.render_released(source, reports.build_repo(root, work / "repo"), work / "out")
            roots[root] = {"exit_code": code, "outputs": {
                fmt: digest(reports.as_version(fmt, data, RECORDED_VERSION, RECORDED_VERSION)) for fmt, data in outputs.items()},
                **summary(outputs["json"])}
        for system in PLATFORMS:
            work = base / f"home-{system}"
            work.mkdir()
            home_reports[system] = home_report_released(source, work, system)
    GOLDEN.mkdir(exist_ok=True)
    document = {"as_of": reports.AS_OF, "release_tag": ref, "scanner_version": RECORDED_VERSION, "roots": roots}
    (GOLDEN / "outputs.json").write_bytes((json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    homes_document = {"as_of": HOME_AS_OF, "release_tag": ref, "scanner_version": RECORDED_VERSION, "homes": home_reports}
    (GOLDEN / "homes.json").write_bytes((json.dumps(homes_document, indent=1, sort_keys=True) + "\n").encode("utf-8"))


if __name__ == "__main__":
    record()
