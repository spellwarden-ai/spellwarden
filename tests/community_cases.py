"""Helpers of the community corpus tests (docs/specs/2026-11-25-community-reports.md, section 11): the scripts loaded by their
path (`scripts/` is not in an sdist, so a test module checks `SCRIPTS` first and skips), synthetic records and cases built in a
temporary directory, and two small skills. Nothing here touches `fixtures/community/`: the real corpus starts with the first
real report."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

FRONT = "---\nname: community-sample\ndescription: A small harmless sample for the community corpus tests.\nlicense: MIT\nversion: 1.0.0\n---\n"
PIP_SKILL = FRONT + "# Sample\n\n```bash\npip install requests\n```\n"  # SW-SKL-009
CLEAN_SKILL = FRONT + "# Sample\n\nSay hello to the user.\n"  # no finding of SW-SKL-009


def load_script(filename: str, name: str):
    """`scripts/<filename>` loaded by its path under `name`, the way tests/test_check_rule_pages.py loads its script."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def rule_areas() -> dict[str, str]:
    from spellwarden_scan import RuleSet

    return {rule.id: rule.area for rule in RuleSet.baseline()}


def record(case_id: str = "COM-0001", **changes) -> dict:
    """A good record (6.2); keyword arguments replace members."""
    value = {"id": case_id, "kind": "miss", "rule": "SW-SKL-009", "kept_hosts": [],
             "reported_against": {"scanner": "1.23.0", "rules": "2026.11.9"}, "outcome": "open", "fixed_in": None,
             "credit": None, "date": "2026-11-26", "issue": 68}
    value.update(changes)
    return value


def write_case(root: Path, case_id: str = "COM-0001", files: dict[str, str | bytes] | None = None, **changes) -> Path:
    """Writes `<root>/<case_id>/record.json` (canonical form) and `files/`, byte for byte, and returns the case directory."""
    directory = root / case_id
    for path, content in (files if files is not None else {"SKILL.md": PIP_SKILL}).items():
        target = directory.joinpath("files", *path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    text = json.dumps(record(case_id, **changes), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (directory / "record.json").write_bytes(text.encode("utf-8"))
    return directory


def write_manifest(path: Path, *, test: list[bytes] = (), tuning: list[bytes] = ()) -> Path:
    """A benchmark manifest with the two members the corpus reads: sets with roles and items with the hashes and sizes of their
    files. Real manifests hold no text, and neither does this."""
    import hashlib

    def item(name: str, set_id: str, data: bytes) -> dict:
        entry = {"path": "SKILL.md", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        return {"id": name, "set": set_id, "stratum": "m", "roots": [{"package_sha256": "0" * 64, "files": [entry]}]}

    items = [item(f"t{number}", "alpha", data) for number, data in enumerate(test)]
    items += [item(f"u{number}", "beta", data) for number, data in enumerate(tuning)]
    document = {"sets": {"alpha": {"role": "test"}, "beta": {"role": "tuning"}}, "items": items}
    path.write_text(json.dumps(document), encoding="utf-8")
    return path
