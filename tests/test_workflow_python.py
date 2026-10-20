"""The workflows' Python (review finding r1:F1 of the 1.0.0 build): astral-sh/setup-uv with `python-version`
activates a uv virtual environment, which has no pip, and puts it first on PATH. After such a step a job may call
pip only through an interpreter named explicitly (setup-python's `python-path` output)."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BARE_PIP = re.compile(r"(?<![\w\"$/.-])python3?\s+-m\s+pip\b")


def _step_lists():
    for path in sorted((ROOT / ".github").rglob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if "runs" in document:
            yield path, "runs", document["runs"].get("steps") or []
        for name, job in (document.get("jobs") or {}).items():
            yield path, name, job.get("steps") or []


def test_no_bare_pip_after_a_uv_environment_is_activated():
    problems = []
    for path, name, steps in _step_lists():
        activated = False
        for step in steps:
            uses = str(step.get("uses", ""))
            if uses.startswith("astral-sh/setup-uv@") and "python-version" in (step.get("with") or {}):
                activated = True
            if activated and BARE_PIP.search(str(step.get("run", ""))):
                problems.append(f"{path.relative_to(ROOT)}: {name}: {step.get('name') or step.get('id') or 'a step'}")
    assert problems == []


def test_the_rule_sees_the_defect_it_guards():
    assert BARE_PIP.search("python3 -m pip download x") and BARE_PIP.search("python -m pip download x")
    assert not BARE_PIP.search('"$SETUP_PYTHON" -m pip download x')
