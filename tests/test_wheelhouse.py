"""O4 spec 7 and claim B2: the steps that fill the image's wheelhouse ask pip for the platform tags and the `abi3` wheels that
`cryptography` ships (`cp311-abi3`, tagged `manylinux_2_17`, `manylinux_2_28` or `manylinux_2_34` by release). The wheelhouse
of `check.yml` is for x86_64 only, the one of `release.yml` for both architectures."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _pip_downloads(workflow: str) -> list[str]:
    """Every `pip download ... --platform ...` command of a workflow, folded into one line."""
    found = []
    for job in yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))["jobs"].values():
        for step in job.get("steps", []):
            run = re.sub(r"\\\n\s*", " ", str(step.get("run", "")))
            found += [line for line in run.splitlines() if "pip download" in line and "--platform" in line]
    return found


def test_each_wheelhouse_command_names_abi3_and_the_four_manylinux_tags_of_its_architecture():
    cases = {"release.yml": ("${arch}",), "check.yml": ("x86_64",)}
    for workflow, arches in cases.items():
        commands = _pip_downloads(workflow)
        assert len(commands) == 1, workflow
        command = commands[0]
        assert "--abi cp313" in command and "--abi abi3" in command and "--python-version 3.13" in command, workflow
        for arch in arches:
            for tag in (f"manylinux_2_17_{arch}", f"manylinux2014_{arch}", f"manylinux_2_28_{arch}", f"manylinux_2_34_{arch}"):
                assert f"--platform {tag}" in command or f'--platform "{tag}"' in command, (workflow, tag)
        assert "--only-binary :all:" in command and "--require-hashes" in command and "--no-deps" in command
