"""Writes `.pre-commit-hooks.yaml` (1.18.0; the entry `spellwarden scan --staged` since 1.19.0) from
`spellwarden_cli.discover.AGENT_CONTENT_REGEX`, so the hook's file filter and
the scanner's discovery never disagree; tests/test_pre_commit_hook.py compares the file with `render()`. Run it from the
repository root after a change to the filter:

    uv run --locked python scripts/write_hooks_yaml.py"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".pre-commit-hooks.yaml"
GUIDE_URL = "https://spellwarden.ai/docs/pre-commit?utm_source=github&utm_medium=readme&utm_campaign=pre-commit"


def render() -> str:
    from spellwarden_cli.discover import AGENT_CONTENT_REGEX

    if "'" in AGENT_CONTENT_REGEX:
        raise ValueError("the filter must not hold a single quote: it is written as a single-quoted YAML scalar")
    return (f"# Spellwarden for the pre-commit framework: {GUIDE_URL}\n"
            "# Written by scripts/write_hooks_yaml.py from spellwarden_cli.discover.AGENT_CONTENT_REGEX. Do not edit by hand.\n"
            "- id: spellwarden\n"
            "  name: Spellwarden (scan agent skills, MCP configuration and hooks)\n"
            "  description: Scans the repository's agent content when it changes.\n"
            "  entry: spellwarden scan --staged\n"
            "  language: python\n"
            "  pass_filenames: false\n"
            "  require_serial: true\n"
            f"  files: '{AGENT_CONTENT_REGEX}'\n"
            "  stages: [pre-commit, pre-push, manual]\n"
            '  minimum_pre_commit_version: "3.2.0"\n')


def main() -> int:
    TARGET.write_bytes(render().encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
