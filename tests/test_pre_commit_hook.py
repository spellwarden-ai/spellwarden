"""1.18.0 (E-1, E-2): the hook definition of the pre-commit framework. `.pre-commit-hooks.yaml` is the file
scripts/write_hooks_yaml.py writes, holds the keys of the hook, links the guide with its campaign tags, and its file filter is
`discover.AGENT_CONTENT_REGEX`, which matches every kind of path of the README's tables and no ordinary source file. The CI job
`pre-commit-hook` runs on Linux and Windows only. With SPELLWARDEN_PRE_COMMIT_TRY_REPO=1 (that job: the framework installs the
hook's environment from the network) the hook runs through `pre-commit try-repo` in a fixture repository: one with a high
finding fails (exit 1), a clean one passes (exit 0)."""
from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from spellwarden_cli.discover import AGENT_CONTENT_REGEX

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("write_hooks_yaml", ROOT / "scripts" / "write_hooks_yaml.py")
hooks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hooks)
HOOKS_FILE = ROOT / ".pre-commit-hooks.yaml"
GUIDE = "https://spellwarden.ai/docs/pre-commit?utm_source=github&utm_medium=readme&utm_campaign=pre-commit"
TRY_REPO = os.environ.get("SPELLWARDEN_PRE_COMMIT_TRY_REPO") == "1"
AGENT_PATHS = ("SKILL.md", "a/b/SKILL.md", "skills/x/skill.md", "skills/deploy/scripts/run.sh", ".claude/skills/hello/SKILL.md",
               ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".MCP.json", ".vscode/mcp.json",
               ".cursor/mcp.json", "claude_desktop_config.json", ".codex/config.toml", ".claude-plugin/marketplace.json",
               "plugins/infra/.claude-plugin/plugin.json", "plugins/infra/hooks/hooks.json", "plugins/infra/.mcp.json",
               "AGENTS.md", "docs/CLAUDE.md", "GEMINI.md", "sub/agents.md", ".github/copilot-instructions.md", ".cursorrules",
               ".windsurfrules", ".cursor/rules/x.mdc", ".windsurf/rules/a.md", "sub/.devin/rules/b.md",
               ".well-known/agent-card.json", ".well-known/agent.json", "deploy/agent/agent-card.json",
               ".spellwarden/config.yml", ".spellwarden/lock.json", ".spellwarden/baseline.yml")
OTHER_PATHS = ("src/main.py", "README.md", "docs/notes.md", "skillset/x.py", "my-skills.md", "package.json", "hooks.json",
               ".github/workflows/check.yml", "agent.json")
# Variables that would make the scanner think it runs in CI (and ping), as tests/cli/conftest.py
_SCRUBBED_PREFIXES = ("GITHUB_", "GITLAB_", "CI_", "SPELLWARDEN_", "RUNNER_")
_SCRUBBED = ("CI", "GITLAB_CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD", "TEAMCITY_VERSION", "BUILDKITE", "CIRCLECI",
             "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "DRONE", "TRAVIS")


def test_the_hooks_file_is_the_one_the_script_writes():
    assert HOOKS_FILE.read_bytes().replace(b"\r\n", b"\n").decode("utf-8") == hooks.render()


def test_the_hook_holds_the_keys_of_the_definition():
    (hook,) = yaml.safe_load(HOOKS_FILE.read_text(encoding="utf-8"))
    assert hook == {"id": "spellwarden", "name": "Spellwarden (scan agent skills, MCP configuration and hooks)",
                    "description": "Scans the repository's agent content when it changes.",
                    "entry": "spellwarden scan --no-upload", "language": "python", "pass_filenames": False,
                    "require_serial": True, "files": AGENT_CONTENT_REGEX, "stages": ["pre-commit", "pre-push", "manual"],
                    "minimum_pre_commit_version": "3.2.0"}


def test_the_first_line_links_the_guide_with_the_campaign_tags():
    assert HOOKS_FILE.read_text(encoding="utf-8").splitlines()[0] == f"# Spellwarden for the pre-commit framework: {GUIDE}"
    assert hooks.GUIDE_URL == GUIDE


@pytest.mark.parametrize("path", AGENT_PATHS)
def test_the_filter_matches_every_kind_of_agent_content(path):
    assert re.search(AGENT_CONTENT_REGEX, path), path


@pytest.mark.parametrize("path", OTHER_PATHS)
def test_the_filter_leaves_ordinary_files_out(path):
    assert re.search(AGENT_CONTENT_REGEX, path) is None, path


def test_the_ci_job_runs_the_hook_on_linux_and_windows_only():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "check.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["pre-commit-hook"]
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "windows-latest"]
    steps = job["steps"]
    assert steps[0]["run"] == "git config --global core.autocrlf false"
    for step in steps:
        if "uses" in step:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
    (try_repo,) = [step for step in steps if (step.get("env") or {}).get("SPELLWARDEN_PRE_COMMIT_TRY_REPO") == "1"]
    assert "tests/test_pre_commit_hook.py" in try_repo["run"]


def _hook_environment(tmp_path: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key not in _SCRUBBED and not key.startswith(_SCRUBBED_PREFIXES)}
    env.update({"PRE_COMMIT_HOME": str(tmp_path / "pre-commit-home"), "DO_NOT_TRACK": "1", "PYTHONIOENCODING": "utf-8",
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})
    return env


@pytest.mark.skipif(not TRY_REPO, reason="installs the hook's environment from the network: the CI job pre-commit-hook sets "
                                         "SPELLWARDEN_PRE_COMMIT_TRY_REPO=1")
@pytest.mark.parametrize("case, expected", [("findings", 1), ("clean", 0)])
def test_the_hook_runs_through_the_pre_commit_framework(case, expected, tmp_path):
    env = _hook_environment(tmp_path)
    repo = tmp_path / case
    subprocess.run([sys.executable, str(ROOT / "fixtures" / "repos" / "make_repo.py"), case, str(repo)], check=True, env=env,
                   capture_output=True)
    done = subprocess.run([sys.executable, "-m", "pre_commit", "try-repo", str(ROOT), "spellwarden", "--all-files"], cwd=repo,
                          env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    assert done.returncode == expected, done.stdout + done.stderr
    assert "Spellwarden (scan agent skills, MCP configuration and hooks)" in done.stdout
    assert ("Failed" if expected else "Passed") in done.stdout
