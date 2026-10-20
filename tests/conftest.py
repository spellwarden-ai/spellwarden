"""Shared helpers of the engine's tests. The engine does no I/O, so every
test builds its package in memory; the fixture directories under
`fixtures/` are read here, by the tests, never by the engine."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from spellwarden_scan.agentconfig import parse_document
from spellwarden_scan.model import ConfigDocument, ProbeResult

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SKILL_FIXTURES = FIXTURES / "skills"
PROBE_FIXTURES = FIXTURES / "probes"
CONFIG_FIXTURES = FIXTURES / "config"


def make_package(files: dict[str, str | bytes]) -> dict[str, bytes]:
    """`{path: text or bytes}` as the engine takes it (`Mapping[str, bytes]`)."""
    return {path: (content.encode("utf-8") if isinstance(content, str) else content) for path, content in files.items()}


def clean_md(name: str = "demo-skill", description: str = "A demo skill for the tests.", **more: str) -> str:
    """A SKILL.md whose frontmatter passes SW-SKL-015 and SW-SKL-031 (version and license present)."""
    fields = {"name": name, "description": description, "version": "1.0.0", "license": "Apache-2.0", **more}
    front = "\n".join(f"{key}: {value}" for key, value in fields.items())
    return f"---\n{front}\n---\n\n# {name}\n\nRead the task, then act.\n"


def credential(kind: str) -> str:
    """Credential-shaped strings built at runtime, so no literal in this
    repository looks like a key to a secret scanner."""
    if kind == "aws":
        return "AK" + "IA" + "ABCDEFGHIJKLMNOP"
    if kind == "github":
        return "gh" + "p_" + "A1b2C3d4" * 5
    if kind == "slack":
        return "xox" + "b-" + "1234567890-abcdefghij"
    if kind == "anthropic":
        return "sk-" + "ant-" + "api03-" + "x7y8z9" * 5
    if kind == "openai":
        return "sk-" + "A1b2C3d4E5f6G7h8" * 2
    if kind == "google":
        return "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
    if kind == "jwt":
        return "eyJ" + "a" * 24 + ".eyJ" + "b" * 24 + "." + "c" * 16
    if kind == "pem":
        return "-----BEGIN " + "RSA PRIVATE KEY-----"
    if kind == "gitlab":
        return "gl" + "pat-" + "abcdefghij1234567890ABCD"
    if kind == "github_pat":
        return "github_" + "pat_" + "11AAAAAAA0" + "bbbbbbbbbbbbbbbbbbbbbb"
    if kind == "password":
        return 'password = "' + "hunter2hunter2" + '"'
    raise ValueError(kind)


def _read_dir(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel == "expected.json":
            continue
        files[rel] = path.read_bytes()
    return files


def _generated_skl_011_positive() -> dict[str, bytes]:
    return make_package({
        "SKILL.md": clean_md("deploy-helper", "Deploys the service."),
        "scripts/deploy.sh": "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=" + credential("aws") + "\naws s3 sync . s3://bucket\n",
    })


def _generated_skl_002_positive() -> dict[str, bytes]:
    return make_package({"SKILL.md": clean_md() + "Run the\u200b command.\n"})


def _generated_skl_002_negative() -> dict[str, bytes]:
    return make_package({"SKILL.md": "\ufeff" + clean_md() + "Plain text only.\n"})


# Fixtures that must not exist on disk as literals (credential-shaped or invisible text): built at test time.
GENERATED: dict[str, object] = {
    "SW-SKL-011/positive": _generated_skl_011_positive,
    "SW-SKL-002/positive": _generated_skl_002_positive,
    "SW-SKL-002/negative": _generated_skl_002_negative,
}


def load_skill_fixture(rule_id: str, side: str) -> tuple[dict[str, bytes], dict]:
    """The package of `fixtures/skills/<rule-id>/<side>/` and its `expected.json`
    (`{"findings": [{"rule_id", "severity", "path", "line"}], "root"?: str}`: the complete finding
    set the scan must report for the fixture, every rule included)."""
    directory = SKILL_FIXTURES / rule_id / side
    expected = json.loads((directory / "expected.json").read_text())
    generator = GENERATED.get(f"{rule_id}/{side}")
    files = generator() if generator is not None else _read_dir(directory)
    return files, expected


def _generated_cfg_002_positive() -> dict[str, bytes]:
    servers = {"mcpServers": {
        "github": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server:v1.2.0"],
                   "env": {"GITHUB_TOKEN": credential("github")}},
        "search": {"type": "http", "url": "https://search.example.com/mcp", "headers": {"Authorization": "Bearer " + "q7" * 8}},
        "cloud": {"command": "node", "args": ["server.js", "--key", credential("aws")]},
    }}
    return {".mcp.json": json.dumps(servers, indent=2).encode()}


def _generated_cfg_010_positive() -> dict[str, bytes]:
    servers = {"mcpServers": {
        "crm": {"command": "node", "args": ["server.js", "--api-key=" + "plain" + "value1"],
                "env": {"CRM_API_TOKEN": "plain" + "value2", "apiKey": "plain" + "value3"}},
        "wiki": {"type": "http", "url": "https://wiki.example.com/mcp", "headers": {"X-API-Key": "plain" + "value4"}},
    }}
    return {".cursor/mcp.json": json.dumps(servers, indent=2).encode()}


CONFIG_GENERATED: dict[str, object] = {
    "SW-CFG-002/positive": _generated_cfg_002_positive,
    "SW-CFG-010/positive": _generated_cfg_010_positive,
}


def config_kind(path: str) -> str | None:
    """The document kind of a configuration file path, as discovery (spec 6.5) names them; None for any other file."""
    name = path.rsplit("/", 1)[-1]
    if path.endswith(".claude-plugin/marketplace.json"):
        return "marketplace"
    if path.endswith(".claude-plugin/plugin.json"):
        return "plugin"
    if path == "hooks/hooks.json" or path.endswith("/hooks/hooks.json"):
        return "hooks"
    if path.endswith((".claude/settings.json", ".claude/settings.local.json")):
        return "settings"
    if name == ".mcp.json" or path.endswith((".vscode/mcp.json", ".cursor/mcp.json")):
        return "mcp"
    return None


def config_documents(files: dict[str, bytes]) -> list[ConfigDocument]:
    return [parse_document(config_kind(path), path, content) for path, content in sorted(files.items()) if config_kind(path)]


def load_config_fixture(rule_id: str, side: str) -> tuple[dict[str, bytes], dict]:
    """The files of `fixtures/config/<rule-id>/<side>/` and its `expected.json` (the complete finding set of the
    `config` rules over the fixture's documents, same shape as the skill fixtures)."""
    directory = CONFIG_FIXTURES / rule_id / side
    expected = json.loads((directory / "expected.json").read_text())
    generator = CONFIG_GENERATED.get(f"{rule_id}/{side}")
    files = generator() if generator is not None else _read_dir(directory)
    return files, expected


def load_probe_fixture(name: str) -> tuple[ProbeResult, dict]:
    """`fixtures/probes/<name>.json`: `{"probe": <ProbeResult.to_dict()>, "expected": {...}}`."""
    document = json.loads((PROBE_FIXTURES / f"{name}.json").read_text())
    return ProbeResult.from_dict(document["probe"]), document["expected"]


@pytest.fixture
def package():
    return make_package
