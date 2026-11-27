"""Scan links back (spec 5.9, 5.11, claim C13): `spellwarden scan --no-invite` leaves the dashboard line and the badge offer out
of the Markdown report and keeps its rule links; every other report is byte-identical across a local run, a local run with
`--no-invite` and a GitHub `push` run on the default branch of a public repository; and each run, repeated in its own environment,
writes the same Markdown (the README's promise as the owner amended it, spec section 14, Q1)."""
from __future__ import annotations

import json

from spellwarden_cli.output import markdown

OTHER_FORMATS = (("json", "report.json"), ("sarif", "report.sarif"), ("text", "report.txt"), ("cyclonedx", "report.cdx.json"),
                 ("html", "report.html"), ("gitlab-codequality", "gl-code-quality-report.json"))
FILES = {".mcp.json": json.dumps({"mcpServers": {"plain": {"url": "http://mcp.example.com/mcp"}}}, indent=2)}
RULE_LINK = "[SW-CFG-001](https://spellwarden.ai/docs/rules/sw-cfg-001?utm_source=scanner&utm_medium={}&utm_campaign=rule-docs)"


def github_push(tmp_path) -> dict[str, str]:
    """A GitHub Actions `push` run on the default branch of a public repository (the event payload names both)."""
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"repository": {"default_branch": "main", "visibility": "public"}}), encoding="utf-8")
    return {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event),
            "GITHUB_REF_NAME": "main", "GITHUB_REPOSITORY": "acme/agents", "GITHUB_SERVER_URL": "https://github.com"}


def scan(run_cli, repo, out, *extra: str, env: dict | None = None) -> tuple[int, dict[str, bytes]]:
    argv = ["scan", str(repo), "--as-of", "2026-11-26", "--no-telemetry", "--no-probe", "--quiet", *extra,
            "--format", "markdown", "--output", str(out / "report.md")]
    for fmt, name in OTHER_FORMATS:
        argv += ["--format", fmt, "--output", str(out / name)]
    code, _, _ = run_cli(argv, env=env)
    return code, {name: (out / name).read_bytes() for name in ("report.md", *(name for _, name in OTHER_FORMATS))}


def test_no_invite_leaves_out_the_line_and_the_offer_and_keeps_the_rule_links(tmp_path, make_repo, run_cli):
    repo = make_repo(tmp_path / "project", FILES)
    _, local = scan(run_cli, repo, tmp_path / "local")
    _, quiet = scan(run_cli, repo, tmp_path / "quiet", "--no-invite")
    _, pushed_quiet = scan(run_cli, repo, tmp_path / "pushed-quiet", "--no-invite", env=github_push(tmp_path))
    assert markdown.dashboard_line("cli") in local["report.md"].decode("utf-8")
    for written, medium in ((quiet, "cli"), (pushed_quiet, "github-action")):
        text = written["report.md"].decode("utf-8")
        assert "Spellwarden dashboard" not in text and markdown.SUMMARY_MARKER not in text
        assert RULE_LINK.format(medium) in text


def test_only_the_markdown_report_depends_on_the_run_and_a_repeated_run_writes_the_same_bytes(tmp_path, make_repo, run_cli):
    repo = make_repo(tmp_path / "project", FILES)
    runs = {"local": ((), None), "no-invite": (("--no-invite",), None), "github push": ((), github_push(tmp_path))}
    written = {}
    for name, (extra, env) in runs.items():
        code, first = scan(run_cli, repo, tmp_path / f"{name}-1", *extra, env=env)
        _, again = scan(run_cli, repo, tmp_path / f"{name}-2", *extra, env=env)
        assert code == 1, name  # SW-CFG-001 is high, the default threshold
        assert first == again, name
        written[name] = first
    for _, file_name in OTHER_FORMATS:
        assert written["local"][file_name] == written["no-invite"][file_name] == written["github push"][file_name], file_name
    pushed = written["github push"]["report.md"].decode("utf-8")
    assert pushed.endswith(markdown.SUMMARY_TAIL) and RULE_LINK.format("github-action") in pushed
    assert markdown.dashboard_line("github-action") in pushed and "utm_medium=cli" not in pushed
    assert written["local"]["report.md"] != written["github push"]["report.md"]
