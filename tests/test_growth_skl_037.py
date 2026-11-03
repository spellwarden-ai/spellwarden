"""SW-SKL-037: executable downloaded from a moving reference and run without an integrity check.
The rule is not registered yet, so the tests call the module's `detect` directly."""
from __future__ import annotations

import ast
import inspect
import time

import pytest
from conftest import GENERATED, SKILL_FIXTURES, _read_dir, clean_md, make_package

from spellwarden_scan.package import Package
from spellwarden_scan.rules import growth_skl_037
from spellwarden_scan.rules.growth_skl_037 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

NEW_IDS = frozenset({f"SW-SKL-{n:03d}" for n in range(32, 38)} | {f"SW-CFG-{n:03d}" for n in range(12, 15)})
SUM = "0123456789abcdef" * 4


def run(body: str = "", **extra: str):
    return list(detect(Package.build(make_package({"SKILL.md": clean_md() + body, **extra}))))


def fenced(*lines: str, language: str = "bash") -> str:
    return f"\n```{language}\n" + "\n".join(lines) + "\n```\n"


def line_number(body: str, needle: str) -> int:
    for number, line in enumerate((clean_md() + body).splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(needle)


def test_module_constants():
    assert RULE_ID == "SW-SKL-037"
    assert TITLE == "Executable downloaded from a moving reference and run without an integrity check"
    assert SEVERITY == "medium"
    assert OWASP == ("ASI04", "ASI05")
    assert NIST == ("SR-3", "SI-7")
    assert MALICIOUS is False


def test_module_imports_no_rule_modules_at_top_level():
    tree = ast.parse(inspect.getsource(growth_skl_037))
    imported = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
    assert not {"spellwarden_scan.rules.skill", "spellwarden_scan.rules.config"} & imported


# --- shell: curl / wget / PowerShell ------------------------------------------------------------

LATEST = "curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool -o tool && chmod +x tool && ./tool"


def test_latest_release_download_made_executable_and_run_fires_at_the_download_line():
    body = fenced("echo start", LATEST)
    findings = run(body)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity == "medium"
    assert finding.title == TITLE
    assert finding.location.path == "SKILL.md"
    assert finding.location.line == line_number(body, "releases/latest")
    assert finding.malicious_indicator is False
    assert "releases/latest" in finding.evidence
    assert len(finding.evidence) <= 300
    assert len(finding.fingerprint) == 64


def test_the_block_in_a_markdown_file_is_read_at_the_file_line():
    body = "\nText before.\n\nMore text.\n" + fenced("# fetch", LATEST)
    assert [f.location.line for f in run(body)] == [line_number(body, "releases/latest")]


def test_script_file_is_read_and_a_continued_command_reports_its_first_line():
    script = "#!/bin/sh\nset -e\ncurl -L \\\n  https://downloads.example.com/acme/tool/releases/latest/download/tool \\\n  -o tool\nchmod +x tool\n./tool\n"
    findings = run(**{"scripts/setup.sh": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/setup.sh", 3)]


def test_download_with_remote_name_and_chmod_in_a_later_command():
    body = fenced("curl -fsSLO https://downloads.example.com/acme/tool/releases/latest/download/tool", "chmod 755 tool", "sudo ./tool install")
    assert len(run(body)) == 1


def test_wget_output_document_then_run_through_an_interpreter():
    body = fenced("wget -q -O install.sh https://raw.example.com/acme/tool/main/install.sh", "bash install.sh")
    assert len(run(body)) == 1


def test_wget_without_output_name_uses_the_url_file_name():
    body = fenced("wget https://raw.githubusercontent.com/example-owner/example-repo/master/bin/runner", "chmod +x runner")
    assert len(run(body)) == 1


def test_redirect_to_a_file_counts_as_a_download():
    body = fenced("curl -s https://downloads.example.com/tool/releases/latest/download/tool > /tmp/tool", "chmod +x /tmp/tool")
    assert len(run(body)) == 1


def test_raw_default_branch_paths_are_moving():
    for url in ("https://raw.githubusercontent.com/example-owner/example-repo/main/run.sh",
                "https://raw.githubusercontent.com/example-owner/example-repo/HEAD/run.sh",
                "https://raw.githubusercontent.com/example-owner/example-repo/refs/heads/master/run.sh",
                "https://git.example.org/example-owner/example-repo/-/raw/main/run.sh",
                "https://git.example.org/example-owner/example-repo/raw/master/run.sh"):
        body = fenced(f"curl -L {url} -o run.sh", "chmod +x run.sh")
        assert len(run(body)) == 1, url


def test_url_with_no_version_segment_is_moving():
    body = fenced("curl -L https://downloads.example.com/acme/tool-linux-amd64 -o tool", "chmod +x tool")
    assert len(run(body)) == 1


def test_extraction_into_a_bin_directory_from_a_pipe():
    body = fenced("curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool.tar.gz | tar -xz -C /usr/local/bin tool")
    assert len(run(body)) == 1
    home = fenced("wget -qO- https://downloads.example.com/acme/tool/releases/latest/download/tool.tgz | tar xz --directory=~/.local/bin")
    assert len(run(home)) == 1


def test_extraction_of_a_downloaded_archive_into_a_bin_directory():
    body = fenced("curl -L -o tool.tgz https://downloads.example.com/acme/tool/releases/latest/download/tool.tgz",
                  "sudo tar -xzf tool.tgz -C /usr/local/bin")
    assert len(run(body)) == 1


def test_move_into_a_bin_directory_is_an_execute_step():
    body = fenced("curl -L -o tool https://downloads.example.com/acme/tool/releases/latest/download/tool", "mv tool ~/.local/bin/tool")
    assert len(run(body)) == 1


def test_powershell_download_then_run():
    ps = "Invoke-WebRequest -Uri https://downloads.example.com/acme/tool/releases/latest/download/tool.exe -OutFile tool.exe\n.\\tool.exe /quiet\n"
    findings = run(**{"scripts/setup.ps1": ps})
    assert [f.location.line for f in findings] == [1]
    body = fenced("iwr https://downloads.example.com/acme/tool/releases/latest/download/tool.exe -OutFile tool.exe; Start-Process tool.exe",
                  language="powershell")
    assert len(run(body)) == 1


def test_execute_step_must_name_the_downloaded_file():
    body = fenced("curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool -o tool", "chmod +x other", "./other")
    assert run(body) == []


def test_execute_step_more_than_five_commands_later_is_out_of_the_window():
    commands = ["curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool -o tool"] + ["ls -l"] * 6 + ["chmod +x tool"]
    assert run(fenced(*commands)) == []
    near = ["curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool -o tool"] + ["ls -l"] * 4 + ["chmod +x tool"]
    assert len(run(fenced(*near))) == 1


def test_only_the_download_line_is_reported_once_per_download():
    body = fenced(LATEST, "echo done", LATEST.replace("-o tool", "-o other").replace("chmod +x tool", "chmod +x other").replace("./tool", "./other"))
    assert len(run(body)) == 2


# --- python and javascript -----------------------------------------------------------------------

PY = (
    "import os, subprocess, urllib.request\n"
    'urllib.request.urlretrieve("https://downloads.example.com/acme/tool/releases/latest/download/tool", "tool")\n'
    'os.chmod("tool", 0o755)\n'
    'subprocess.run(["./tool", "--init"], check=True)\n'
)


def test_python_download_then_chmod_and_subprocess_fires_at_the_url_line():
    findings = run(**{"scripts/fetch.py": PY})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/fetch.py", 2)]


def test_python_requests_write_then_spawn_without_chmod():
    code = (
        "import requests, subprocess\n"
        'r = requests.get("https://raw.githubusercontent.com/example-owner/example-repo/main/helper.py")\n'
        'open("helper_bin", "wb").write(r.content)\n'
        'subprocess.run(["python3", "helper_bin"])\n'
    )
    assert [f.location.line for f in run(**{"scripts/fetch.py": code})] == [2]


def test_python_in_a_fenced_block():
    body = fenced(*PY.splitlines(), language="python")
    assert [f.location.line for f in run(body)] == [line_number(body, "urlretrieve")]


def test_python_download_with_a_url_constant_defined_earlier():
    code = (
        "import os, urllib.request\n"
        'URL = "https://downloads.example.com/acme/tool/releases/latest/download/tool"\n'
        "target = os.path.join(os.getcwd(), 'tool')\n"
        "urllib.request.urlretrieve(URL, target)\n"
        "os.chmod(target, 0o755)\n"
    )
    assert [f.location.line for f in run(**{"scripts/fetch.py": code})] == [2]


def test_javascript_stream_to_a_file_then_chmod_and_exec():
    code = (
        'const fs = require("fs"); const https = require("https"); const { execFileSync } = require("child_process");\n'
        'const file = fs.createWriteStream("tool");\n'
        'https.get("https://downloads.example.com/acme/tool/releases/latest/download/tool", (res) => {\n'
        "  res.pipe(file);\n"
        '  file.on("finish", () => { fs.chmodSync("tool", 0o755); execFileSync("./tool"); });\n'
        "});\n"
    )
    assert [f.location.line for f in run(**{"scripts/fetch.js": code})] == [3]


def test_python_download_never_made_executable_is_quiet():
    code = (
        "import urllib.request\n"
        'urllib.request.urlretrieve("https://downloads.example.com/acme/tool/releases/latest/download/data.bin", "data.bin")\n'
        'print(open("data.bin", "rb").read()[:4])\n'
    )
    assert run(**{"scripts/fetch.py": code}) == []


def test_python_with_a_non_executable_mode_is_quiet():
    code = PY.replace("0o755", "0o644")
    assert run(**{"scripts/fetch.py": code.replace('subprocess.run(["./tool", "--init"], check=True)', "print('ok')")}) == []


def test_python_download_pinned_to_a_version_is_quiet():
    code = PY.replace("releases/latest/download", "releases/download/v2.4.1")
    assert run(**{"scripts/fetch.py": code}) == []


def test_python_with_a_hash_comparison_is_quiet():
    code = PY + (
        "import hashlib\n"
        f'if hashlib.sha256(open("tool", "rb").read()).hexdigest() != "{SUM}":\n'
        "    raise SystemExit(1)\n"
    )
    assert run(**{"scripts/fetch.py": code}) == []


# --- git clone ------------------------------------------------------------------------------------

def test_git_clone_without_a_tag_then_install_inside_it():
    body = fenced("git clone https://git.example.org/acme/helper-kit.git", "cd helper-kit", "pip install .")
    findings = run(body)
    assert [f.location.line for f in findings] == [line_number(body, "git clone")]
    one_line = fenced("git clone --depth 1 https://git.example.org/acme/helper-kit.git kit && cd kit && ./install.sh")
    assert len(run(one_line)) == 1


def test_git_clone_install_by_path_without_cd():
    body = fenced("git clone https://git.example.org/acme/helper-kit.git", "pip install ./helper-kit")
    assert len(run(body)) == 1
    other = fenced("git clone https://git.example.org/acme/helper-kit.git", "bash helper-kit/install.sh")
    assert len(run(other)) == 1


def test_git_clone_of_a_default_branch_is_moving_even_when_named():
    body = fenced("git clone --branch main https://git.example.org/acme/helper-kit.git", "cd helper-kit", "make install")
    assert len(run(body)) == 1


def test_git_clone_of_a_tag_is_quiet():
    body = fenced("git clone --branch v2.4.1 https://git.example.org/acme/helper-kit.git", "cd helper-kit", "pip install .")
    assert run(body) == []
    short = fenced("git clone -b v2.4.1 --depth 1 https://git.example.org/acme/helper-kit.git", "cd helper-kit", "make install")
    assert run(short) == []


def test_git_clone_then_checkout_of_a_commit_is_quiet():
    body = fenced("git clone https://git.example.org/acme/helper-kit.git", "cd helper-kit", "git checkout 3f9a1c2d7b", "pip install .")
    assert run(body) == []


def test_git_clone_only_read_is_quiet():
    body = fenced("git clone https://git.example.org/acme/helper-kit.git", "cd helper-kit", "ls", "cat README.md")
    assert run(body) == []


# --- negatives -------------------------------------------------------------------------------------

def test_explicit_version_tag_with_sha256_check_is_quiet():
    body = fenced(
        "curl -L https://downloads.example.com/acme/tool/releases/download/v2.4.1/tool -o tool",
        f'echo "{SUM}  tool" | sha256sum -c -',
        "chmod +x tool",
        "./tool",
    )
    assert run(body) == []


def test_explicit_version_tag_alone_is_not_a_moving_reference():
    body = fenced("curl -L https://downloads.example.com/acme/tool/releases/download/v2.4.1/tool -o tool", "chmod +x tool", "./tool")
    assert run(body) == []
    dated = fenced("curl -L https://downloads.example.com/acme/tool/2026.11.1/tool-linux -o tool", "chmod +x tool")
    assert run(dated) == []
    variable = fenced("curl -L https://downloads.example.com/acme/tool/${VERSION}/tool -o tool", "chmod +x tool")
    assert run(variable) == []


@pytest.mark.parametrize("check", [
    f'echo "{SUM}  tool" | sha256sum -c - || exit 1',
    f'echo "{SUM}  tool" | sha256sum --check --status',
    "shasum -a 256 -c tool.sha256",
    f'[ "$(sha256sum tool | cut -d" " -f1)" = "{SUM}" ] || exit 1',
    "gpg --verify tool.sig tool",
    "cosign verify-blob --signature tool.sig tool",
    "minisign -Vm tool -P RWQexampleexampleexampleexampleexampleexampleexample",
])
def test_integrity_check_in_the_same_block_suppresses(check):
    body = fenced("curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool -o tool", check, "chmod +x tool", "./tool")
    assert run(body) == []


def test_hashing_without_a_comparison_is_not_a_check():
    body = fenced("curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool -o tool", "sha256sum tool", "chmod +x tool", "./tool")
    assert len(run(body)) == 1


def test_a_check_in_another_block_does_not_suppress():
    body = fenced(LATEST) + "\nOther page.\n" + fenced("sha256sum -c tool.sha256")
    assert len(run(body)) == 1


def test_weights_download_never_executed_is_quiet():
    body = fenced("curl -L https://models.example.org/acme/releases/latest/download/style-model.gguf -o style-model.gguf", "ls -l style-model.gguf")
    assert run(body) == []
    data = fenced("curl -L https://downloads.example.com/acme/releases/latest/download/rules.json -o rules.json", "chmod +x rules.json")
    assert run(data) == []


def test_reachability_check_to_dev_null_is_quiet():
    body = fenced('curl -s -o /dev/null -w "%{http_code}" https://downloads.example.com/acme/tool/releases/latest/', "chmod +x tool", "./tool")
    assert run(body) == []
    ps = fenced("curl -sSL https://downloads.example.com/acme/tool/releases/latest/download/tool > /dev/null", "chmod +x tool")
    assert run(ps) == []


def test_package_manager_installs_are_quiet():
    body = fenced("pip install requests", "npm install --save-dev prettier", "brew install acme/tap/tool", "cargo install tool-cli")
    assert run(body) == []


def test_download_to_stdout_is_not_this_rule():
    body = fenced("curl -fsSL https://downloads.example.com/acme/tool/releases/latest/download/install.sh | sh")
    assert run(body) == []


def test_bare_prose_and_non_shell_blocks_are_quiet_but_an_inline_span_is_read():
    assert run(f"\nRun {LATEST} yourself.\n") == []
    assert run(fenced(LATEST, language="text")) == []
    # since 1.8.0 a single-backtick inline span that runs a download is read as a command of its own
    assert len(run(f"\nRun `{LATEST}` yourself.\n")) == 1


def test_output_is_bounded():
    commands = [f"curl -L https://downloads.example.com/acme/t{n}/releases/latest/download/t{n} -o t{n} && chmod +x t{n}" for n in range(200)]
    assert 0 < len(run(fenced(*commands))) <= 25


# --- linear time ------------------------------------------------------------------------------------

@pytest.mark.parametrize("unit", [
    "curl https://x.example.com/releases/latest/download/t -o t && ",
    "curl -o ",
    "https://",
    "git clone ",
    "chmod +x t; ./t; ",
    "urlretrieve(",
    "sha256sum -c ; ",
    "| tar -xz -C ",
])
def test_long_lines_are_read_in_linear_time(unit):
    line = (unit * (300_000 // len(unit) + 1))[:300_000]
    assert len(line) == 300_000
    started = time.perf_counter()
    run(fenced(line))
    run(**{"scripts/long.sh": line + "\n", "scripts/long.py": line + "\n", "scripts/long.js": line + "\n"})
    assert time.perf_counter() - started < 1.0


def test_many_pipe_stages_in_one_command_are_read_in_linear_time():
    same = "curl -L https://dl.example.com/tool -o tool | " * 8_000 + "true"
    distinct = "".join(f"curl -L https://dl.example.com/t{n} -o t{n} | " for n in range(8_000)) + "true"
    for line in (same, distinct):
        started = time.perf_counter()
        run(**{"scripts/a.sh": line + "\n"})
        run(fenced(line))
        assert time.perf_counter() - started < 1.0
    # many stages in the command and in each command of its execute window
    started = time.perf_counter()
    run(**{"scripts/b.sh": "\n".join([same] * 6) + "\n"})
    assert time.perf_counter() - started < 1.0


def test_download_run_by_a_nearby_pipe_stage_still_fires():
    assert run(**{"scripts/a.sh": "curl -L https://dl.example.com/tool -o tool | cat | ./tool\n"})


def test_an_execute_step_far_along_a_pipeline_or_deep_in_the_next_command_still_fires():
    # No position limit: the run step after twenty stages, and after twenty stages of the next command.
    far = "curl -L https://dl.example.com/tool -o tool | " + "cat | " * 20 + "./tool"
    assert run(**{"scripts/a.sh": far + "\n"})
    deep = "curl -L https://dl.example.com/tool -o tool\ntrue " + "| cat " * 20 + "| chmod +x tool\n"
    assert run(**{"scripts/b.sh": deep})


def test_a_pipeline_of_many_distinct_run_steps_is_read_in_linear_time():
    # Each stage runs a different file: the per-command facts must not copy a growing set per stage.
    line = "curl -L https://dl.example.com/t0 -o t0 | " + "".join(f"./t{n} | " for n in range(1, 30_000)) + "./t0"
    started = time.perf_counter()
    assert run(**{"scripts/a.sh": line + "\n"})
    assert time.perf_counter() - started < 1.0


def test_many_downloads_followed_by_one_large_command_are_read_in_linear_time():
    # Review r1:F1: each download stage used to re-read the next command; now each command is read once.
    downloads = "".join(f"curl -L https://dl.example.com/t{n} -o t{n} | " for n in range(5_000)) + "true"
    large = "./" + "a" * 200_000 + " " + "b" * 100_000
    started = time.perf_counter()
    run(**{"scripts/a.sh": downloads + "\n" + large + "\n"})
    assert time.perf_counter() - started < 1.0


# --- 1.8.0 revision: inline spans, extract then place, latest tag resolved, moving constants, keywords --------

REL_TGZ = "https://github.com/example-org/tool/releases/latest/download/tool-linux-amd64.tar.gz"
RAW_INSTALL = "https://raw.githubusercontent.com/example-org/tool/main/install.sh"
API_LATEST = "https://api.github.com/repos/example-org/tool/releases/latest"
TEMPLATE = "https://github.com/example-org/tool/releases/download/${TAG}/tool-linux-amd64"
LATEST_TAG = f"TAG=$(curl -fsSL {API_LATEST} | grep tag_name | cut -d '\"' -f 4)"


def lines_of(findings):
    return [(f.location.path, f.location.line) for f in findings]


def test_inline_span_extracting_into_a_bin_directory_fires_at_the_span_line():
    body = f"\n- Install the CLI with `curl -fsSL {REL_TGZ} | tar xz -C /usr/local/bin tool` and check `tool --version`.\n"
    assert lines_of(run(body)) == [("SKILL.md", line_number(body, "releases/latest"))]


def test_inline_span_with_a_dollar_prompt_and_sudo_is_read():
    body = f"\n1. Run `$ sudo curl -fsSL {REL_TGZ} | tar xz -C /usr/local/bin tool`.\n"
    assert lines_of(run(body)) == [("SKILL.md", line_number(body, "releases/latest"))]


def test_inline_span_extracting_then_moving_into_a_bin_directory_fires():
    body = f"\n- Install: `curl -fsSL {REL_TGZ} | tar xz && sudo mv tool /usr/local/bin/`\n"
    assert lines_of(run(body)) == [("SKILL.md", line_number(body, "releases/latest"))]


def test_fenced_extract_then_move_into_a_bin_directory_fires_at_the_download_line():
    body = fenced(f"curl -sL {REL_TGZ} | tar xz", "sudo mv tool /usr/local/bin/")
    assert lines_of(run(body)) == [("SKILL.md", line_number(body, "releases/latest"))]


def test_fenced_extract_then_chmod_of_the_extracted_file_fires():
    body = fenced(f"curl -sL {REL_TGZ} | tar xz", "chmod +x tool")
    assert len(run(body)) == 1


def test_extract_without_a_bin_destination_or_chmod_is_quiet():
    for step in ("mv tool-main newname", 'cp -r tool-main/skills "$WORKSPACE/"'):
        archive = "https://github.com/example-org/tool/archive/refs/heads/main.tar.gz"
        assert run(fenced(f"curl -sL {archive} | tar xz", step)) == [], step
        assert run(f"\n- Fetch `curl -sL {archive} | tar xz && {step}`\n") == [], step


def test_inline_span_piping_a_default_branch_script_into_sh_is_quiet():
    body = f"\n- Install: `curl -sSfL {RAW_INSTALL} | sh -s -- -b /usr/local/bin`\n"
    assert run(body) == []


def test_inline_span_that_is_not_a_download_command_is_not_read():
    body = f"\n- Install: `echo curl {REL_TGZ} -o tool && chmod +x tool` and `tool --help`\n"
    assert run(body) == []


def test_inline_span_that_downloads_and_chmods_is_quiet_when_another_span_verifies_a_checksum():
    body = ("\n- Fetch `curl -fsSL https://github.com/example-org/tool/releases/latest/download/tool -o tool && chmod +x tool`\n"
            "- Then run `sha256sum -c tool.sha256` before using it.\n")
    assert run(body) == []
    assert len(run(body.split("- Then")[0])) == 1


def test_inline_span_inside_a_fenced_line_is_reported_once_by_the_fenced_path():
    span = "curl -L https://github.com/example-org/tool/releases/latest/download/tool -o tool"
    body = fenced(f"`{span}` && chmod +x tool")
    assert lines_of(run(body)) == [("SKILL.md", line_number(body, "releases/latest"))]
    quoted = fenced(f'echo "run `{span} && chmod +x tool` now"')
    assert run(quoted) == []


def test_several_inline_spans_are_each_their_own_unit():
    body = ("\n- First `curl -L https://github.com/example-org/a/releases/latest/download/a -o a` then `chmod +x a`.\n"
            "- Second `curl -L https://github.com/example-org/b/releases/latest/download/b -o b && chmod +x b`.\n")
    assert lines_of(run(body)) == [("SKILL.md", line_number(body, "example-org/b"))]


def test_double_backtick_spans_and_unclosed_spans_are_not_inline_spans():
    body = ("\n- Install ``curl -L https://github.com/example-org/a/releases/latest/download/a -o a && chmod +x a`` now.\n"
            "- Broken `curl -L https://github.com/example-org/b/releases/latest/download/b -o b && chmod +x b\n")
    assert run(body) == []


def test_latest_tag_resolved_then_templated_download_through_a_variable_fires_at_the_curl_line():
    script = ("#!/bin/sh\nset -e\n" + LATEST_TAG + "\n" + f'URL="{TEMPLATE}"\n'
              'curl -fsSL "$URL" -o "$HOME/.local/bin/tool"\nchmod +x "$HOME/.local/bin/tool"\n')
    assert lines_of(run(**{"scripts/install.sh": script})) == [("scripts/install.sh", 5)]
    braces = script.replace('"$URL"', '"${URL}"')
    assert lines_of(run(**{"scripts/install.sh": braces})) == [("scripts/install.sh", 5)]


def test_latest_tag_resolved_then_templated_download_inside_a_quoted_heredoc_fires():
    script = ("#!/bin/sh\n" + LATEST_TAG + "\ncat > /tmp/install-tool.sh <<'EOF'\n" + f'URL="{TEMPLATE}"\n'
              'curl -fsSL "$URL" -o "$HOME/.local/bin/tool"\nchmod +x "$HOME/.local/bin/tool"\nEOF\nsh /tmp/install-tool.sh\n')
    assert lines_of(run(**{"scripts/install.sh": script})) == [("scripts/install.sh", 5)]


def test_literal_templated_url_after_the_latest_tag_is_moving():
    script = "#!/bin/sh\n" + LATEST_TAG + f'\ncurl -fsSL "{TEMPLATE}" -o tool\nchmod +x tool\n'
    assert lines_of(run(**{"scripts/install.sh": script})) == [("scripts/install.sh", 3)]


def test_variable_download_without_a_resolved_latest_tag_is_quiet():
    plain = f'#!/bin/sh\nURL="{TEMPLATE}"\ncurl -fsSL "$URL" -o tool\nchmod +x tool\n'
    assert run(**{"scripts/install.sh": plain}) == []
    no_template = ("#!/bin/sh\n" + LATEST_TAG + '\nURL="https://downloads.example.com/dl/tool-$TAG"\n'
                   'curl "$URL" -o tool\nchmod +x tool\n')
    assert run(**{"scripts/install.sh": no_template}) == []


def test_the_output_variable_is_not_taken_for_the_url():
    for download in ('curl -fsSL -o "$OUT"', 'curl -fsSLo "$OUT"', 'curl -fsSL --output "$OUT"', 'curl -fsSL > "$OUT"'):
        script = "#!/bin/sh\n" + LATEST_TAG + f'\nURL="{TEMPLATE}"\n{download}\nchmod +x "$OUT"\n'
        assert run(**{"scripts/install.sh": script}) == [], download


def test_latest_tag_download_followed_by_a_checksum_comparison_is_quiet():
    script = ("#!/bin/sh\n" + LATEST_TAG + "\n" + f'URL="{TEMPLATE}"\n'
              'curl -fsSL "$URL" -o tool\nACTUAL=$(sha256sum tool | cut -d " " -f1)\n'
              '[ "$ACTUAL" = "$EXPECTED" ] || exit 1\nchmod +x tool\n')
    assert run(**{"scripts/install.sh": script}) == []
    unchecked = script.replace('ACTUAL=$(sha256sum tool | cut -d " " -f1)\n[ "$ACTUAL" = "$EXPECTED" ] || exit 1\n', "")
    assert len(run(**{"scripts/install.sh": unchecked})) == 1


def test_latest_tag_download_to_a_data_file_is_quiet():
    script = ("#!/bin/sh\n" + LATEST_TAG + "\n" + f'URL="{TEMPLATE}"\n'
              'curl -fsSL "$URL" -o config.json\nchmod +x config.json\n')
    assert run(**{"scripts/install.sh": script}) == []


PY_CONSTANT = (
    "import os\nimport urllib.request\n\n"
    'BASE = "https://github.com/example-org/tool/releases/latest/download"\n'
    + "".join(f"\n\ndef helper_{n}():\n    return {n}\n" for n in range(10))
    + "\n\ndef install(asset, dest):\n"
    '    url = f"{BASE}/{asset}"\n'
    "    data = urllib.request.urlopen(url).read()\n"
    '    with open(dest, "wb") as handle:\n'
    "        handle.write(data)\n"
    "    os.chmod(dest, 0o755)\n"
)


def test_python_constant_holding_a_latest_url_is_an_anchor_far_from_its_definition():
    lines = PY_CONSTANT.splitlines()
    assert next(n for n, text in enumerate(lines, 1) if "BASE" in text and "{" not in text) < next(
        n for n, text in enumerate(lines, 1) if "url = f" in text) - 30
    expected = next(n for n, text in enumerate(lines, 1) if "url = f" in text)
    assert lines_of(run(**{"scripts/fetch.py": PY_CONSTANT})) == [("scripts/fetch.py", expected)]


def test_javascript_const_with_a_type_annotation_and_a_python_annotation_are_collected():
    annotated = PY_CONSTANT.replace('BASE = "', 'BASE: str = "')
    assert len(run(**{"scripts/fetch.py": annotated})) == 1
    js = (
        'const fs = require("fs"); const https = require("https");\n'
        'const BASE: string = "https://github.com/example-org/tool/releases/latest/download";\n'
        + "".join(f"function helper{n}() {{ return {n}; }}\n" for n in range(40))
        + "function install(asset, dest) {\n"
        "  const file = fs.createWriteStream(dest);\n"
        "  https.get(`${BASE}/${asset}`, (res) => {\n"
        "    res.pipe(file);\n"
        '    file.on("finish", () => { fs.chmodSync(dest, 0o755); });\n'
        "  });\n"
        "}\n"
    )
    assert len(run(**{"scripts/fetch.ts": js})) == 1


def test_python_constant_with_a_weak_url_is_not_an_anchor():
    weak = PY_CONSTANT.replace("https://github.com/example-org/tool/releases/latest/download", "https://api.example.com/download")
    assert run(**{"scripts/fetch.py": weak}) == []


def test_python_latest_constant_whose_download_is_never_made_executable_or_run_is_quiet():
    unrun = PY_CONSTANT.replace("    os.chmod(dest, 0o755)\n", "    print(len(data))\n")
    assert run(**{"scripts/fetch.py": unrun}) == []


def test_python_name_that_only_contains_the_constant_name_is_not_a_mention():
    other = PY_CONSTANT.replace('url = f"{BASE}/{asset}"', 'url = f"{BASEMENT}/{asset}"')
    assert run(**{"scripts/fetch.py": other}) == []


CLONE_IF = (
    'if ! git clone --depth 1 https://github.com/example-org/tool.git "$DIR" 2>/dev/null; then\n'
    '  echo "clone failed"\n  echo "see the docs"\n  exit 1\nfi\necho "cloned"\ncd "$DIR"\nif ! npm install; then\n  exit 2\nfi\n'
)


def test_clone_inside_an_if_negation_then_install_fires_at_the_clone_line():
    assert lines_of(run(**{"scripts/setup.sh": "#!/bin/sh\n" + CLONE_IF})) == [("scripts/setup.sh", 2)]
    body = fenced(*CLONE_IF.splitlines())
    assert lines_of(run(body)) == [("SKILL.md", line_number(body, "git clone"))]


def test_download_after_a_then_keyword_on_the_same_line_is_read():
    script = ("#!/bin/sh\nif [ ! -x tool ]; then curl -L https://downloads.example.com/acme/tool/releases/latest/download/tool -o tool "
              "&& chmod +x tool; fi\n")
    assert lines_of(run(**{"scripts/setup.sh": script})) == [("scripts/setup.sh", 2)]


def test_clone_followed_only_by_mkdir_and_copying_data_files_is_quiet():
    script = ('#!/bin/sh\nif git clone --depth 1 https://github.com/example-org/tool.git "$tmp/x"; then\n'
              '  mkdir -p out\n  cp "$tmp/x/"*.json out/\nfi\n')
    assert run(**{"scripts/setup.sh": script}) == []


def test_pinned_clone_in_an_if_negation_is_quiet():
    script = ("#!/bin/sh\nif ! git clone --branch v1.2.3 https://github.com/example-org/tool.git dir; then\n"
              "  echo failed\n  exit 1\nfi\ncd dir\nmake\n")
    assert run(**{"scripts/setup.sh": script}) == []


def test_clone_window_counts_significant_commands_only():
    clone = "git clone https://github.com/example-org/tool.git dir"
    far = ["#!/bin/sh", clone] + ["ls -l"] * 6 + ["cd dir", "npm install"]
    assert run(**{"scripts/setup.sh": "\n".join(far) + "\n"}) == []
    near = ["#!/bin/sh", clone] + ["ls -l"] * 3 + ["echo a", ":", "then", "cd dir", "npm install"]
    assert len(run(**{"scripts/setup.sh": "\n".join(near) + "\n"})) == 1


@pytest.mark.parametrize("unit", [
    "`curl https://x.example.com/releases/latest/download/t -o t` ",
    "`$ curl https://x.example.com/v1.2.3/t | tar xz` and ``curl `` ",
    "` ` `curl ",
])
def test_inline_spans_are_read_in_linear_time(unit):
    line = (unit * (300_000 // len(unit) + 1))[:300_000]
    assert len(line) == 300_000
    started = time.perf_counter()
    run("\n- " + line + "\n")
    assert time.perf_counter() - started < 1.0


def test_thousands_of_keyword_only_commands_are_read_in_linear_time():
    keywords = "then\nfi\ndone\nelse\nesac\ndo\n"
    clone = "git clone https://github.com/example-org/tool.git dir\n"
    started = time.perf_counter()
    clone_found = run(**{"scripts/a.sh": clone + keywords * 1_000 + "echo x\n" * 5_000 + "cd dir\nnpm install\n"})
    download_found = run(**{"scripts/b.sh": "curl -L https://dl.example.com/tool -o tool\n" + keywords * 1_000 + "chmod +x tool\n"})
    assert time.perf_counter() - started < 1.0
    assert len(clone_found) == 1 and len(download_found) == 1


def test_a_long_variable_url_line_after_a_latest_tag_is_read_in_linear_time():
    unit = f"curl -fsSL $URL -o t && {TEMPLATE} ; "
    line = (unit * (300_000 // len(unit) + 1))[:300_000]
    started = time.perf_counter()
    run(**{"scripts/a.sh": LATEST_TAG + "\n" + line + "\n"})
    run(fenced(LATEST_TAG, line))
    assert time.perf_counter() - started < 1.0


def test_many_markdown_files_with_many_fenced_blocks_are_read_in_linear_time():
    block = "\n```text\nplain\n```\n"
    body = clean_md() + block * 300
    files = {f"references/r{n}.md": body for n in range(600)}
    started = time.perf_counter()
    run(**files)
    assert time.perf_counter() - started < 1.0


# --- fixtures ----------------------------------------------------------------------------------------

def test_positive_fixture_fires_at_each_download_line():
    findings = list(detect(Package.build(_read_dir(SKILL_FIXTURES / RULE_ID / "positive"))))
    assert sorted((f.location.path, f.location.line) for f in findings) == [
        ("SKILL.md", 17), ("scripts/bootstrap.sh", 4), ("scripts/fetch_linter.py", 6),
    ]


def test_negative_fixture_is_quiet():
    assert list(detect(Package.build(_read_dir(SKILL_FIXTURES / RULE_ID / "negative")))) == []


# --- invariant 4: no finding on any existing skill fixture ---------------------------------------------

def _existing_skill_packages():
    for directory in sorted(SKILL_FIXTURES.iterdir()):
        if not directory.is_dir() or directory.name in NEW_IDS:
            continue
        for side in sorted(p for p in directory.iterdir() if p.is_dir()):
            generator = GENERATED.get(f"{directory.name}/{side.name}")
            yield f"{directory.name}/{side.name}", (generator() if generator is not None else _read_dir(side))


def test_no_finding_on_any_existing_skill_fixture():
    seen = 0
    for name, files in _existing_skill_packages():
        seen += 1
        assert list(detect(Package.build(files))) == [], name
    assert seen >= 30
