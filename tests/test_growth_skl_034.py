"""SW-SKL-034: TLS certificate checks switched off where credentials are sent.
The rule is not registered yet, so the tests call the module's `detect` directly."""
from __future__ import annotations

import time

import pytest
from conftest import GENERATED, SKILL_FIXTURES, _read_dir, clean_md, make_package

from spellwarden_scan.package import Package
from spellwarden_scan.rules.growth_skl_034 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

NEW_IDS = frozenset({f"SW-SKL-{n:03d}" for n in range(32, 38)})
FAKE_BEARER = "Bearer EXAMPLEEXAMPLEEXAMPLE"


def run(body: str = "", **extra: str):
    return list(detect(Package.build(make_package({"SKILL.md": clean_md() + body, **extra}))))


def at(findings) -> list[tuple[str, int]]:
    return [(f.location.path, f.location.line) for f in findings]


def fenced(language: str, code: str) -> str:
    return f"\n```{language}\n{code}```\n"


def test_module_constants():
    assert RULE_ID == "SW-SKL-034"
    assert TITLE == "TLS certificate checks switched off where credentials are sent"
    assert SEVERITY == "high"
    assert OWASP == ("MCP01",)
    assert NIST == ("SC-8", "IA-5")
    assert MALICIOUS is False


# --- positives --------------------------------------------------------------------------------

def test_requests_verify_false_with_a_bearer_header_fires_at_the_switch_line():
    script = (
        "import requests\n\n"
        "def fetch():\n"
        f'    headers = {{"Authorization": "{FAKE_BEARER}"}}\n'
        '    return requests.get("https://api.example.com/v1/items", headers=headers,\n'
        "                        verify=False, timeout=10)\n"
    )
    findings = run(**{"scripts/fetch.py": script})
    assert at(findings) == [("scripts/fetch.py", 6)]
    first = findings[0]
    assert first.rule_id == RULE_ID
    assert first.severity == "high"
    assert first.title == TITLE
    assert first.malicious_indicator is False
    assert "verify=False" in first.evidence
    assert len(first.evidence) <= 300
    assert len(first.fingerprint) == 64


def test_the_secret_is_not_echoed_in_the_evidence():
    script = 'requests.get(url, headers={"Authorization": "Bearer ghp_EXAMPLE0123456789012345678901234567"}, verify=False)\n'
    findings = run(**{"scripts/fetch.py": script})
    assert len(findings) == 1
    assert "ghp_EXAMPLE0123456789012345678901234567" not in findings[0].evidence


def test_node_reject_unauthorized_false_with_an_api_key_fires():
    script = (
        "const https = require('https');\n"
        "const agent = new https.Agent({ rejectUnauthorized: false });\n"
        "fetch('https://api.example.net/data', {\n"
        "  agent,\n"
        "  headers: { 'X-API-Key': process.env.EXAMPLE_API_KEY },\n"
        "});\n"
    )
    assert at(run(**{"scripts/pull.js": script})) == [("scripts/pull.js", 2)]


def test_curl_dash_k_with_an_authorization_header_in_a_fenced_block_fires():
    body = fenced("bash", 'curl -k -H "Authorization: Bearer $EXAMPLE_TOKEN" https://api.example.org/v1/me\n')
    findings = run(body)
    assert at(findings) == [("SKILL.md", len((clean_md() + body).splitlines()) - 1)]


@pytest.mark.parametrize("command", [
    'curl -sSk -H "Authorization: Bearer $EXAMPLE_TOKEN" https://api.example.org/v1/me',
    'curl --insecure -H "X-API-Key: $EXAMPLE_KEY" https://api.example.org/v1/me',
    'curl -s https://api.example.org/v1/me -k -u "svc:$EXAMPLE_PASSWORD"',
    'wget --no-check-certificate --header="Authorization: Bearer $EXAMPLE_TOKEN" https://api.example.org/v1/me',
    'NODE_TLS_REJECT_UNAUTHORIZED=0 node pull.js --token "$EXAMPLE_TOKEN"',
    'export NODE_TLS_REJECT_UNAUTHORIZED=0; curl -H "Authorization: $EXAMPLE_TOKEN" https://api.example.org/',
])
def test_shell_switches_with_a_credential_fire(command):
    assert at(run(**{"scripts/run.sh": "#!/bin/sh\n" + command + "\n"})) == [("scripts/run.sh", 2)]


@pytest.mark.parametrize("switch", [
    "ctx = ssl._create_unverified_context()",
    "ctx.verify_mode = ssl.CERT_NONE",
    "ctx.check_hostname = False",
    "session.verify = False",
    "client = httpx.Client(verify = False)",
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
    "tr := &tls.Config{InsecureSkipVerify: true}",
    'opts = {"rejectUnauthorized": False}',
])
def test_each_switch_spelling_fires_next_to_a_password(switch):
    findings = run(**{"scripts/mail.py": f'password = os.environ["EXAMPLE_PASSWORD"]\n{switch}\n'})
    assert at(findings) == [("scripts/mail.py", 2)]


def test_go_file_is_scanned_although_it_is_not_a_script_extension():
    code = (
        "package main\n\n"
        "func client(token string) *http.Client {\n"
        "\treq.Header.Set(\"Authorization\", \"Bearer \"+token)\n"
        "\treturn &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}\n"
        "}\n"
    )
    assert at(run(**{"tools/client.go": code})) == [("tools/client.go", 5)]


def test_smtp_login_with_an_unverified_context_fires():
    script = (
        "import smtplib, ssl\n"
        "ctx = ssl._create_unverified_context()\n"
        "with smtplib.SMTP_SSL('mail.example.com', 465, context=ctx) as s:\n"
        "    s.login('svc@example.com', os.environ['EXAMPLE_MAIL_PASSWORD'])\n"
    )
    assert at(run(**{"scripts/mail.py": script})) == [("scripts/mail.py", 2)]


def test_curl_flags_continued_on_the_next_line_fire_at_the_k_line():
    script = (
        "#!/bin/sh\n"
        "curl https://api.example.org/v1/me \\\n"
        "  -k \\\n"
        '  -H "Authorization: Bearer $EXAMPLE_TOKEN"\n'
    )
    assert at(run(**{"scripts/run.sh": script})) == [("scripts/run.sh", 3)]


def test_credential_five_lines_away_counts_six_lines_away_does_not():
    near = "# note\n" * 4 + 'headers = {"Authorization": "Bearer EXAMPLEEXAMPLEEXAMPLE"}\n'
    far = "# note\n" * 5 + 'headers = {"Authorization": "Bearer EXAMPLEEXAMPLEEXAMPLE"}\n'
    assert len(run(**{"scripts/a.py": "requests.get(url, verify=False)\n" + near})) == 1
    assert run(**{"scripts/a.py": "requests.get(url, verify=False)\n" + far}) == []


def test_each_switch_line_is_reported_with_a_cap():
    script = 'requests.get(u, headers=H, verify=False)  # Authorization\n' * 500
    findings = run(**{"scripts/many.py": script})
    assert 1 <= len(findings) <= 25


# --- negatives --------------------------------------------------------------------------------

def test_loopback_target_in_the_call_is_quiet():
    script = 'requests.get("https://localhost:8443/health", headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n'
    assert run(**{"scripts/a.py": script}) == []
    script = 'requests.get("https://127.0.0.1:8443/h", headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n'
    assert run(**{"scripts/a.py": script}) == []
    script = 'requests.get("https://[::1]:8443/h", headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n'
    assert run(**{"scripts/a.py": script}) == []


def test_default_url_constant_pointing_at_loopback_is_quiet():
    script = (
        'BASE_URL = os.environ.get("EXAMPLE_URL", "https://localhost:9443")\n\n\n'
        "def call(token):\n"
        '    return requests.get(BASE_URL + "/v1/ping", headers={"Authorization": f"Bearer {token}"},\n'
        "                        verify=False)\n"
    )
    assert run(**{"scripts/a.py": script}) == []


def test_default_url_constant_pointing_at_a_remote_host_still_fires():
    script = (
        'BASE_URL = os.environ.get("EXAMPLE_URL", "https://api.example.com")\n\n\n'
        "def call(token):\n"
        '    return requests.get(BASE_URL + "/v1/ping", headers={"Authorization": f"Bearer {token}"},\n'
        "                        verify=False)\n"
    )
    assert at(run(**{"scripts/a.py": script})) == [("scripts/a.py", 6)]


def test_loopback_word_next_to_a_remote_url_still_fires():
    script = 'requests.get("https://api.example.com/x", headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)  # not localhost\n'
    assert len(run(**{"scripts/a.py": script})) == 1


def test_switch_behind_an_opt_in_variable_that_defaults_off_is_quiet():
    script = (
        "import os\n"
        'if os.environ.get("EXAMPLE_ALLOW_INSECURE") == "1":\n'
        "    verify = False\n"
        'requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=verify)\n'
    )
    assert run(**{"scripts/a.py": script}) == []
    script = (
        "if (process.env.EXAMPLE_INSECURE) {\n"
        "  agent = new https.Agent({ rejectUnauthorized: false });\n"
        "}\n"
        "headers['X-API-Key'] = key;\n"
    )
    assert run(**{"scripts/a.js": script}) == []
    script = 'if [ "${EXAMPLE_INSECURE:-0}" = "1" ]; then curl -k -H "Authorization: $T" "$URL"; fi\n'
    assert run(**{"scripts/a.sh": script}) == []


def test_unrelated_condition_does_not_hide_the_switch():
    script = (
        "if not response.ok:\n"
        '    requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n'
    )
    assert len(run(**{"scripts/a.py": script})) == 1


@pytest.mark.parametrize("prose", [
    "You MUST NOT pass verify=False when sending a token.",
    "Never use curl -k with an Authorization header.",
    "Anti-pattern: rejectUnauthorized: false next to an API key.",
])
def test_guidance_in_prose_is_quiet(prose):
    assert run("\n" + prose + "\n") == []


def test_guidance_above_a_fenced_block_and_in_a_comment_is_quiet():
    body = ("\nDo not do this, it sends the token over an unverified connection:\n"
            + fenced("python", 'requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n'))
    assert run(body) == []
    script = ('# MUST NOT be copied: disables TLS checks next to a token.\n'
              'requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n')
    assert run(**{"scripts/a.py": script}) == []
    script = ('requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)  # never do this\n')
    assert run(**{"scripts/a.py": script}) == []


def test_scanner_pattern_table_is_quiet():
    script = (
        "# token-bearing request detectors\n"
        "INSECURE_TLS = [\n"
        '    "verify=False",\n'
        '    "rejectUnauthorized: false",\n'
        '    "InsecureSkipVerify: true",\n'
        '    "curl -k",\n'
        "]\n"
        'AUTH_WORDS = ["Authorization", "Bearer", "password", "token"]\n'
    )
    assert run(**{"scripts/lint.py": script}) == []
    script = 'RE = re.compile(r"verify\\s*=\\s*False|rejectUnauthorized.*false")  # Authorization token\n'
    assert run(**{"scripts/lint.py": script}) == []


def test_switch_with_no_credential_nearby_is_quiet():
    assert run(**{"scripts/a.py": 'requests.get("https://api.example.com/public/list", verify=False)\n'}) == []
    assert run(**{"scripts/a.sh": "curl -k https://api.example.com/public/list\n"}) == []
    # max_tokens is not a credential
    assert run(**{"scripts/a.py": 'client.create(max_tokens=100, url="https://api.example.com", verify=False)\n'}) == []


def test_secure_defaults_and_prose_mentions_are_quiet():
    script = 'requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=True)\n'
    assert run(**{"scripts/a.py": script}) == []
    script = 'requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify="/etc/ssl/ca.pem")\n'
    assert run(**{"scripts/a.py": script}) == []
    assert run("\nThe client sets verify=False and an Authorization header, which is how the old script worked.\n") == []
    # `-k` is only curl's switch; another tool's `-k` and a `-K` config file are not
    assert run(**{"scripts/a.sh": 'sort -k2 --header="Authorization" list.txt\n'}) == []
    assert run(**{"scripts/a.sh": 'curl -K curl.conf -H "Authorization: Bearer $T" https://api.example.org/\n'}) == []
    assert run(**{"scripts/a.sh": 'export no_verify=False; echo "$TOKEN"\n'}) == []


@pytest.mark.parametrize("path", [
    "tests/test_client.py", "test/client.js", "scripts/test_client.py", "scripts/client_test.go", "pkg/tests/helpers/net.sh",
])
def test_test_files_are_excluded(path):
    code = 'requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n'
    assert run(**{path: code}) == []


def test_files_outside_the_script_list_are_not_scanned():
    code = 'requests.get(url, headers={"Authorization": "Bearer EXAMPLEEXAMPLE"}, verify=False)\n'
    assert run(**{"notes/example.txt": code, "scripts/client.rb": code}) == []


def test_empty_package_yields_nothing():
    assert list(detect(Package.build({}))) == []


# --- linear time and bounds -------------------------------------------------------------------

def test_long_repeated_switch_line_is_read_in_linear_time():
    line = "requests.get(u, " + "verify=False, " * 21_500 + 'headers={"Authorization": t})'
    assert len(line) > 300_000
    started = time.perf_counter()
    findings = run(**{"scripts/long.py": line + "\n"})
    assert time.perf_counter() - started < 1
    assert len(findings) == 1
    assert len(findings[0].evidence) <= 300


def test_long_quiet_lines_are_read_in_linear_time():
    for line in ("verify=False, " * 21_500 + "\n", "curl " + "-k " * 100_000 + "\n", "= " * 150_000 + "\n",
                 "token " * 50_000 + "verify=False" + " localhost" * 20_000 + "\n"):
        started = time.perf_counter()
        run(**{"scripts/long.sh": line})
        assert time.perf_counter() - started < 1


# --- invariant 4: no finding on any existing skill fixture ------------------------------------

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


# --- the rule's own fixtures ------------------------------------------------------------------

def test_own_positive_fixture_fires_and_negative_stays_quiet():
    positive = list(detect(Package.build(_read_dir(SKILL_FIXTURES / RULE_ID / "positive"))))
    negative = list(detect(Package.build(_read_dir(SKILL_FIXTURES / RULE_ID / "negative"))))
    assert len(positive) >= 3
    assert {f.location.path for f in positive} >= {"scripts/fetch.py", "scripts/pull.js", "SKILL.md"}
    assert negative == []
