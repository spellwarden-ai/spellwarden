"""Phase 3 batch 2a spec 7.1, 7.2 and T-8 (the module's half): `spellwarden_scan.cyclonedx` writes documents that validate
against the vendored CycloneDX 1.7.2 schema, for every case of the hosted column of 7.3, with a reproducible serial number."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from conftest import CYCLONEDX_FILES, CYCLONEDX_SCHEMAS, cyclonedx_problems, cyclonedx_schema_bytes, cyclonedx_validator

from spellwarden_scan import cyclonedx as cdx

RECORDED = {
    "bom-1.7.schema.json": "73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce",
    "spdx.schema.json": "4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "cryptography-defs.schema.json": "027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44",
}
RULE_PAGE = "https://spellwarden.ai/docs/rules/SW-SKL-007?utm_source=ai-bom&utm_medium=export&utm_campaign=ai-bom"
HOME = "https://spellwarden.ai/?utm_source=ai-bom&utm_medium=export&utm_campaign=ai-bom"


@pytest.mark.parametrize("name", CYCLONEDX_FILES)
def test_the_vendored_schema_files_are_the_recorded_bytes_of_the_1_7_2_tag(name):
    assert hashlib.sha256(cyclonedx_schema_bytes(name)).hexdigest() == RECORDED[name]
    assert RECORDED[name] in (CYCLONEDX_SCHEMAS / "SOURCE.md").read_text(encoding="utf-8")


def hosted_document(*, timestamp: str = "2026-11-14T10:00:00Z") -> dict:
    """Every hosted case of 7.3 at once: a git skill, a plugin with its marketplace and skill, a stdio and a remote server, a
    repository with an agent, a runtime-only server and skill, a rule finding, an accepted finding, an org rule's finding, a
    manual finding, and the service the tool component names."""
    marketplace = cdx.component(ref="marketplace:3f2a", type="data", name="tools",
                                external=[("distribution", "https://github.com/example/tools")],
                                properties=[cdx.prop("kind", "marketplace")])
    plugin = cdx.component(ref="plugin:0123456789abcdef", type="library", name="lint", properties=[cdx.prop("kind", "plugin")])
    skill = cdx.component(ref="skill:s1", type="library", name="deploy", version="1.0.0", hashes=["a" * 64],
                          external=[("vcs", "https://github.com/example/skills")],
                          properties=[cdx.prop("kind", "skill"), cdx.prop("source", "git"), cdx.prop("curated", True)])
    repository = cdx.component(ref="repository:r1", type="application", name="github.com/example/app",
                               properties=[cdx.prop("kind", "repository"), cdx.prop("items:skill", 3), cdx.prop("agent_cards", 51),
                                           cdx.prop("agent_cards_omitted", 1)])
    runtime_skill = cdx.component(ref="runtime-skill:k1", type="library", name="unknown-skill",
                                  properties=[cdx.prop("kind", "skill"), cdx.prop("runtime_only", True)])
    stdio = cdx.service(ref="mcp-server:m1", name="files", properties=[
        cdx.prop("kind", "mcp-server"), cdx.prop("transport", "stdio"), cdx.prop("command", "cmd:npx pkg@1.0.0")])
    remote = cdx.service(ref="mcp-server:m2", name="remote", endpoints=["https://mcp.example.com/mcp"], authenticated=True,
                         properties=[cdx.prop("kind", "mcp-server"), cdx.prop("tool", "search"), cdx.prop("tool", "fetch")])
    agent = cdx.service(ref="agent:r1:0", name=".well-known/agent-card.json", properties=[
        cdx.prop("kind", "a2a-agent"), cdx.prop("source", "repository"), cdx.prop("protocol_version", "1.0")])
    runtime_server = cdx.service(ref="runtime-server:k2", name="mystery", properties=[
        cdx.prop("kind", "mcp-server"), cdx.prop("runtime_only", True), cdx.prop("first_seen", "2026-10-01")])
    state, response = cdx.ANALYSIS["open"]
    accepted_state, accepted_response = cdx.ANALYSIS["accepted"]
    vulnerabilities = [
        cdx.vulnerability(ref="finding:f1", title="Remote script piped to a shell", severity="high", affects=["skill:s1"],
                          state=state, response=response, rule_id="SW-SKL-007", url=RULE_PAGE, created="2026-11-01T08:00:00Z",
                          properties=[cdx.prop("status", "open"), cdx.prop("origin", "rule")]),
        cdx.vulnerability(ref="finding:f2", title="Unpinned package", severity="medium", affects=["mcp-server:m1"],
                          state=accepted_state, response=accepted_response, rule_id="SW-CFG-003", url=RULE_PAGE,
                          detail="Reviewed by the platform team.", properties=[cdx.prop("status", "accepted")]),
        cdx.vulnerability(ref="finding:f3", title="Staging host in a skill", severity="low", affects=["repository:r1"],
                          state=state, rule_id="SW-ORG-010"),
        cdx.vulnerability(ref="finding:f4", title="Reported by a reviewer", severity="critical", affects=["agent:r1:0"],
                          state=state, properties=[cdx.prop("origin", "manual")]),
    ]
    dependencies = [cdx.dependency("marketplace:3f2a", ["plugin:0123456789abcdef"]),
                    cdx.dependency("plugin:0123456789abcdef", ["skill:s1"]), cdx.dependency("repository:r1", ["agent:r1:0"])]
    return cdx.document(
        subject=cdx.component(ref="org:acme", type="application", name="Acme"), tool_version="1.14.0", tool_url=HOME,
        timestamp=timestamp, components=[marketplace, plugin, skill, repository, runtime_skill],
        services=[stdio, remote, agent, runtime_server], vulnerabilities=vulnerabilities, dependencies=dependencies,
        properties=[cdx.prop("count:skills", 1), cdx.prop("runtime_partial", False), cdx.prop("vulnerabilities_omitted", 0)],
        tool_properties=[cdx.prop("service", "dash.spellwarden.ai")])


def test_every_hosted_case_of_the_mapping_validates_and_every_reference_resolves():
    document = hosted_document()
    assert cyclonedx_problems(document) == []
    assert list(document)[:5] == ["$schema", "bomFormat", "specVersion", "serialNumber", "version"]
    assert (document["specVersion"], document["$schema"]) == ("1.7", "http://cyclonedx.org/schema/bom-1.7.schema.json")
    tool = document["metadata"]["tools"]["components"][0]  # 7.3: the hosted export names its service on the tool component
    assert (tool["name"], tool["version"]) == ("Spellwarden", "1.14.0")
    assert tool["properties"] == [{"name": "spellwarden:service", "value": "dash.spellwarden.ai"}]


def test_a_manual_finding_has_no_id_and_no_link_and_an_org_rule_finding_has_its_id_and_no_link():
    by_ref = {entry["bom-ref"]: entry for entry in hosted_document()["vulnerabilities"]}
    assert "id" not in by_ref["finding:f4"] and by_ref["finding:f4"]["source"] == {"name": "Spellwarden"}
    assert by_ref["finding:f3"]["id"] == "SW-ORG-010" and by_ref["finding:f3"]["source"] == {"name": "Spellwarden"}
    assert by_ref["finding:f1"]["source"] == {"name": "Spellwarden", "url": RULE_PAGE}
    assert by_ref["finding:f2"]["analysis"] == {"state": "exploitable", "response": ["will_not_fix"],
                                                "detail": "Reviewed by the platform team."}
    assert by_ref["finding:f1"]["analysis"] == {"state": "in_triage"}
    assert by_ref["finding:f1"]["ratings"] == [{"source": {"name": "Spellwarden", "url": RULE_PAGE}, "severity": "high",
                                                "method": "other"}]


def test_the_serial_number_depends_on_the_content_and_not_on_the_timestamp():
    first, second = hosted_document(), hosted_document(timestamp="2027-01-01T00:00:00Z")
    assert first["serialNumber"] == second["serialNumber"]
    assert first["serialNumber"].startswith("urn:uuid:") and first["serialNumber"][23] == "5"  # UUID version 5
    changed = cdx.document(subject=cdx.component(ref="org:other", type="application", name="Other"), tool_version="1.14.0",
                           tool_url=HOME, timestamp="2026-11-14T10:00:00Z", components=[], services=[], vulnerabilities=[],
                           dependencies=[], properties=[])
    assert changed["serialNumber"] != first["serialNumber"]
    assert cyclonedx_problems(changed) == []
    assert "properties" not in changed["metadata"]["tools"]["components"][0]  # no `tool_properties`, as the scanner writes it


def test_properties_are_prefixed_strings():
    assert cdx.prop("runtime_only", True) == {"name": "spellwarden:runtime_only", "value": "true"}
    assert cdx.prop("spellwarden:calls", 12) == {"name": "spellwarden:calls", "value": "12"}


@pytest.mark.parametrize("given, reduced", [
    ("https://user:secret@Mcp.Example.com:8443/mcp?token=abc#frag", "https://mcp.example.com:8443/mcp"),
    ("http://[::1]:9000/sse", "http://[::1]:9000/sse"),
    ("https://github.com/example/tools.git", "https://github.com/example/tools.git"),
    ("example/tools", None), ("/srv/data", None), ("https://a.example/ b", None), (None, None),
    # A token carried in a path segment is masked, the other segments and the host stay readable
    ("https://mcp.example.com/api/mcp/s/q8F3kZ7vR2mX9pL4tW6yB1nC5dH0jA/mcp",
     "https://mcp.example.com/api/mcp/s/q8F3***/mcp"),
    ("https://hooks.example.com/services/T0001/B0002/ghp_abcdefghijklmnopqrstuvwxyz0123456789",
     "https://hooks.example.com/services/T0001/B0002/ghp_***"),
])
def test_reduce_url_keeps_scheme_host_port_and_path_only(given, reduced):
    assert cdx.reduce_url(given) == reduced


def test_reduce_url_is_idempotent_on_a_masked_path():
    once = cdx.reduce_url("https://mcp.example.com/s/q8F3kZ7vR2mX9pL4tW6yB1nC5dH0jA/mcp")
    assert once is not None and "q8F3kZ7vR2mX9pL4tW6yB1nC5dH0jA" not in once
    assert cdx.reduce_url(once) == once


def test_a_workstation_subject_carries_no_identifier():
    subject = cdx.component(ref=None, type="device", name="workstation")
    assert subject == {"type": "device", "name": "workstation"}


GOLDEN_DOCUMENTS = sorted((Path(__file__).resolve().parent / "golden").rglob("*.cdx.json"))


def test_the_validator_checks_date_time_and_iri_reference():
    """1.16.2: with `rfc3339-validator` and `rfc3987-syntax` installed (development dependencies only) the validator checks
    the two formats the CycloneDX schema uses most, which 1.16.1's locked dependencies left unchecked."""
    checker = cyclonedx_validator().format_checker
    assert {"date-time", "iri-reference"} <= set(checker.checkers)
    assert checker.conforms("2026-11-16T10:00:00Z", "date-time") and checker.conforms(RULE_PAGE, "iri-reference")
    assert not checker.conforms("2026-11-16 10:00", "date-time") and not checker.conforms("16 Nov 2026", "date-time")
    assert not checker.conforms("https://exa mple.com/<x>", "iri-reference")
    document = hosted_document()
    assert cyclonedx_problems(document) == []
    bad_time = hosted_document(timestamp="2026-11-14 10:00")
    assert any("date-time" in problem for problem in cyclonedx_problems(bad_time)), cyclonedx_problems(bad_time)
    bad_url = json.loads(json.dumps(document))
    bad_url["components"][0]["externalReferences"][0]["url"] = "https://github.com/example/<tools> here"
    (error,) = cyclonedx_validator().iter_errors(bad_url)  # `url` is an iri-reference or a BOM-Link: neither matches
    assert list(error.absolute_path) == ["components", 0, "externalReferences", 0, "url"]
    assert any(sub.validator == "format" and sub.validator_value == "iri-reference" for sub in error.context)


@pytest.mark.parametrize("path", GOLDEN_DOCUMENTS, ids=lambda path: path.name)
def test_every_recorded_cyclonedx_document_validates_with_the_format_checks(path):
    assert GOLDEN_DOCUMENTS  # the recorded documents of 1.14.0 (repository and homes)
    assert cyclonedx_problems(json.loads(path.read_text(encoding="utf-8"))) == []


# --- 1.16.2: `reduce_url` writes a valid IRI reference and masks `name=value` credential segments as the backend does --------

# The hosted backend's `util.mask_path_credentials` expression, copied: the engine's must be the same, so the two never disagree.
BACKEND_PATH_CREDENTIAL = r"^((?:[A-Za-z0-9]+[_-])*(?:key|apikey|token|secret|password|passwd|sig|signature))=.+$"


def _iri(text: str) -> bool:
    return cyclonedx_validator().format_checker.conforms(text, "iri-reference")


@pytest.mark.parametrize("char, escaped", [("<", "%3C"), (">", "%3E"), ('"', "%22"), ("{", "%7B"), ("}", "%7D"), ("|", "%7C"),
                                           ("\\", "%5C"), ("^", "%5E"), ("`", "%60"), ("[", "%5B"), ("]", "%5D"),
                                           ("\x9f", "%C2%9F"), ("", "%EE%80%80"), ("﷐", "%EF%B7%90")])
def test_reduce_url_percent_encodes_what_an_iri_reference_does_not_allow_in_the_path(char, escaped):
    reduced = cdx.reduce_url(f"https://mcp.example.com/a{char}b/mcp")
    assert reduced == f"https://mcp.example.com/a{escaped}b/mcp"
    assert _iri(reduced) and cdx.reduce_url(reduced) == reduced


@pytest.mark.parametrize("given", ["https://mcp.example.com/a b", "https://mcp.example.com/a\tb", "https://mcp.example.com/a\x7fb",
                                   "https://mcp.example.com/a\x00b", "https://mcp.example.com/a\x85b"])
def test_reduce_url_still_refuses_whitespace_and_ascii_control_characters(given):
    assert cdx.reduce_url(given) is None


def test_reduce_url_escapes_a_mixed_url_keeps_valid_escapes_and_non_ascii_and_drops_query_and_fragment():
    given = 'https://User:pw@Mcp.Example.com:8443/café/日本/a<{|^"b/%3Cok%3e/50%/x%zz?q=<1>#<frag>'
    reduced = cdx.reduce_url(given)
    assert reduced == "https://mcp.example.com:8443/café/日本/a%3C%7B%7C%5E%22b/%3Cok%3e/50%25/x%25zz"
    assert _iri(reduced) and cdx.reduce_url(reduced) == reduced


def test_reduce_url_escapes_the_host_too_and_refuses_a_bracketed_host_that_is_no_ipv6_address():
    assert cdx.reduce_url("https://ex<am{ple.com/mcp") == "https://ex%3Cam%7Bple.com/mcp"
    assert cdx.reduce_url("https://a%5db/") == "https://a%5Db/"  # the host is lower-cased: its escapes keep upper-case digits
    assert cdx.reduce_url(cdx.reduce_url("https://a]b/")) == "https://a%5Db/"
    assert cdx.reduce_url("https://[fe80::1%25eth0]/mcp") is None and cdx.reduce_url("https://[::g]/mcp") is None
    # review of 1.16.2, Minor 1: a bracketed host without `:` is no IP literal, and never reads as another host
    for given in ("https://[evil.example]/mcp", "https://[v1.x]/mcp", "https://[1.2.3.4]/"):
        assert cdx.reduce_url(given) is None, given
    assert cdx.reduce_url("http://[::1]:9000/sse") == "http://[::1]:9000/sse"


def test_reduce_url_is_idempotent_and_never_raises():
    pieces = ["a", "Z", "9", "-", ".", "_", "~", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=", ":", "@", "/", "%", "%3C",
              "%zz", "%4", "<", ">", '"', "{", "}", "|", "\\", "^", "`", "[", "]", "é", "\u0085", "\ud800", "",
              "\U000f0000", "﷐", "￿", "key=", "sig=", "api_key=", "token=", "q8F3kZ7vR2mX9pL4tW6yB1nC5dH0jA",
              "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "Bearer", "user:pw@"]
    import random

    rng = random.Random(1162)
    for _ in range(4000):
        host = rng.choice(["mcp.example.com", "ex<am{ple.com", "[::1]", "[v1.x]", "h%41st", "a]b", "Hé.example", "x\u0085y"])
        url = f"https://{host}/" + "".join(rng.choice(pieces) for _ in range(rng.randint(0, 12))) + rng.choice(["", "?q=<", "#<"])
        once = cdx.reduce_url(url)
        if once is not None:
            assert cdx.reduce_url(once) == once, url
            assert "[::1]" in once or _iri(once), url  # rfc3987-syntax 1.1.0 refuses compressed IPv6 literals (see conftest)
    for value in (None, 1, b"https://x.example/", "", "https://", "https://:80/", "http://[/", "https://x.example/\ud800"):
        cdx.reduce_url(value)


@pytest.mark.parametrize("segment, masked", [
    ("key=abc123", "key=***"), ("sig=AbC%2Bdef", "sig=***"), ("signature=deadbeef", "signature=***"),
    ("x-api-key=v", "x-api-key=***"), ("API_KEY=v", "API_KEY=***"), ("apikey=v", "apikey=***"), ("access_token=v", "access_token=***"),
    ("client-secret=v", "client-secret=***"), ("db_password=v", "db_password=***"), ("passwd=v", "passwd=***"), ("Sig=v", "Sig=***"),
    # not credential names: the backend leaves these, and so does the engine
    ("monkey=1", "monkey=1"), ("design=x", "design=x"), ("keys=1", "keys=1"), ("keyring=x", "keyring=x"),
    ("signatures=2", "signatures=2"), ("key=", "key="), ("passkey", "passkey"),
    # review of 1.16.2, Minor 2: the name is judged percent-decoded, once
    ("k%65y=secret", "key=***"), ("%6Bey=secret", "key=***"), ("x-key%3Dsecret", "x-key=***"), ("API%5FKEY=v", "API_KEY=***"),
    ("%2565y=secret", "%2565y=secret"), ("mon%6Bey=1", "mon%6Bey=1"),
])
def test_reduce_url_masks_name_value_segments_as_the_backend_does(segment, masked):
    reduced = cdx.reduce_url(f"https://hooks.example.com/v1/{segment}/run")
    assert reduced == f"https://hooks.example.com/v1/{masked}/run"
    assert _backend_mask(reduced) == reduced  # the backend's masking finds nothing left to do
    assert cdx.reduce_url(reduced) == reduced


def _backend_mask(url: str) -> str:
    """`util.mask_path_credentials` of the hosted backend, as written there."""
    import re

    pattern = re.compile(BACKEND_PATH_CREDENTIAL, re.IGNORECASE)
    scheme, _, rest = url.partition("://")
    host, slash, path = rest.partition("/")
    if not slash:
        return url
    return f"{scheme}://{host}/" + "/".join(pattern.sub(r"\1=***", segment) for segment in path.split("/"))


def test_the_engine_s_path_credential_expression_is_the_backend_s():
    import re

    assert (cdx._PATH_CREDENTIAL.pattern, cdx._PATH_CREDENTIAL.flags & re.IGNORECASE) == (BACKEND_PATH_CREDENTIAL, re.IGNORECASE)


def test_a_document_with_an_endpoint_and_a_reference_holding_iri_breaking_characters_validates():
    endpoint = cdx.reduce_url('https://mcp.example.com/a<{|^"b/mcp')
    source = cdx.reduce_url('https://git.example.com/acme/to<{|^"ols')
    assert endpoint is not None and source is not None
    document = cdx.document(
        subject=cdx.component(ref="org:acme", type="application", name="Acme"), tool_version="1.16.2", tool_url=HOME,
        timestamp="2026-11-16T10:00:00Z",
        components=[cdx.component(ref="marketplace:m", type="data", name="tools", external=[("distribution", source)])],
        services=[cdx.service(ref="mcp-server:s", name="odd", endpoints=[endpoint])], vulnerabilities=[], dependencies=[],
        properties=[])
    assert cyclonedx_problems(document) == []


# review of 1.16.2, Major 1: a segment is masked as written, before it is escaped, so escaping never hides a credential


@pytest.mark.parametrize("given, reduced", [
    ('https://h.example/{"token":"Zq7Wv3Kp"}/x', 'https://h.example/%7B%22token%22:%22***%22%7D/x'),
    ('https://h.example/a/token"="Zq7Wv3Kp', None),
    ("https://h.example/a/<Authorization:Zq7Wv3Kp", None),
])
def test_escaping_never_unmasks_a_credential(given, reduced):
    out = cdx.reduce_url(given)
    assert out is not None and "Zq7Wv3Kp" not in out
    assert reduced is None or out == reduced
    assert _iri(out) and cdx.reduce_url(out) == out


def _reduce_1_16_1(text: str) -> str | None:
    """1.16.1's `reduce_url`, vendored for the differential test below."""
    from spellwarden_scan.agentconfig import url_parts
    from spellwarden_scan.evidence import mask_credentials

    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in text):
        return None
    parts = url_parts(text)
    if parts is None:
        return None
    host = f"[{parts.host}]" if ":" in parts.host else parts.host
    path = "/".join(mask_credentials(segment) for segment in parts.path.split("/"))
    return f"{parts.scheme}://{host}{':' + parts.port if parts.port else ''}{path}"


def test_nothing_1_16_1_masked_comes_out_unmasked():
    import itertools
    import random

    secret = "Zq7Wv3Kp"
    names = ["token", "password", "api_key", "secret", "key", "Authorization", "access_token", "pwd", "auth", "client_secret"]
    ops = ["=", ":", "=\"", "%3D", ":\"", "='", "=%22", "\"=\"", "\":\"", "=\\\"", "\\\":\\\""]
    pres = ["", "\"", "{", "<", "|", "%", "\u00e9", "^", "\\", "{\"", "`", "["]
    posts = ["", "\"", "}", ">", "]"]
    corpus = [f"https://h.example/a/{pre}{name}{op}{secret}{post}/b"
              for pre, name, op, post in itertools.product(pres, names, ops, posts)]
    rng = random.Random(20261116)
    pieces = [*pres, *posts, *names, *ops, "Bearer ", "user:", "@", "-", "_"]
    corpus += ["https://h.example/" + "".join(rng.choice(pieces) for _ in range(rng.randint(1, 6))) + secret
               + "".join(rng.choice(posts) for _ in range(rng.randint(0, 2))) for _ in range(3000)]
    checked = 0
    for url in corpus:
        old = _reduce_1_16_1(url)
        if old is None or secret in old:
            continue
        checked += 1
        new = cdx.reduce_url(url)
        assert new is not None and secret not in new, (url, old, new)
    assert checked > 1000


def test_a_canonical_repository_url_is_escaped_and_never_masked():
    for url in ("https://github.com/acme/mcp-server-2024-edition-v2", "https://git.example.com/acme/Tools2024ForTheWholeTeamV3"):
        assert cdx.reduce_url(url, masking="none") == url
        assert cdx.reduce_url(url) != url  # what `masking="full"` would have done to the link
    assert cdx.reduce_url("https://git.example.com/a/b<c", masking="none") == "https://git.example.com/a/b%3Cc"
    assert cdx.reduce_url("https://hooks.example.com/key=v", masking="evidence") == "https://hooks.example.com/key=v"
    with pytest.raises(ValueError):
        cdx.reduce_url("https://x.example/", masking="some")
