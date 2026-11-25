"""1.21.0 (P6-15 spec 6.2, 6.12 E-1 and E-2): every baseline rule carries the fix sentence of spec section 5, word for word, in the
form of spec 4.2 (F1 to F6), and its page, the address with the id in lower case; an organisation rule carries neither. `make_rule`
refuses a sentence that breaks the form and `RuleSet.baseline()` refuses a baseline rule without one. `SECTION_5` is the spec's
table, which the owner approved on 2026-11-23: a change to a sentence changes it here and in the rule module, in one reviewed
commit."""
from __future__ import annotations

import dataclasses
import json

import pytest

from spellwarden_scan import RuleSet, compile_org_rule
from spellwarden_scan.rules import FIX_MAX, FIX_VERBS, RULE_PAGE, a2a, config, fix_problem, make_rule, mcp, registry, skill
from spellwarden_cli.rulescmd import rules_json

SECTION_5 = {
    "SW-SKL-001": "Delete the sentence that tells the model to ignore its instructions or keep things from the user, and describe the task in plain steps instead.",
    "SW-SKL-002": "Delete the hidden characters the finding names, for example by retyping the line in an editor that shows invisible characters, and check the lines around it.",
    "SW-SKL-003": "Remove the instruction to skip approvals or disable hooks, and approve the commands a step needs once, in the agent's own permission settings.",
    "SW-SKL-004": "Write the command out in plain text where a reviewer can read it, and remove the step that decodes and runs it.",
    "SW-SKL-005": "Take the change to the agent's configuration out of the skill and describe the setting instead, so the project's owner makes it by hand in a reviewed change.",
    "SW-SKL-006": "Add a step that shows what the command will remove and asks the user to confirm before it runs, and limit it to a path the script created.",
    "SW-SKL-007": "Download the script to a file and check it against a published checksum before you run it, or install the tool from a package manager at a pinned version.",
    "SW-SKL-008": "Remove the command that sends local files, and send only data the skill produced itself, to a host its description names.",
    "SW-SKL-009": "Pin each install to an exact version, for example package==1.4.2 for pip, and add a lock file or hashes where the tool supports them.",
    "SW-SKL-010": "Replace the bundled binary with source code or a pinned install from a package manager, or publish its source and checksum next to it.",
    "SW-SKL-011": "Revoke the credential at its provider, remove it from the package and have the skill read it from an environment variable or the user's secret store.",
    "SW-SKL-012": "Stop reading the credential file, or say in the line above the read why the skill needs it, so a reviewer can judge it.",
    "SW-SKL-013": "Call the service by its real host name over https instead of a raw IP address, and replace a shortened link with the address it points to.",
    "SW-SKL-014": "Replace the obfuscated or evaluated code with plain code that does the one thing the script needs, and move large data blocks into a data file.",
    "SW-SKL-015": "Start SKILL.md with a front matter block that holds a name in lower case letters, digits and hyphens and a one-sentence description.",
    "SW-SKL-019": "List the hosts the skill may read from, and treat what a fetched page says as data to summarise, never as instructions.",
    "SW-SKL-031": "Add a license line, such as MIT or Apache-2.0, and a version line to the skill, and raise the version whenever the skill changes.",
    "SW-SKL-032": "Remove the download and the pasted script, and name the tool by its package so the user installs it from a package manager or the vendor's site.",
    "SW-SKL-036": "Scope each pre-approved shell entry to the named program the skill runs, or drop the entry if the skill needs no shell.",
    "SW-SKL-037": "Download a release with a version in its address and compare its published checksum or signature before you make the file executable.",
    "SW-SKL-038": "Take the write to the agent's memory or instruction file out of the skill, and describe the text to add so the project's owner adds it by hand in a reviewed change.",
    "SW-MCP-001": "Require authentication before the server answers tools/list, using OAuth with protected resource metadata.",
    "SW-MCP-002": "Move the server from a static key to OAuth with protected resource metadata, and until then scope the key to one client and rotate it.",
    "SW-MCP-003": "Turn on Client ID Metadata Documents at the authorization server and publish client_id_metadata_document_supported as true in its metadata.",
    "SW-MCP-004": "Move the server from HTTP+SSE to the streamable HTTP transport, which answers POST requests on one address.",
    "SW-MCP-005": "Update the MCP server library to a release that supports protocol version 2026-07-28, and list that version in supportedVersions.",
    "SW-MCP-006": "Make the server stateless: stop issuing Mcp-Session-Id and keep what the session held in each request or in your own storage.",
    "SW-MCP-007": "Add a server/discover handler that returns the supported versions, the capabilities and the server information.",
    "SW-MCP-008": "Replace Roots, Sampling and Logging as the migration checklist describes, then remove them from the capabilities the server declares.",
    "SW-MCP-009": "Serve the endpoint over https, with a proxy you operate in front of the server if it cannot terminate TLS itself.",
    "SW-MCP-010": "Publish protected resource metadata at the address the 401 answer names, list your authorization server in it, and make that server's issuer match its address.",
    "SW-MCP-011": "Rewrite the description so it says only what the tool does and what its arguments mean, or stop using the server if you do not run it.",
    "SW-MCP-012": "Read each changed tool, then approve the new tool list if you expected the change, or remove the server from your agents if you did not.",
    "SW-MCP-013": "Replace the free-text command with named operations that take typed arguments, or run the tool in a sandbox that allows a short list of programs and no network.",
    "SW-CFG-001": "Change the server address to https, or put a proxy you operate in front of a server that only offers http.",
    "SW-CFG-002": "Revoke the credential at its provider, then replace the value in the file with a reference such as ${NAME} that your client expands.",
    "SW-CFG-003": "Launch the server at an exact version, such as name@1.4.2 for npx, name==1.4.2 for uvx or an image digest, and update it through a reviewed change.",
    "SW-CFG-004": "Give the server a host name you control and serve it over https, and replace a shortened link with the address it expands to.",
    "SW-CFG-005": "Commit the script to the repository and call that file from the hook, or check the download's SHA-256 against a value kept in the repository before it runs.",
    "SW-CFG-006": "Delete the hook, treat it as an incident, and rotate the credentials in the files it read on every machine that ran it.",
    "SW-CFG-007": "Remove the hook, decode the string without running it to learn what it does, and rotate anything the machine could reach if it ran.",
    "SW-CFG-008": "Remove the settings that switch off approval prompts, or narrow them to named commands and to MCP servers approved one by one.",
    "SW-CFG-009": "Add a sha with the full 40-character commit id the plugin was reviewed at, and move to a newer commit only through a reviewed change.",
    "SW-CFG-010": "Change the secret at its source, then replace the literal value with a reference such as ${NAME} that your client expands.",
    "SW-CFG-012": "Remove the setting that approves every tool call, or limit it to tools that only read, so the client asks before the others run.",
    "SW-CFG-013": "Add the server's read-only switch, and give write access to a separate entry that stays disabled until the work needs it.",
    "SW-CFG-015": "Give the server only the project folder it needs, for example the path of the repository, and keep the home directory and the credentials in it out of its reach.",
    "SW-REG-001": "Request the skill's admission to your organisation's private registry with the link in the report, or take the skill out of the change.",
    "SW-REG-002": "Request the MCP server's admission to your organisation's private registry with the link in the report, or take the server out of the change.",
    "SW-REG-003": "Make the item identifiable, for example by pinning every package to an exact version and writing the launch out in full, then request its admission.",
    "SW-A2A-001": "Add the missing members, correct the wrong types and write each protocolVersion as 1.0, then scan again.",
    "SW-A2A-002": "Move the card to the A2A 1.0 format, with supportedInterfaces and securityRequirements in place of the old members, then sign it again.",
    "SW-A2A-003": "Serve the card at /.well-known/agent-card.json, and keep a copy at the old path only until a date you set.",
    "SW-A2A-004": "Serve the agent endpoint and every authentication address over https, and write the final https addresses in the card.",
    "SW-A2A-005": "Replace the implicit or password flow with authorizationCode and pkceRequired, clientCredentials or deviceCode, and switch the old flow off at the identity provider.",
    "SW-A2A-006": "Set pkceRequired to true in the authorization code flow, and turn on the matching setting at the identity provider.",
    "SW-A2A-007": "Define a scheme in securitySchemes and name it in securityRequirements, or accept the finding with a note if the agent is meant to be open.",
    "SW-A2A-008": "Send the API key in a header instead of the URL query, and rotate every key that has already been sent in an address.",
    "SW-A2A-009": "Give each skill its own securityRequirements that name only the scopes that skill needs.",
    "SW-A2A-010": "Sign the final card again after the last edit, or add the signing key to the key file that a2a.keys names, as the evidence says.",
    "SW-A2A-011": "Fix the signer so it writes a compact JWS with an allowed algorithm and a kid in the protected header, then sign the card again.",
    "SW-A2A-012": "Sign the card as the last step of each release, and list the public key in the file that a2a.keys names.",
    "SW-A2A-013": "Publish the signing key on the card's own host or list it in the file that a2a.keys names, then sign the card again.",
    "SW-A2A-014": "Delete the injected sentence or the hidden characters and describe the agent in plain words, and fix the source if the card is generated.",
    "SW-A2A-015": "Revoke the credential at its provider first, then remove it from the card, which describes how to authenticate and never holds a key.",
    "SW-A2A-016": "Remove the redirect, or point the a2a.agents entry at the final address of the card.",
    "SW-A2A-017": "Sign the card with a public-key algorithm such as ES256, publish the public key, and remove the HMAC signature.",
    "SW-A2A-018": "Make the card strict JSON in UTF-8, without comments, trailing commas or repeated keys, and keep it under the size limit.",
    "SW-A2A-019": "Keep only the camelCase JSON name of each member and delete the other spelling, then sign the card again if it is signed.",
}


def test_every_baseline_rule_has_the_sentence_of_section_5():
    assert {rule.id: rule.fix for rule in RuleSet.baseline()} == SECTION_5


def test_each_area_keeps_its_sentences_beside_its_titles():
    for module in (skill, mcp, config, a2a):
        assert set(module.FIXES) == set(module.TITLES), module.__name__
        assert all(module.FIXES[rule.id] == rule.fix for rule in module.RULES), module.__name__
    assert all(rule.fix == SECTION_5[rule.id] for rule in registry.RULES)


def test_every_sentence_keeps_the_form_of_spec_4_2():
    for rule_id, sentence in SECTION_5.items():
        assert fix_problem(sentence) is None, rule_id
    assert max(len(sentence) for sentence in SECTION_5.values()) == 165 < FIX_MAX == 200
    assert {sentence.split(" ", 1)[0] for sentence in SECTION_5.values()} == FIX_VERBS


@pytest.mark.parametrize("sentence, problem", [
    ("", "not one sentence"),
    ("pin each install to an exact version.", "not one sentence"),
    ("Pin each install to an exact version", "not one sentence"),
    ("Pin each install. Then add a lock file.", "not one sentence"),
    ("Pin " + "x" * 200 + ".", "longer than 200 characters"),
    ("Pin the caf\u00e9 package.", "not printable ASCII"),
    ("Pin the package; then lock it.", "one of ! ? ; < > | or a backtick"),
    ("Pin `package==1.4.2` in the file.", "one of ! ? ; < > | or a backtick"),
    ("Read https://example.com before you start.", "an address or the product name"),
    ("Ask Spellwarden support for help.", "an address or the product name"),
    ("Consider pinning each install.", "first word is not one of FIX_VERBS"),
])
def test_the_form_refuses_what_breaks_it(sentence, problem):
    assert problem in fix_problem(sentence)


def test_make_rule_refuses_a_sentence_that_breaks_the_form_and_takes_none():
    with pytest.raises(ValueError, match="SW-CFG-999: the fix sentence breaks its form"):
        make_rule("SW-CFG-999", "t", "low", "config", owasp=(), nist=(), atlas=(), detect=lambda _: iter(()), fix="pin it.")
    own = make_rule("SW-CFG-999", "t", "low", "config", owasp=(), nist=(), atlas=(), detect=lambda _: iter(()))
    assert own.fix == "" and own.to_dict()["fix"] is None


def test_the_baseline_refuses_a_rule_without_its_sentence(monkeypatch):
    monkeypatch.setattr(registry, "RULES", (dataclasses.replace(registry.RULES[0], fix=""), *registry.RULES[1:]))
    with pytest.raises(ValueError, match="baseline rules without a fix sentence: SW-REG-001"):
        RuleSet.baseline()


def test_the_page_is_the_id_in_lower_case_and_an_organisation_rule_has_neither():
    for rule in RuleSet.baseline():
        assert rule.page == RULE_PAGE.format(rule.id.lower()) == f"https://spellwarden.ai/docs/rules/{rule.id.lower()}"
    org = compile_org_rule({"id": "SW-ORG-001", "title": "Org pattern", "severity": "high", "area": "skill", "owasp": ["ASI01"],
                            "nist": ["SI-10"], "detection": {"kind": "pattern", "pattern": "needle"}})
    assert org.fix == "" and org.page is None
    assert (org.to_dict()["fix"], org.to_dict()["page"]) == (None, None)


def test_the_rules_listing_gives_each_rule_its_fix_and_page():
    listed = {entry["id"]: entry for entry in json.loads(rules_json(RuleSet.baseline()))}
    assert len(listed) == 69
    assert listed["SW-SKL-009"]["fix"] == SECTION_5["SW-SKL-009"]
    assert listed["SW-SKL-009"]["page"] == "https://spellwarden.ai/docs/rules/sw-skl-009"
