"""A2A agent reports (O4 spec 6.4 and 6.6): the cards of the repository, the trusted key file, and what becomes of each
signature. For every card file discovery found, in path order: `parse_agent_card`, the signature outcomes, then
`evaluate_agent_card`. The engine never verifies; `jws.py` does, over the inputs `signature_inputs` rebuilds.

What "verified" means is in the outcome's `key_source`: `keys_file` says a key of `a2a.keys` (the base revision's, on a pull
or merge request) signed the card, `jku` says only that whoever serves the key set the card names did. The outputs print it.

Nothing here opens a connection: a key set fetched under `--probe` arrives as `fetched` (`a2a_probe.py`)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit

from spellwarden_scan import (
    A2aScanResult, CardOrigin, RuleSet, SignatureOutcome, evaluate_agent_card, parse_agent_card, signature_inputs,
)
from spellwarden_scan.a2a import AgentCardDocument
from spellwarden_scan.a2a_signing import SignatureInput, must_be_signed
from spellwarden_scan.evidence import bounded_evidence

from spellwarden_cli import jws
from spellwarden_cli.discover import CardFile, Discovery, is_card
from spellwarden_cli.report import AgentReport, Notice, ReportFinding
from spellwarden_cli.settings import A2a

NO_KEY_SOURCE = "no_key_source"
SHARED_SECRET_DETAIL = "a shared-secret signature can only be checked by the agent that holds the secret"
ED448_DETAIL = "Ed448 is not verified by this release"
_NOT_A_CARD = {"too_large": "over 1 MiB"}


@dataclass(frozen=True)
class Trust:
    """The trusted key file: `state` is `none` (no `a2a.keys`), `missing` (named, absent from the revision read), `invalid`
    (present, not a key set: the run exits 2) or `loaded`."""
    path: str | None = None
    state: str = "none"
    keyset: jws.KeySet | None = None


@dataclass(frozen=True)
class KeyFetch:
    """What the probe phase got for one `jku` URL: the key set, or `reason` (`network`, `timeout`, `http_status`, `not_json`,
    `limit`, `budget`) when it could not be fetched or read."""
    keyset: jws.KeySet | None = None
    reason: str | None = None


@dataclass
class RemotePhase:
    """What the probe phase hands the scan about A2A (6.5): the reports of the remote agents (fetched or not), the key sets
    fetched for the repository's cards by `jku` URL (6.6), and the trusted key file."""
    trust: Trust = field(default_factory=Trust)
    reports: list[AgentReport] = field(default_factory=list)
    fetched: dict[str, KeyFetch] = field(default_factory=dict)


def reduced(url: str | None) -> str | None:
    """`url` without userinfo, query and fragment (what a report and a finding may show)."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return None
    host = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{host}{port}{parts.path}" if parts.scheme and host else None


def load_trust(a2a: A2a, notices: list[Notice], errors: list[Notice]) -> Trust:
    """The trusted key file of `a2a.keys` (6.2): absent is the notice `a2a_keys_missing`, one that is not a key set is the
    error `settings_invalid` naming `a2a.keys` (exit 2), a key without a `kid` or with a private member is a notice and is
    never used."""
    if a2a.keys is None:
        return Trust()
    if a2a.keys_bytes is None:
        notices.append(Notice("a2a_keys_missing", a2a.keys, f"a2a.keys names {a2a.keys}, which the revision read does not hold; "
                              "signed agent cards are not verified"))
        return Trust(a2a.keys, "missing")
    try:
        keyset = jws.load_jwks(a2a.keys_bytes, max_keys=jws.KEYS_MAX)
    except jws.JwksError as exc:
        errors.append(Notice("settings_invalid", a2a.keys, f"a2a.keys: {a2a.keys} is not a key set ({exc.args[0]}): a trusted "
                             "key file that cannot be read must not become no keys"))
        return Trust(a2a.keys, "invalid")
    notice_keys(keyset, a2a.keys, notices)
    return Trust(a2a.keys, "loaded", keyset)


def notice_keys(keyset: jws.KeySet, source: str, notices: list[Notice]) -> None:
    if keyset.without_kid:
        notices.append(Notice("a2a_key_without_kid", source, f"{keyset.without_kid} keys have no kid and are never used: keys "
                              "are matched to signatures by kid alone"))
    if keyset.private:
        notices.append(Notice("a2a_private_key_in_jwks", source, f"{keyset.private} keys hold a private member and are not used: "
                              "a published key set must hold public keys only"))


def _outcome(si: SignatureInput, kind: str, **over) -> SignatureOutcome:
    fields = {"index": si.index, "alg": si.alg, "kid": si.kid, "jku": reduced(si.jku), "key_source": None, "outcome": kind}
    fields.update(over)
    return SignatureOutcome(**fields)


def _from(keyset: jws.KeySet | None, si: SignatureInput, source: str, no_key: str) -> SignatureOutcome | tuple[jws.Jwk, ...]:
    """The candidate keys of `si` in `keyset`, or the outcome that says there is none."""
    assert si.alg is not None and si.kid is not None
    found = jws.candidates(keyset, si.alg, si.kid) if keyset is not None else ()
    if not found:
        return _outcome(si, no_key, key_source=source)
    return found


def _verify(si: SignatureInput, keys: tuple[jws.Jwk, ...], source: str) -> SignatureOutcome:
    assert si.alg is not None and si.signature is not None
    if si.alg in ("EdDSA", "Ed25519") and all(key.public is None for key in keys):
        return _outcome(si, "unverifiable_alg", detail=ED448_DETAIL)
    for key in keys:
        for form, signing_input, unsigned in si.inputs:
            if jws.verify(si.alg, key, signing_input, si.signature):
                legacy = tuple(pointer for pointer in unsigned if must_be_signed(pointer))
                # A legacy member or a proto field-name alias that nobody signed changes what a client does: not verified
                # (5.6, `must_be_signed`). A plain vendor member, or an empty value the sdk form removed, is only listed.
                if legacy:
                    return _outcome(si, "unsigned_legacy", key_source=source, payload_form=form, unsigned_members=unsigned,
                                    detail=f"signed without members clients read: {', '.join(legacy)}")
                return _outcome(si, "verified", key_source=source, payload_form=form, unsigned_members=unsigned)
    return _outcome(si, "bad_signature", key_source=source)


def outcome_of(si: SignatureInput, trust: Trust, fetched: Mapping[str, KeyFetch]) -> SignatureOutcome:
    """What becomes of one signature (6.6). Algorithm first: `none` and unknown names are refused, `HS*` and Ed448 cannot be
    checked by anyone outside the agent or by this release. Then the key source: the trusted key file when `a2a.keys` is set
    (and then no other), else the key set the card's `jku` names when it was fetched, else a key the header carries itself
    (`embedded_key_only`), else none (`key_unavailable`, `no_key_source`)."""
    if si.error is not None:
        return _outcome(si, "malformed", detail=si.error)
    alg = si.alg or ""
    if alg in jws.SHARED_SECRET_ALGS:
        return _outcome(si, "unverifiable_alg", detail=SHARED_SECRET_DETAIL)
    if alg == "Ed448":
        return _outcome(si, "unverifiable_alg", detail=ED448_DETAIL)
    if alg not in jws.VERIFIED_ALGS:
        return _outcome(si, "refused_alg")
    assert si.signature is not None
    problem = jws.ecdsa_problem(alg, si.signature)
    if problem is not None:
        return _outcome(si, "malformed", detail=problem)
    if trust.path is not None:  # `a2a.keys` is in force: the only trusted source, whatever the jku says
        if trust.state == "missing":
            return _outcome(si, "key_unavailable", detail="keys_file_missing")
        if trust.state == "invalid":
            return _outcome(si, "key_unavailable", detail="keys_file_invalid")
        found = _from(trust.keyset, si, "keys_file", "untrusted_key")
        return found if isinstance(found, SignatureOutcome) else _verify(si, found, "keys_file")
    if si.jku is not None and si.jku in fetched:
        got = fetched[si.jku]
        if got.keyset is None:
            return _outcome(si, "key_unavailable", detail=got.reason or "network")
        found = _from(got.keyset, si, "jku", "no_key")
        return found if isinstance(found, SignatureOutcome) else _verify(si, found, "jku")
    if si.jku is None and (si.has_jwk or si.has_x5c or si.has_x5u):
        return _outcome(si, "embedded_key_only")
    return _outcome(si, "key_unavailable", detail=NO_KEY_SOURCE)


def outcomes_of(document: AgentCardDocument, trust: Trust, fetched: Mapping[str, KeyFetch]) -> tuple[SignatureOutcome, ...]:
    return tuple(outcome_of(si, trust, fetched) for si in signature_inputs(document))


def key_notices(item: str, outcomes: tuple[SignatureOutcome, ...]) -> list[Notice]:
    """`a2a_signature_unverified` once per card with a signature that had no key source, `a2a_keys_unavailable` once per
    signature whose key set could not be fetched (the reason is the outcome's detail)."""
    notices = []
    if any(o.outcome == "key_unavailable" and o.detail == NO_KEY_SOURCE for o in outcomes):
        notices.append(Notice("a2a_signature_unverified", item, "this card is signed but its signature was not verified: set "
                              "a2a.keys to a key file of the repository, or run with --probe to fetch the key set it names"))
    for o in outcomes:
        if o.outcome == "key_unavailable" and o.detail in ("network", "timeout", "http_status", "not_json", "limit", "budget"):
            notices.append(Notice("a2a_keys_unavailable", item, f"the key set {o.jku or ''} could not be used ({o.detail}); the "
                                  "signature was not verified"))
    return notices


def not_a_card_notice(card: CardFile, document: AgentCardDocument) -> Notice:
    """A file whose name is only a look-alike (`legacy_path`, `named`) that is not an agent card is a notice, never an error
    (invariant 10): the reason is the document error code, "over 1 MiB" or "not an agent card"."""
    reason = _NOT_A_CARD.get(document.error or "", document.error or "not an agent card")
    return Notice("a2a_not_card", card.path, f"not checked as an agent card: {reason}")


def _card_jkus(found: Discovery, trust: Trust) -> list[str]:
    """Every distinct `jku` of a verifiable signature of the repository's cards, in the order of first use; empty when `a2a.keys`
    is in force (then no `jku` is fetched for any card)."""
    if trust.path is not None:
        return []
    urls: dict[str, None] = {}
    for card in found.agent_cards:
        if card.read_error is not None:
            continue
        document = parse_agent_card(card.path, card.content)
        if not is_card(card, document):
            continue
        for si in signature_inputs(document):
            if si.error is None and si.jku is not None and si.alg in jws.VERIFIED_ALGS:
                urls.setdefault(si.jku, None)
    return list(urls)


def fetchable_https(url: str) -> bool:
    """Whether a `jku` is an `https` URL that parses (the scheme is case-insensitive, r1:F3). A `jku` is text from a card:
    `urlsplit` raises `ValueError` on a bracketed host and `.port` on a bad port, and that must never reach a run as an
    internal error (invariant 10); one that does not parse is not fetchable, like a non-`https` one (r0:F1)."""
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for a port that is not a number in range
        return parts.scheme.lower() == "https"
    except ValueError:
        return False


def jku_urls(found: Discovery, trust: Trust) -> list[str]:
    """The distinct `https` `jku` URLs of the repository's cards, in the order of first use: the ones that may be fetched; empty
    when `a2a.keys` is in force."""
    return [url for url in _card_jkus(found, trust) if fetchable_https(url)]


def refused_jku_urls(found: Discovery, trust: Trust) -> list[str]:
    """The `jku` URLs of the repository's cards that are never fetched because they are not `https` or do not parse. Under
    `--probe` each is recorded as `KeyFetch(None, "network")`, the reason a remote card's non-https `jku` gets
    (`AgentTask._key_sets`), so the outcome is `key_unavailable` and the advice to run with `--probe` is not given to someone
    who did (r0:F5)."""
    return [url for url in _card_jkus(found, trust) if not fetchable_https(url)]


def repository_reports(found: Discovery, rules: RuleSet, a2a: A2a, notices: list[Notice], errors: list[Notice], *,
                       fetched: Mapping[str, KeyFetch] | None = None, trust: Trust | None = None
                       ) -> tuple[list[AgentReport], list[ReportFinding]]:
    """One `AgentReport` per card file of the repository that is checked as a card, and their findings (item `a2a-card:<path>`).
    Look-alike files that are not cards are notices. `fetched` are the key sets the probe phase got by `jku` URL."""
    trust = trust if trust is not None else load_trust(a2a, notices, errors)
    reports: list[AgentReport] = []
    findings: list[ReportFinding] = []
    for card in found.agent_cards:
        document = parse_agent_card(card.path, card.content)
        if card.read_error is not None:  # a card that could not be read: SW-A2A-018 with the reason and detail (r1:F2)
            document = replace(document, error=card.read_error[0])
        elif not is_card(card, document):
            notices.append(not_a_card_notice(card, document))
            continue
        item = f"a2a-card:{card.path}"
        outcomes = outcomes_of(document, trust, fetched or {})
        result = evaluate_agent_card(document, rules, origin=CardOrigin("repository", card.path_form), signatures=outcomes,
                                     location_path=card.path)
        if card.read_error is not None:
            code, detail = card.read_error
            evidence = bounded_evidence(f"{code}: {detail}")
            kept = tuple(replace(f, evidence=evidence) if f.rule_id == "SW-A2A-018" else f for f in result.findings)
            result = replace(result, findings=kept)
        notices.extend(key_notices(item, outcomes))
        notices.extend(truncation_notices(item, result))
        reports.append(AgentReport(item, "repository", card.path_form, "checked", result=result))
        findings.extend(ReportFinding(finding, item) for finding in result.findings)
    return reports, findings


def truncation_notices(item: str, result: A2aScanResult) -> list[Notice]:
    notices = []
    if result.truncated:
        notices.append(Notice("findings_truncated", item, f"{result.truncated} more findings were not kept"))
    if result.document_truncated:
        notices.append(Notice("findings_truncated", item, "more entries than the scanner reads; the first entries were judged, "
                                                         "the rest were not"))
    return notices
