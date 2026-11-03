"""SW-SKL-035: agent told to spend money on its own with no confirmation or cap.

Read over SKILL.md and the skill's other Markdown files. A file fires when it holds a payment capability (an HTTP
402 or x402 client, a wallet send, transfer or swap, a charge, payout or payment-intent create, a buy or purchase API
call) with autonomy wording within ten lines ("pays automatically", "handled automatically", "autonomously",
"without asking", "no confirmation", "auto-creates a wallet", ...) and the skill holds no safeguard anywhere: no step
that asks the user to confirm before paying ("confirm before", "ask the user", "explicit confirmation", "do not
proceed until", an escalation to a human) and no spending cap stated as required (a cap that is optional does not
count). The finding is at the payment capability's line, one per Markdown file.

Quiet: a skill that documents how to build a paywall or accept payments; a capability line that is read-only or
prohibited ("never run a wallet transfer"); wording that is itself negated ("do not ask the user"). Everything is a
substring search or a token scan with constant look-around, so a long line is read in linear time. The module is
registered by the rule set, not here."""
from __future__ import annotations

import re
from bisect import bisect_left
from collections.abc import Iterator

from spellwarden_scan.evidence import excerpt, fingerprint
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import Package

RULE_ID = "SW-SKL-035"
TITLE = "Agent told to spend money on its own with no confirmation or cap"
SEVERITY = "high"
OWASP = ("ASI02", "ASI09")
NIST = ("AC-3", "AC-6")
MALICIOUS = False

_NEAR = 10  # lines either side of the capability searched for autonomy wording
_PER_PACKAGE = 10
_OCCURRENCES = 20  # occurrences of one phrase examined per line
_TOKEN = re.compile(r"[a-z0-9]+")

_PROHIBIT = frozenset({"never", "not", "dont", "cannot", "cant", "nor", "no"})
_SAFEGUARD_NEGATORS = frozenset({"not", "never", "no", "dont", "cannot", "cant", "skip", "skips", "avoid"})

_AUTONOMY = (
    "pays automatically", "pay automatically", "paid automatically", "automatically pays", "automatically pay",
    "handled automatically", "handles payment", "handle payment", "automatically handles", "automatically signs",
    "automatically sends", "automatically transfer", "autonomously", "autonomous payment", "autonomous spending",
    "autonomous purchas", "autonomous trading", "without asking", "without confirmation", "without approval",
    "without prompting", "without human", "without user", "no confirmation", "no approval", "no human",
    "no need to confirm", "no need to ask", "auto-creates a wallet", "auto-create a wallet", "auto-creates wallet",
    "automatically creates a wallet", "automatically create a wallet", "auto-pay", "autopay", "auto pay",
    "on its own", "on their own", "on its behalf automatically",
)

_SAFEGUARDS = (
    "confirm before", "confirm with the user", "confirmation before", "explicit confirmation", "explicit approval",
    "ask the user", "ask user", "asks the user", "asking the user", "ask the human", "ask for confirmation",
    "ask for approval", "ask for permission", "request confirmation", "request approval", "require confirmation",
    "requires confirmation", "require approval", "requires approval", "require user", "requires user",
    "user must approve", "user must confirm", "user confirms", "human approval", "human-in-the-loop",
    "human in the loop", "escalate to a human", "escalates to a human", "escalate to the user",
    "escalates to the user", "escalate to a person", "escalates to a person", "do not proceed until",
    "wait for the user", "wait for approval", "wait for confirmation", "user's approval", "user's confirmation",
    "approval from the user", "confirmation from the user", "before every payment", "before each payment",
    "before every transaction", "before each transaction", "before every purchase", "before each purchase",
)

# A skill about building a paywall or taking payments is not an agent told to spend.
_BUILDING = (
    "build a paywall", "building a paywall", "add a paywall", "implement a paywall", "create a paywall",
    "paywall middleware", "accept payments", "accepting payments", "accept payment", "accept a payment",
    "collect payments", "collecting payments", "receive payments", "payment middleware", "monetize your",
    "monetise your", "charge your customers", "charge your users", "protect your endpoint", "protect your api",
    "protect your routes",
)

_WALLET_VERBS = frozenset({"send", "sends", "transfer", "transfers", "swap", "swaps", "pay", "pays", "withdraw"})
_MOVE_VERBS = frozenset({"send", "sends", "transfer", "transfers", "swap", "swaps", "withdraw", "withdraws"})
_ASSETS = frozenset({"usdc", "usdt", "eth", "btc", "funds", "crypto", "dai", "lamports", "satoshis"})
_CHARGES = frozenset({"charge", "charges", "payout", "payouts"})
_INTENTS = frozenset({"paymentintent", "paymentintents"})
_CREATE = frozenset({"create", "creates", "new", "make", "makes"})
_BUYS = frozenset({"buy", "buys", "purchase", "purchases"})
_ENDPOINTS = frozenset({"api", "endpoint", "call", "request"})

_CAP_WORDS = frozenset({"cap", "caps", "limit", "limits", "budget", "ceiling", "maximum", "max"})
_SPEND_WORDS = frozenset({"spend", "spending", "spent", "payment", "payments", "transaction", "transactions", "daily",
                          "usd", "usdc", "eur", "dollars", "budget"})
_REQUIRED_WORDS = frozenset({"required", "require", "requires", "must", "mandatory", "always", "enforced", "enforce",
                             "enforces", "hard"})
_OPTIONAL_WORDS = frozenset({"optional", "optionally", "may", "can", "could", "consider", "recommended", "suggested",
                             "desired"})


def _clause_tokens(prefix: str) -> list[str]:
    """The tokens of the clause that ends at the end of `prefix` (the text after its last sentence break)."""
    cut = max(prefix.rfind(mark) for mark in ".;:!?")
    prefix = prefix[cut + 1:]
    return _TOKEN.findall(prefix)


def _occurrences(low: str, phrase: str) -> Iterator[int]:
    start = 0
    for _ in range(_OCCURRENCES):
        index = low.find(phrase, start)
        if index < 0:
            return
        yield index
        start = index + 1


def _prefix(low: str, index: int) -> str:
    return low[max(0, index - 48):index]


def _autonomous(low: str) -> bool:
    for phrase in _AUTONOMY:
        for index in _occurrences(low, phrase):
            if not _PROHIBIT & set(_clause_tokens(_prefix(low, index))[-3:]):
                return True
    return False


def _negated_safeguard(tokens: list[str]) -> bool:
    if tokens and tokens[-1] == "without":
        return not _PROHIBIT & set(tokens[-4:-1])
    if _SAFEGUARD_NEGATORS & set(tokens[-2:]):
        return True
    return "need" in tokens[-4:] and bool(_SAFEGUARD_NEGATORS & set(tokens[-4:]))


_GENERIC_CONSENT = frozenset({"wait for confirmation", "wait for approval", "wait for the user", "ask for confirmation",
                              "ask for approval", "ask for permission"})
_SUGGEST = frozenset({"suggest", "suggests", "suggested", "suggesting", "offer", "offers", "recommend", "recommends"})
_PAY_CONTEXT = frozenset({
    "pay", "pays", "paid", "paying", "payment", "payments", "purchase", "purchases", "buy", "buys", "spend", "spending",
    "transaction", "transactions", "transfer", "transfers", "swap", "swaps", "trade", "trades", "charge", "charges",
    "cost", "costs", "price", "fee", "fees", "amount", "invoice", "order", "orders", "wallet", "funds", "usdc", "x402",
    "402",
})


def _suggestion_consent(low: str, index: int, phrase: str, tokens: list[str]) -> bool:
    """`Suggest the tool ... and wait for confirmation`: consent to use a tool, not a confirm-before-pay step. True when
    the phrase is generic, its clause opens with a suggestion, and no money word stands in the clause before or after."""
    if phrase not in _GENERIC_CONSENT or not set(tokens) & _SUGGEST or set(tokens) & _PAY_CONTEXT:
        return False
    after = low[index + len(phrase):index + len(phrase) + 48]
    for mark in ".;:!?":
        after = after.split(mark, 1)[0]
    return not set(_TOKEN.findall(after)) & _PAY_CONTEXT


def _safeguard(low: str) -> bool:
    for phrase in _SAFEGUARDS:
        for index in _occurrences(low, phrase):
            tokens = _clause_tokens(_prefix(low, index))
            if not _negated_safeguard(tokens) and not _suggestion_consent(low, index, phrase, tokens):
                return True
    return False


def _required_cap(tokens: list[str]) -> bool:
    words = set(tokens)
    if not (words & _CAP_WORDS and words & _SPEND_WORDS and words & _REQUIRED_WORDS) or words & _OPTIONAL_WORDS:
        return False
    for index, token in enumerate(tokens):
        if token in _CAP_WORDS and not _PROHIBIT & set(tokens[max(0, index - 2):index]):
            return True
    return False


def _capability(low: str) -> bool:
    """The line holds a payment capability that is not read-only or prohibited."""
    if "read-only" in low or "read only" in low:
        return False
    tokens = _TOKEN.findall(low)
    size = len(tokens)
    for i, token in enumerate(tokens):
        hit = False
        if token == "x402":
            hit = True
        elif token == "402":
            hit = (i > 0 and tokens[i - 1] in ("http", "status")) or (i + 1 < size and tokens[i + 1] == "payment")
        elif token == "wallet" or token == "wallets":
            hit = bool(_WALLET_VERBS & set(tokens[i + 1:i + 4]))
        elif token in ("sendtransaction", "sendrawtransaction"):
            hit = True
        elif token in _MOVE_VERBS:
            hit = bool(_ASSETS & set(tokens[i + 1:i + 4])) or (token.startswith("send") and tokens[i + 1:i + 2] == ["transaction"])
        elif token in _CHARGES:
            hit = bool(_CREATE & set(tokens[max(0, i - 2):i + 3])) or "card" in tokens[i + 1:i + 4]
        elif token in _INTENTS or (token == "payment" and tokens[i + 1:i + 2] in (["intent"], ["intents"])):
            hit = bool(_CREATE & set(tokens[max(0, i - 3):i + 4]))
        elif token in _BUYS:
            hit = bool(_ENDPOINTS & set(tokens[max(0, i - 3):i + 4]))
        if hit and not _PROHIBIT & set(tokens[max(0, i - 3):i]):
            return True
    return False


def _finding(path: str, line: int, matched: str) -> Finding:
    return Finding(RULE_ID, SEVERITY, TITLE, Location(path, line), excerpt(matched), fingerprint(RULE_ID, path, matched), MALICIOUS)


def detect(package: Package) -> Iterator[Finding]:
    sources = package.instructions()
    lows = {source.path: [line.lower().replace("’", "'") for line in source.lines] for source in sources}
    every = [low for lines in lows.values() for low in lines]
    if any(phrase in low for low in every for phrase in _BUILDING):
        return
    if any(_safeguard(low) or _required_cap(_TOKEN.findall(low)) for low in every):
        return
    total = 0
    for source in sources:
        lines = lows[source.path]
        autonomy = [index for index, low in enumerate(lines) if _autonomous(low)]
        if not autonomy:
            continue
        for index, low in enumerate(lines):
            if not _capability(low):
                continue
            nearest = bisect_left(autonomy, index - _NEAR)
            if nearest < len(autonomy) and autonomy[nearest] <= index + _NEAR:
                yield _finding(source.path, index + 1, source.lines[index])
                total += 1
                break
        if total >= _PER_PACKAGE:
            return
