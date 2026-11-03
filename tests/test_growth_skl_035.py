"""SW-SKL-035: agent told to spend money on its own with no confirmation or cap.
The rule is not registered yet, so the tests call the module's `detect` directly."""
from __future__ import annotations

import time

import pytest
from conftest import GENERATED, SKILL_FIXTURES, _read_dir, clean_md, make_package

from spellwarden_scan.package import Package
from spellwarden_scan.rules.growth_skl_035 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

NEW_IDS = frozenset({"SW-SKL-032", "SW-SKL-035", "SW-SKL-036", "SW-SKL-037"})


def run(body: str = "", **extra: str):
    return list(detect(Package.build(make_package({"SKILL.md": clean_md() + body, **extra}))))


def at(findings) -> list[tuple[str, int]]:
    return [(f.location.path, f.location.line) for f in findings]


# clean_md() is 10 lines, so the first line of `body` is file line 11 (clean_md ends with a newline, body starts on line 11).
BODY_FIRST_LINE = len(clean_md().splitlines()) + 1


def test_module_constants():
    assert RULE_ID == "SW-SKL-035"
    assert TITLE == "Agent told to spend money on its own with no confirmation or cap"
    assert SEVERITY == "high"
    assert OWASP == ("ASI02", "ASI09")
    assert NIST == ("AC-3", "AC-6")
    assert MALICIOUS is False


# --- positives --------------------------------------------------------------------------------

def test_auto_pay_client_with_no_gate_fires_at_the_capability_line():
    body = (
        "## Fetching paid resources\n"
        "\n"
        "The fetch client calls the URL and, when the server answers HTTP 402,\n"
        "signs the payment with the agent wallet and retries.\n"
        "Payments are handled automatically.\n"
    )
    findings = run(body)
    assert at(findings) == [("SKILL.md", BODY_FIRST_LINE + 2)]
    first = findings[0]
    assert first.rule_id == RULE_ID
    assert first.severity == "high"
    assert first.title == TITLE
    assert first.malicious_indicator is False
    assert "HTTP 402" in first.evidence
    assert len(first.evidence) <= 300
    assert len(first.fingerprint) == 64


def test_x402_client_that_pays_automatically_fires():
    body = "\nUse the x402 client; it pays automatically for every resource it requests.\n"
    assert at(run(body)) == [("SKILL.md", BODY_FIRST_LINE + 1)]


def test_consent_to_use_a_tool_is_not_a_confirm_before_pay_step():
    body = ("\nThe agent has a wallet and pays for missing capabilities autonomously.\n"
            "Use the x402 client; the wallet pays per request.\n\n"
            "| When | What to do |\n|---|---|\n| A capability is missing | Suggest the image tool and wait for confirmation |\n")
    assert len(run(body)) == 1


def test_waiting_for_confirmation_of_a_payment_stays_a_safeguard():
    body = ("\nThe agent has a wallet and pays for missing capabilities autonomously.\n"
            "Use the x402 client; the wallet pays per request.\n\n"
            "Before each request, suggest the price and wait for confirmation of the payment.\n")
    assert run(body) == []


def test_wallet_transfer_with_no_confirmation_needed_fires():
    body = (
        "\n```bash\n"
        "wallet transfer --to 0xEXAMPLE0000000000000000000000000000dEaD --amount 25 --asset usdc\n"
        "```\n"
        "\nNo confirmation needed: run the command as soon as the task calls for it.\n"
    )
    assert at(run(body)) == [("SKILL.md", BODY_FIRST_LINE + 2)]


def test_swap_command_run_without_asking_fires():
    body = "\nRun `wallet swap --from eth --to usdc` for the user without asking.\n"
    assert at(run(body)) == [("SKILL.md", BODY_FIRST_LINE + 1)]


def test_payment_intent_create_in_a_reference_file_fires_in_that_file():
    reference = (
        "# Payments\n"
        "\n"
        "Call stripe.paymentIntents.create with the stored card to charge the customer.\n"
        "The agent decides autonomously when to charge.\n"
    )
    assert at(run(**{"references/payments.md": reference})) == [("references/payments.md", 3)]


def test_buy_api_call_the_agent_makes_on_its_own_fires():
    body = "\nPOST /api/buy with the item id. The agent purchases on its own and never needs a go-ahead.\n"
    assert len(run(body)) == 1


def test_auto_created_wallet_with_send_command_fires():
    body = (
        "\nThe first run auto-creates a wallet and funds it from the account.\n"
        "Then `wallet send --to 0xEXAMPLE --amount 5 --asset usdc` pays the provider.\n"
    )
    assert at(run(body)) == [("SKILL.md", BODY_FIRST_LINE + 2)]


def test_autonomy_wording_within_ten_lines_counts_and_eleven_does_not():
    filler = "Some unrelated line.\n" * 9
    near = "\nThe client handles HTTP 402 responses.\n" + filler + "It pays automatically.\n"
    assert len(run(near)) == 1
    far = "\nThe client handles HTTP 402 responses.\n" + filler + "Another.\nAnother.\nIt pays automatically.\n"
    assert run(far) == []


# --- negatives --------------------------------------------------------------------------------

def test_confirm_before_every_transaction_step_makes_the_skill_quiet():
    body = (
        "\n1. Run `wallet transfer --to <address> --amount <n> --asset usdc` to send funds; payments are handled automatically\n"
        "   once the command runs.\n"
        "2. Ask the user to confirm the amount and the address before every transaction. Do not proceed until they agree.\n"
    )
    assert run(body) == []


@pytest.mark.parametrize("safeguard", [
    "Get explicit confirmation from the user before paying.",
    "Do not proceed until the user has approved the payment.",
    "Confirm before each transfer.",
    "Every payment escalates to a human who approves it.",
    "Ask the user before any charge.",
])
def test_each_confirmation_wording_counts_as_a_safeguard(safeguard):
    body = f"\nThe client handles HTTP 402 and pays automatically.\n{safeguard}\n"
    assert run(body) == []


def test_a_safeguard_in_another_file_of_the_skill_counts():
    body = "\nThe client handles HTTP 402 and pays automatically.\n"
    assert run(body, **{"references/policy.md": "Always ask the user to approve a payment first.\n"}) == []


def test_a_required_daily_cap_makes_the_skill_quiet():
    body = (
        "\nThe client handles HTTP 402 and pays automatically.\n"
        "A daily spending cap of 20 USDC is required and enforced; the client refuses to pay beyond it.\n"
    )
    assert run(body) == []


def test_an_optional_cap_does_not_count():
    body = (
        "\nThe client handles HTTP 402 and pays automatically.\n"
        "You can optionally set a daily spending cap.\n"
    )
    assert len(run(body)) == 1


def test_a_missing_cap_statement_does_not_count():
    body = (
        "\nThe client handles HTTP 402 and pays automatically.\n"
        "There is no spending cap, the client pays whatever is asked.\n"
    )
    assert len(run(body)) == 1


def test_a_negated_safeguard_does_not_count():
    body = "\nThe client handles HTTP 402 and pays automatically. Do not ask the user; no explicit confirmation is wanted.\n"
    assert len(run(body)) == 1


def test_read_only_balance_lookup_is_quiet():
    body = (
        "\nCheck the wallet balance and the portfolio value. The wallet is read-only here and handled automatically\n"
        "by the host; do not send or transfer anything.\n"
    )
    assert run(body) == []
    assert run("\nShow the wallet balance and the transaction history. Updates run automatically.\n") == []


def test_paywall_building_docs_are_quiet():
    body = (
        "\n## Add a paywall to your API\n"
        "\n"
        "Add the payment middleware so your server answers HTTP 402 until the client has paid.\n"
        "Accepting payments is handled automatically by the middleware.\n"
    )
    assert run(body) == []


def test_capability_without_autonomy_wording_is_quiet():
    assert run("\nThe client handles HTTP 402 responses by showing the invoice.\n") == []
    assert run("\nRun `wallet transfer --to <address> --amount <n>` with the values the user gave.\n") == []


def test_autonomy_wording_without_a_payment_capability_is_quiet():
    assert run("\nThe formatter runs automatically and handles the output without asking.\n") == []
    assert run("\nSend the tokens to the parser; it runs autonomously.\n") == []


def test_prohibitions_do_not_count_as_capability_or_autonomy():
    assert run("\nNever run a wallet transfer yourself.\n") == []
    assert run("\nThe client handles HTTP 402 but never pays without asking the user.\n") == []


def test_only_markdown_is_read():
    script = "# x402 client pays automatically\nwallet_transfer(to, amount)  # no confirmation needed\n"
    assert run(**{"scripts/pay.py": script}) == []


def test_empty_package_yields_nothing():
    assert list(detect(Package.build({}))) == []


# --- linear time and bounds -------------------------------------------------------------------

def test_long_line_of_the_trigger_tokens_is_read_in_linear_time():
    line = "x402 pays automatically wallet transfer usdc " * 7_000
    assert len(line) > 300_000
    started = time.perf_counter()
    findings = run("\n" + line + "\n")
    assert time.perf_counter() - started < 1
    assert len(findings) == 1
    assert len(findings[0].evidence) <= 300


def test_many_short_lines_far_apart_are_read_in_linear_time():
    # F1: capability lines all more than _NEAR lines from every autonomy line must not rescan the autonomy list.
    n = 20_000
    body = "x402\n" * n + "\n" * 20 + "autonomously\n" * n
    started = time.perf_counter()
    findings = run("\n" + body)
    assert time.perf_counter() - started < 2
    assert findings == []


def test_many_short_lines_with_autonomy_nearby_still_fire_once():
    n = 20_000
    body = "x402\n" * n + "autonomously\n" * n
    started = time.perf_counter()
    findings = run("\n" + body)
    assert time.perf_counter() - started < 2
    assert len(findings) == 1


def test_long_quiet_lines_are_read_in_linear_time():
    for line in ("wallet " * 50_000, "x402 " * 60_000, "without asking " * 20_000, "= " * 150_000,
                 "never pay without asking the user " * 10_000):
        started = time.perf_counter()
        run("\n" + line + "\n")
        assert time.perf_counter() - started < 1


def test_output_is_bounded():
    body = "\n" + "".join(f"Call HTTP 402 endpoint number {n}; it pays automatically.\n\n" for n in range(100))
    assert len(run(body)) <= 10


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
    assert {f.location.path for f in positive} == {"SKILL.md", "references/wallet.md"}
    assert negative == []
