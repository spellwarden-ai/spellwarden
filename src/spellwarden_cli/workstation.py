"""`spellwarden scan --user` from the command line (phase 3 batch 2a spec 11.3). The usage checks are `main`'s; this module
runs the scan (`userscan.scan`) and writes every requested output. A `--user` run sends no usage ping and starts no connected
mode, whatever `SPELLWARDEN_ORG` and `SPELLWARDEN_API_KEY` say: it reads neither."""
from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

from spellwarden_cli import clients
from spellwarden_cli.report import LockState, Notice, Report
from spellwarden_cli.secret import Credentials
from spellwarden_cli.settings import Settings


def _stderr(line: str) -> None:
    print(f"spellwarden: {line}", file=sys.stderr)


def _silent(_line: str) -> None:
    return None


def _platform() -> str:
    """`sys.platform`; the tests replace it to run the command as on another system."""
    return sys.platform


def _error_report(as_of: str, fail_on: str, code: str, message: str) -> Report:
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of=as_of, fail_on=fail_on, items=(),
                  findings=(), probes=(), lock=LockState(), notices=(), errors=(Notice(code, "", message),), repo_prefix=None,
                  rules=RuleSet.baseline(), user="scan")


def cmd_user(args: argparse.Namespace, outputs: list[tuple[str, str | None]], credentials: Credentials) -> int:  # noqa: ARG001
    from spellwarden_cli import userscan
    from spellwarden_cli.main import write_outputs

    as_of = args.as_of or datetime.now(UTC).date()
    fail_on = args.fail_on or "high"
    log = _stderr if args.verbose else _silent
    env = dict(os.environ)
    home = os.path.expanduser("~")
    settings = Settings(fail_on=fail_on, probe=bool(args.probe), probe_private=bool(args.probe_private), telemetry=False)
    try:
        report, not_found = userscan.scan(home, _platform(), env, settings=settings, as_of=as_of, inventory=args.inventory,
                                          log=log)
    except Exception as exc:  # a scanner crash still writes every output (spec 6.2)
        report, not_found = _error_report(as_of.isoformat(), fail_on, "crash", f"internal error: {type(exc).__name__}: {exc}"), ()
    for client in not_found:
        log(f"notice client_not_found: {clients.CLIENT_NAMES[client]}: no file of the client table was found")
    write_outputs(report, outputs, stdout=sys.stdout)
    if not args.quiet:
        for fmt, path in outputs:
            if path is not None:
                _stderr(f"wrote the {fmt} report to {path}")
    return report.exit_code()  # no usage ping from --user, whatever `telemetry` says (11.3)


__all__ = ["cmd_user"]
