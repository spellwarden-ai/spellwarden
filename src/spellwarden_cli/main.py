"""The `spellwarden` command (spec 6.2): argument parsing, the `scan` and
`version` commands, output writing and exit codes. Later commands live in
their own modules and register a sub-parser below the anchor line of
`build_parser`; each sub-parser sets `handler`, which `main` calls."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from datetime import UTC, date, datetime
from typing import TextIO

from spellwarden_scan import RULES_VERSION, RuleSet, __version__

from spellwarden_cli import run
from spellwarden_cli.output import FORMATS
from spellwarden_cli.report import LockState, Notice, Report
from spellwarden_cli.settings import FAIL_ON, Flags, SettingsError, load_settings


def _iso_date(text: str) -> date:
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not a date of the form YYYY-MM-DD") from exc


class _FormatAction(argparse.Action):
    """`--format` appends `[format, None]`; the next `--output` names that format's file (spec 6.2)."""

    def __call__(self, parser, namespace, values, _option_string=None):
        if values not in FORMATS:
            parser.error(f"--format: {values!r} is not one of {', '.join(sorted(FORMATS))}")
        outputs = list(getattr(namespace, "outputs", None) or [])
        outputs.append([values, None])
        namespace.outputs = outputs


class _OutputAction(argparse.Action):
    def __call__(self, parser, namespace, values, _option_string=None):
        outputs = list(getattr(namespace, "outputs", None) or [])
        if not outputs or outputs[-1][1] is not None:
            parser.error("--output must follow the --format it writes")
        outputs[-1][1] = values
        namespace.outputs = outputs


def _add_scan(commands) -> None:
    scan = commands.add_parser("scan", help="scan a directory for agent content and judge it")
    scan.add_argument("path", nargs="?", default=".", help="the scan root (default: the current directory)")
    scan.add_argument("--format", action=_FormatAction, metavar="FMT", dest="format",
                      help="text (default), json, sarif, markdown or gitlab-codequality; repeatable")
    scan.add_argument("--output", action=_OutputAction, metavar="FILE", help="the file the preceding --format writes")
    scan.add_argument("--fail-on", choices=FAIL_ON, default=None, help="fail at this severity or worse (default: high)")
    scan.add_argument("--locked", action="store_true", help="fail when .spellwarden/lock.json is absent or stale")
    probe = scan.add_mutually_exclusive_group()
    probe.add_argument("--probe", dest="probe", action="store_true", default=None,
                       help="probe remote MCP servers of the configuration (off by default)")
    probe.add_argument("--no-probe", dest="probe", action="store_false")
    private = scan.add_mutually_exclusive_group()
    private.add_argument("--probe-private", dest="probe_private", action="store_true", default=None,
                         help="allow probing private addresses on a trusted run (spec 6.8)")
    private.add_argument("--no-probe-private", dest="probe_private", action="store_false")
    scan.add_argument("--baseline", metavar="FILE", help="the baseline file, relative to the scan root")
    scan.add_argument("--config", metavar="FILE", help="a settings file instead of .spellwarden/config.yml")
    scan.add_argument("--as-of", type=_iso_date, metavar="YYYY-MM-DD", help="evaluation date (default: today, UTC)")
    scan.add_argument("--no-telemetry", action="store_true", help="send no usage ping")
    talk = scan.add_mutually_exclusive_group()
    talk.add_argument("--quiet", action="store_true", help="print only the requested outputs and errors")
    talk.add_argument("--verbose", action="store_true", help="print network events and timings to stderr")
    scan.set_defaults(handler=cmd_scan, outputs=None)


def _add_version(commands) -> None:
    version = commands.add_parser("version", help="print the scanner and rules versions")
    version.set_defaults(handler=cmd_version)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spellwarden",
                                     description="Scan agent skills, MCP server configurations and Claude Code hooks.")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND",
                                     parser_class=argparse.ArgumentParser)
    _add_scan(commands)
    _add_version(commands)
    # Tasks 8, 9 and 10 add their sub-parsers below this line.
    from spellwarden_cli import baseline, lockfile  # imported here: both import `run`, which main also imports

    lockfile.add_parser(commands)
    baseline.add_parser(commands)
    return parser


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"spellwarden {__version__} (rules {RULES_VERSION})")
    return 0


def _stderr(line: str) -> None:
    print(f"spellwarden: {line}", file=sys.stderr)


def _error_report(fail_on: str, as_of: date, code: str, path: str, message: str) -> Report:
    """A report that holds one error and nothing else: written in every requested format, exit 2."""
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of=as_of.isoformat(), fail_on=fail_on,
                  items=(), findings=(), probes=(), lock=LockState(), notices=(),
                  errors=(Notice(code, path, message),), repo_prefix=None, rules=RuleSet.baseline())


def _scan_report(args: argparse.Namespace) -> Report:
    as_of = args.as_of or datetime.now(UTC).date()
    fail_on = args.fail_on or "high"
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        return _error_report(fail_on, as_of, "path_not_directory", args.path, "the scan path must be a directory")
    flags = Flags(fail_on=args.fail_on, probe=args.probe, probe_private=args.probe_private,
                  telemetry=False if args.no_telemetry else None)
    try:
        settings = load_settings(root, config=args.config, flags=flags, env=os.environ)
    except SettingsError as exc:
        return _error_report(fail_on, as_of, "settings_invalid", args.config or ".spellwarden/config.yml", str(exc))
    options = run.ScanOptions(root=root, settings=settings, as_of=as_of, locked=args.locked, baseline=args.baseline,
                              env=dict(os.environ), log=_stderr if args.verbose else run._silent)
    started = time.monotonic()
    try:
        report = run.scan(options)
    except Exception as exc:  # a scanner crash still writes every output (spec 6.2)
        return _error_report(settings.fail_on, as_of, "crash", "", f"internal error: {type(exc).__name__}: {exc}")
    options.log(f"scan took {time.monotonic() - started:.2f} s")
    return report


def write_outputs(report: Report, outputs: list[tuple[str, str | None]], *, stdout: TextIO) -> None:
    """Each format to its file (written to a temporary file in the same directory, then renamed) or to stdout."""
    for fmt, path in outputs:
        text = FORMATS[fmt](report)
        if path is None:
            buffer = getattr(stdout, "buffer", None)
            if buffer is not None:
                stdout.flush()
                buffer.write(text.encode("utf-8"))
                buffer.flush()
            else:
                stdout.write(text)
            continue
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(dir=directory, prefix=".spellwarden-", delete=False)
        try:
            with handle:
                handle.write(text.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, path)
        except BaseException:
            if os.path.exists(handle.name):
                os.unlink(handle.name)
            raise


def cmd_scan(args: argparse.Namespace) -> int:
    outputs = [tuple(pair) for pair in (args.outputs or [["text", None]])]
    if sum(1 for _, path in outputs if path is None) > 1:
        _stderr("at most one format can go to stdout; give the others an --output")
        return 2
    report = _scan_report(args)
    write_outputs(report, outputs, stdout=sys.stdout)
    if not args.quiet:
        for fmt, path in outputs:
            if path is not None:
                _stderr(f"wrote the {fmt} report to {path}")
    return report.exit_code()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on a usage error and 0 after --help
        return exc.code if isinstance(exc.code, int) else 2
    try:
        return int(args.handler(args))
    except KeyboardInterrupt:
        return 2
    except Exception as exc:  # never a traceback and never exit 1 for an internal error (spec 6.2)
        _stderr(f"internal error: {type(exc).__name__}: {exc}")
        return 2
