#!/usr/bin/env python3
"""Manage offline engagement metadata; records grant no execution authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class _ArgumentFailure(Exception):
    pass


class _DiscardOutput:
    def write(self, value):
        return len(value)

    def flush(self):
        pass


def _emit(encoded):
    try:
        output = encoded + "\n"
        count = sys.stdout.write(output)
        if type(count) is not int or count != len(output):
            raise OSError("engagement_output_unavailable")
        sys.stdout.flush()
        return True
    except (Exception, KeyboardInterrupt):
        # A partial output cannot be repaired by printing another JSON object.
        # Prevent shutdown from retrying a broken buffered stdout and leaking
        # an unraisable OS diagnostic. Never redirect an arbitrary stream FD.
        try:
            if sys.stdout.fileno() == 1:
                descriptor = os.open(os.devnull, os.O_WRONLY)
                try:
                    os.dup2(descriptor, 1)
                finally:
                    if descriptor != 1:
                        os.close(descriptor)
        except (Exception, KeyboardInterrupt):
            pass
        sys.stdout = _DiscardOutput()
        return False


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        # argparse messages can contain the complete untrusted argument.
        raise _ArgumentFailure from None

    def print_help(self, file=None):
        # argparse exits immediately afterward: flush before it reports success.
        if not _emit(self.format_help().removesuffix("\n")):
            raise SystemExit(2)


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if hasattr(namespace, self.dest):
            raise _ArgumentFailure
        setattr(namespace, self.dest, values)


def _decimal(value):
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]?", value) is None:
        raise _ArgumentFailure
    result = int(value)
    if result > 64:
        raise _ArgumentFailure
    return result


def _arguments(argv):
    parser = _Parser(prog="engagement_records.py", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    flags = {
        "create": ("store", "engagement-id", "roe-file", "event-id"),
        "revise": ("store", "roe-file", "event-id", "expected-revision", "expected-generation"),
        "revoke": ("store", "event-id", "expected-revision", "expected-generation"),
        "show": ("store",),
        "receipt": ("store", "event-id"),
        "export": ("store", "output"),
        "inspect": ("export",),
    }
    for name, fields in flags.items():
        command = commands.add_parser(name)
        for field in fields:
            command.add_argument("--" + field, required=True, action=_Once,
                                 default=argparse.SUPPRESS,
                                 type=_decimal if field.startswith("expected-") else str)
    args = parser.parse_args(argv)
    if getattr(args, "expected_revision", 1) == 0:
        raise _ArgumentFailure
    return args


def _run(args):
    from recon_cockpit.secure_agent.engagement_contract import canonical
    from recon_cockpit.secure_agent import engagement_inspection as inspection

    if args.command == "inspect":
        return inspection.inspect_export(Path(args.export))

    # Saved-export inspection and help must never import/open SQLite.
    from recon_cockpit.secure_agent.engagement_store import EngagementStore

    if args.command == "create":
        roe = inspection.read_roe_file(Path(args.roe_file))
        with EngagementStore.create(Path(args.store), engagement_id=args.engagement_id,
                                    roe=roe, event_id=args.event_id) as store:
            return store.event_receipt(args.event_id)
    read_only = args.command in {"show", "receipt", "export"}
    # Invalid external ROE must not open a writable store.
    roe = inspection.read_roe_file(Path(args.roe_file)) if args.command == "revise" else None
    with EngagementStore.open(Path(args.store), read_only=read_only) as store:
        if args.command == "revise":
            return store.append_revision(roe, expected_revision=args.expected_revision,
                                         expected_generation=args.expected_generation,
                                         event_id=args.event_id)
        if args.command == "revoke":
            return store.revoke(expected_revision=args.expected_revision,
                                expected_generation=args.expected_generation,
                                event_id=args.event_id)
        if args.command == "receipt":
            return store.event_receipt(args.event_id)
        snapshot = store.snapshot()
    if args.command == "export":
        return inspection.write_export(Path(args.output), snapshot)
    return inspection.report_export(snapshot, raw_sha256=hashlib.sha256(canonical(snapshot)).hexdigest())


def main(argv=None):
    from recon_cockpit.secure_agent.engagement_contract import EngagementError

    code = None
    try:
        result = _run(_arguments(argv))
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
        if len(encoded.encode("ascii")) + 1 > 4096:
            raise EngagementError("engagement_limit_exceeded")
    except _ArgumentFailure:
        code = "engagement_invalid_input"
    except EngagementError as exc:
        code = exc.code
    except (Exception, KeyboardInterrupt):
        # Never expose a path, SQLite error, input fragment or traceback.
        code = "engagement_store_unavailable"
    if code is not None:
        encoded = json.dumps({"schema_version": "1", "error": code},
                             sort_keys=True, separators=(",", ":"))
    if not _emit(encoded):
        return 2
    return 2 if code is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
