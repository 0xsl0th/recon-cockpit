#!/usr/bin/env python3
"""Inspect and administer offline dispatch records; data grants no authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class _ArgumentFailure(Exception):
    pass


class _DiscardOutput:
    def write(self, value):
        return len(value)

    def flush(self):
        pass


def _emit(encoded, deadline=None):
    blocking = None
    def check_time():
        if deadline is not None and time.monotonic() >= deadline:
            raise OSError("engagement_dispatch_output_unavailable")
    try:
        output = encoded + "\n"
        check_time()
        try:
            actual_stdout = sys.stdout.fileno() == 1
        except (AttributeError, OSError, ValueError):
            actual_stdout = False
        if actual_stdout:
            # Only the process's actual stdout descriptor may be changed.
            # Never wait indefinitely for a consumer that stops reading.
            blocking = os.get_blocking(1)
            os.set_blocking(1, False)
            check_time()
            sys.stdout.flush()
            raw, offset, attempts = output.encode("utf-8"), 0, 0
            while offset < len(raw):
                check_time()
                # A refusal has no fresh work budget: one nonblocking attempt
                # is permitted, never a wait or a retry after partial delivery.
                if deadline is None and attempts:
                    raise OSError("engagement_dispatch_output_unavailable")
                attempts += 1
                try:
                    count = os.write(1, raw[offset:])
                except BlockingIOError:
                    remaining = 0 if deadline is None else max(0, deadline - time.monotonic())
                    if not remaining or not select.select([], [1], [], remaining)[1]:
                        raise OSError("engagement_dispatch_output_unavailable") from None
                    continue
                if count <= 0:
                    raise OSError("engagement_dispatch_output_unavailable")
                offset += count
            check_time()
            sys.stdout.flush()
        else:
            check_time()
            count = sys.stdout.write(output)
            if type(count) is not int or count != len(output):
                raise OSError("engagement_dispatch_output_unavailable")
            check_time()
            sys.stdout.flush()
        if blocking is not None:
            os.set_blocking(1, blocking)
            blocking = None
        return True
    except (Exception, KeyboardInterrupt):
        if blocking is not None:
            try:
                os.set_blocking(1, blocking)
            except (Exception, KeyboardInterrupt):
                pass
            blocking = None
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
        from recon_cockpit.secure_agent.engagement_dispatch_contract import _operation_deadline, _check_deadline
        # argparse exits immediately afterward: flush before it reports success.
        help_text = self.format_help().removesuffix("\n")
        deadline = _operation_deadline()
        if len(help_text.encode("utf-8")) + 1 > 8192 or not _emit(help_text, deadline):
            raise SystemExit(2)
        try:
            _check_deadline(deadline)
        except Exception:
            raise SystemExit(2) from None


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
    parser = _Parser(prog="engagement_dispatch_records.py", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    flags = {
        "create": ("directory", "engagement-id", "roe", "event-id"),
        "revise": ("directory", "roe", "event-id", "expected-revision", "expected-generation"),
        "revoke": ("directory", "event-id", "expected-revision", "expected-generation"),
        "show": ("directory",),
        "receipt": ("directory", "event-id"),
        "export": ("directory", "output"),
        "inspect": ("input",),
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
    from recon_cockpit.secure_agent.engagement_dispatch_contract import canonical
    from recon_cockpit.secure_agent import engagement_dispatch_inspection as inspection

    if args.command == "inspect":
        return inspection.inspect_export(Path(args.input))

    # Saved-export inspection and help must never import/open SQLite.
    from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger

    if args.command == "create":
        roe = inspection.read_roe_file(Path(args.roe))
        with DispatchLedger.create(Path(args.directory), engagement_id=args.engagement_id,
                                    roe=roe, event_id=args.event_id) as store:
            return {"schema_version": "2", "kind": "data_only", "disposition": "recorded",
                    "receipt": store.event_receipt(args.event_id)}
    read_only = args.command in {"show", "receipt", "export"}
    # Invalid external ROE must not open a writable store.
    roe = inspection.read_roe_file(Path(args.roe)) if args.command == "revise" else None
    with DispatchLedger.open(Path(args.directory), read_only=read_only) as store:
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
    from recon_cockpit.secure_agent.engagement_dispatch_contract import (
        DispatchLedgerError, _operation_deadline, _deadline_context, _check_deadline,
    )

    code, emitted = None, False
    deadline = _operation_deadline()
    try:
        with _deadline_context(deadline):
            result = _run(_arguments(argv))
            encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False)
            if len(encoded.encode("ascii")) + 1 > 8192:
                raise DispatchLedgerError("engagement_dispatch_limit_exceeded")
            _check_deadline(deadline)
            if not _emit(encoded, deadline):
                return 2
            emitted = True
            _check_deadline(deadline)
    except _ArgumentFailure:
        code = "engagement_dispatch_invalid_input"
    except DispatchLedgerError as exc:
        code = exc.code
    except (Exception, KeyboardInterrupt):
        # Never expose a path, SQLite error, input fragment or traceback.
        code = "engagement_dispatch_store_unavailable"
    if emitted:
        # An output already delivered cannot be repaired by a second object.
        return 2 if code is not None else 0
    if code is not None:
        encoded = json.dumps({"schema_version": "2", "error": code},
                             sort_keys=True, separators=(",", ":"))
    if not _emit(encoded):
        return 2
    return 2 if code is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
