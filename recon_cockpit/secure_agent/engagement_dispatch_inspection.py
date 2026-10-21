"""Private file custody for dispatch ledger data; no store or execution imports."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from functools import wraps
from contextlib import contextmanager

from .engagement_contract import EngagementError as _RecordError, decode_roe as _decode_record_roe
from .engagement_dispatch_contract import (
    DispatchLedgerError, _deadline_context, _operation_deadline, _check_deadline,
    canonical, decode_export, validate_export,
)

MAX_EXPORT_BYTES = 2097152
MAX_ROE_BYTES = 4096
MAX_REPORT_BYTES = 8192
STATE_DOMAIN = b"recon-engagement-dispatch-state-v2\x00"


def _bounded_operation(function):
    @wraps(function)
    def bounded(*args, **kwargs):
        deadline = _operation_deadline()
        with _deadline_context(deadline):
            result = function(*args, **kwargs)
            _check_deadline(deadline)
        return result
    return bounded


def _check_time(deadline):
    _check_deadline(deadline)


def decode_roe(raw):
    try:
        return _decode_record_roe(raw)
    except _RecordError as error:
        suffix = {"engagement_timeout": "timeout",
                  "engagement_limit_exceeded": "limit_exceeded"}.get(error.code, "invalid_roe")
        raise DispatchLedgerError("engagement_dispatch_" + suffix) from None


def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _check_parent(parent_fd, parent_path, identity, *, changed=True):
    code = "engagement_dispatch_snapshot_changed" if changed else "engagement_dispatch_invalid_input"
    try:
        held = os.fstat(parent_fd)
        named = parent_path.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(held.st_mode) or held.st_uid != os.getuid()
                or stat.S_IMODE(held.st_mode) != 0o700
                or _directory_identity(held) != identity
                or _directory_identity(named) != identity):
            raise DispatchLedgerError(code)
    except OSError:
        raise DispatchLedgerError(code) from None


@contextmanager
def _private_parent(path):
    """Resolve trusted ancestor aliases once; hold the actual private parent."""
    parent_fd = None
    try:
        try:
            raw = os.fspath(path)
            if type(raw) is not str or not raw or "\x00" in raw:
                raise DispatchLedgerError("engagement_dispatch_invalid_input")
            supplied = Path(raw)
            if supplied.name in {"", ".", ".."} or raw.endswith("/"):
                raise DispatchLedgerError("engagement_dispatch_invalid_input")
            parent = supplied.parent.resolve(strict=True)
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            identity = _directory_identity(os.fstat(parent_fd))
            _check_parent(parent_fd, parent, identity, changed=False)
        except DispatchLedgerError:
            raise
        except (OSError, ValueError, TypeError, RuntimeError):
            raise DispatchLedgerError("engagement_dispatch_invalid_input") from None
        yield parent_fd, parent, supplied.name, identity
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                raise DispatchLedgerError("engagement_dispatch_store_unavailable") from None


def _regular(info, *, code):
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid() or info.st_nlink != 1):
        raise DispatchLedgerError(code)


def _outside_store(parent_fd):
    """Refuse the reserved store parent without ever opening its database."""
    try:
        os.stat("records.sqlite3", dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise DispatchLedgerError("engagement_dispatch_invalid_input")


def _check_file(fd, parent_fd, name, identity):
    try:
        held = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _file_identity(held) != identity or _file_identity(named) != identity:
            raise DispatchLedgerError("engagement_dispatch_snapshot_changed")
    except OSError:
        raise DispatchLedgerError("engagement_dispatch_snapshot_changed") from None


def _read_to_eof(fd, maximum, deadline):
    chunks = []
    total = 0
    while True:
        _check_time(deadline)
        chunk = os.read(fd, min(65536, maximum - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise DispatchLedgerError("engagement_dispatch_limit_exceeded")
        chunks.append(chunk)
    _check_time(deadline)
    return b"".join(chunks)


def _read_file(path, maximum, decoder, deadline):
    fd = None
    try:
        with _private_parent(path) as (parent_fd, parent, name, parent_identity):
            _check_time(deadline)
            # Closing even a rejected JSON-input descriptor for a live SQLite
            # database could release this process's POSIX locks. Refuse the
            # whole reserved store parent before opening any input descriptor.
            _outside_store(parent_fd)
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _regular(named, code="engagement_dispatch_invalid_input")
            # NONBLOCK avoids hanging even when a raced entry is a FIFO/device.
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent_fd)
            info = os.fstat(fd)
            _regular(info, code="engagement_dispatch_invalid_input")
            if info.st_size > maximum:
                raise DispatchLedgerError("engagement_dispatch_limit_exceeded")
            if info.st_size < 1:
                raise DispatchLedgerError("engagement_dispatch_invalid_input")
            identity = _file_identity(info)
            if identity != _file_identity(named):
                raise DispatchLedgerError("engagement_dispatch_snapshot_changed")
            _check_file(fd, parent_fd, name, identity)
            first = _read_to_eof(fd, maximum, deadline)
            _check_file(fd, parent_fd, name, identity)
            _check_parent(parent_fd, parent, parent_identity)
            value = decoder(first)
            _check_time(deadline)
            _check_file(fd, parent_fd, name, identity)
            os.lseek(fd, 0, os.SEEK_SET)
            second = _read_to_eof(fd, maximum, deadline)
            if first != second:
                raise DispatchLedgerError("engagement_dispatch_snapshot_changed")
            _check_file(fd, parent_fd, name, identity)
            _check_parent(parent_fd, parent, parent_identity)
            _check_time(deadline)
            return value, first
    except DispatchLedgerError:
        raise
    except (OSError, ValueError, TypeError):
        raise DispatchLedgerError("engagement_dispatch_invalid_input") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                raise DispatchLedgerError("engagement_dispatch_store_unavailable") from None


@_bounded_operation
def read_roe_file(path):
    deadline = _operation_deadline()
    value, _ = _read_file(path, MAX_ROE_BYTES, decode_roe, deadline)
    _check_time(deadline)
    return value


@_bounded_operation
def report_export(snapshot, *, raw_sha256):
    deadline = _operation_deadline()
    value = validate_export(snapshot)
    if (type(raw_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", raw_sha256) is None
            or raw_sha256 != hashlib.sha256(canonical(value)).hexdigest()):
        raise DispatchLedgerError("engagement_dispatch_invalid_export")
    state = value["state"]
    outcomes = {name: 0 for name in ("reported_success", "reported_failure", "cancelled", "unresolved")}
    for row in value["completions"]:
        outcomes[row["outcome"]] += 1
    report = {"schema_version": "2", "kind": "engagement_dispatch_report",
              "engagement_id": value["engagement_id"], "revision": state["revision"],
              "generation": state["generation"], "status": state["status"],
              "usage": dict(state["usage"]), "utc_high_water_ns": state["utc_high_water_ns"],
              "counts": {name: len(value[name]) for name in
                         ("revisions", "sessions", "reservations", "completions", "events")},
              "reported_outcomes": outcomes,
              "uncompleted_reservations": len(value["reservations"]) - len(value["completions"]),
              "state_sha256": hashlib.sha256(STATE_DOMAIN + canonical(state)).hexdigest(),
              "export_sha256": raw_sha256, "consistency": "validated",
              "authority": "none", "physical_delivery": "unverified"}
    if len(canonical(report)) > MAX_REPORT_BYTES:
        raise DispatchLedgerError("engagement_dispatch_limit_exceeded")
    _check_time(deadline)
    return report


@_bounded_operation
def inspect_export(path):
    deadline = _operation_deadline()
    value, raw = _read_file(path, MAX_EXPORT_BYTES, decode_export, deadline)
    report = report_export(value, raw_sha256=hashlib.sha256(raw).hexdigest())
    _check_time(deadline)
    return report


@_bounded_operation
def write_export(path, snapshot):
    """Create one new private canonical output; leave any failed partial file."""
    deadline = _operation_deadline()
    value = validate_export(snapshot)
    raw = canonical(value)
    report = report_export(value, raw_sha256=hashlib.sha256(raw).hexdigest())
    _check_time(deadline)
    fd = None
    try:
        with _private_parent(path) as (parent_fd, parent, name, parent_identity):
            _check_time(deadline)
            # An export is never a foreign entry in an engagement store. Check
            # the reserved database name without opening/closing a DB descriptor
            # (which could release this process's SQLite POSIX locks).
            if name == "records.sqlite3":
                raise DispatchLedgerError("engagement_dispatch_invalid_input")
            _outside_store(parent_fd)
            try:
                # Read/write uses the same retained descriptor for bounded readback.
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
            except FileExistsError:
                raise DispatchLedgerError("engagement_dispatch_output_exists") from None
            initial = os.fstat(fd)
            _regular(initial, code="engagement_dispatch_invalid_input")
            stable = _file_identity(initial)[:6]
            offset = 0
            while offset < len(raw):
                _check_time(deadline)
                count = os.write(fd, raw[offset:])
                if type(count) is not int or not 0 < count <= len(raw) - offset:
                    raise DispatchLedgerError("engagement_dispatch_store_unavailable")
                offset += count
            _check_time(deadline)
            os.fsync(fd)
            os.fsync(parent_fd)
            info = os.fstat(fd)
            if _file_identity(info)[:6] != stable or info.st_size != len(raw):
                raise DispatchLedgerError("engagement_dispatch_snapshot_changed")
            identity = _file_identity(info)
            _check_file(fd, parent_fd, name, identity)
            _check_parent(parent_fd, parent, parent_identity)
            os.lseek(fd, 0, os.SEEK_SET)
            if _read_to_eof(fd, MAX_EXPORT_BYTES, deadline) != raw:
                raise DispatchLedgerError("engagement_dispatch_snapshot_changed")
            _check_file(fd, parent_fd, name, identity)
            _check_parent(parent_fd, parent, parent_identity)
            _check_time(deadline)
    except DispatchLedgerError:
        raise
    except (OSError, ValueError, TypeError):
        raise DispatchLedgerError("engagement_dispatch_store_unavailable") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                raise DispatchLedgerError("engagement_dispatch_store_unavailable") from None
    _check_time(deadline)
    return report
