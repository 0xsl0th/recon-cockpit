"""Inspect saved N15 composites without restoring execution authority.

The unchanged production validator may start bounded isolated Python parsers.
It does not start native clients, fixture daemons, owners or approval grants.
Callers running a combined inspection apply its declared outer time allowance.
"""

import hashlib
import os
from pathlib import Path
import stat

from .name_tls_evidence import MAX_JSON_BYTES, _decode, validate_probe_evidence


def _identity(info):
    # Reading can update atime; it cannot legitimately change these fields.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 0 < info.st_size <= MAX_JSON_BYTES):
        raise ValueError("name_tls_composite_private_file")
    return _identity(info)


def _unchanged(path, descriptor, initial):
    if (_identity(os.fstat(descriptor)) != initial
            or _identity(path.stat(follow_symlinks=False)) != initial):
        raise ValueError("name_tls_composite_changed")


def _read(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks, size = [], 0
    while True:
        chunk = os.read(descriptor, min(65536, MAX_JSON_BYTES + 1 - size))
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_JSON_BYTES:
            raise ValueError("name_tls_composite_size")
        chunks.append(chunk)


def _report(raw):
    probes = _decode(raw)
    try:
        owners = probes["owners"]
        if (probes["case"] != "N15" or probes["test_authority"] != "scripted_owned_pty"
                or type(owners) is not list or len(owners) != 3):
            raise ValueError("name_tls_composite_shape")
        primary = owners[0]
        manifest, outcome = primary["manifest"], primary["dns_outcome"]
        selection = manifest["selection"]
        if (selection["case"] != "N15" or selection["configuration"] not in ("A", "B")
                or type(outcome) is not dict):
            raise ValueError("name_tls_composite_shape")
        passed = validate_probe_evidence(probes, manifest=manifest,
            results=[outcome["untrusted_result"]],
            outcomes=[{key: value for key, value in outcome.items() if key != "untrusted_result"}])
    except (KeyError, IndexError, TypeError, AttributeError) as error:
        raise ValueError("name_tls_composite_shape") from error
    if type(passed) is not bool:
        raise ValueError("name_tls_composite_validation_result")
    return {"schema_version": "1", "case_passed": passed is True,
            "classification": "expected_negative" if passed else "incomplete", "case": "N15",
            "configuration": selection["configuration"], "test_authority": "scripted_owned_pty",
            "composite_sha256": hashlib.sha256(raw).hexdigest(),
            "actual_provider_calls": 0, "owner_count": len(owners)}


def inspect_composite(path):
    """Validate one unchanged, private N15 file and return its historical report."""
    path = Path(path)
    # NONBLOCK prevents a substituted FIFO from blocking before fstat rejects it.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        initial = _private_file(os.fstat(descriptor))
        _unchanged(path, descriptor, initial)
        raw = _read(descriptor)
        _unchanged(path, descriptor, initial)
        if len(raw) != initial[6]:
            raise ValueError("name_tls_composite_changed")
        report = _report(raw)
        _unchanged(path, descriptor, initial)
        if _read(descriptor) != raw:
            raise ValueError("name_tls_composite_changed")
        _unchanged(path, descriptor, initial)
        return report
    finally:
        os.close(descriptor)
