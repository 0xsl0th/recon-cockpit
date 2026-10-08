"""Read-only replay of development TLS captures, with no assessment authority."""

import os
from pathlib import Path
import stat

from .tls_posture_observation_contract import MAX_INPUT_BYTES, encode_input
from .tls_posture_observation_runtime import parse_isolated_observation


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def inspect_saved_diagnostic(path, version, *, control=None):
    """Read one bounded regular file; interpret its bytes only in the parser.

    The caller supplies the expected fixed version. The parser independently
    matches it to the capture. A parsed result is a diagnostic observation and
    cannot create a policy, grant, consumed permit or authorized assessment.
    """
    # Validate the trusted selection before touching an input path.
    encode_input(b"{}", version)
    if control is not None:
        control.check()
    descriptor = os.open(Path(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT_BYTES:
            raise ValueError("invalid_tls_diagnostic_file")
        chunks, count = [], 0
        while True:
            if control is not None:
                control.check()
            chunk = os.read(descriptor, min(65536, MAX_INPUT_BYTES + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > MAX_INPUT_BYTES:
                raise ValueError("tls_diagnostic_file_too_large")
        if _stamp(before) != _stamp(os.fstat(descriptor)) or count != before.st_size:
            raise ValueError("tls_diagnostic_file_changed")
    finally:
        os.close(descriptor)
    # The descriptor is closed before the worker starts. Do not load JSON or
    # follow any runtime source paths in the untrusted retained capture.
    return parse_isolated_observation(encode_input(b"".join(chunks), version), control=control)
