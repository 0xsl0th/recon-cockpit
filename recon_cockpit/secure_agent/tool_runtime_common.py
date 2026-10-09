"""Bounded byte staging for repository-selected ELF tool profiles."""

import hashlib
import os
import stat

from .isolation import IsolationUnavailable

MAX_FILE_BYTES = 16 * 1024 * 1024


def _read_regular(source, *, maximum=MAX_FILE_BYTES):
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise IsolationUnavailable("Web tool runtime contains an invalid file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) != info.st_size:
            raise IsolationUnavailable("Web tool runtime changed during inspection")
        return raw
    finally:
        os.close(descriptor)


def sealed_snapshots(manifest, compiled_source, compiled, control, *, maximum_file_bytes=MAX_FILE_BYTES,
                     additional_compiled=()):
    import fcntl
    compiled_files = {} if compiled_source is None else {compiled_source: compiled}
    for source, raw in additional_compiled:
        if (type(source) is not str or not source.startswith("compiled:") or source in compiled_files
                or type(raw) is not bytes or not 0 < len(raw) <= maximum_file_bytes):
            raise IsolationUnavailable("Invalid additional compiled runtime file")
        compiled_files[source] = raw
    descriptors = []
    try:
        for item in manifest["files"]:
            control.check()
            raw = (compiled_files[item["source"]] if item["source"] in compiled_files else
                   _read_regular(item["source"]) if maximum_file_bytes == MAX_FILE_BYTES else
                   _read_regular(item["source"], maximum=maximum_file_bytes))
            if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise IsolationUnavailable("Web tool runtime differs from its pinned manifest")
            fd = os.memfd_create("recon-web-tool-runtime", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


_CLOSE_EXCEPT = """import os,sys
keep={int(v) for v in sys.argv[1].split(',')}
for name in os.listdir('/proc/self/fd'):
    if int(name)>2 and int(name) not in keep:
        try: os.close(int(name))
        except OSError as exc:
            if exc.errno != 9: raise
os.execv(sys.argv[2],sys.argv[2:])
"""
