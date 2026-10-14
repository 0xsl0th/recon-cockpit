"""Read-only pins for the selected stock nginx diagnostic, never a launcher.

ELF-linked dependencies are a finite preflight observation. They do not establish
nginx startup, runtime-loaded modules, configuration validity or confinement.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _runtime_probe, _trusted_program
from . import stock_http_spec as spec


PROFILE = "stock-nginx-static-preflight-v1"
EXECUTABLE = "/usr/sbin/nginx"
DESTINATION = "/tool/nginx"
INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
LIBRARY_ROOT = "/usr/lib/x86_64-linux-gnu/"
LIBRARIES = (
    "libc.so.6", "libcrypt.so.1", "libcrypto.so.3", "libpcre2-8.so.0",
    "libssl.so.3", "libz.so.1", "libzstd.so.1",
)
DEPENDENCIES = frozenset((INTERPRETER, *(LIBRARY_ROOT + name for name in LIBRARIES)))
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 16384
MAX_FILES = 24
MAX_PROBE_BYTES = 32768
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_LIBRARY_SOURCE = re.compile(r"/usr/lib/x86_64-linux-gnu/[A-Za-z0-9_+-]+\.so(?:\.[0-9]+)+\Z")


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _control(control):
    if type(control) is not ExecutionControl:
        raise ValueError("invalid_stock_http_inspection_control")
    control.check()


def _selected(configuration, case):
    # Selection validation precedes filesystem or process access.
    spec.selection(configuration, case)
    return tuple(spec.compiled_files(configuration, case))


def _source_allowed(source, destination):
    if type(source) is not str or type(destination) is not str:
        return False
    if destination == DESTINATION:
        return source == EXECUTABLE
    if destination == INTERPRETER:
        return source == LIBRARY_ROOT + "ld-linux-x86-64.so.2"
    if destination not in DEPENDENCIES or _LIBRARY_SOURCE.fullmatch(source) is None:
        return False
    return source == destination or bool(re.fullmatch(re.escape(destination) + r"(?:\.[0-9]+)+", source))


def _compiled(configuration, case):
    rows = _selected(configuration, case)
    result = {}
    for source, destination, raw in rows:
        if (type(source) is not str or not source.startswith("compiled:")
                or type(destination) is not str or not destination.startswith("/")
                or any(part in ("", ".", "..") for part in destination.split("/")[1:])
                or type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES
                or destination in result or destination in DEPENDENCIES | {DESTINATION}):
            raise ValueError("invalid_stock_http_compiled_files")
        result[destination] = (source, raw)
    if not result or len(rows) != len({source for source, _, _ in rows}):
        raise ValueError("invalid_stock_http_compiled_files")
    return result


def validate_manifest(value):
    """Validate and detach only the fixed preflight identity; this is no grant."""
    fields = {"schema_version", "profile", "configuration", "case", "selection_sha256",
        "executable", "interpreter", "dependency_kind", "runtime_closure_verified",
        "daemon_execution_performed", "files"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("invalid_stock_http_manifest")
    compiled = _compiled(value["configuration"], value["case"])
    if (value["schema_version"] != "1" or value["profile"] != PROFILE
            or value["selection_sha256"] != spec.selection_digest(value["configuration"], value["case"])
            or value["executable"] != DESTINATION or value["interpreter"] != INTERPRETER
            or value["dependency_kind"] != "elf_linked_dependencies_only"
            or value["runtime_closure_verified"] is not False
            or value["daemon_execution_performed"] is not False
            or type(value["files"]) is not list
            or len(value["files"]) != 1 + len(DEPENDENCIES) + len(compiled)
            or len(value["files"]) > MAX_FILES):
        raise ValueError("invalid_stock_http_manifest")
    destinations, sources, total = set(), set(), 0
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"source", "destination", "size", "sha256"}
                or type(row["source"]) is not str or type(row["destination"]) is not str
                or type(row["size"]) is not int or not 1 <= row["size"] <= MAX_FILE_BYTES
                or type(row["sha256"]) is not str or _DIGEST.fullmatch(row["sha256"]) is None):
            raise ValueError("invalid_stock_http_manifest_file")
        source, destination = row["source"], row["destination"]
        if destination in compiled:
            expected, raw = compiled[destination]
            allowed = source == expected and row["size"] == len(raw) and row["sha256"] == hashlib.sha256(raw).hexdigest()
        else:
            allowed = _source_allowed(source, destination)
        if not allowed or destination in destinations or source in sources:
            raise ValueError("invalid_stock_http_manifest_path")
        destinations.add(destination)
        sources.add(source)
        total += row["size"]
    if (destinations != DEPENDENCIES | {DESTINATION} | set(compiled)
            or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])
            or len(_encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_stock_http_manifest_closure")
    return deepcopy(value)


def manifest_digest(value):
    return hashlib.sha256(_encode(validate_manifest(value))).hexdigest()


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(source, control):
    """Read bounded regular bytes without following a final symlink or FIFO."""
    _control(control)
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o022
                or not 0 < before.st_size <= MAX_FILE_BYTES):
            raise IsolationUnavailable("Unsupported stock nginx runtime file")
        chunks, count = [], 0
        while True:
            control.check()
            raw = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - count))
            if not raw:
                break
            chunks.append(raw)
            count += len(raw)
            if count > MAX_FILE_BYTES:
                raise IsolationUnavailable("Stock nginx runtime file exceeds its bound")
        if (count != before.st_size or _stamp(before) != _stamp(os.fstat(descriptor))
                or _stamp(before) != _stamp(os.stat(source, follow_symlinks=False))):
            raise IsolationUnavailable("Stock nginx runtime changed during inspection")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _elf(raw, *, executable=False):
    if (len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<HHI", raw, 16) not in ((2, 62, 1), (3, 62, 1))):
        raise IsolationUnavailable("Stock nginx requires the reviewed x86-64 ELF runtime")
    if not executable:
        return
    offset = struct.unpack_from("<Q", raw, 32)[0]
    entry_size, entries = struct.unpack_from("<HH", raw, 54)
    if (entry_size != 56 or not 1 <= entries <= 128 or offset < 64
            or offset + entry_size * entries > len(raw)):
        raise IsolationUnavailable("Unsupported stock nginx ELF program headers")
    interpreters = []
    for index in range(entries):
        row = offset + index * entry_size
        if struct.unpack_from("<I", raw, row)[0] == 3:
            start, size = struct.unpack_from("<Q", raw, row + 8)[0], struct.unpack_from("<Q", raw, row + 32)[0]
            if not 2 <= size <= 256 or start + size > len(raw):
                raise IsolationUnavailable("Invalid stock nginx ELF interpreter")
            interpreters.append(raw[start:start + size])
    if interpreters != [INTERPRETER.encode("ascii") + b"\0"]:
        raise IsolationUnavailable("Unreviewed stock nginx ELF interpreter")


def _dependencies(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROBE_BYTES:
        raise IsolationUnavailable("Invalid stock nginx dependency listing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise IsolationUnavailable("Invalid stock nginx dependency listing") from exc
    paths, vdso = set(), 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r"linux-vdso\.so\.1 \(0x[0-9a-f]+\)", line):
            vdso += 1
            continue
        match = re.fullmatch(r"(?:(lib[A-Za-z0-9_+.-]+) => )?(/[^\s]+) \(0x[0-9a-f]+\)", line)
        if match is None:
            raise IsolationUnavailable("Unsupported stock nginx dependency listing")
        soname, path = match.groups()
        if (path not in DEPENDENCIES or path in paths
                or (soname is not None and soname != Path(path).name)
                or (path != INTERPRETER and soname is None)):
            raise IsolationUnavailable("Unreviewed stock nginx dependency")
        paths.add(path)
    if paths != DEPENDENCIES or vdso != 1:
        raise IsolationUnavailable("Stock nginx dependencies differ from the reviewed finite closure")
    return sorted(paths)


def verify_current(manifest, control):
    """Recheck content pins only; never probe or execute capture-supplied paths."""
    value = validate_manifest(manifest)
    _control(control)
    compiled = _compiled(value["configuration"], value["case"])
    try:
        for row in value["files"]:
            control.check()
            if row["destination"] in compiled:
                raw = compiled[row["destination"]][1]
            else:
                current = EXECUTABLE if row["destination"] == DESTINATION else row["destination"]
                if (str(Path(row["source"]).resolve(strict=True)) != row["source"]
                        or str(Path(current).resolve(strict=True)) != row["source"]):
                    raise IsolationUnavailable("Stock nginx runtime path changed")
                raw = _read_file(row["source"], control)
                _elf(raw, executable=row["destination"] == DESTINATION)
            if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise IsolationUnavailable("Stock nginx runtime differs from its pinned manifest")
    except OSError as exc:
        raise IsolationUnavailable("Cannot read the pinned stock nginx runtime") from exc
    control.check()
    return value


def inspect_runtime(configuration, case, control):
    """Inspect the sole selected nginx ELF and finite linked dependencies.

    Only the fixed trusted ldd metadata probe runs. nginx is never launched;
    late-loaded libraries, modules, startup and sandbox compatibility stay open.
    """
    compiled = _compiled(configuration, case)
    _control(control)
    if sys.platform != "linux":
        raise IsolationUnavailable("Stock nginx inspection requires the reviewed Linux runtime")
    try:
        if str(Path(EXECUTABLE).resolve(strict=True)) != EXECUTABLE:
            raise IsolationUnavailable("Unreviewed stock nginx executable location")
        executable = _read_file(EXECUTABLE, control)
        _elf(executable, executable=True)
        files = [{"source": EXECUTABLE, "destination": DESTINATION,
                  "size": len(executable), "sha256": hashlib.sha256(executable).hexdigest()}]
        for destination in sorted(DEPENDENCIES):
            control.check()
            source = str(Path(destination).resolve(strict=True))
            if not _source_allowed(source, destination):
                raise IsolationUnavailable("Unreviewed stock nginx library location")
            raw = _read_file(source, control)
            _elf(raw)
            files.append({"source": source, "destination": destination, "size": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
        if sum(row["size"] for row in files) > MAX_RUNTIME_BYTES:
            raise IsolationUnavailable("Stock nginx runtime exceeds its aggregate bound")
        # Read every selected file before ldd, then recheck all pins after it.
        # A changed dependency cannot silently produce a mixed-time manifest.
        probe = _trusted_program("ldd")
        if probe != "/usr/bin/ldd":
            raise IsolationUnavailable("Unreviewed stock nginx dependency inspector")
        _dependencies(_runtime_probe([probe, EXECUTABLE],
            min(3, control.remaining()), MAX_PROBE_BYTES, control))
        for destination, (source, raw) in compiled.items():
            files.append({"source": source, "destination": destination, "size": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
        manifest = {"schema_version": "1", "profile": PROFILE,
            "configuration": configuration, "case": case,
            "selection_sha256": spec.selection_digest(configuration, case),
            "executable": DESTINATION, "interpreter": INTERPRETER,
            "dependency_kind": "elf_linked_dependencies_only",
            "runtime_closure_verified": False, "daemon_execution_performed": False,
            "files": sorted(files, key=lambda row: row["destination"])}
        return verify_current(manifest, control)
    except (OSError, UnicodeError) as exc:
        raise IsolationUnavailable("Cannot inspect the fixed stock nginx runtime") from exc
