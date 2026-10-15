"""Finite DNS/name/TLS preparation pins; this module grants no execution.

Four trusted ldd metadata probes observe linked ELF dependencies only. They do
not establish configuration validity, daemon/client startup, runtime-loaded
providers/modules, name/trust enforcement or a complete runtime closure.
"""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _runtime_probe, _trusted_program
from . import name_tls_spec as spec
from . import stock_http_runtime as shared


PROFILE = "owned-name-tls-static-preflight-v1"
INTERPRETER = shared.INTERPRETER
LIBRARY_ROOT = shared.LIBRARY_ROOT
DNSMASQ_LIBRARIES = (
    "libc.so.6", "libdbus-1.so.3", "libgmp.so.10", "libhogweed.so.6", "libidn2.so.0",
    "libjansson.so.4", "libm.so.6", "libmnl.so.0", "libnetfilter_conntrack.so.3",
    "libnettle.so.8", "libnfnetlink.so.0", "libnftables.so.1", "libnftnl.so.11",
    "libsystemd.so.0", "libunistring.so.5", "libxtables.so.12",
)
DIG_LIBRARIES = (
    "libc.so.6", "libcom_err.so.2", "libcrypto.so.3", "libdns-9.20.15-2-Debian.so",
    "libfstrm.so.0", "libgcc_s.so.1", "libgssapi_krb5.so.2", "libidn2.so.0",
    "libisc-9.20.15-2-Debian.so", "libisccfg-9.20.15-2-Debian.so", "libjemalloc.so.2",
    "libjson-c.so.5", "libk5crypto.so.3", "libkeyutils.so.1", "libkrb5.so.3",
    "libkrb5support.so.0", "liblmdb.so.0", "libm.so.6", "libmaxminddb.so.0",
    "libnghttp2.so.14", "libns-9.20.15-2-Debian.so", "libprotobuf-c.so.1", "libresolv.so.2",
    "libssl.so.3", "libstdc++.so.6", "libunistring.so.5", "liburcu-cds.so.8",
    "liburcu-common.so.8", "liburcu.so.8", "libuv.so.1", "libxml2.so.16",
    "libz.so.1", "libzstd.so.1",
)
OPENSSL_LIBRARIES = ("libc.so.6", "libcrypto.so.3", "libssl.so.3", "libz.so.1", "libzstd.so.1")
DEPENDENCIES = frozenset((INTERPRETER, *(LIBRARY_ROOT + name for name in
    set(DNSMASQ_LIBRARIES) | set(DIG_LIBRARIES) | set(shared.LIBRARIES) | set(OPENSSL_LIBRARIES))))
BIND_DEPENDENCIES = frozenset(LIBRARY_ROOT + name for name in (
    "libdns-9.20.15-2-Debian.so", "libisc-9.20.15-2-Debian.so",
    "libisccfg-9.20.15-2-Debian.so", "libns-9.20.15-2-Debian.so"))
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
MAX_RUNTIME_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_FILES = 128
MAX_PROBE_BYTES = 32768
MAX_INSPECTION_SECONDS = 15
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_UNVERIFIED = ("runtime_closure_verified", "native_execution_performed",
               "daemon_execution_performed", "client_execution_performed", "configuration_validation_performed")


def _control(control):
    if (type(control) is not ExecutionControl or control.clock is not time.monotonic
            or control.remaining() > MAX_INSPECTION_SECONDS):
        raise ValueError("invalid_name_tls_inspection_control")
    control.check()


def _native_files():
    return {"/tool/dnsmasq": "/usr/sbin/dnsmasq", "/tool/nginx": "/usr/sbin/nginx",
            "/tool/dig": "/usr/bin/dig", "/tool/openssl": "/usr/bin/openssl"}


def _elf_dependencies():
    libraries = {"/tool/dnsmasq": DNSMASQ_LIBRARIES, "/tool/nginx": shared.LIBRARIES,
                 "/tool/dig": DIG_LIBRARIES, "/tool/openssl": OPENSSL_LIBRARIES}
    return {destination: sorted((INTERPRETER, *(LIBRARY_ROOT + name for name in names)))
            for destination, names in sorted(libraries.items())}


def _source_allowed(source, destination):
    if type(source) is not str or type(destination) is not str or len(source) > 512:
        return False
    if destination in _native_files():
        return source == _native_files()[destination]
    if destination == INTERPRETER:
        return source == LIBRARY_ROOT + "ld-linux-x86-64.so.2"
    if destination not in DEPENDENCIES:
        return False
    if source == destination:
        return True
    # Debian BIND embeds its reviewed release in the SONAME itself; allow no
    # wildcard release or source alias for those four exact shared objects.
    return (destination not in BIND_DEPENDENCIES
            and re.fullmatch(re.escape(destination) + r"(?:\.[0-9]{1,10}){1,4}", source) is not None)


def _compiled(configuration, case):
    # Closed selectors are checked before filesystem or metadata access.
    spec.selection(configuration, case)
    rows = tuple(spec.compiled_files(configuration, case))
    result = {}
    for source, destination, raw in rows:
        if (type(source) is not str or not source.startswith("compiled:")
                or type(destination) is not str or not destination.startswith("/")
                or any(part in ("", ".", "..") for part in destination.split("/")[1:])
                or type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES
                or destination in result or destination in DEPENDENCIES | set(_native_files())):
            raise ValueError("invalid_name_tls_compiled_files")
        result[destination] = (source, raw)
    if not result or len(rows) != len({source for source, _, _ in rows}):
        raise ValueError("invalid_name_tls_compiled_files")
    return result


def validate_manifest(value):
    """Pure, detached validation of fixed metadata, without claiming readiness."""
    strings = {"schema_version", "profile", "configuration", "case", "selection_sha256",
               "interpreter", "dependency_kind"}
    fields = strings | {"executables", "elf_dependencies", "files", *_UNVERIFIED}
    if (type(value) is not dict or set(value) != fields
            or any(type(value[name]) is not str for name in strings)):
        raise ValueError("invalid_name_tls_manifest")
    compiled = _compiled(value["configuration"], value["case"])
    native, dependencies = _native_files(), _elf_dependencies()
    if (value["schema_version"] != "1" or value["profile"] != PROFILE
            or value["selection_sha256"] != spec.selection_digest(value["configuration"], value["case"])
            or value["interpreter"] != INTERPRETER
            or type(value["executables"]) is not dict or value["executables"] != native
            or any(type(k) is not str or type(v) is not str for k, v in value["executables"].items())
            or type(value["elf_dependencies"]) is not dict or value["elf_dependencies"] != dependencies
            or any(type(k) is not str or type(v) is not list or any(type(p) is not str for p in v)
                   for k, v in value["elf_dependencies"].items())
            or value["dependency_kind"] != "fixed_four_elf_linked_dependencies_only"
            or any(value[name] is not False for name in _UNVERIFIED)
            or type(value["files"]) is not list
            or len(value["files"]) != len(native) + len(DEPENDENCIES) + len(compiled)
            or len(value["files"]) > MAX_FILES):
        raise ValueError("invalid_name_tls_manifest")
    destinations, sources, total = set(), set(), 0
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"source", "destination", "size", "sha256"}
                or type(row["source"]) is not str or type(row["destination"]) is not str
                or type(row["size"]) is not int or not 1 <= row["size"] <= MAX_FILE_BYTES
                or type(row["sha256"]) is not str or _DIGEST.fullmatch(row["sha256"]) is None):
            raise ValueError("invalid_name_tls_manifest_file")
        source, destination = row["source"], row["destination"]
        if destination in compiled:
            expected, raw = compiled[destination]
            allowed = source == expected and row["size"] == len(raw) and row["sha256"] == hashlib.sha256(raw).hexdigest()
        else:
            allowed = _source_allowed(source, destination)
        if not allowed or destination in destinations or source in sources:
            raise ValueError("invalid_name_tls_manifest_path")
        destinations.add(destination)
        sources.add(source)
        total += row["size"]
    if (destinations != DEPENDENCIES | set(native) | set(compiled) or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])
            or len(spec.encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_name_tls_manifest_closure")
    return deepcopy(value)


def manifest_digest(value):
    return hashlib.sha256(spec.encode(validate_manifest(value))).hexdigest()


def _read_file(source, control):
    # The shared reader rejects symlinks, FIFOs, group/other writes and unstable
    # inode/ownership/mode/size/timestamps. Bind its read to root ownership too.
    _control(control)
    before = os.stat(source, follow_symlinks=False)
    if before.st_uid != 0 or not stat.S_ISREG(before.st_mode) or before.st_mode & 0o022:
        raise IsolationUnavailable("Name/TLS runtime files must be root-owned non-writable regular files")
    raw = shared._read_file(source, control)
    if shared._stamp(before) != shared._stamp(os.stat(source, follow_symlinks=False)):
        raise IsolationUnavailable("Name/TLS runtime ownership or file changed during inspection")
    return raw


def _elf(raw, *, executable=False):
    shared._elf(raw, executable=executable)
    if not executable and struct.unpack_from("<H", raw, 16)[0] != 3:
        raise IsolationUnavailable("Name/TLS libraries must be shared ELF objects")


def _dependencies(raw, expected):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROBE_BYTES:
        raise IsolationUnavailable("Invalid name/TLS dependency listing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise IsolationUnavailable("Invalid name/TLS dependency listing") from exc
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
            raise IsolationUnavailable("Unsupported name/TLS dependency listing")
        soname, path = match.groups()
        if (path not in expected or path in paths or soname is not None and soname != Path(path).name
                or path != INTERPRETER and soname is None):
            raise IsolationUnavailable("Unreviewed name/TLS dependency")
        paths.add(path)
    if paths != expected or vdso != 1:
        raise IsolationUnavailable("Name/TLS dependencies differ from the reviewed finite closure")
    return sorted(paths)


def verify_current(manifest, control):
    """Recheck fixed current files; never run metadata or supplied commands."""
    value = validate_manifest(manifest)
    _control(control)
    compiled, native = _compiled(value["configuration"], value["case"]), _native_files()
    try:
        for row in value["files"]:
            control.check()
            if row["destination"] in compiled:
                raw = compiled[row["destination"]][1]
            else:
                current = native.get(row["destination"], row["destination"])
                if (str(Path(row["source"]).resolve(strict=True)) != row["source"]
                        or str(Path(current).resolve(strict=True)) != row["source"]):
                    raise IsolationUnavailable("Name/TLS runtime path changed")
                raw = _read_file(row["source"], control)
                _elf(raw, executable=row["destination"] in native)
            if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise IsolationUnavailable("Name/TLS runtime differs from its pinned manifest")
    except OSError as exc:
        raise IsolationUnavailable("Cannot read the pinned name/TLS runtime") from exc
    control.check()
    return value


def inspect_runtime(configuration, case, control):
    """Read fixed ELFs and run exactly four bounded trusted ldd metadata probes."""
    compiled = _compiled(configuration, case)
    _control(control)
    if sys.platform != "linux":
        raise IsolationUnavailable("Name/TLS inspection requires the reviewed Linux runtime")
    native, dependencies = _native_files(), _elf_dependencies()
    try:
        files = []
        for destination in sorted(DEPENDENCIES | set(native)):
            control.check()
            source = str(Path(native.get(destination, destination)).resolve(strict=True))
            if not _source_allowed(source, destination):
                raise IsolationUnavailable("Unreviewed name/TLS runtime location")
            raw = _read_file(source, control)
            _elf(raw, executable=destination in native)
            files.append({"source": source, "destination": destination, "size": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
        if sum(row["size"] for row in files) > MAX_RUNTIME_BYTES:
            raise IsolationUnavailable("Name/TLS runtime exceeds its aggregate bound")
        probe = _trusted_program("ldd")
        if probe != "/usr/bin/ldd":
            raise IsolationUnavailable("Unreviewed name/TLS dependency inspector")
        for destination, source in sorted(native.items()):
            control.check()
            _dependencies(_runtime_probe([probe, source], min(3, control.remaining()),
                MAX_PROBE_BYTES, control), set(dependencies[destination]))
        for destination, (source, raw) in compiled.items():
            files.append({"source": source, "destination": destination, "size": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
        manifest = {"schema_version": "1", "profile": PROFILE, "configuration": configuration, "case": case,
            "selection_sha256": spec.selection_digest(configuration, case), "interpreter": INTERPRETER,
            "executables": native, "elf_dependencies": dependencies,
            "dependency_kind": "fixed_four_elf_linked_dependencies_only", **dict.fromkeys(_UNVERIFIED, False),
            "files": sorted(files, key=lambda row: row["destination"])}
        return verify_current(manifest, control)
    except (OSError, UnicodeError) as exc:
        raise IsolationUnavailable("Cannot inspect the fixed name/TLS runtime") from exc
