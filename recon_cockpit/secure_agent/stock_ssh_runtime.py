"""Read-only pins for finite stock OpenSSH preparation; never a launcher.

Each installed daemon/helper has a separate fixed ELF dependency expectation.
These metadata observations do not verify runtime-loaded libraries, helper
execution, privilege separation, configuration parsing or native compatibility.
"""

from copy import deepcopy
import hashlib
from pathlib import Path
import re
import struct
import sys

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _runtime_probe, _trusted_program
from . import stock_ssh_spec as spec
from . import stock_http_runtime as shared


PROFILE = "stock-openssh-static-preflight-v1"
EXECUTABLE = "/usr/sbin/sshd"
DESTINATION = "/tool/sshd"
INTERPRETER = shared.INTERPRETER
LIBRARY_ROOT = shared.LIBRARY_ROOT
DAEMON_LIBRARIES = (
    "libc.so.6", "libcrypto.so.3", "libpcre2-8.so.0", "libselinux.so.1",
    "libz.so.1", "libzstd.so.1",
)
SESSION_LIBRARIES = (*DAEMON_LIBRARIES,
    "libaudit.so.1", "libcap-ng.so.0", "libcom_err.so.2", "libcrypt.so.1",
    "libgssapi_krb5.so.2", "libk5crypto.so.3", "libkeyutils.so.1", "libkrb5.so.3",
    "libkrb5support.so.0", "libm.so.6", "libpam.so.0", "libresolv.so.2",
    "libsqlite3.so.0", "libwrap.so.0", "libwtmpdb.so.0",
)
AUTH_LIBRARIES = tuple(name for name in SESSION_LIBRARIES if name != "libwrap.so.0")
DEPENDENCIES = frozenset((INTERPRETER, *(LIBRARY_ROOT + name for name in SESSION_LIBRARIES)))
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 24576
MAX_FILES = 40
MAX_PROBE_BYTES = 32768
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_LIBRARY_SOURCE = re.compile(r"/usr/lib/x86_64-linux-gnu/[A-Za-z0-9_+-]+\.so(?:\.[0-9]+)+\Z")


def _control(control):
    if type(control) is not ExecutionControl:
        raise ValueError("invalid_stock_ssh_inspection_control")
    control.check()


def _native_files():
    return {DESTINATION: EXECUTABLE,
            "/usr/lib/openssh/sshd-session": "/usr/lib/openssh/sshd-session",
            "/usr/lib/openssh/sshd-auth": "/usr/lib/openssh/sshd-auth"}


def _elf_dependencies():
    libraries = {DESTINATION: DAEMON_LIBRARIES,
                 "/usr/lib/openssh/sshd-session": SESSION_LIBRARIES,
                 "/usr/lib/openssh/sshd-auth": AUTH_LIBRARIES}
    return {destination: sorted((INTERPRETER, *(LIBRARY_ROOT + name for name in names)))
            for destination, names in sorted(libraries.items())}


def _source_allowed(source, destination):
    if type(source) is not str or type(destination) is not str:
        return False
    if destination in _native_files():
        return source == _native_files()[destination]
    if destination == INTERPRETER:
        return source == LIBRARY_ROOT + "ld-linux-x86-64.so.2"
    if destination not in DEPENDENCIES or _LIBRARY_SOURCE.fullmatch(source) is None:
        return False
    return source == destination or bool(re.fullmatch(re.escape(destination) + r"(?:\.[0-9]+)+", source))


def _compiled(configuration, case):
    # Reject selectors before filesystem or metadata-process access.
    spec.selection(configuration, case)
    rows = tuple(spec.compiled_files(configuration, case))
    result = {}
    for source, destination, raw in rows:
        if (type(source) is not str or not source.startswith("compiled:")
                or type(destination) is not str or not destination.startswith("/")
                or any(part in ("", ".", "..") for part in destination.split("/")[1:])
                or type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES
                or destination in result or destination in DEPENDENCIES | set(_native_files())):
            raise ValueError("invalid_stock_ssh_compiled_files")
        result[destination] = (source, raw)
    if not result or len(rows) != len({source for source, _, _ in rows}):
        raise ValueError("invalid_stock_ssh_compiled_files")
    return result


def validate_manifest(value):
    """Detach exact preparation metadata; no supplied field grants readiness."""
    fields = {"schema_version", "profile", "configuration", "case", "selection_sha256",
        "executable", "interpreter", "executables", "elf_dependencies", "dependency_kind",
        "runtime_closure_verified", "daemon_execution_performed", "files"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("invalid_stock_ssh_manifest")
    compiled = _compiled(value["configuration"], value["case"])
    if (value["schema_version"] != "1" or value["profile"] != PROFILE
            or value["selection_sha256"] != spec.selection_digest(value["configuration"], value["case"])
            or value["executable"] != DESTINATION or value["interpreter"] != INTERPRETER
            or value["executables"] != _native_files() or value["elf_dependencies"] != _elf_dependencies()
            or value["dependency_kind"] != "fixed_daemon_helpers_and_elf_linked_dependencies_only"
            or value["runtime_closure_verified"] is not False
            or value["daemon_execution_performed"] is not False
            or type(value["files"]) is not list
            or len(value["files"]) != len(_native_files()) + len(DEPENDENCIES) + len(compiled)
            or len(value["files"]) > MAX_FILES):
        raise ValueError("invalid_stock_ssh_manifest")
    destinations, sources, total = set(), set(), 0
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"source", "destination", "size", "sha256"}
                or type(row["source"]) is not str or type(row["destination"]) is not str
                or type(row["size"]) is not int or not 1 <= row["size"] <= MAX_FILE_BYTES
                or type(row["sha256"]) is not str or _DIGEST.fullmatch(row["sha256"]) is None):
            raise ValueError("invalid_stock_ssh_manifest_file")
        source, destination = row["source"], row["destination"]
        if destination in compiled:
            expected, raw = compiled[destination]
            allowed = source == expected and row["size"] == len(raw) and row["sha256"] == hashlib.sha256(raw).hexdigest()
        else:
            allowed = _source_allowed(source, destination)
        if not allowed or destination in destinations or source in sources:
            raise ValueError("invalid_stock_ssh_manifest_path")
        destinations.add(destination)
        sources.add(source)
        total += row["size"]
    if (destinations != DEPENDENCIES | set(_native_files()) | set(compiled)
            or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])
            or len(shared._encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_stock_ssh_manifest_closure")
    return deepcopy(value)


def manifest_digest(value):
    return hashlib.sha256(shared._encode(validate_manifest(value))).hexdigest()


def _read_file(source, control):
    # The accepted bounded reader rejects final symlinks/FIFOs/writable files
    # and checks stable inode, ownership, mode, size and timestamps across reads.
    try:
        return shared._read_file(source, control)
    except IsolationUnavailable as exc:
        raise IsolationUnavailable("Unsupported or changed stock OpenSSH runtime file") from exc


def _elf(raw, *, executable=False):
    try:
        shared._elf(raw, executable=executable)
    except IsolationUnavailable as exc:
        raise IsolationUnavailable("Unsupported stock OpenSSH x86-64 ELF runtime") from exc
    if not executable and struct.unpack_from("<H", raw, 16)[0] != 3:
        raise IsolationUnavailable("Stock OpenSSH libraries must be shared ELF objects")


def _dependencies(raw, expected):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROBE_BYTES:
        raise IsolationUnavailable("Invalid stock OpenSSH dependency listing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise IsolationUnavailable("Invalid stock OpenSSH dependency listing") from exc
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
            raise IsolationUnavailable("Unsupported stock OpenSSH dependency listing")
        soname, path = match.groups()
        if (path not in expected or path in paths
                or (soname is not None and soname != Path(path).name)
                or (path != INTERPRETER and soname is None)):
            raise IsolationUnavailable("Unreviewed stock OpenSSH dependency")
        paths.add(path)
    if paths != expected or vdso != 1:
        raise IsolationUnavailable("Stock OpenSSH dependencies differ from the reviewed finite closure")
    return sorted(paths)


def verify_current(manifest, control):
    """Recheck pins without a metadata process or capture-supplied command."""
    value = validate_manifest(manifest)
    _control(control)
    compiled = _compiled(value["configuration"], value["case"])
    native = _native_files()
    try:
        for row in value["files"]:
            control.check()
            if row["destination"] in compiled:
                raw = compiled[row["destination"]][1]
            else:
                current = native.get(row["destination"], row["destination"])
                if (str(Path(row["source"]).resolve(strict=True)) != row["source"]
                        or str(Path(current).resolve(strict=True)) != row["source"]):
                    raise IsolationUnavailable("Stock OpenSSH runtime path changed")
                raw = _read_file(row["source"], control)
                _elf(raw, executable=row["destination"] in native)
            if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise IsolationUnavailable("Stock OpenSSH runtime differs from its pinned manifest")
    except OSError as exc:
        raise IsolationUnavailable("Cannot read the pinned stock OpenSSH runtime") from exc
    control.check()
    return value


def inspect_runtime(configuration, case, control):
    """Inspect fixed ELFs; only three bounded trusted ldd metadata probes run.

    No sshd configuration check, daemon/helper startup, key generation, account
    lookup or authentication is requested. Late loading and execution stay open.
    """
    compiled = _compiled(configuration, case)
    _control(control)
    if sys.platform != "linux":
        raise IsolationUnavailable("Stock OpenSSH inspection requires the reviewed Linux runtime")
    native, dependencies = _native_files(), _elf_dependencies()
    try:
        files = []
        for destination in sorted(DEPENDENCIES | set(native)):
            control.check()
            source = str(Path(native.get(destination, destination)).resolve(strict=True))
            if not _source_allowed(source, destination):
                raise IsolationUnavailable("Unreviewed stock OpenSSH runtime location")
            raw = _read_file(source, control)
            _elf(raw, executable=destination in native)
            files.append({"source": source, "destination": destination,
                          "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        if sum(row["size"] for row in files) > MAX_RUNTIME_BYTES:
            raise IsolationUnavailable("Stock OpenSSH runtime exceeds its aggregate bound")
        probe = _trusted_program("ldd")
        if probe != "/usr/bin/ldd":
            raise IsolationUnavailable("Unreviewed stock OpenSSH dependency inspector")
        for destination, source in sorted(native.items()):
            control.check()
            _dependencies(_runtime_probe([probe, source], min(3, control.remaining()),
                MAX_PROBE_BYTES, control), set(dependencies[destination]))
        for destination, (source, raw) in compiled.items():
            files.append({"source": source, "destination": destination, "size": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
        manifest = {"schema_version": "1", "profile": PROFILE,
            "configuration": configuration, "case": case,
            "selection_sha256": spec.selection_digest(configuration, case),
            "executable": DESTINATION, "interpreter": INTERPRETER,
            "executables": native, "elf_dependencies": dependencies,
            "dependency_kind": "fixed_daemon_helpers_and_elf_linked_dependencies_only",
            "runtime_closure_verified": False, "daemon_execution_performed": False,
            "files": sorted(files, key=lambda row: row["destination"])}
        return verify_current(manifest, control)
    except (OSError, UnicodeError) as exc:
        raise IsolationUnavailable("Cannot inspect the fixed stock OpenSSH runtime") from exc
