"""Read-only pins for one finite Apache configuration; never a launcher.

The selected loadable modules and their linked ELF dependencies are inspected
explicitly. These pins establish neither daemon startup nor a complete runtime
closure: module loading, confinement and actual compatibility remain unverified.
"""

from copy import deepcopy
import hashlib
from pathlib import Path
import re
import struct
import sys

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _runtime_probe, _trusted_program
from . import stock_apache_spec as spec
from . import stock_http_runtime as shared


PROFILE = "stock-apache-static-preflight-v1"
EXECUTABLE = "/usr/sbin/apache2"
DESTINATION = "/tool/apache2"
INTERPRETER = shared.INTERPRETER
LIBRARY_ROOT = shared.LIBRARY_ROOT
LIBRARIES = (
    "libapr-1.so.0", "libaprutil-1.so.0", "libc.so.6", "libcrypt.so.1",
    "libexpat.so.1", "libpcre2-8.so.0", "libuuid.so.1",
)
DEPENDENCIES = frozenset((INTERPRETER, *(LIBRARY_ROOT + name for name in LIBRARIES)))
MODULE_DEPENDENCIES = frozenset((INTERPRETER, LIBRARY_ROOT + "libc.so.6"))
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 16384
MAX_FILES = 24
MAX_PROBE_BYTES = 32768
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_LIBRARY_SOURCE = re.compile(r"/usr/lib/x86_64-linux-gnu/[A-Za-z0-9_+-]+\.so(?:\.[0-9]+)+\Z")


def _control(control):
    if type(control) is not ExecutionControl:
        raise ValueError("invalid_stock_apache_inspection_control")
    control.check()


def _modules():
    return [{"name": name, "source": source, "destination": destination}
            for name, source, destination in spec.APACHE_MODULES]


def _native_files():
    return {DESTINATION: EXECUTABLE, **{destination: source
        for _, source, destination in spec.APACHE_MODULES}}


def _elf_dependencies():
    return {destination: sorted(DEPENDENCIES if destination == DESTINATION else MODULE_DEPENDENCIES)
            for destination in sorted(_native_files())}


def _source_allowed(source, destination):
    if type(source) is not str or type(destination) is not str:
        return False
    native = _native_files()
    if destination in native:
        return source == native[destination]
    if destination == INTERPRETER:
        return source == LIBRARY_ROOT + "ld-linux-x86-64.so.2"
    if destination not in DEPENDENCIES or _LIBRARY_SOURCE.fullmatch(source) is None:
        return False
    return source == destination or bool(re.fullmatch(re.escape(destination) + r"(?:\.[0-9]+)+", source))


def _compiled(configuration, case):
    # Reject selections before any filesystem access or metadata process.
    spec.selection(configuration, case)
    rows = tuple(spec.compiled_files(configuration, case))
    result = {}
    for source, destination, raw in rows:
        if (type(source) is not str or not source.startswith("compiled:")
                or type(destination) is not str or not destination.startswith("/")
                or any(part in ("", ".", "..") for part in destination.split("/")[1:])
                or type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES
                or destination in result or destination in DEPENDENCIES | set(_native_files())):
            raise ValueError("invalid_stock_apache_compiled_files")
        result[destination] = (source, raw)
    if not result or len(rows) != len({source for source, _, _ in rows}):
        raise ValueError("invalid_stock_apache_compiled_files")
    return result


def validate_manifest(value):
    """Detach the finite preparation identity; no field can claim readiness."""
    fields = {"schema_version", "profile", "configuration", "case", "selection_sha256",
        "executable", "interpreter", "modules", "elf_dependencies", "dependency_kind",
        "runtime_closure_verified", "daemon_execution_performed", "files"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("invalid_stock_apache_manifest")
    compiled = _compiled(value["configuration"], value["case"])
    if (value["schema_version"] != "1" or value["profile"] != PROFILE
            or value["selection_sha256"] != spec.selection_digest(value["configuration"], value["case"])
            or value["executable"] != DESTINATION or value["interpreter"] != INTERPRETER
            or value["modules"] != _modules() or value["elf_dependencies"] != _elf_dependencies()
            or value["dependency_kind"] != "fixed_modules_and_elf_linked_dependencies_only"
            or value["runtime_closure_verified"] is not False
            or value["daemon_execution_performed"] is not False
            or type(value["files"]) is not list
            or len(value["files"]) != len(_native_files()) + len(DEPENDENCIES) + len(compiled)
            or len(value["files"]) > MAX_FILES):
        raise ValueError("invalid_stock_apache_manifest")
    destinations, sources, total = set(), set(), 0
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"source", "destination", "size", "sha256"}
                or type(row["source"]) is not str or type(row["destination"]) is not str
                or type(row["size"]) is not int or not 1 <= row["size"] <= MAX_FILE_BYTES
                or type(row["sha256"]) is not str or _DIGEST.fullmatch(row["sha256"]) is None):
            raise ValueError("invalid_stock_apache_manifest_file")
        source, destination = row["source"], row["destination"]
        if destination in compiled:
            expected, raw = compiled[destination]
            allowed = source == expected and row["size"] == len(raw) and row["sha256"] == hashlib.sha256(raw).hexdigest()
        else:
            allowed = _source_allowed(source, destination)
        if not allowed or destination in destinations or source in sources:
            raise ValueError("invalid_stock_apache_manifest_path")
        destinations.add(destination)
        sources.add(source)
        total += row["size"]
    if (destinations != DEPENDENCIES | set(_native_files()) | set(compiled)
            or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])
            or len(shared._encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_stock_apache_manifest_closure")
    return deepcopy(value)


def manifest_digest(value):
    return hashlib.sha256(shared._encode(validate_manifest(value))).hexdigest()


def _read_file(source, control):
    # Reuse the accepted bounded regular-file reader: no final symlink/FIFO,
    # no group/world writes, and stable inode/mode/size/timestamps across read.
    try:
        return shared._read_file(source, control)
    except IsolationUnavailable as exc:
        raise IsolationUnavailable("Unsupported or changed stock Apache runtime file") from exc


def _elf(raw, *, executable=False):
    try:
        shared._elf(raw, executable=executable)
    except IsolationUnavailable as exc:
        raise IsolationUnavailable("Unsupported stock Apache x86-64 ELF runtime") from exc
    if not executable and struct.unpack_from("<H", raw, 16)[0] != 3:
        raise IsolationUnavailable("Stock Apache modules and libraries must be shared ELF objects")


def _dependencies(raw, expected):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROBE_BYTES:
        raise IsolationUnavailable("Invalid stock Apache dependency listing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise IsolationUnavailable("Invalid stock Apache dependency listing") from exc
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
            raise IsolationUnavailable("Unsupported stock Apache dependency listing")
        soname, path = match.groups()
        if (path not in expected or path in paths
                or (soname is not None and soname != Path(path).name)
                or (path != INTERPRETER and soname is None)):
            raise IsolationUnavailable("Unreviewed stock Apache dependency")
        paths.add(path)
    if paths != expected or vdso != 1:
        raise IsolationUnavailable("Stock Apache dependencies differ from the reviewed finite closure")
    return sorted(paths)


def verify_current(manifest, control):
    """Recheck pins without probing or executing any capture-supplied path."""
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
                    raise IsolationUnavailable("Stock Apache runtime path changed")
                raw = _read_file(row["source"], control)
                _elf(raw, executable=row["destination"] == DESTINATION)
            if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise IsolationUnavailable("Stock Apache runtime differs from its pinned manifest")
    except OSError as exc:
        raise IsolationUnavailable("Cannot read the pinned stock Apache runtime") from exc
    control.check()
    return value


def inspect_runtime(configuration, case, control):
    """Read exact binaries; run only fixed ldd metadata probes, never Apache.

    Configuration parsing, module initialization, daemon startup and isolation
    require the later execution gate and are not exercised by this inspection.
    """
    compiled = _compiled(configuration, case)
    _control(control)
    if sys.platform != "linux":
        raise IsolationUnavailable("Stock Apache inspection requires the reviewed Linux runtime")
    native = _native_files()
    try:
        files = []
        for destination in sorted(DEPENDENCIES | set(native)):
            control.check()
            current = native.get(destination, destination)
            source = str(Path(current).resolve(strict=True))
            if not _source_allowed(source, destination):
                raise IsolationUnavailable("Unreviewed stock Apache runtime location")
            raw = _read_file(source, control)
            _elf(raw, executable=destination == DESTINATION)
            files.append({"source": source, "destination": destination,
                          "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        if sum(row["size"] for row in files) > MAX_RUNTIME_BYTES:
            raise IsolationUnavailable("Stock Apache runtime exceeds its aggregate bound")
        # Read every selected native file before metadata probes and recheck all
        # pins afterwards. Each DSO has its own finite dependency expectation.
        probe = _trusted_program("ldd")
        if probe != "/usr/bin/ldd":
            raise IsolationUnavailable("Unreviewed stock Apache dependency inspector")
        for destination, source in sorted(native.items()):
            control.check()
            expected = DEPENDENCIES if destination == DESTINATION else MODULE_DEPENDENCIES
            _dependencies(_runtime_probe([probe, source], min(3, control.remaining()),
                MAX_PROBE_BYTES, control), expected)
        for destination, (source, raw) in compiled.items():
            files.append({"source": source, "destination": destination, "size": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
        manifest = {"schema_version": "1", "profile": PROFILE,
            "configuration": configuration, "case": case,
            "selection_sha256": spec.selection_digest(configuration, case),
            "executable": DESTINATION, "interpreter": INTERPRETER,
            "modules": _modules(), "elf_dependencies": _elf_dependencies(),
            "dependency_kind": "fixed_modules_and_elf_linked_dependencies_only",
            "runtime_closure_verified": False, "daemon_execution_performed": False,
            "files": sorted(files, key=lambda row: row["destination"])}
        return verify_current(manifest, control)
    except (OSError, UnicodeError) as exc:
        raise IsolationUnavailable("Cannot inspect the fixed stock Apache runtime") from exc
