"""Exact reviewed Python source pins and sealed staging, without fixture imports.

This pins repository source files. The separately inspected Python interpreter,
stdlib and linked bootstrap are not described as a full syscall/open trace.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from copy import deepcopy

PROFILE = "owned-name-tls-python-sources-v1"
MAX_FILE_BYTES = 131072
MAX_TOTAL_BYTES = 4194304
MAX_MANIFEST_BYTES = 16384
MODULES = (
    "name_tls", "name_tls_backend", "name_tls_client", "name_tls_client_worker", "name_tls_context",
    "name_tls_contract", "name_tls_daemon", "name_tls_daemon_worker", "name_tls_evidence", "name_tls_execution",
    "name_tls_frontend_worker", "name_tls_lab", "name_tls_ledger", "name_tls_native_runtime", "name_tls_parser",
    "name_tls_parser_runtime", "name_tls_parser_worker", "name_tls_probes", "name_tls_public", "name_tls_python_runtime",
    "name_tls_recorder", "name_tls_role_spec", "name_tls_runtime", "name_tls_services", "name_tls_spec",
    "name_tls_topology", "name_tls_topology_spec", "name_tls_topology_worker", "name_tls_transport",
    "name_tls_wire", "name_tls_worker_common", "worker", "tool_worker_common", "models", "tool_parameters",
    "tool_adapters", "session_limits", "tls_posture_hello", "planner_worker", "http_headers_parser",
)
PACKAGE_FILES = {"recon_cockpit.__init__": "/app/recon_cockpit/__init__.py",
                 "recon_cockpit.secure_agent.__init__": "/app/recon_cockpit/secure_agent/__init__.py"}
DESTINATIONS = {**{module: "/app/recon_cockpit/secure_agent/" + module + ".py" for module in MODULES}, **PACKAGE_FILES}
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def validate_sources(value):
    if (type(value) is not dict or set(value) != {"profile", "files"} or value["profile"] != PROFILE
            or type(value["files"]) is not list or len(value["files"]) != len(DESTINATIONS)):
        raise ValueError("name_tls_python_sources_shape")
    seen, total = set(), 0
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"module", "destination", "size", "sha256"}
                or type(row["module"]) is not str or row["module"] not in DESTINATIONS
                or row["module"] in seen or row["destination"] != DESTINATIONS[row["module"]]
                or type(row["size"]) is not int or not 0 < row["size"] <= MAX_FILE_BYTES
                or type(row["sha256"]) is not str or _DIGEST.fullmatch(row["sha256"]) is None):
            raise ValueError("name_tls_python_source_file")
        seen.add(row["module"])
        total += row["size"]
    if (seen != set(DESTINATIONS) or total > MAX_TOTAL_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["module"])
            or len(encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("name_tls_python_source_inventory")
    return deepcopy(value)


def source_digest(value):
    return hashlib.sha256(encode(validate_sources(value))).hexdigest()


def source_path(module):
    if type(module) is not str or module not in DESTINATIONS:
        raise ValueError("name_tls_python_source_module")
    directory = Path(__file__).parent
    # Both sandbox package levels use the reviewed inert secure-agent package
    # initializer. The application's outer initializer imports unrelated models.
    if module in PACKAGE_FILES:
        return directory / "__init__.py"
    return directory / (module + ".py")


def _read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_FILE_BYTES:
            raise ValueError("name_tls_python_source_file_type")
        raw = bytearray()
        while len(raw) <= MAX_FILE_BYTES:
            part = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if stamp(os.fstat(descriptor)) != stamp(before) or len(raw) != before.st_size:
            raise ValueError("name_tls_python_source_changed_during_read")
        return bytes(raw)
    finally:
        os.close(descriptor)


def inspect_sources(control):
    result = []
    for module, destination in sorted(DESTINATIONS.items()):
        control.check()
        raw = _read(source_path(module))
        result.append({"module": module, "destination": destination, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    control.check()
    return validate_sources({"profile": PROFILE, "files": result})


def verify_sources(value, modules, control=None):
    value = validate_sources(value)
    chosen = checked_modules(modules)
    for row in value["files"]:
        if row["module"] not in chosen:
            continue
        if control is not None:
            control.check()
        raw = _read(source_path(row["module"]))
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("name_tls_python_source_pin_changed")
    return value


def checked_modules(modules):
    if (type(modules) not in (tuple, list) or not modules or len(modules) > len(DESTINATIONS)
            or any(type(module) is not str or module not in DESTINATIONS for module in modules)
            or len(set(modules)) != len(modules)):
        raise ValueError("name_tls_python_source_selection")
    return tuple(modules)


def snapshot_sources(bundle, modules, control):
    """Stage chosen reviewed source bytes, closing every FD on a partial failure."""
    import fcntl
    if type(bundle) is not dict or "python_sources" not in bundle:
        raise ValueError("name_tls_python_runtime_missing")
    manifest = validate_sources(bundle["python_sources"])
    chosen = checked_modules(modules)
    result = {}
    try:
        for row in manifest["files"]:
            if row["module"] not in chosen:
                continue
            control.check()
            raw = _read(source_path(row["module"]))
            if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise ValueError("name_tls_python_source_pin_changed")
            descriptor = os.memfd_create("recon-name-tls-source", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            result[row["destination"]] = descriptor
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise ValueError("name_tls_python_snapshot_short_write")
                offset += written
            os.lseek(descriptor, 0, os.SEEK_SET)
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        control.check()
        return result
    except BaseException:
        for descriptor in result.values():
            os.close(descriptor)
        raise


def mount_sources(argv, modules, descriptors):
    """Append exact sealed source mounts; no fallback to mutable source binds."""
    chosen = checked_modules(modules)
    expected = {DESTINATIONS[module] for module in chosen}
    if (type(descriptors) is not dict or set(descriptors) != expected
            or any(type(fd) is not int or fd < 3 for fd in descriptors.values())
            or len(set(descriptors.values())) != len(descriptors)):
        raise ValueError("name_tls_python_snapshot_inventory")
    import fcntl
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    for destination, descriptor in sorted(descriptors.items()):
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
            raise ValueError("name_tls_python_snapshot_unsealed")
        argv += ["--perms", "0444", "--ro-bind-data", str(descriptor), destination]
    return argv
