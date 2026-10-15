"""Pinned NULL-only stock SSH recognition, with the accepted execution closure.

Only the fixed probe database differs from the native Nmap service profile.
A legacy validation view reuses its closed executable/library/path rules; real
hashes, snapshots and mounted-file checks always use the stock SSH bytes.
"""

from copy import deepcopy
import hashlib
import os

from . import network_tools_runtime as native
from . import stock_ssh_nmap_spec as spec
from .tool_runtime_common import sealed_snapshots

PROFILE = spec.PROFILE


def _probe_row(source, raw):
    return {"source": source, "destination": spec.PROBE_DESTINATION,
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _legacy_validation_view(value, *, tool_id=None):
    if (type(value) is not dict
            or set(value) != {"version", "profile", "tool_id", "executable", "interpreter", "files"}
            or value["profile"] != PROFILE or value["tool_id"] != native.NMAP_SERVICE
            or (tool_id is not None and tool_id != native.NMAP_SERVICE)
            or type(value["files"]) is not list or not 6 <= len(value["files"]) <= 48
            or len(native.encode(value)) > native.MAX_MANIFEST_BYTES):
        raise ValueError("invalid_stock_ssh_nmap_manifest")
    expected = _probe_row(spec.PROBE_SOURCE, spec.PROBES)
    probes = [item for item in value["files"]
              if type(item) is dict and item.get("destination") == spec.PROBE_DESTINATION]
    if (len(probes) != 1 or probes[0] != expected
            or any(type(probes[0][key]) is not type(item) for key, item in expected.items())):
        raise ValueError("invalid_stock_ssh_nmap_probe")
    projected = deepcopy(value)
    projected["profile"] = native.PROFILE
    projected["files"] = [
        _probe_row("compiled:nmap-service-probes", native.NMAP_SERVICE_PROBES)
        if item == expected else item for item in projected["files"]]
    native.validate_manifest(projected, tool_id=native.NMAP_SERVICE)
    # Enforce the actual byte count independently of the structural validation view.
    if sum(item["size"] for item in value["files"]) > native.MAX_RUNTIME_BYTES:
        raise ValueError("invalid_stock_ssh_nmap_runtime_size")
    return projected


def validate_manifest(value, *, tool_id=None):
    _legacy_validation_view(value, tool_id=tool_id)
    return deepcopy(value)


def from_native_manifest(value):
    value = deepcopy(native.validate_manifest(value, tool_id=native.NMAP_SERVICE))
    value["profile"] = PROFILE
    value["files"] = [_probe_row(spec.PROBE_SOURCE, spec.PROBES)
                      if row["destination"] == spec.PROBE_DESTINATION else row
                      for row in value["files"]]
    return validate_manifest(value)


def inspect_runtime(control):
    return from_native_manifest(native.inspect_tool_runtime(native.NMAP_SERVICE, control))


def manifest_digest(value):
    return hashlib.sha256(native.encode(validate_manifest(value))).hexdigest()


def runtime_files(manifest):
    return validate_manifest(manifest)["files"]


def runtime_source_mounts(manifest):
    return [(path, path) for path in sorted({row["source"] for row in runtime_files(manifest)
                                            if not row["source"].startswith("compiled:")})]


def snapshot(manifest, control):
    manifest = validate_manifest(manifest)
    compiled = spec.compiled_files()
    source, _, raw = compiled[0]
    return sealed_snapshots(manifest, source, raw, control,
                            additional_compiled=tuple((label, payload) for label, _, payload in compiled[1:]))


def verify_files(manifest):
    manifest = validate_manifest(manifest)
    for item in manifest["files"]:
        raw = native.read_runtime_file(item["destination"], native.NMAP_SERVICE)
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("stock_ssh_nmap_mounted_runtime_mismatch")
        if item["destination"] == manifest["executable"] and not raw.startswith(b"\x7fELF"):
            raise ValueError("stock_ssh_nmap_requires_elf")
        if "security.capability" in os.listxattr(item["destination"]):
            raise ValueError("stock_ssh_nmap_runtime_file_capabilities")


def landlock(manifest):
    # Landlock consumes only the unchanged destination/read/execute allowlist.
    # It never selects probe bytes; verify_files and snapshot use the real pins.
    from .network_tools_worker import landlock as native_landlock
    native_landlock(_legacy_validation_view(manifest))
