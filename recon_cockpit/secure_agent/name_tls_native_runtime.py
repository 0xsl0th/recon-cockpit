"""Host-side extraction of exact native role manifests from accepted preparation."""

from copy import deepcopy
import hashlib

from . import name_tls_runtime as preparation, name_tls_spec as spec, name_tls_role_spec as roles
from . import name_tls_python_runtime as python_runtime

PROFILE = "owned-name-tls-native-runtime-v1"
validate_manifest = roles.validate_manifest
manifest_digest = roles.manifest_digest


def partition(preflight_manifest, role):
    roles.validate_role(role)
    prepared = preparation.validate_manifest(preflight_manifest)
    selected = set(roles.destinations(role))
    value = {"schema_version": "1", "profile": roles.PROFILE, "role": role,
        "configuration": prepared["configuration"], "case": prepared["case"],
        "selection_sha256": prepared["selection_sha256"], "preflight_sha256": preparation.manifest_digest(prepared),
        "executable": roles.PROGRAMS[role][0], "interpreter": roles.INTERPRETER,
        "files": [row for row in prepared["files"] if row["destination"] in selected]}
    return roles.validate_manifest(value)


def partitions(preflight_manifest, *, python_sources):
    prepared = preparation.validate_manifest(preflight_manifest)
    return {"profile": PROFILE, "preflight": prepared, "python_sources": python_runtime.validate_sources(python_sources),
            "roles": {role: partition(prepared, role) for role in roles.ROLES}}


def validate_runtime(value):
    if (type(value) is not dict or set(value) != {"profile", "preflight", "roles", "python_sources"}
            or value["profile"] != PROFILE or type(value["roles"]) is not dict or set(value["roles"]) != set(roles.ROLES)):
        raise ValueError("name_tls_native_runtime_shape")
    expected = partitions(value["preflight"], python_sources=value["python_sources"])
    if roles.encode(expected) != roles.encode(value):
        raise ValueError("name_tls_native_runtime_partition_changed")
    return deepcopy(expected)


def runtime_digest(value):
    return hashlib.sha256(roles.encode(validate_runtime(value))).hexdigest()


def compiled_snapshots(manifest):
    selected = roles.validate_manifest(manifest)
    files = {destination: (source, raw) for source, destination, raw in
             spec.compiled_files(selected["configuration"], selected["case"])}
    result = []
    for row in selected["files"]:
        if row["destination"] not in files:
            continue
        source, raw = files[row["destination"]]
        if source != row["source"] or len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("name_tls_native_compiled_file_changed")
        result.append((source, raw))
    return tuple(result)


def inspect_runtime(configuration, case, control):
    prepared = preparation.inspect_runtime(configuration, case, control)
    return partitions(prepared, python_sources=python_runtime.inspect_sources(control))


def verify_current(value, control):
    checked = validate_runtime(value)
    preparation.verify_current(checked["preflight"], control)
    python_runtime.verify_sources(checked["python_sources"], tuple(python_runtime.DESTINATIONS), control)
    return checked
