"""Retained native observations are bound to sealed partitions and real limits."""

from copy import deepcopy

import pytest

from recon_cockpit.secure_agent import name_tls_daemon as daemon
from recon_cockpit.secure_agent import name_tls_native_runtime as native
from recon_cockpit.secure_agent import name_tls_role_spec as roles
from test_name_tls_native_runtime import prepared


def receipt(role):
    manifest = native.partition(prepared(), role)
    tasks = 16 if role == "dns_client" else 1
    cap = 8192 if role.endswith("daemon") else 0
    limits = {"Max cpu time": 5, "Max core file size": 0, "Max file size": cap,
              "Max processes": tasks, "Max open files": 64, "Max address space": 268435456}
    namespaces = {key: key + ":[123]" for key in ("user", "net", "mnt", "pid")}
    mapping = {"launcher_uid": 1000, "launcher_gid": 1000}
    image = next(row for row in manifest["files"] if row["destination"] == manifest["executable"])
    value = {"ready": True, "native_executable": manifest["executable"], "native_sha256": image["sha256"],
             "runtime_digest": roles.manifest_digest(manifest), "namespaces": namespaces,
             "mapped_images": sorted([manifest["executable"], manifest["interpreter"]]),
             "threads": tasks, "observed_tasks": tasks, "file_descriptors": 4, "inner_pid": 1,
             "observed_uid": 1000, "observed_gid": 1000, "capabilities_zero": True, "no_new_privs": True,
             "resource_limits": {key: [count, count] for key, count in limits.items()}}
    return value, manifest, namespaces, mapping


@pytest.mark.parametrize("role", ("dns_client", "tls_client"))
def test_client_image_receipt_matches_role_partition_and_observer_mapping(role):
    value, *arguments = receipt(role)
    assert daemon.validate_client_ready(value, *arguments) == value


@pytest.mark.parametrize("field,replacement", (
    ("ready", 1), ("native_executable", "/usr/bin/python3"), ("native_sha256", "b" * 64),
    ("runtime_digest", "b" * 64), ("namespaces", {}), ("mapped_images", ["/tool/dig"]),
    ("threads", 17), ("threads", True), ("observed_tasks", 0), ("file_descriptors", 65),
    ("inner_pid", 2), ("observed_uid", 65534), ("observed_gid", True),
    ("capabilities_zero", False), ("no_new_privs", 1), ("resource_limits", {})))
def test_client_receipt_cannot_substitute_runtime_identity_or_boundary(field, replacement):
    value, *arguments = receipt("dns_client")
    value[field] = replacement
    with pytest.raises(ValueError):
        daemon.validate_client_ready(value, *arguments)


@pytest.mark.parametrize("limit", ("Max cpu time", "Max core file size", "Max file size", "Max processes",
                                   "Max open files", "Max address space"))
def test_retained_client_soft_and_hard_resource_caps_must_both_hold(limit):
    value, *arguments = receipt("tls_client")
    value["resource_limits"][limit][1] += 1
    with pytest.raises(ValueError, match="limits"):
        daemon.validate_client_ready(value, *arguments)


@pytest.mark.parametrize("operation", ("dns", "http", "tls"))
def test_daemon_native_receipt_exact_listener_inventory(operation):
    value, manifest, namespaces, mapping = receipt(daemon.selected_role(operation))
    endpoints = daemon.endpoints("A")
    selected = ["dns"] if operation == "dns" else ["http", "tls"]
    value.update(tcp_listeners=[{"endpoint": list(endpoints[name]), "inode": 10 + index}
                               for index, name in enumerate(selected)],
                 udp_listeners=[{"endpoint": list(endpoints["dns"]), "inode": 30}] if operation == "dns" else [],
                 observed_route_discovery_sockets=2 if operation == "dns" else 0,
                 entropy_device=dict(daemon.ENTROPY_DEVICE) if operation == "dns" else None)
    assert daemon.validate_daemon_ready(value, manifest, namespaces, mapping, operation) == value
    altered = deepcopy(value)
    altered["tcp_listeners"][0]["endpoint"][1] += 1
    with pytest.raises(ValueError, match="listeners"):
        daemon.validate_daemon_ready(altered, manifest, namespaces, mapping, operation)
    altered = deepcopy(value)
    altered["entropy_device"] = None if operation == "dns" else dict(daemon.ENTROPY_DEVICE)
    with pytest.raises(ValueError, match="entropy_device"):
        daemon.validate_daemon_ready(altered, manifest, namespaces, mapping, operation)


def test_native_limits_are_observed_from_bounded_proc_records(monkeypatch):
    raw = b"Limit                     Soft Limit           Hard Limit           Units\n"
    names = {"Max cpu time": (5, "seconds"), "Max core file size": (0, "bytes"),
             "Max file size": (0, "bytes"), "Max processes": (16, "processes"),
             "Max open files": (64, "files"), "Max address space": (268435456, "bytes")}
    raw += b"".join(f"{key}  {count}  {count}  {unit}\n".encode() for key, (count, unit) in names.items())
    monkeypatch.setattr(daemon, "_read", lambda *_: raw)
    assert daemon._limits(3, tasks=16, file_bytes=0)["Max processes"] == [16, 16]
    with pytest.raises(ValueError, match="limit_changed"):
        daemon._limits(3, tasks=1, file_bytes=0)
