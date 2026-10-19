"""Fixed daemon launch recipe and independent readiness observations."""

import hashlib
import os
from pathlib import Path
import socket
import stat

from . import name_tls_role_spec as roles
from .name_tls_topology_spec import endpoints, encode

DAEMON_READY = b"NAME_TLS_DAEMON_READY "
SCRATCH_BYTES = 786432
BOUNDS = {"address_space_bytes": 268435456, "file_descriptors": 64,
          "cpu_seconds": 5, "core_bytes": 0, "scratch_bytes": SCRATCH_BYTES,
          "log_bytes": 8192, "threads": 1, "processes": 1}
MODULES = ("name_tls_daemon", "name_tls_daemon_worker", "name_tls_role_spec", "name_tls_transport",
           "name_tls_topology", "name_tls_topology_spec", "name_tls_topology_worker", "worker", "tool_worker_common",
           "name_tls_python_runtime", "name_tls_worker_common")
SOURCE_MODULES = (*MODULES, "recon_cockpit.__init__", "recon_cockpit.secure_agent.__init__")
ENVIRONMENT = {"LC_ALL": "C", "MALLOC_ARENA_MAX": "1", "OPENSSL_CONF": roles.DATA + "openssl.cnf", "TZ": "UTC0"}


def selected_role(operation):
    if type(operation) is not str or operation not in ("dns", "http", "tls"):
        raise ValueError("name_tls_daemon_operation")
    return "dns_daemon" if operation == "dns" else "web_daemon"


def argv_for(operation):
    selected_role(operation)
    if operation == "dns":
        return ("/tool/dnsmasq", "--no-daemon", "--log-facility=-", "--conf-file=" + roles.DATA + "dnsmasq.conf")
    return ("/tool/nginx", "-p", "/scratch/", "-c", roles.DATA + "nginx.conf")


def daemon_command(bootstrap, manifest, descriptors, selected, operation, info_fd, *, source_descriptors):
    from .isolation import _trusted_program
    manifest = roles.validate_manifest(manifest, role=selected_role(operation))
    if (type(selected) is not dict or selected.get("configuration") != manifest["configuration"]
            or selected.get("case") != manifest["case"] or len(descriptors) != len(manifest["files"])
            or any(type(fd) is not int or fd < 3 for fd in descriptors) or len(set(descriptors)) != len(descriptors)
            or type(info_fd) is not int or info_fd < 3 or info_fd in descriptors):
        raise ValueError("name_tls_daemon_command_identity")
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_SYS_ADMIN",
        "--die-with-parent", "--new-session", "--as-pid-1",
        "--info-fd", str(info_fd), "--clearenv", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
        "--ro-bind", stdlib, stdlib, "--perms", "0700", "--size", str(SCRATCH_BYTES), "--tmpfs", "/scratch"]
    forbidden = {"bwrap", "nsenter", "ip", "nginx", "dnsmasq", "dig", "openssl"}
    destinations = set(roles.destinations(manifest["role"]))
    for source, destination in files:
        if Path(destination).name not in forbidden and destination not in destinations:
            argv += ["--ro-bind", source, destination]
    from .name_tls_python_runtime import mount_sources
    mount_sources(argv, SOURCE_MODULES, source_descriptors)
    for item, descriptor in zip(manifest["files"], descriptors, strict=True):
        mode = "0555" if item["destination"] in (manifest["executable"], manifest["interpreter"]) else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(descriptor), item["destination"]]
    for name, value in ENVIRONMENT.items():
        argv += ["--setenv", name, value]
    # Only owned proc sysctls remain writable during pre-exec setup. Landlock
    # and capability removal seal them before the native image is released.
    return argv + ["--remount-ro", "/dev", "--remount-ro", "/", "/usr/bin/python3", "-I", "-S",
        "/app/recon_cockpit/secure_agent/name_tls_daemon_worker.py"]


def _read(process_directory, path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=process_directory)
    try:
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum:
            raise ValueError("name_tls_daemon_observation_limit")
        return raw
    finally:
        os.close(descriptor)


def _check_namespace_pins(process_directory, expected, namespace_fds):
    if type(expected) is not dict or set(expected) != {"user", "net", "mnt", "pid"} or len(namespace_fds) != 2:
        raise ValueError("name_tls_daemon_namespace_pins")
    for name, value in expected.items():
        if os.readlink("ns/" + name, dir_fd=process_directory) != value:
            raise ValueError("name_tls_daemon_namespace_changed")
    for name, descriptor in zip(("user", "net"), namespace_fds, strict=True):
        if (os.readlink("/proc/self/fd/" + str(descriptor)) != expected[name]
                or os.readlink("ns/" + name, dir_fd=process_directory) != expected[name]):
            raise ValueError("name_tls_daemon_namespace_changed")


def launcher_mapping(process_directory, expected_namespaces, namespace_fds):
    _check_namespace_pins(process_directory, expected_namespaces, namespace_fds)
    result = {"launcher_uid": os.getuid(), "launcher_gid": os.getgid()}
    if min(result.values()) <= 0:
        raise ValueError("name_tls_daemon_privileged_launcher")
    for name in ("uid", "gid"):
        rows = [list(map(int, line.split())) for line in _read(process_directory, name + "_map", 1024).decode("ascii").splitlines()]
        if rows != [[65534, result["launcher_" + name], 1]]:
            raise ValueError("name_tls_daemon_launcher_mapping")
        result[name + "_map"] = rows
    return result


def _socket_rows(raw, *, protocol):
    lines = raw.decode("ascii").splitlines()
    if not lines or lines[0].split()[:4] != ["sl", "local_address", "rem_address", "st"]:
        raise ValueError("name_tls_daemon_socket_table")
    rows = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10 or not fields[9].isdigit() or int(fields[9]) <= 0:
            raise ValueError("name_tls_daemon_socket_table")
        address, port = fields[1].split(":")
        if len(address) != 8 or len(port) != 4 or fields[2] != "00000000:0000" or fields[3] != ("0A" if protocol == "tcp" else "07"):
            raise ValueError("name_tls_daemon_unexpected_socket")
        rows.append({"endpoint": [socket.inet_ntoa(bytes.fromhex(address)[::-1]), int(port, 16)], "inode": int(fields[9])})
    return sorted(rows, key=encode)


def _limits(process_directory, *, tasks, file_bytes):
    observed = {}
    names = {"Max cpu time": (5, "seconds"), "Max core file size": (0, "bytes"),
             "Max file size": (file_bytes, "bytes"), "Max processes": (tasks, "processes"),
             "Max open files": (64, "files"), "Max address space": (268435456, "bytes")}
    for line in _read(process_directory, "limits", 8192).decode("ascii").splitlines()[1:]:
        for name, (maximum, unit) in names.items():
            if line.startswith(name + " "):
                values = line[len(name):].split()
                if (len(values) != 3 or values[2] != unit or not all(v.isdigit() for v in values[:2])
                        or not 0 <= int(values[0]) <= int(values[1]) <= maximum):
                    raise ValueError("name_tls_native_resource_limit_changed")
                observed[name] = [int(values[0]), int(values[1])]
    if set(observed) != set(names):
        raise ValueError("name_tls_native_resource_limit_missing")
    return observed


def _process_boundary(process_directory, *, tasks, file_bytes):
    statuses = {key: value.strip() for line in _read(process_directory, "status", 65536).decode("ascii").splitlines()
                if ":" in line for key, value in [line.split(":", 1)]}
    # proc reports IDs translated into the observing launcher's user namespace.
    # launcher_mapping independently establishes the child's inner 65534 map.
    if (statuses.get("NoNewPrivs") != "1" or any(int(statuses[key], 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or statuses.get("Uid", "").split() != [str(os.getuid())] * 4
            or statuses.get("Gid", "").split() != [str(os.getgid())] * 4
            or not statuses.get("NSpid", "").split() or statuses["NSpid"].split()[-1] != "1"
            or not statuses.get("Threads", "").isdigit() or not 1 <= int(statuses["Threads"]) <= tasks):
        raise ValueError("name_tls_native_process_boundary_changed")
    directory = os.open("task", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=process_directory)
    try:
        task_ids = os.listdir(directory)
    finally:
        os.close(directory)
    if not 1 <= len(task_ids) <= tasks or any(not name.isdigit() for name in task_ids):
        raise ValueError("name_tls_native_task_limit")
    directory = os.open("fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=process_directory)
    try:
        descriptors = os.listdir(directory)
    finally:
        os.close(directory)
    if len(descriptors) > 64 or any(not name.isdigit() for name in descriptors):
        raise ValueError("name_tls_native_descriptor_limit")
    return {"threads": int(statuses["Threads"]), "observed_tasks": len(task_ids),
            "file_descriptors": len(descriptors), "inner_pid": 1,
            "observed_uid": os.getuid(), "observed_gid": os.getgid(),
            "capabilities_zero": True, "no_new_privs": True,
            "resource_limits": _limits(process_directory, tasks=tasks, file_bytes=file_bytes)}


def client_ready(process_directory, expected_namespaces, namespace_fds, manifest, operation, *, waiting_image=None):
    """Observe the released client while its recorder still withholds replies.

    Only the exact pinned pre-exec Python inode is a pending state. An unknown
    executable or mapped file is a refusal, never a readiness retry.
    """
    if operation not in ("dns", "tls"):
        raise ValueError("name_tls_native_client_operation")
    manifest = roles.validate_manifest(manifest, role=operation + "_client")
    _check_namespace_pins(process_directory, expected_namespaces, namespace_fds)
    descriptor = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=process_directory)
    try:
        before = os.fstat(descriptor)
        if waiting_image is not None:
            if (type(waiting_image) is not tuple or len(waiting_image) != 2
                    or any(type(number) is not int or number < 0 for number in waiting_image)):
                raise ValueError("name_tls_native_waiting_image")
            if (before.st_dev, before.st_ino) == waiting_image:
                return False
        image = next(row for row in manifest["files"] if row["destination"] == manifest["executable"])
        raw = bytearray()
        while len(raw) <= image["size"]:
            part = os.read(descriptor, min(65536, image["size"] + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (not stat.S_ISREG(before.st_mode) or any(getattr(before, field) != getattr(after, field) for field in fields)
            or before.st_size != image["size"] or len(raw) != image["size"]
            or hashlib.sha256(raw).hexdigest() != image["sha256"]):
        raise ValueError("name_tls_native_client_image_changed")
    allowed = {}
    for row in manifest["files"]:
        if row["destination"] in roles.COMPILED[manifest["role"]]:
            continue
        observed = os.stat("root" + row["destination"], dir_fd=process_directory)
        allowed[(os.major(observed.st_dev), os.minor(observed.st_dev), observed.st_ino)] = row["destination"]
    if allowed.get((os.major(before.st_dev), os.minor(before.st_dev), before.st_ino)) != manifest["executable"]:
        raise ValueError("name_tls_native_client_inode_changed")
    mapped = set()
    for line in _read(process_directory, "maps", 262144).decode("ascii").splitlines():
        values = line.split(maxsplit=5)
        if len(values) < 5 or not values[4].isdigit():
            raise ValueError("name_tls_native_client_maps")
        if not int(values[4]):
            continue
        device = tuple(int(number, 16) for number in values[3].split(":"))
        destination = allowed.get((*device, int(values[4])))
        if destination is None:
            raise ValueError("name_tls_native_client_unreviewed_image")
        mapped.add(destination)
    if {manifest["executable"], manifest["interpreter"]} - mapped:
        # The loader can still be mapping the reviewed ELF closure immediately
        # after exec. Missing images are pending; any extra image was refused.
        return False
    boundary = _process_boundary(process_directory, tasks=16 if operation == "dns" else 1, file_bytes=0)
    return {"ready": True, "native_executable": manifest["executable"], "native_sha256": image["sha256"],
            "mapped_images": sorted(mapped), "runtime_digest": roles.manifest_digest(manifest),
            "namespaces": dict(expected_namespaces), **boundary}


def validate_client_ready(value, manifest, namespaces, mapping):
    """Replay the retained point-in-time client receipt without filesystem reads."""
    manifest = roles.validate_manifest(manifest)
    if manifest["role"] not in ("dns_client", "tls_client"):
        raise ValueError("name_tls_native_client_role")
    tasks = 16 if manifest["role"] == "dns_client" else 1
    return _validate_image_receipt(value, manifest, namespaces, mapping, tasks=tasks, file_bytes=0)


def _validate_image_receipt(value, manifest, namespaces, mapping, *, tasks, file_bytes):
    fields = {"ready", "native_executable", "native_sha256", "mapped_images", "runtime_digest", "namespaces",
              "threads", "observed_tasks", "file_descriptors", "inner_pid", "observed_uid", "observed_gid",
              "capabilities_zero", "no_new_privs", "resource_limits"}
    image = next(row for row in manifest["files"] if row["destination"] == manifest["executable"])
    allowed = {row["destination"] for row in manifest["files"]
               if row["destination"] not in roles.COMPILED[manifest["role"]]}
    if (type(value) is not dict or set(value) != fields or value["ready"] is not True
            or value["native_executable"] != manifest["executable"] or value["native_sha256"] != image["sha256"]
            or value["runtime_digest"] != roles.manifest_digest(manifest) or value["namespaces"] != namespaces
            or type(value["mapped_images"]) is not list or any(type(path) is not str for path in value["mapped_images"])
            or sorted(set(value["mapped_images"])) != value["mapped_images"]
            or set(value["mapped_images"]) - allowed
            or {manifest["executable"], manifest["interpreter"]} - set(value["mapped_images"])
            or any(type(value[key]) is not int or not 1 <= value[key] <= tasks for key in ("threads", "observed_tasks"))
            or type(value["file_descriptors"]) is not int or not 3 <= value["file_descriptors"] <= 64
            or type(value["inner_pid"]) is not int or value["inner_pid"] != 1
            or value["capabilities_zero"] is not True or value["no_new_privs"] is not True
            or any(type(value["observed_" + key]) is not int or value["observed_" + key] != mapping["launcher_" + key]
                   for key in ("uid", "gid"))):
        raise ValueError("name_tls_native_client_receipt_changed")
    caps = {"Max cpu time": 5, "Max core file size": 0, "Max file size": file_bytes,
            "Max processes": tasks, "Max open files": 64, "Max address space": 268435456}
    limits = value["resource_limits"]
    if (type(limits) is not dict or set(limits) != set(caps) or any(
            type(pair) is not list or len(pair) != 2 or any(type(number) is not int for number in pair)
            or not 0 <= pair[0] <= pair[1] <= caps[name] for name, pair in limits.items())):
        raise ValueError("name_tls_native_client_receipt_limits")
    return value


def validate_daemon_ready(value, manifest, namespaces, mapping, operation):
    """Validate an observed daemon receipt against its sealed native partition."""
    manifest = roles.validate_manifest(manifest, role=selected_role(operation))
    extras = {"tcp_listeners", "udp_listeners", "observed_route_discovery_sockets"}
    if type(value) is not dict or not extras <= set(value):
        raise ValueError("name_tls_daemon_receipt_shape")
    _validate_image_receipt({key: item for key, item in value.items() if key not in extras},
                           manifest, namespaces, mapping, tasks=1, file_bytes=8192)
    expected = endpoints(manifest["configuration"])
    expected_tcp = [list(expected["dns"])] if operation == "dns" else [list(expected[op]) for op in ("http", "tls")]
    expected_udp = [list(expected["dns"])] if operation == "dns" else []
    inodes = []
    for name, expected_rows in (("tcp_listeners", expected_tcp), ("udp_listeners", expected_udp)):
        rows = value[name]
        if (type(rows) is not list or any(type(row) is not dict or set(row) != {"endpoint", "inode"}
                or type(row["endpoint"]) is not list or len(row["endpoint"]) != 2
                or type(row["endpoint"][0]) is not str or type(row["endpoint"][1]) is not int
                or type(row["inode"]) is not int or row["inode"] <= 0 for row in rows)
                or sorted(row["endpoint"] for row in rows) != sorted(expected_rows)):
            raise ValueError("name_tls_daemon_receipt_listeners")
        inodes.extend(row["inode"] for row in rows)
    if (len(inodes) != len(set(inodes)) or type(value["observed_route_discovery_sockets"]) is not int
            or not 0 <= value["observed_route_discovery_sockets"] <= (2 if operation == "dns" else 0)):
        raise ValueError("name_tls_daemon_receipt_sockets")
    return value


def listener_ready(process_directory, expected_namespaces, namespace_fds, manifest, operation):
    """Observe a pinned native image and listeners without opening a connection.

    This is a point-in-time image/map observation, not a full syscall trace.
    The owner-controlled deadline and one-use socket grant remain authoritative.
    """
    manifest = roles.validate_manifest(manifest, role=selected_role(operation))
    _check_namespace_pins(process_directory, expected_namespaces, namespace_fds)
    expected = endpoints(manifest["configuration"])
    tcp = _socket_rows(_read(process_directory, "net/tcp", 8192), protocol="tcp")
    udp = _socket_rows(_read(process_directory, "net/udp", 8192), protocol="udp")
    want_tcp = [list(expected["dns"])] if operation == "dns" else [list(expected[op]) for op in ("http", "tls")]
    want_udp = [list(expected["dns"])] if operation == "dns" else []
    actual_tcp, actual_udp = [row["endpoint"] for row in tcp], [row["endpoint"] for row in udp]
    if any(endpoint not in want_tcp for endpoint in actual_tcp) or any(endpoint not in want_udp for endpoint in actual_udp):
        raise ValueError("name_tls_daemon_unexpected_listener")
    if sorted(actual_tcp) != sorted(want_tcp) or sorted(actual_udp) != sorted(want_udp):
        return False
    descriptor = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=process_directory)
    try:
        info = os.fstat(descriptor)
        raw = os.read(descriptor, roles.MAX_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    image = next(row for row in manifest["files"] if row["destination"] == manifest["executable"])
    if not stat.S_ISREG(info.st_mode) or len(raw) != image["size"] or hashlib.sha256(raw).hexdigest() != image["sha256"]:
        raise ValueError("name_tls_daemon_native_image_changed")
    statuses = {key: value.strip() for line in _read(process_directory, "status", 65536).decode("ascii").splitlines()
                if ":" in line for key, value in [line.split(":", 1)]}
    if statuses.get("Threads") != "1" or statuses.get("NoNewPrivs") != "1" or any(int(statuses[key], 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise ValueError("name_tls_daemon_native_boundary_changed")
    allowed = {}
    for row in manifest["files"]:
        if row["destination"] in roles.COMPILED[manifest["role"]]:
            continue
        observed = os.stat("root" + row["destination"], dir_fd=process_directory)
        allowed[(os.major(observed.st_dev), os.minor(observed.st_dev), observed.st_ino)] = row["destination"]
    if allowed.get((os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)) != manifest["executable"]:
        raise ValueError("name_tls_daemon_native_inode_changed")
    mapped = set()
    for line in _read(process_directory, "maps", 262144).decode("ascii").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5 or not fields[4].isdigit():
            raise ValueError("name_tls_daemon_native_maps")
        if int(fields[4]) == 0:
            continue
        device = tuple(int(number, 16) for number in fields[3].split(":"))
        destination = allowed.get((*device, int(fields[4])))
        if destination is None:
            raise ValueError("name_tls_daemon_unreviewed_mapped_image")
        mapped.add(destination)
    if {manifest["executable"], manifest["interpreter"]} - mapped:
        raise ValueError("name_tls_daemon_native_mapping_missing")
    fd_directory = os.open("fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=process_directory)
    try:
        names = os.listdir(fd_directory)
        if len(names) > BOUNDS["file_descriptors"]:
            raise ValueError("name_tls_daemon_native_fd_limit")
        sockets = set()
        for name in names:
            link = os.readlink(name, dir_fd=fd_directory)
            if link.startswith("socket:[") and link.endswith("]"):
                sockets.add(int(link[8:-1]))
    finally:
        os.close(fd_directory)
    netlink = []
    for line in _read(process_directory, "net/netlink", 8192).decode("ascii").splitlines()[1:]:
        row = line.split()
        if len(row) < 10:
            raise ValueError("name_tls_daemon_netlink_table")
        if int(row[-1]) in sockets:
            if row[1] != "0":
                raise ValueError("name_tls_daemon_netlink_protocol")
            netlink.append(int(row[-1]))
    if len(netlink) > (2 if operation == "dns" else 0):
        raise ValueError("name_tls_daemon_discovery_socket_limit")
    boundary = _process_boundary(process_directory, tasks=1, file_bytes=8192)
    return {"ready": True, "native_executable": manifest["executable"], "native_sha256": image["sha256"],
            "mapped_images": sorted(mapped), "tcp_listeners": tcp, "udp_listeners": udp,
            "observed_route_discovery_sockets": len(netlink),
            "runtime_digest": roles.manifest_digest(manifest), "namespaces": dict(expected_namespaces), **boundary}
