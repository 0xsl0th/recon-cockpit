"""Key-free bootstrap descriptor and namespace identity checks."""

import errno
import fcntl
import os
import re
import socket
import stat
import sys

from .name_tls_topology_spec import validate_namespace_identity


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        number = int(name)
        if number <= 2:
            continue
        try:
            os.fstat(number)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        raise ValueError("name_tls_worker_inherited_descriptor")
    return True


def close_import_descriptor(*, entry_verified):
    """Close only libffi's verified read-only descriptor opened after entry.

    The initial inventory predates all ctypes imports. The distribution libffi
    retains a descriptor to its mapped image for optional callback trampolines;
    this worker does not construct callbacks and needs no retained image FD.
    """
    if not entry_verified:
        raise ValueError("name_tls_worker_entry_descriptors_unverified")
    extra = []
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor <= 2:
            continue
        try:
            identity = os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
            continue
        extra.append((descriptor, identity))
    if len(extra) > 1:
        raise ValueError("name_tls_worker_import_descriptor_count")
    if not extra:
        return
    descriptor, identity = extra[0]
    path = os.readlink("/proc/self/fd/" + str(descriptor))
    if (not re.fullmatch(r"/(?:usr/)?lib(?:64)?/(?:[a-zA-Z0-9_-]+/)?libffi\.so\.\d+(?:\.\d+)*", path)
            or not stat.S_ISREG(identity.st_mode)
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) != os.O_RDONLY
            or not os.statvfs(path).f_flag & os.ST_RDONLY):
        raise ValueError("name_tls_worker_import_descriptor_identity")
    with open("/proc/self/maps", encoding="ascii") as stream:
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise ValueError("name_tls_worker_import_mapping_limit")
    expected_device = (os.major(identity.st_dev), os.minor(identity.st_dev))
    verified = False
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[1] == "r-xp" and fields[5] == path:
            device = tuple(int(part, 16) for part in fields[3].split(":"))
            if device == expected_device and int(fields[4]) == identity.st_ino:
                verified = True
    if not verified:
        raise ValueError("name_tls_worker_import_mapping_changed")
    os.close(descriptor)


def namespace_identity():
    result = {"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups()}
    for name in ("uid", "gid"):
        with open("/proc/self/" + name + "_map", encoding="ascii") as stream:
            raw = stream.read(1025)
        if len(raw) > 1024:
            raise ValueError("name_tls_worker_mapping_limit")
        result[name + "_map"] = [list(map(int, line.split())) for line in raw.splitlines()]
    with open("/proc/self/setgroups", encoding="ascii") as stream:
        if stream.read(6) != "deny\n":
            raise ValueError("name_tls_worker_mutable_group_mapping")
    return validate_namespace_identity(result)


def assert_private_namespaces(host):
    if (sys.platform != "linux" or type(host) is not dict or set(host) != {"user", "net", "mnt", "pid"}
            or any(type(value) is not str or re.fullmatch(name + r":\[\d+\]", value) is None
                   for name, value in host.items())):
        raise ValueError("name_tls_worker_host_identity")
    for name, identity in host.items():
        if os.readlink("/proc/self/ns/" + name) == identity:
            raise ValueError("name_tls_worker_host_namespace")
    if [name for _, name in socket.if_nameindex()] != ["lo"] or not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise ValueError("name_tls_worker_attached_or_writable_namespace")
    identity = namespace_identity()
    if identity["uid_map"][0][1] == 0 or identity["gid_map"][0][1] == 0:
        raise ValueError("name_tls_worker_privileged_mapping")
    return identity


def seal_group_identity(before):
    before = validate_namespace_identity(before)
    if namespace_identity() != before:
        raise ValueError("name_tls_worker_group_identity_changed")
    try:
        os.setgroups(before["groups"])
    except PermissionError:
        pass
    else:
        raise ValueError("name_tls_worker_groups_mutable")
    return before
