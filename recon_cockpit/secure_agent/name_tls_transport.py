"""Bounded one-use descriptor transfer for owned name/TLS workers."""

import array
import errno
import fcntl
import hashlib
import os
import socket
import stat
import struct

from .name_tls_topology_spec import encode as _encode, decode as _decode

MAX_PACKET = 262144
BOOTSTRAP_BYTES = 262144
SO_NETNS_COOKIE = 71


def encode(value):
    raw = _encode(value)
    if len(raw) > BOOTSTRAP_BYTES:
        raise ValueError("name_tls_bootstrap_limit")
    return raw


def decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > BOOTSTRAP_BYTES:
        raise ValueError("name_tls_bootstrap_limit")
    return _decode(raw)


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


encode_bootstrap, decode_bootstrap = encode, decode


def receive_bootstrap(channel):
    """Only the audit and approval reader FDs enter the witnessed launcher."""
    descriptors = []
    try:
        raw, ancillary, flags, _ = channel.recvmsg(BOOTSTRAP_BYTES + 1, socket.CMSG_SPACE(256))
        invalid = bool(flags)
        for level, kind, data in ancillary:
            if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                invalid = True
                continue
            values = array.array("i")
            invalid |= bool(len(data) % values.itemsize)
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
        if invalid or len(descriptors) != 2:
            raise ValueError("name_tls_bootstrap_descriptors")
        for descriptor in descriptors:
            os.set_inheritable(descriptor, False)
        value = decode(raw)
        result, descriptors = descriptors, []
        return value, result
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def netns_cookie(channel):
    raw = channel.getsockopt(socket.SOL_SOCKET, SO_NETNS_COOKIE, 8)
    if type(raw) is not bytes or len(raw) != 8:
        raise ValueError("name_tls_socket_cookie")
    value = struct.unpack("=Q", raw)[0]
    if not value:
        raise ValueError("name_tls_socket_cookie")
    return value


def socket_identity(channel):
    info = os.fstat(channel.fileno())
    if (not stat.S_ISSOCK(info.st_mode) or info.st_ino <= 0
            or channel.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_DOMAIN", 39)) != socket.AF_INET
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or channel.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PROTOCOL", 38)) != socket.IPPROTO_TCP
            or channel.getsockname() != ("0.0.0.0", 0) or channel.getblocking()
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            or not fcntl.fcntl(channel.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK):
        raise ValueError("name_tls_private_descriptor_identity")
    try:
        channel.getpeername()
    except OSError as error:
        if error.errno != errno.ENOTCONN:
            raise ValueError("name_tls_private_descriptor_peer") from error
    else:
        raise ValueError("name_tls_private_descriptor_already_connected")
    return {"daemon_netns_cookie": netns_cookie(channel), "inode": info.st_ino}


def validate_descriptor_identity(value):
    if (type(value) is not dict or set(value) != {"daemon_netns_cookie", "inode"}
            or any(type(item) is not int or not 0 < item < 2**64 for item in value.values())):
        raise ValueError("name_tls_private_descriptor_shape")
    return dict(value)


def assert_descriptor_copies(identity, expected, *, maximum=64):
    identity = validate_descriptor_identity(identity)
    if type(maximum) is not int or not 1 <= maximum <= 128:
        raise ValueError("name_tls_private_descriptor_scan_bound")
    observed = []
    for descriptor in range(maximum):
        try:
            info = os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
            continue
        if stat.S_ISSOCK(info.st_mode) and info.st_ino == identity["inode"]:
            observed.append(descriptor)
    if observed != sorted(expected):
        raise ValueError("name_tls_private_descriptor_copy_leaked")


def owned_socket(descriptor):
    channel = None
    try:
        channel = socket.socket(fileno=descriptor)
        channel.setblocking(False)
        return channel
    except BaseException:
        if channel is not None:
            channel.close()
        else:
            os.close(descriptor)
        raise


def send_packet(channel, value, descriptor=None):
    raw = encode(value)
    if len(raw) > MAX_PACKET:
        raise ValueError("name_tls_transport_packet_limit")
    ancillary = [] if descriptor is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))]
    if channel.sendmsg([raw], ancillary) != len(raw):
        raise ValueError("name_tls_transport_short_send")


def receive_packet(channel, *, descriptor_required):
    if type(descriptor_required) is not bool:
        raise ValueError("name_tls_transport_descriptor_mode")
    raw, ancillary, flags, _ = channel.recvmsg(MAX_PACKET + 1, socket.CMSG_SPACE(8 * array.array("i").itemsize),
        getattr(socket, "MSG_CMSG_CLOEXEC", 0x40000000))
    descriptors, keep = [], False
    try:
        invalid = False
        for level, kind, payload in ancillary:
            if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                invalid = True
                continue
            rows = array.array("i")
            invalid |= bool(len(payload) % rows.itemsize)
            rows.frombytes(payload[:len(payload) - len(payload) % rows.itemsize])
            descriptors.extend(rows)
        if (invalid or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) > MAX_PACKET
                or len(descriptors) != int(descriptor_required)):
            raise ValueError("name_tls_transport_unexpected_descriptors")
        value = decode(raw)
        if descriptors:
            if os.get_inheritable(descriptors[0]):
                raise ValueError("name_tls_transport_inheritable_descriptor")
            keep = True
            return value, descriptors[0]
        return value, None
    finally:
        if not keep:
            for descriptor in descriptors:
                os.close(descriptor)
