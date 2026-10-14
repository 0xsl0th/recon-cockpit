"""One-use daemon namespace socket custody; never grants execution authority."""

import array
import errno
import fcntl
import os
import socket
import stat
import struct

from .stock_http_recorder import Service
from .stock_http_owner_worker import MAX_PACKET, decode, encode

SO_NETNS_COOKIE = 71  # Linux UAPI; unsupported kernels fail closed.
SO_DOMAIN = getattr(socket, "SO_DOMAIN", 39)
SO_PROTOCOL = getattr(socket, "SO_PROTOCOL", 38)
RECEIVE_CLOEXEC = getattr(socket, "MSG_CMSG_CLOEXEC", 0x40000000)
PRIVATE_ENDPOINT = ("127.0.0.1", 19080)


def netns_cookie(channel):
    raw = channel.getsockopt(socket.SOL_SOCKET, SO_NETNS_COOKIE, 8)
    if type(raw) is not bytes or len(raw) != 8:
        raise ValueError("stock_production_invalid_netns_cookie")
    value = struct.unpack("=Q", raw)[0]
    if not value:
        raise ValueError("stock_production_invalid_netns_cookie")
    return value


def socket_identity(channel):
    """Inspect an unconnected TCP capability without contacting any endpoint."""
    info = os.fstat(channel.fileno())
    if (not stat.S_ISSOCK(info.st_mode) or info.st_ino <= 0
            or channel.getsockopt(socket.SOL_SOCKET, SO_DOMAIN) != socket.AF_INET
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or channel.getsockopt(socket.SOL_SOCKET, SO_PROTOCOL) != socket.IPPROTO_TCP
            or channel.getsockname() != ("0.0.0.0", 0)
            or channel.getblocking()
            or not fcntl.fcntl(channel.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK):
        raise ValueError("stock_production_invalid_private_descriptor")
    try:
        channel.getpeername()
    except OSError as error:
        if error.errno != errno.ENOTCONN:
            raise ValueError("stock_production_invalid_private_peer") from error
    else:
        raise ValueError("stock_production_descriptor_already_connected")
    return {"daemon_netns_cookie": netns_cookie(channel), "inode": info.st_ino}


def owned_socket(descriptor):
    """Take custody even when wrapping an unexpected non-socket FD fails."""
    channel = None
    try:
        channel = socket.socket(fileno=descriptor)
        channel.setblocking(False)
        return channel
    except BaseException:
        if channel is not None:
            channel.close()
        else:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
        raise


def validate_descriptor_identity(value):
    if (type(value) is not dict or set(value) != {"daemon_netns_cookie", "inode"}
            or any(type(item) is not int or not 0 < item < 2**64 for item in value.values())):
        raise ValueError("stock_production_invalid_descriptor_identity")
    return dict(value)


def send_packet(channel, value, descriptor=None):
    raw = encode(value)
    ancillary = [] if descriptor is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))]
    if channel.sendmsg([raw], ancillary) != len(raw):
        raise ValueError("stock_production_packet_truncated")


def receive_packet(channel, *, descriptor_required):
    """Own every received descriptor, including malformed ancillary messages."""
    if type(descriptor_required) is not bool:
        raise ValueError("stock_production_invalid_descriptor_mode")
    raw, ancillary, flags, _ = channel.recvmsg(MAX_PACKET + 1, socket.CMSG_SPACE(8 * 4), RECEIVE_CLOEXEC)
    descriptors = []
    keep = False
    try:
        malformed = False
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                malformed = True
                continue
            rows = array.array("i")
            if len(payload) % rows.itemsize:
                malformed = True
            rows.frombytes(payload[:len(payload) - len(payload) % rows.itemsize])
            descriptors.extend(rows)
        if (malformed or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(descriptors) != int(descriptor_required)):
            raise ValueError("stock_production_unexpected_descriptors")
        value = decode(raw)
        if descriptors:
            if os.get_inheritable(descriptors[0]):
                raise ValueError("stock_production_descriptor_inheritable")
            keep = True
            return value, descriptors[0]
        return value, None
    finally:
        if not keep:
            for descriptor in descriptors:
                os.close(descriptor)


class DescriptorService(Service):
    """The recorder's existing admission machine consumes one private socket."""

    def __init__(self, configuration, case, listener, *, private_socket, identity, deadline):
        self._private_socket = private_socket
        self._private_identity = validate_descriptor_identity(identity)
        if socket_identity(private_socket) != self._private_identity:
            raise ValueError("stock_production_private_descriptor_changed")
        self.recorder_cookie = netns_cookie(listener)
        if self.recorder_cookie == self._private_identity["daemon_netns_cookie"]:
            raise ValueError("stock_production_descriptor_not_separate")
        super().__init__(configuration, case, listener, deadline=deadline)

    def _connect_daemon(self):
        channel, self._private_socket = self._private_socket, None
        if channel is None:
            raise ValueError("stock_production_private_descriptor_consumed")
        try:
            if socket_identity(channel) != self._private_identity:
                raise ValueError("stock_production_private_descriptor_changed")
            result = channel.connect_ex(PRIVATE_ENDPOINT)
            if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                raise OSError(result, "stock_production_private_connect_failed")
            return channel
        except BaseException:
            channel.close()
            raise

    def close(self, reason="closed"):
        try:
            super().close(reason)
        finally:
            channel, self._private_socket = self._private_socket, None
            if channel is not None:
                channel.close()
