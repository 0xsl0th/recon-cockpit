"""Fixed diagnostic client with explicit private-peer bypass witnesses."""

import os
import socket
import stat
import sys
import time

if __package__:
    from . import tls_posture_diagnostic_worker as fixed
else:
    sys.path.insert(0, "/app")
    from recon_cockpit.secure_agent import tls_posture_diagnostic_worker as fixed


READY_PREFIX = b"RECON_TLS_MEDIATED_READY_V1 "


def unix_socket_witnesses():
    """The private owner socketpair must have no client-created counterpart."""
    try:
        descriptor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except PermissionError:
        pass
    else:
        descriptor.close()
        raise ValueError("mediated_unix_socket_allowed")
    try:
        descriptors = socket.socketpair()
    except PermissionError:
        pass
    else:
        for descriptor in descriptors:
            descriptor.close()
        raise ValueError("mediated_socketpair_allowed")


def main():
    try:
        fixed.private_descriptors()
        if len(sys.argv) != 2 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("diagnostic_requires_private_pipe")
        request = fixed.validate_request(sys.stdin.buffer.read(fixed.MAX_REQUEST_BYTES + 1), sys.argv[1])
        sys.path.insert(0, "/app")
        from recon_cockpit.secure_agent import tool_worker_common as common, worker
        fixed._namespaces(request, worker)
        fixed.verify_files(request["manifest"])
        fixed.limits()
        worker.drop_privileges()
        common.syscall_filter(allow_threads=False)
        common._witnesses()
        unix_socket_witnesses()
        try:
            denied = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        except PermissionError:
            pass
        else:
            denied.close()
            raise ValueError("diagnostic_udp_allowed")
        sys.stdin.close()
        fixed.close_private_descriptors()
        fixed.private_descriptors()
        try:
            os.close(0)
        except OSError as exc:
            if exc.errno != 9:
                raise
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        common.apply_landlock(fixed.permissions(request["manifest"]))
        if time.monotonic() >= request["deadline"]:
            raise ValueError("diagnostic_expired")
        os.write(2, READY_PREFIX + sys.argv[1].encode("ascii") + b"\n")
        os.execve("/tool/openssl", fixed.FIXED_ARGV[request["version"]], dict(fixed.ENVIRONMENT))
    except Exception:
        sys.stderr.write("tls_posture_mediated_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
