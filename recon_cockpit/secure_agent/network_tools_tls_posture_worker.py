"""One production-authorized TLS client with no owner or key modules mounted."""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor > 2:
            try:
                os.fstat(descriptor)
            except OSError as error:
                if error.errno != 9:
                    raise
            else:
                raise ValueError("tls_posture_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("network_tls_posture_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import socket
import stat
import time

from recon_cockpit.secure_agent import network_tools_tls_posture_runtime as runtime
from recon_cockpit.secure_agent import tool_worker_common as common, worker


def transport_witnesses():
    for family, kind, protocol in ((socket.AF_UNIX, socket.SOCK_STREAM, 0),
                                  (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)):
        try:
            descriptor = socket.socket(family, kind, protocol)
        except PermissionError as error:
            if error.errno != 1:
                raise
        else:
            descriptor.close()
            raise ValueError("tls_posture_extra_transport_allowed")
    try:
        pair = socket.socketpair()
    except PermissionError as error:
        if error.errno != 1:
            raise
    else:
        for descriptor in pair:
            descriptor.close()
        raise ValueError("tls_posture_socketpair_allowed")


def main():
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("tls_posture_requires_authority_pipe")
        request = runtime.consume_launch(sys.stdin.buffer.read(runtime.MAX_LAUNCH_BYTES + 1), sys.argv[1], sys.argv[2])
        runtime.fixed._namespaces(request, worker)
        manifest = runtime.diagnostic_manifest(request["manifest"])
        runtime.fixed.verify_files(manifest)
        runtime.fixed.limits()
        worker.drop_privileges()
        common.syscall_filter(allow_threads=False)
        common._witnesses()
        transport_witnesses()
        sys.stdin.close()
        runtime.fixed.close_private_descriptors()
        private_descriptors()
        try:
            os.close(0)
        except OSError as error:
            if error.errno != 9:
                raise
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        common.apply_landlock(runtime.fixed.permissions(manifest))
        if time.monotonic() >= request["deadline"]:
            raise ValueError("tls_posture_authority_expired")
        os.write(2, runtime.READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        os.execve("/tool/openssl", runtime.FIXED_ARGV[request["tool_id"]], dict(runtime.ENVIRONMENT))
    except Exception:
        sys.stderr.write("network_tls_posture_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
