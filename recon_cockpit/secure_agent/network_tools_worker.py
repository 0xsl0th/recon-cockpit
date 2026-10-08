"""One independently authorized network-tool exec under a distinct confinement profile.

Unlike the existing Python-only workers this profile permits exec of its small
read/execute allowlist. It does not claim seccomp counts or prohibits re-exec.
"""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError:
                continue
            raise ValueError("network_tool_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("network_tool_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import errno
import hashlib
import json
import resource
import socket
import stat
import time

from recon_cockpit.secure_agent import tool_worker_common as common

if __package__:
    from . import network_tools_runtime as runtime, worker
    from .network_tools_execution import consume_launch
    from .owned_lab_executor import assert_lab_namespaces
else:
    from recon_cockpit.secure_agent import network_tools_runtime as runtime, worker
    from recon_cockpit.secure_agent.network_tools_execution import consume_launch
    from recon_cockpit.secure_agent.owned_lab_executor import assert_lab_namespaces


def verify_files(manifest):
    runtime.validate_manifest(manifest)
    for item in runtime.runtime_files(manifest):
        raw = runtime.read_runtime_file(item["destination"], manifest["tool_id"])
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("network_tool_mounted_runtime_mismatch")
        if item["destination"] == manifest["executable"] and not raw.startswith(b"\x7fELF"):
            raise ValueError("network_tool_requires_elf")
        if "security.capability" in os.listxattr(item["destination"]):
            raise ValueError("network_tools_runtime_file_capabilities")


def _landlock_permissions(manifest):
    permissions = {item["destination"]: 4 for item in runtime.runtime_files(manifest)}
    permissions[manifest["executable"]] |= 1
    permissions[manifest["interpreter"]] |= 1
    permissions.update({"/dev/null": 6, "/dev/urandom": 4, "/dev/random": 4,
                        "/proc/self/status": 4})
    if manifest["tool_id"] in (runtime.OPENSSL, runtime.NMAP_SERVICE, runtime.POSTGRESQL_TLS, runtime.MYSQL_TLS, runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS):
        permissions["/tool/data"] = 8
    if manifest["tool_id"] == runtime.WHATWEB:
        # RubyGems and WhatWeb enumerate only directories containing the
        # exact pinned files. READ_DIR does not grant file-read authority.
        from pathlib import Path
        for item in runtime.runtime_files(manifest):
            permissions[str(Path(item["destination"]).parent)] = 8
    return permissions


def landlock(manifest):
    common.apply_landlock(_landlock_permissions(manifest))


def syscall_filter(tool_id):
    if tool_id not in (runtime.DIG, runtime.DIG_SRV, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.SMB,
                       runtime.RPCINFO, runtime.SHOWMOUNT, runtime.FTP, runtime.SMTP,
                       runtime.DOCKER_PING, runtime.DOCKER_VERSION, runtime.WINRM, runtime.NMAP_SERVICE,
                       runtime.KERBRUTE, runtime.REDIS, runtime.SNMP, runtime.POSTGRESQL_TLS, runtime.MYSQL_TLS,
                       runtime.WHATWEB, runtime.RDP, runtime.SMB2, runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS):
        raise ValueError("unsupported_network_tool")
    common.syscall_filter(allow_threads=tool_id in (runtime.DIG, runtime.DIG_SRV, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.KERBRUTE, runtime.WHATWEB, runtime.RDP, runtime.SMB2))


def _limits(tool_id):
    address_space = (2048 if tool_id == runtime.KERBRUTE else 256) * 1024 * 1024
    threads = 16 if tool_id == runtime.DIG else 1
    if tool_id == runtime.DIG_SRV:
        threads = 16
    if tool_id == runtime.DIG_NSID:
        threads = 16
    if tool_id == runtime.DIG_AXFR:
        threads = 16
    if tool_id == runtime.KERBRUTE:
        threads = 16
    if tool_id == runtime.WHATWEB:
        threads = 16
    if tool_id == runtime.RDP:
        threads = 16
    if tool_id == runtime.SMB2:
        threads = 16
    for kind, maximum in ((resource.RLIMIT_AS, address_space), (resource.RLIMIT_CPU, 5),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, threads),
                           (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))


# Preserve the reviewed worker API while sharing the fixed kernel witnesses.
clone_denials = common.clone_denials
_namespace_task_count = common._namespace_task_count
_thread_bound_witness = common._thread_bound_witness
_witnesses = common._witnesses


def _kerberos_transport_witness():
    # The stock client attempts UDP before TCP; it must fail at socket creation
    # without emitting a packet. Only its bounded TCP fallback may reach the lab.
    try:
        descriptor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except PermissionError:
        return
    descriptor.close()
    raise RuntimeError("kerbrute_udp_socket_allowed")


def _metadata_transport_witness():
    """Fixed metadata profiles are TCP-only; clients cannot fall back to UDP."""
    try:
        descriptor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except PermissionError:
        return
    descriptor.close()
    raise RuntimeError("metadata_udp_socket_allowed")


def main():
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("network_tool_requires_authority_pipe")
        raw = sys.stdin.buffer.read(32769)
        request, deadline, namespaces, digest = consume_launch(raw, sys.argv[1], sys.argv[2])
        manifest = json.loads(raw)["runtime"]
        if runtime.manifest_digest(manifest) != digest:
            raise ValueError("network_tools_runtime_commitment_mismatch")
        assert_lab_namespaces(request["host_namespaces"], namespaces)
        verify_files(manifest)
        _limits(request["tool_id"])
        worker.drop_privileges()
        syscall_filter(request["tool_id"])
        if request["tool_id"] in (runtime.RPCINFO, runtime.SHOWMOUNT):
            _witnesses(port=111)
        else:
            _witnesses()
        if request["tool_id"] in (runtime.DIG, runtime.DIG_SRV, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.KERBRUTE, runtime.WHATWEB, runtime.RDP, runtime.SMB2):
            _thread_bound_witness()
        if request["tool_id"] == runtime.KERBRUTE:
            _kerberos_transport_witness()
        if request["tool_id"] in (runtime.DIG_SRV, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.REDIS, runtime.SNMP, runtime.POSTGRESQL_TLS, runtime.MYSQL_TLS,
                                  runtime.WHATWEB, runtime.RDP, runtime.SMB2, runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS):
            _metadata_transport_witness()
        # The authority stdin and any loader-retained descriptors are gone.
        sys.stdin.close()
        for name in os.listdir("/proc/self/fd"):
            if int(name) > 2:
                try:
                    os.close(int(name))
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
        # A real EOF descriptor prevents OpenSSL treating a reused socket fd
        # as stdin. It contains no authority bytes or interactive commands.
        try:
            os.close(0)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        landlock(manifest)
        if time.monotonic() >= deadline:
            raise TimeoutError("network_tool_authority_expired")
        # Only a fixed EOF device is inherited as stdin.
        os.write(2, runtime.READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        argv = runtime.FIXED_ARGV[request["tool_id"]]
        os.execve(argv[0], argv, runtime.execution_environment(request["tool_id"]))
        return 78
    except Exception:
        sys.stderr.write("network_tool_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
