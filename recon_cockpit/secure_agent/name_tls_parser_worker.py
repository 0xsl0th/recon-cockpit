"""Networkless finite parser entered only through the fixed sandbox launcher."""

import os
import sys

ENTRY_VERIFIED = False
if __name__ == "__main__":
    for _name in os.listdir("/proc/self/fd"):
        if int(_name) > 2:
            try:
                os.fstat(int(_name))
            except OSError:
                continue
            raise SystemExit(78)
    ENTRY_VERIFIED = True
    sys.path.insert(0, "/app")

import json
import re
import resource
import socket

from recon_cockpit.secure_agent import name_tls_parser as parser, planner_worker
from recon_cockpit.secure_agent import name_tls_worker_common as common

READY = b"NAME_TLS_PARSER_READY_V1 "


def _boundary(host):
    identity = common.namespace_identity()
    namespaces = {name: os.readlink("/proc/self/ns/" + name) for name in host}
    if (set(host) != {"user", "net", "mnt", "pid"}
            or any(not re.fullmatch(name + r":\[\d+\]", value) or namespaces[name] == value for name, value in host.items())
            or [name for _, name in socket.if_nameindex()] != ["lo"]):
        raise ValueError("name_tls_parser_namespaces")
    common.close_import_descriptor(entry_verified=ENTRY_VERIFIED)
    common.private_descriptors()
    planner_worker._zero_capabilities()
    planner_worker._no_new_privileges()
    planner_worker._set_limits()
    planner_worker._install_syscall_filter()
    planner_worker._sockets_blocked()
    planner_worker._process_creation_blocked()
    planner_worker._namespace_creation_blocked()
    planner_worker._root_read_only()
    common.seal_group_identity(identity)
    return {name: True for name in planner_worker.BOUNDARY_NAMES}, identity, namespaces


def main():
    try:
        if len(sys.argv) != 5:
            raise ValueError("name_tls_parser_arguments")
        host = dict(zip(("user", "net", "mnt", "pid"), sys.argv[1:]))
        checks, identity, namespaces = _boundary(host)
        for kind, value in ((resource.RLIMIT_AS, 128 * 1024 * 1024), (resource.RLIMIT_CPU, 1),
                            (resource.RLIMIT_NOFILE, 32), (resource.RLIMIT_CORE, 0),
                            (resource.RLIMIT_FSIZE, 0), (resource.RLIMIT_NPROC, 1)):
            resource.setrlimit(kind, (value, value))
            if resource.getrlimit(kind) != (value, value):
                raise ValueError("name_tls_parser_resource_limit")
        for path in ("/tool/dig", "/tool/openssl", "/tool/dnsmasq", "/tool/nginx", "/usr/bin/dig", "/usr/bin/openssl",
                     "/usr/sbin/nginx", "/usr/sbin/dnsmasq", "/tool/data/name-tls/server.key",
                     "/tool/data/name-tls/server.pem", "/tool/data/name-tls/nginx.conf",
                     "/app/recon_cockpit/secure_agent/name_tls_spec.py",
                     "/app/recon_cockpit/secure_agent/network_tools_fixture.py",
                     "/app/recon_cockpit/secure_agent/network_tools_tls_certificate_material.py"):
            if os.path.exists(path):
                raise ValueError("name_tls_parser_forbidden_runtime")
        readiness = {"parser_version": parser.PARSER_VERSION, "boundary_checks": checks,
                     "identity": identity, "namespaces": namespaces, "runtime_absence_verified": True}
        ready_raw = json.dumps(readiness, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(ready_raw) > 2048:
            raise ValueError("name_tls_parser_readiness_limit")
        sys.stdout.buffer.write(READY + ready_raw + b"\n")
        sys.stdout.buffer.flush()
        raw = sys.stdin.buffer.read(parser.MAX_INPUT_BYTES + 1)
        try:
            result = parser.parse_input(raw)
            status = "parsed"
        except (ValueError, TypeError, IndexError):
            status, result = "invalid", None
        common.seal_group_identity(identity)
        reply = {**readiness, "status": status, "result": result}
        encoded = json.dumps(reply, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(encoded) + 1 > parser.MAX_OUTPUT_BYTES:
            raise ValueError("name_tls_parser_output_limit")
        sys.stdout.buffer.write(encoded + b"\n")
        return 0
    except Exception:
        sys.stderr.write("name_tls_parser_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
