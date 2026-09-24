"""One independently validated action in a fresh sandbox sharing only lab net.

The parent-owned network has its immutable singleton filter. This executor's
new descendant user namespace has no network-administration rights over it.
"""

from __future__ import annotations

import os
import sys


def assert_private_descriptors():
    # Run at script entry, before ctypes/worker imports: the distribution libffi
    # loader can retain its own read-only runtime FD. listdir's directory FD is
    # already closed by return; every persistent inherited FD above stderr fails.
    for name in os.listdir("/proc/self/fd"):
        if not name.isdecimal() or int(name) <= 2:
            continue
        try:
            os.fstat(int(name))
        except OSError:
            continue
        raise RuntimeError("owned_lab_executor_inherited_descriptor")


if __name__ == "__main__":
    try:
        assert_private_descriptors()
    except Exception:
        sys.stderr.write("owned_lab_executor_refused\n")
        raise SystemExit(78) from None


import hashlib
import hmac
import json
import re
import resource
import stat

if __package__:
    from . import worker
    from .executor_worker import LaunchVerifier, MAX_LAUNCH_BYTES, encode
    from .models import load_json
    from .owned_lab_contract import validate_identity
else:
    sys.path.insert(0, "/app")
    import worker
    from recon_cockpit.secure_agent.executor_worker import LaunchVerifier, MAX_LAUNCH_BYTES, encode
    from recon_cockpit.secure_agent.models import load_json
    from recon_cockpit.secure_agent.owned_lab_contract import validate_identity


MAX_OWNED_LAUNCH_BYTES = MAX_LAUNCH_BYTES + 4096


def validate_launch(raw, nonce, context_digest):
    if (type(raw) is not bytes or len(raw) > MAX_OWNED_LAUNCH_BYTES
            or type(context_digest) is not str or not re.fullmatch(r"[a-f0-9]{64}", context_digest)
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), context_digest)):
        raise ValueError("owned_lab_launch_mismatch")
    envelope = load_json(raw)
    if type(envelope) is not dict or set(envelope) != {"mode", "launch", "identity", "namespaces"} or envelope["mode"] != "owned_lab":
        raise ValueError("invalid_owned_lab_launch")
    identity = validate_identity(envelope["identity"])
    launch = envelope["launch"]
    if type(launch) is not dict or launch.get("mode") != "discovery_fixture":
        raise ValueError("invalid_owned_lab_authority")
    # Reuse the already reviewed complete action/policy/session/budget verifier.
    # The outer commitment additionally binds this explicit runtime and owner.
    inner = encode(launch)
    request, deadline = LaunchVerifier(nonce, hashlib.sha256(inner).hexdigest()).consume(inner)
    namespaces = envelope["namespaces"]
    if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
            or any(type(value) is not str or not re.fullmatch(name + r":\[\d+\]", value)
                   or value == launch["host_namespaces"][name] for name, value in namespaces.items())):
        raise ValueError("invalid_owned_lab_namespaces")
    if request.get("tool_id") != "tcp_connect":
        parameters = request["parameters"]
        if (parameters["path"] not in {f"/assessment/{identity['scenario']}/index.json",
                                      f"/assessment/{identity['scenario']}/diagnostics.json"}
                or parameters["method"] != "GET" or parameters["timeout_seconds"] != 1
                or parameters["max_output_bytes"] != 1024):
            raise ValueError("owned_lab_case_or_profile_mismatch")
    return request, deadline, namespaces


def assert_lab_namespaces(host, lab):
    if sys.platform != "linux" or os.getuid() != 0 or os.getgid() != 0:
        raise RuntimeError("invalid_owned_lab_executor_identity")
    for name in ("user", "net", "mnt", "pid"):
        current = os.readlink(f"/proc/self/ns/{name}")
        if current == host[name] or (current != lab[name] if name == "net" else current == lab[name]):
            raise RuntimeError("owned_lab_namespace_mismatch")
    import socket
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise RuntimeError("owned_lab_interface_mismatch")
    with open("/proc/self/uid_map", encoding="ascii") as source:
        if [tuple(map(int, line.split())) for line in source] != [(0, 0, 1)]:
            raise RuntimeError("owned_lab_user_mapping_mismatch")
    if int(worker._status()["CapEff"], 16) & (1 << 12):
        raise RuntimeError("owned_lab_executor_has_net_admin")


def execute(request, deadline, namespaces):
    assert_lab_namespaces(request["host_namespaces"], namespaces)
    parameters = request["parameters"]
    worker._remaining(deadline, parameters["timeout_seconds"])
    worker._set_limits(parameters["timeout_seconds"])
    worker.drop_privileges()
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    worker.install_syscall_filter()
    worker._remaining(deadline, parameters["timeout_seconds"])
    checks = worker.verify_network_boundary(8080)
    operation = worker.tcp_connect_probe if request.get("tool_id") == "tcp_connect" else worker.probe
    result = operation(request["target"], parameters, deadline=deadline)
    result["boundary_checks"] = checks
    return result


def main():
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("owned_lab_executor_requires_authority_pipe")
        raw = sys.stdin.buffer.read(MAX_OWNED_LAUNCH_BYTES + 1)
        sys.stdin.close()
        request, deadline, namespaces = validate_launch(raw, sys.argv[1], sys.argv[2])
        print(json.dumps(execute(request, deadline, namespaces), separators=(",", ":")), flush=True)
        return 0
    except Exception:
        sys.stderr.write("owned_lab_executor_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
