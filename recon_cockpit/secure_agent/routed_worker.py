"""Fixed single-destination HTTP worker for the routed Bubblewrap backend.

The controller attaches transport only after this worker has installed its
destination firewall and dropped privileges. No network setup runs on the host.
"""

from __future__ import annotations

import ctypes
import errno
import importlib.util
import ipaddress
import json
from pathlib import Path
import resource
import socket
import subprocess
import sys
from typing import BinaryIO


if __package__:
    from . import worker
else:
    # Isolated Python (-I -S) omits the script directory from sys.path. Load
    # only the fixed, adjacent, read-only runtime file supplied by Bubblewrap.
    _spec = importlib.util.spec_from_file_location(
        "recon_secure_fixed_worker", Path(__file__).with_name("worker.py"))
    if _spec is None or _spec.loader is None:
        raise RuntimeError("missing fixed worker runtime")
    worker = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(worker)


_EXCLUDED_TARGETS = tuple(ipaddress.IPv4Network(network) for network in (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    "240.0.0.0/4", "10.0.2.0/24",
))
_REQUEST_FIELDS = {"target", "parameters", "host_namespaces", "boundary_witnesses"}


def validate_target(target: object) -> str:
    """Reject aliases, networks, IPv6 and addresses reserved for transport."""
    if type(target) is not str:
        raise ValueError("invalid routed target")
    try:
        address = ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError as exc:
        raise ValueError("invalid routed target") from exc
    if str(address) != target or any(address in network for network in _EXCLUDED_TARGETS):
        raise ValueError("invalid routed target")
    return target


def _unique_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate execution field")
        result[key] = value
    return result


def validate_request(raw: bytes) -> dict:
    if len(raw) > 8192:
        raise ValueError("request too large")
    request = json.loads(raw, object_pairs_hook=_unique_fields)
    if type(request) is not dict or set(request) != _REQUEST_FIELDS:
        raise ValueError("invalid routed request fields")
    validate_target(request["target"])
    parameters = request["parameters"]
    if type(parameters) is not dict or set(parameters) != worker._PARAMETERS:
        raise ValueError("invalid parameters")
    port = parameters["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid routed port")
    # Reuse the fixture's strict HTTP parameter validation while keeping its
    # fixture address and port restrictions unchanged.
    worker.validate_request(json.dumps({
        "target": "127.0.0.1", "parameters": {**parameters, "port": 8080},
        "verify_boundary": False, "host_namespaces": request["host_namespaces"],
    }).encode("utf-8"))
    witnesses = request["boundary_witnesses"]
    if witnesses is not None:
        if type(witnesses) is not dict or set(witnesses) != {"forbidden_ip", "forbidden_port"}:
            raise ValueError("invalid routed witnesses")
        validate_target(witnesses["forbidden_ip"])
        if witnesses["forbidden_ip"] == request["target"]:
            raise ValueError("witness IP must be forbidden")
        forbidden_port = witnesses["forbidden_port"]
        if (type(forbidden_port) is not int or not 1 <= forbidden_port <= 65535
                or forbidden_port == port):
            raise ValueError("witness port must be forbidden")
    return request


def read_request(source: BinaryIO) -> dict:
    raw = source.readline(8193)
    if not raw.endswith(b"\n"):
        raise ValueError("unterminated execution request")
    return validate_request(raw)


def await_release(source: BinaryIO) -> None:
    if source.readline(4) != b"GO\n":
        raise RuntimeError("transport release refused")


def firewall_rules(target: str, port: int) -> str:
    validate_target(target)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid routed firewall port")
    return f"""table inet recon_routed {{
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname "tap0" ip daddr {target} tcp dport {port} ct direction original accept
  }}
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "tap0" meta l4proto tcp ct direction reply ct state established ct original ip daddr {target} ct original proto-dst {port} accept
  }}
  chain forward {{ type filter hook forward priority 0; policy drop; }}
}}
"""


def verify_network_boundary(target: str, port: int, witnesses: dict) -> dict[str, bool]:
    """Controller-owned listening witnesses make timeouts meaningful evidence."""
    checks = {}
    for name, destination in (
        ("forbidden_ip_blocked", (witnesses["forbidden_ip"], port)),
        ("forbidden_port_blocked", (target, witnesses["forbidden_port"])),
    ):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.2)
            try:
                connection.connect(destination)
            except (TimeoutError, PermissionError):
                checks[name] = True
            else:
                raise RuntimeError("forbidden routed destination was reachable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x10000000) == 0 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError("namespace creation was not blocked")
    checks["namespace_creation_blocked"] = True
    status = worker._status()
    checks["capabilities_dropped"] = all(
        int(status[key], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    if not checks["capabilities_dropped"] or status["NoNewPrivs"] != "1":
        raise RuntimeError("routed privileges were not dropped")
    return checks


def main() -> int:
    try:
        request = read_request(sys.stdin.buffer)
        worker.assert_private_namespaces(request["host_namespaces"])
        parameters = request["parameters"]
        worker._set_limits(parameters["timeout_seconds"])
        subprocess.run(
            ["/usr/sbin/nft", "-f", "-"],
            input=firewall_rules(request["target"], parameters["port"]).encode("ascii"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=3,
            env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}, close_fds=True,
        )
        worker.drop_privileges()
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
        worker.install_syscall_filter()
        sys.stdout.write("READY\n")
        sys.stdout.flush()
        await_release(sys.stdin.buffer)
        if sorted(name for _, name in socket.if_nameindex()) != ["lo", "tap0"]:
            raise RuntimeError("unexpected routed interfaces")
        # Transport release is a bootstrap gate, not a continuing tool channel.
        sys.stdin.close()
        boundary = (verify_network_boundary(request["target"], parameters["port"], request["boundary_witnesses"])
                    if request["boundary_witnesses"] is not None else None)
        result = worker.probe(request["target"], parameters)
        if boundary is not None:
            result["boundary_checks"] = boundary
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 0
    except Exception:
        sys.stderr.write("secure routed setup failed; execution refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
