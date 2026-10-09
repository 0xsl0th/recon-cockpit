"""One synthetic service in a private namespace; never attaches to a host lab."""

import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

if __package__:
    from . import owned_lab_worker as owner, configurable_scope as scope_contract
    from . import http_headers_fixture as headers, network_tools_fixture as network, network_tools_ssh_fixture as ssh
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    owner = _load("configurable_fixed_owner", "owned_lab_worker.py")
    scope_contract = _load("configurable_fixed_scope", "configurable_scope.py")
    headers = _load("configurable_fixed_headers", "http_headers_fixture.py")
    network = _load("configurable_fixed_network", "network_tools_fixture.py")
    ssh = _load("configurable_fixed_ssh", "network_tools_ssh_fixture.py")

MAX_REQUEST_BYTES = 4096


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_configurable_lab_request")
    value = json.loads(raw, object_pairs_hook=owner._unique)
    if (type(value) is not dict or set(value) != {"scope", "endpoint", "deadline", "host_namespaces"}
            or type(value["endpoint"]) is not str or value["endpoint"] not in ("http", "ssh")
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("invalid_configurable_lab_request")
    value["scope"] = scope_contract.validate_scope(value["scope"])
    return value


def address_message(address, interface_index, sequence):
    """Exactly one IPv4 /32 RTM_NEWADDR, no routes or host interface changes."""
    if (type(interface_index) is not int or interface_index <= 0
            or type(sequence) is not int or not 1 <= sequence <= 4):
        raise ValueError("invalid_configurable_address_request")
    raw = socket.inet_pton(socket.AF_INET, scope_contract._target(address))
    # ifaddrmsg: AF_INET, /32, no flags, global scope, loopback interface index.
    body = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, interface_index)
    body += struct.pack("=HH", 8, 1) + raw  # IFA_ADDRESS
    body += struct.pack("=HH", 8, 2) + raw  # IFA_LOCAL
    # NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE; RTM_NEWADDR.
    return struct.pack("=IHHII", 16 + len(body), 20, 0x605, sequence, 0) + body


def validate_address_ack(raw, message, sender):
    # NLMSG_ERROR with error=0 includes the exact acknowledged request header.
    if (type(raw) is not bytes or len(raw) < 36 or sender != (0, 0)
            or len(raw) > 4096):
        raise ValueError("invalid_configurable_address_ack")
    size, kind, _flags, sequence, _pid = struct.unpack("=IHHII", raw[:16])
    if (size != len(raw) or kind != 2 or sequence != struct.unpack("=I", message[8:12])[0]
            or struct.unpack("=i", raw[16:20])[0] != 0 or raw[20:36] != message[:16]):
        raise ValueError("configurable_address_setup_refused")


def prepare_addresses(request):
    # This assertion precedes the first privileged operation, including the
    # netlink socket. Only a fresh disconnected namespace with one UID mapping
    # can reach this function's setup operations.
    owner.worker.assert_private_namespaces(request["host_namespaces"])
    selected = scope_contract.endpoint(request["scope"], request["endpoint"])
    destinations = [(selected["target"], selected["port"]),
                    *scope_contract.witness_addresses(request["scope"], request["endpoint"])]
    addresses = tuple(dict.fromkeys(target for target, _ in destinations))
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(owner.worker._remaining(request["deadline"], 2))
        channel.bind((0, 0))
        for sequence, address in enumerate(addresses, start=1):
            message = address_message(address, socket.if_nametoindex("lo"), sequence)
            if channel.sendto(message, (0, 0)) != len(message):
                raise ValueError("configurable_address_setup_truncated")
            raw, sender = channel.recvfrom(4097)
            validate_address_ack(raw, message, sender)


def firewall_rules(scope, endpoint_name):
    selected = scope_contract.endpoint(scope, endpoint_name)
    target, port = selected["target"], selected["port"]
    return f'''table inet recon_configurable {{
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname "lo" ip daddr {target} tcp dport {port} ct direction original accept
    oifname "lo" ct direction reply ct state established ct original ip daddr {target} ct original proto-dst {port} accept
  }}
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" ip daddr {target} tcp dport {port} ct direction original accept
    iifname "lo" ct direction reply ct state established ct original ip daddr {target} ct original proto-dst {port} accept
  }}
  chain forward {{ type filter hook forward priority 0; policy drop; }}
}}
'''


def read_http(connection, deadline, *, initial_scan=False):
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        if len(raw) >= MAX_REQUEST_BYTES:
            raise ValueError("configurable_http_request_limit")
        connection.settimeout(owner.worker._remaining(deadline, 2))
        try:
            part = connection.recv(MAX_REQUEST_BYTES - len(raw))
        except ConnectionResetError:
            if initial_scan and not raw:
                return b""
            raise
        if not part:
            if not raw:
                return b""
            raise ValueError("configurable_http_request_incomplete")
        raw.extend(part)
    if not raw.endswith(b"\r\n\r\n") or raw.count(b"\r\n\r\n") != 1:
        raise ValueError("configurable_http_body_or_pipeline")
    return bytes(raw)


def header_request(selected):
    return (f'GET {selected["path"]} HTTP/1.1\r\nHost: {selected["target"]}:{selected["port"]}\r\n'
            'Connection: close\r\n\r\n').encode("ascii")


def header_response():
    status, body, extra = headers.response("vulnerable", headers.PORTAL_PATH)
    return (f"HTTP/1.1 {status} Owned\r\nContent-Length: {len(body)}\r\nConnection: close\r\n".encode("ascii")
            + extra + b"\r\n" + body)


class ConfigurableService(owner.Service):
    def __init__(self, request, listener):
        self.deadline = request["deadline"]
        self.selected = scope_contract.endpoint(request["scope"], request["endpoint"])
        super().__init__(request["endpoint"], listener)

    def _metadata(self):
        with self.condition:
            self.requests += 1
            self.condition.notify_all()

    def _http(self, connection):
        raw = read_http(connection, self.deadline, initial_scan=self.connections == 1 and self.requests == 0)
        if self.requests == 0:
            if not raw and self.connections in (1, 2):
                return
            if self.connections not in (2, 3) or raw != network.NMAP_SERVICE_GET:
                raise ValueError("configurable_nmap_http_phase")
            reply = network.NMAP_SERVICE_HTTP
        elif self.requests == 1 and raw == header_request(self.selected):
            reply = header_response()
        else:
            raise ValueError("configurable_header_phase")
        connection.settimeout(owner.worker._remaining(self.deadline, 2))
        connection.sendall(reply)
        self._metadata()

    def _ssh(self, connection):
        if self.connections == 1 and self.requests == 0:
            if read_http(connection, self.deadline, initial_scan=True):
                raise ValueError("configurable_ssh_initial_scan_must_be_empty")
        elif self.connections == 2 and self.requests == 0:
            connection.settimeout(owner.worker._remaining(self.deadline, 2))
            connection.sendall(network.NMAP_SERVICE_SSH)
            self._metadata()
        elif self.connections == 3 and self.requests == 1:
            connection.settimeout(owner.worker._remaining(self.deadline, 2))
            ssh.serve(connection, banner=network.NMAP_SERVICE_SSH[:-2], deadline=self.deadline)
            self._metadata()
        else:
            raise ValueError("configurable_ssh_phase")

    def _serve(self):
        try:
            while True:
                connection, _ = self.listener.accept()
                try:
                    if self.connections >= (4 if self.case == "http" else 3) or self.requests >= 2:
                        raise ValueError("configurable_exchange_limit")
                    with self.condition:
                        self.connections += 1
                        self.condition.notify_all()
                    (self._http if self.case == "http" else self._ssh)(connection)
                finally:
                    connection.close()
        except BaseException:
            with self.condition:
                self.failed = True
                self.condition.notify_all()


class ConfigurableOwner:
    def run(self):
        listeners = []
        try:
            if not stat.S_ISFIFO(os.fstat(0).st_mode):
                raise ValueError("configurable_lab_requires_private_pipe")
            request = read_request(sys.stdin.buffer)
            owner.worker.assert_private_namespaces(request["host_namespaces"])
            deadline = request["deadline"]
            owner.worker._set_limits(owner.worker._remaining(deadline, 60))
            signal.signal(signal.SIGALRM, owner.worker._deadline)
            signal.setitimer(signal.ITIMER_REAL, owner.worker._remaining(deadline, 60))
            prepare_addresses(request)
            selected = scope_contract.endpoint(request["scope"], request["endpoint"])
            for address in ((selected["target"], selected["port"]),
                            *scope_contract.witness_addresses(request["scope"], request["endpoint"])):
                listeners.append(owner._listen(address))
            for listener in listeners[1:]:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(owner.worker._remaining(deadline, 1))
                    connection.connect(listener.getsockname())
                    accepted, _ = listener.accept()
                    accepted.close()
            subprocess.run(["/usr/sbin/nft", "-f", "-"],
                input=firewall_rules(request["scope"], request["endpoint"]).encode("ascii"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                timeout=owner.worker._remaining(deadline, 3),
                env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}, close_fds=True)
            owner.worker.drop_privileges()
            service = ConfigurableService(request, listeners[0])
            resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
            owner.worker.install_syscall_filter()
            namespaces = {name: os.readlink(f"/proc/self/ns/{name}") for name in ("user", "net", "mnt", "pid")}
            print(json.dumps({"ready": True, "namespaces": namespaces, "witness_baselines": True,
                              "connection_count": 0, "request_count": 0}, separators=(",", ":")), flush=True)
            sequence = 0
            while True:
                ready, _, _ = select.select([0, *listeners[1:]], [], [], owner.worker._remaining(deadline, 1))
                if any(listener in ready for listener in listeners[1:]):
                    raise RuntimeError("configurable_lab_witness_leak")
                if 0 not in ready:
                    continue
                raw = sys.stdin.buffer.readline(1025)
                if not raw:
                    return 0
                if len(raw) > 1024 or not raw.endswith(b"\n"):
                    raise ValueError("invalid_configurable_lab_command")
                command = json.loads(raw, object_pairs_hook=owner._unique)
                if (type(command) is not dict or set(command) != {"sequence", "minimum_connections", "minimum_requests"}
                        or type(command["sequence"]) is not int or command["sequence"] != sequence + 1
                        or not 1 <= command["sequence"] <= 16
                        or type(command["minimum_connections"]) is not int
                        or not 0 <= command["minimum_connections"] <= (4 if request["endpoint"] == "http" else 3)
                        or type(command["minimum_requests"]) is not int
                        or not 0 <= command["minimum_requests"] <= 2):
                    raise ValueError("invalid_configurable_lab_command")
                sequence += 1
                counts = service.snapshot(command["minimum_connections"], command["minimum_requests"], deadline)
                print(json.dumps({"sequence": sequence, **counts}, separators=(",", ":")), flush=True)
        except Exception:
            sys.stderr.write("configurable_lab_owner_refused\n")
            return 78
        finally:
            for listener in listeners:
                listener.close()


def main():
    return ConfigurableOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
