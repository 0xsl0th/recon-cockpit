"""Fixed credential-free owner of one session's disconnected HTTP service.

Only the trusted launcher supplies stdin. Tool executors receive network access
to the single filtered service, never this management pipe or its namespace FDs.
"""

from __future__ import annotations

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
import subprocess
import sys
import threading
import time

if __package__:
    from . import worker
else:
    _spec = importlib.util.spec_from_file_location("owned_fixed_worker", Path(__file__).with_name("worker.py"))
    worker = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(worker)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_owned_lab_field")
        result[key] = value
    return result


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_owned_lab_request")
    value = json.loads(raw, object_pairs_hook=_unique)
    if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
            or type(value["case"]) is not str or value["case"] not in "abcdef"
            or len(value["case"]) != 1 or type(value["deadline"]) not in {int, float}
            or not math.isfinite(value["deadline"]) or not 0 < value["deadline"] - time.monotonic() <= 600):
        raise ValueError("invalid_owned_lab_request")
    return value


def _listen(address):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(address)
        listener.listen(8)
        return listener
    except BaseException:
        listener.close()
        raise


class Service:
    """Exactly one server thread; counters are acknowledged after accepted work."""

    def __init__(self, case, listener):
        self.case = case
        self.listener = listener
        self.condition = threading.Condition()
        self.connections = 0
        self.requests = 0
        self.failed = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def response(self, path):
        allowed = {f"/assessment/{self.case}/index.json", f"/assessment/{self.case}/diagnostics.json"}
        return (worker._response(path) if path in allowed
                else (404, b'{"error":"not_found"}', b""))

    def _serve(self):
        try:
            while True:
                connection, _ = self.listener.accept()
                with self.condition:
                    self.connections += 1
                    self.condition.notify_all()
                with connection:
                    try:
                        connection.settimeout(1)
                        request = bytearray()
                        while b"\r\n\r\n" not in request and len(request) < 4096:
                            chunk = connection.recv(4096 - len(request))
                            if not chunk:
                                break
                            request.extend(chunk)
                        if not request:  # TCP discovery sends no application payload.
                            continue
                        line = bytes(request).split(b"\r\n", 1)[0].split(b" ")
                        if len(line) != 3 or line[0] not in (b"GET", b"HEAD"):
                            continue
                        path = line[1].decode("ascii")
                        with self.condition:
                            self.requests += 1
                            self.condition.notify_all()
                        status, body, extra = self.response(path)
                        headers = (f"HTTP/1.1 {status} Owned\r\nContent-Length: {len(body)}\r\n"
                                   "Connection: close\r\n").encode("ascii") + extra + b"\r\n"
                        connection.sendall(headers + (b"" if line[0] == b"HEAD" else body))
                    except (OSError, UnicodeError):
                        pass
        except BaseException:
            with self.condition:
                self.failed = True
                self.condition.notify_all()

    def snapshot(self, minimum_connections, minimum_requests, deadline):
        with self.condition:
            while self.connections < minimum_connections or self.requests < minimum_requests:
                if self.failed:
                    raise RuntimeError("owned_lab_service_failed")
                self.condition.wait(timeout=worker._remaining(deadline, 0.05))
            if self.failed or not 0 <= self.requests <= self.connections <= 16:
                raise RuntimeError("owned_lab_service_failed")
            return {"connection_count": self.connections, "request_count": self.requests}


class Owner:
    """Fixed owner lifecycle, specialized only by reviewed subclass methods."""

    def read_request(self, source):
        return read_request(source)

    def create_service(self, request, listener):
        return Service(request["case"], listener)

    def service_port(self, request):
        return 8080

    def firewall_rules(self, request):
        return worker.firewall_rules("127.0.0.1", 8080)

    def run(self):
        listeners = []
        try:
            if not stat.S_ISFIFO(os.fstat(0).st_mode):
                raise ValueError("owned_lab_requires_private_pipe")
            request = self.read_request(sys.stdin.buffer)
            worker.assert_private_namespaces(request["host_namespaces"])
            deadline = request["deadline"]
            worker._set_limits(worker._remaining(deadline, 600))
            signal.signal(signal.SIGALRM, worker._deadline)
            signal.setitimer(signal.ITIMER_REAL, worker._remaining(deadline, 600))
            port = self.service_port(request)
            for address in (("127.0.0.1", port), ("127.0.0.2", port), ("127.0.0.1", port + 1)):
                listeners.append(_listen(address))
            # Demonstrate both forbidden witnesses really accept before filtering.
            # The allowed service is untouched, so only actions advance its counters.
            for listener in listeners[1:]:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(worker._remaining(deadline, 1))
                    connection.connect(listener.getsockname())
                    accepted, _ = listener.accept()
                    accepted.close()
            subprocess.run(["/usr/sbin/nft", "-f", "-"], input=self.firewall_rules(request).encode("ascii"),
                           stdin=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                           timeout=worker._remaining(deadline, 3), env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
                           close_fds=True)
            worker.drop_privileges()
            service = self.create_service(request, listeners[0])
            resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
            worker.install_syscall_filter()
            namespaces = {name: os.readlink(f"/proc/self/ns/{name}") for name in ("user", "net", "mnt", "pid")}
            print(json.dumps({"ready": True, "namespaces": namespaces, "witness_baselines": True,
                              "connection_count": 0, "request_count": 0}, separators=(",", ":")), flush=True)
            sequence = 0
            while True:
                ready, _, _ = select.select([0, *listeners[1:]], [], [], worker._remaining(deadline, 1))
                if any(listener in ready for listener in listeners[1:]):
                    raise RuntimeError("owned_lab_witness_leak")
                if 0 not in ready:
                    continue
                raw = sys.stdin.buffer.readline(1025)
                if not raw:
                    return 0
                if len(raw) > 1024 or not raw.endswith(b"\n"):
                    raise ValueError("invalid_owned_lab_command")
                command = json.loads(raw, object_pairs_hook=_unique)
                if (type(command) is not dict or set(command) != {"sequence", "minimum_connections", "minimum_requests"}
                        or type(command["sequence"]) is not int or command["sequence"] != sequence + 1
                        or not 1 <= command["sequence"] <= 32
                        or any(type(command[key]) is not int or not 0 <= command[key] <= 16
                               for key in ("minimum_connections", "minimum_requests"))):
                    raise ValueError("invalid_owned_lab_command")
                sequence += 1
                snapshot = service.snapshot(command["minimum_connections"], command["minimum_requests"], deadline)
                print(json.dumps({"sequence": sequence, **snapshot}, separators=(",", ":")), flush=True)
        except Exception:
            sys.stderr.write("owned_lab_owner_refused\n")
            return 78
        finally:
            for listener in listeners:
                listener.close()


def main():
    return Owner().run()


if __name__ == "__main__":
    raise SystemExit(main())
