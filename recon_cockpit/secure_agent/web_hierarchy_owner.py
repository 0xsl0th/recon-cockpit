"""One select-driven HTTP owner for a disconnected development diagnostic.

The independent in-flight high-water mark includes requests waiting for their
delayed reply. Accepting and reading other sockets during that delay makes
concurrent native requests observable; a serial server would conceal them.
"""

import base64
import importlib.util
import json
import math
from pathlib import Path
import select
import threading
import time

if __package__:
    from . import owned_lab_worker as owner
    from . import web_hierarchy_fixture as fixture
    from . import web_hierarchy_spec as spec
else:
    def _load(name, filename):
        definition = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(definition)
        definition.loader.exec_module(module)
        return module
    owner = _load("hierarchy_base_owner", "owned_lab_worker.py")
    fixture = _load("hierarchy_fixture", "web_hierarchy_fixture.py")
    spec = _load("hierarchy_owner_spec", "web_hierarchy_spec.py")


RESPONSE_DELAY_SECONDS = 0.05


def _encoded(raw):
    return base64.b64encode(raw).decode("ascii")


class Service:
    def __init__(self, request, listener):
        self.case = spec.validate_case(request["case"])
        self.deadline = request["deadline"]
        self.listener = listener
        self.listener.setblocking(False)
        self.condition = threading.Condition()
        self.connections = self.requests = self.active_requests = self.max_active_requests = 0
        self.ledger, self.errors, self.pending = [], [], {}
        self.seen = set()
        self.stopping = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _error(self, reason):
        # Closed internal reason vocabulary; peer strings never enter errors.
        if reason not in self.errors and len(self.errors) < spec.MAX_CONNECTIONS:
            self.errors.append(reason)

    def _close_connection(self, connection):
        state = self.pending.pop(connection)
        if state["entry"] is not None:
            self.active_requests -= 1
        connection.close()
        self.condition.notify_all()

    def _begin_request(self, connection, state, now):
        raw = bytes(state["received"])
        method, path, status, response = "", "", 0, b""
        try:
            method, path = fixture.validate_request(raw)
            if path in self.seen:
                self._error("duplicate_path")
            else:
                self.seen.add(path)
            response = fixture.wire_response(self.case, path)
            status = int(response.split(b" ", 2)[1])
        except ValueError as error:
            if str(error) == "unexpected_hierarchy_path":
                self._error("unexpected_path")
            else:
                self._error("invalid_request")
        entry = {"raw_request_base64": _encoded(raw), "response_base64": "",
                 "method": method, "path": path, "status_code": status, "completed": False}
        self.ledger.append(entry)
        self.requests += 1
        self.active_requests += 1
        self.max_active_requests = max(self.max_active_requests, self.active_requests)
        state.update(entry=entry, response=response, due=now + RESPONSE_DELAY_SECONDS)
        self.condition.notify_all()
        if not response:
            self._close_connection(connection)

    def _read(self, connection, now):
        state = self.pending[connection]
        remaining = spec.MAX_REQUEST_BYTES - len(state["received"])
        if remaining <= 0:
            self._error("request_limit")
            if state["entry"] is None:
                self._begin_request(connection, state, now)
            if connection in self.pending:
                self._close_connection(connection)
            return
        try:
            chunk = connection.recv(remaining)
        except BlockingIOError:
            return
        except OSError:
            self._error("request_read")
            self._close_connection(connection)
            return
        if not chunk:
            if state["entry"] is None:
                if state["received"]:
                    self._begin_request(connection, state, now)
                else:
                    self._error("empty_connection")
            if connection in self.pending:
                self._close_connection(connection)
            return
        state["received"].extend(chunk)
        if state["entry"] is not None:
            state["entry"]["raw_request_base64"] = _encoded(bytes(state["received"]))
            self._error("extra_request_bytes")
            self._close_connection(connection)
        elif b"\r\n\r\n" in state["received"] or len(state["received"]) == spec.MAX_REQUEST_BYTES:
            self._begin_request(connection, state, now)

    def _write(self, connection):
        state = self.pending[connection]
        try:
            count = connection.send(state["response"][state["sent"]:])
        except BlockingIOError:
            return
        except OSError:
            self._error("response_write")
            self._close_connection(connection)
            return
        if type(count) is not int or not 0 < count <= len(state["response"]) - state["sent"]:
            self._error("response_write")
            self._close_connection(connection)
            return
        state["sent"] += count
        state["entry"]["response_base64"] = _encoded(state["response"][:state["sent"]])
        if state["sent"] == len(state["response"]):
            state["entry"]["completed"] = True
            self._close_connection(connection)

    def _poll_once(self):
        now = time.monotonic()
        if now >= self.deadline:
            self.stopping = True
            return
        readers = ([self.listener] if self.listener is not None else []) + list(self.pending)
        writers = [connection for connection, state in self.pending.items()
                   if state["entry"] is not None and state["due"] <= now and self.case != "stalled"]
        readable, writable, _ = select.select(readers, writers, [], min(0.01, self.deadline - now))
        with self.condition:
            if self.listener in readable:
                try:
                    connection, _ = self.listener.accept()
                except BlockingIOError:
                    connection = None
                if connection is not None:
                    connection.setblocking(False)
                    self.connections += 1
                    self.pending[connection] = {"received": bytearray(), "entry": None,
                        "response": b"", "sent": 0, "due": self.deadline}
                    if self.connections == spec.MAX_CONNECTIONS:
                        self.listener.close()
                        self.listener = None
                    self.condition.notify_all()
            for connection in readable:
                if connection in self.pending:
                    self._read(connection, time.monotonic())
            for connection in writable:
                if connection in self.pending:
                    self._write(connection)

    def _serve(self):
        try:
            while not self.stopping:
                self._poll_once()
        except Exception:
            with self.condition:
                self._error("service_failed")
        finally:
            with self.condition:
                for connection in list(self.pending):
                    self._close_connection(connection)
                self.stopping = True
                self.condition.notify_all()

    def snapshot(self, minimum_connections, minimum_requests, deadline):
        with self.condition:
            while self.connections < minimum_connections or self.requests < minimum_requests:
                if self.stopping:
                    raise RuntimeError("hierarchy_service_stopped")
                self.condition.wait(timeout=owner.worker._remaining(deadline, 0.05))
            value = {"connection_count": self.connections, "request_count": self.requests,
                "diagnostic": {"case": self.case, "ledger": self.ledger,
                    "max_active_requests": self.max_active_requests, "errors": self.errors}}
            raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                             allow_nan=False).encode("ascii")
            if len(raw) > spec.MAX_OWNER_MESSAGE - 1024:
                raise ValueError("hierarchy_owner_record_limit")
            return json.loads(raw)

    def close(self):
        self.stopping = True
        self.thread.join(timeout=1)
        if self.thread.is_alive():
            raise RuntimeError("hierarchy_owner_thread_survived")


class Owner(owner.Owner):
    def read_request(self, source):
        raw = source.readline(8193)
        if len(raw) > 8192 or not raw.endswith(b"\n"):
            raise ValueError("invalid_hierarchy_owner_request")
        value = json.loads(raw, object_pairs_hook=owner._unique)
        if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
                or type(value["deadline"]) not in {int, float}
                or not math.isfinite(value["deadline"])
                or not 0 < value["deadline"] - time.monotonic() <= spec.SESSION_SECONDS):
            raise ValueError("invalid_hierarchy_owner_request")
        spec.validate_case(value["case"])
        return value

    def create_service(self, request, listener):
        self.service = Service(request, listener)
        return self.service

    def run(self):
        try:
            return super().run()
        finally:
            if hasattr(self, "service"):
                self.service.close()


def main():
    return Owner().run()


if __name__ == "__main__":
    raise SystemExit(main())
