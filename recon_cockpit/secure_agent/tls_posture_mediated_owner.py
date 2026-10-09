"""Owner-private TLS relay for the unaccepted request-boundary experiment.

Only the relay owns the allowed TCP listener. The actual TLS fixture lives on
an unnamed socketpair, never on another TCP port. A complete client record is
accounted and checked before any of its bytes can reach that fixture.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import select
import socket
import threading
import time

if __package__:
    from . import tls_posture_diagnostic_fixture as fixture
    from . import tls_posture_mediator as gate_module
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    fixture = _load("t02_mediated_fixture", "tls_posture_diagnostic_fixture.py")
    gate_module = _load("t02_mediated_gate", "tls_posture_mediator.py")


OWNER_SECONDS = 30
CONNECTION_SECONDS = 5
CLIENT_BYTES = 8192
CLIENT_RECORDS = 8
SERVER_BYTES = 32768
SERVER_RECORDS = 32


def new_mediation():
    return {
        "version": "1", "completed": False, "error": None,
        "blocked": False, "block_reason": None, "blocked_record_index": None,
        "client_ingress_bytes": 0, "client_ingress_records": [],
        "client_forwarded_bytes": 0, "client_forwarded_records": [],
        "client_transmitted_bytes": 0, "server_transmitted_bytes": 0,
        "server_ingress_bytes": 0, "server_ingress_record_count": 0,
        "server_ingress_records": [], "server_pending_record": None,
        "server_forwarded_bytes": 0, "server_forwarded_records": [],
        "peer_streams_admitted": 0, "frontend_connections_admitted": 0,
        "extra_frontend_connections_refused": 0,
        "client_eof": False, "backend_eof": False,
        "connection_deadline_expired": False, "threads_joined": False,
        "gate_state": "expect_client_hello", "forwarded_client_hellos": 0,
    }


def record_description(raw, *, include_raw):
    result = {"type": raw[0], "version": raw[1:3].hex(),
              "payload_length": len(raw) - 5}
    result["raw_hex" if include_raw else "raw_sha256"] = (
        raw.hex() if include_raw else hashlib.sha256(raw).hexdigest())
    return result


def _shutdown(endpoint):
    try:
        endpoint.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    endpoint.close()


class Service:
    """One frontend stream, one private peer, and no dynamically created thread."""

    def __init__(self, request, listener):
        self.request, self.listener = request, listener
        self.condition = threading.Condition()
        self.stop = threading.Event()
        # Relay completion also sets stop. Only explicit owner cancellation
        # interrupts peer reads; an ordinary retry refusal must retain the
        # actual EOF caused by withholding and closing the private stream.
        self.cancel_peer = threading.Event()
        self.connected = threading.Event()
        self.connections, self.requests = 0, 0
        self.ledger = fixture.new_ledger(request["case"], request["version"])
        self.mediation = new_mediation()
        self.context = fixture.tls_context(request["case"], self.ledger)
        self.frontend = None
        self.deadline = None
        self.relay_done = self.peer_done = False
        # Both descriptors remain in this owner process; the client bootstrap
        # accepts only its sealed runtime descriptors and namespace handles.
        self.relay_pair, self.peer_pair = socket.socketpair()
        self.peer_thread = threading.Thread(target=self._peer, daemon=True)
        self.thread = threading.Thread(target=self._relay, daemon=True)
        try:
            self.peer_thread.start()
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def _progress(self):
        with self.condition:
            self.requests += 1
            self.condition.notify_all()

    def _wait(self, endpoint, *, readable=True):
        while not self.stop.is_set():
            left = fixture.remaining(self.deadline)
            ready, writable, _ = select.select(
                [endpoint] if readable else [], [] if readable else [endpoint], [], min(left, 0.05))
            if ready or writable:
                return
        raise ValueError("tls_mediated_cancelled")

    def _receive_record(self, endpoint, framer, direction):
        chunks = bytearray()
        size = 5
        maximum = CLIENT_BYTES if direction == "client" else SERVER_BYTES
        while len(chunks) < size:
            self._wait(endpoint)
            available = maximum - self.mediation[direction + "_ingress_bytes"]
            if available <= 0:
                raise gate_module.MediatorViolation("direction_byte_limit")
            chunk = endpoint.recv(min(size - len(chunks), available))
            if not chunk:
                framer.finish()
                if chunks:
                    raise ValueError("tls_mediated_partial_record")
                return None
            self.mediation[direction + "_ingress_bytes"] += len(chunk)
            chunks.extend(chunk)
            records = framer.feed(chunk)
            if len(chunks) == 5:
                size += int.from_bytes(chunks[3:5], "big")
                if self.mediation[direction + "_ingress_bytes"] - len(chunks) + size > maximum:
                    raise gate_module.MediatorViolation("direction_byte_limit")
            if records:
                if len(records) != 1 or records[0] != bytes(chunks):
                    raise ValueError("tls_mediated_framer_accounting")
                return records[0]
        raise ValueError("tls_mediated_empty_record")

    def _send(self, endpoint, raw, direction):
        offset = 0
        while offset < len(raw):
            self._wait(endpoint, readable=False)
            sent = endpoint.send(raw[offset:])
            if sent <= 0:
                raise ValueError("tls_mediated_send_eof")
            offset += sent
            self.mediation[direction + "_transmitted_bytes"] += sent

    def _peer(self):
        try:
            while not self.connected.wait(0.05):
                if self.stop.is_set():
                    return
                fixture.remaining(self.request["deadline"])
            if self.stop.is_set():
                return
            fixture.serve(self.peer_pair, case=self.request["case"], version=self.request["version"],
                          deadline=self.deadline, context=self.context, ledger=self.ledger,
                          on_request=self._progress, cancel_event=self.cancel_peer)
        except (ValueError, OSError) as error:
            self.ledger["error"] = (str(error)[:160] if isinstance(error, ValueError)
                                    else type(error).__name__)
        finally:
            _shutdown(self.peer_pair)
            with self.condition:
                self.ledger["completed"] = True
                self.peer_done = True
                self.condition.notify_all()

    def _accept(self):
        self.listener.settimeout(0.05)
        while not self.stop.is_set():
            fixture.remaining(self.request["deadline"])
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            self.frontend = connection
            connection.setblocking(False)
            self.relay_pair.setblocking(False)
            self.deadline = min(self.request["deadline"], time.monotonic() + CONNECTION_SECONDS)
            with self.condition:
                self.connections += 1
                self.mediation["frontend_connections_admitted"] = 1
            self.connected.set()
            return connection
        raise ValueError("tls_mediated_cancelled")

    def _relay(self):
        gate = gate_module.ClientGate(self.request["version"], fixture.validate_client_hello)
        client_framer = gate_module.RecordFramer(max_bytes=CLIENT_BYTES, max_records=CLIENT_RECORDS)
        server_framer = gate_module.RecordFramer(max_bytes=SERVER_BYTES, max_records=SERVER_RECORDS)
        direction = None
        raw = None
        try:
            frontend = self._accept()
            readable = [frontend, self.relay_pair]
            while readable and not self.stop.is_set():
                left = fixture.remaining(self.deadline)
                ready, _, _ = select.select(readable, [], [], min(left, 0.05))
                for endpoint in ready:
                    direction = "client" if endpoint is frontend else "server"
                    raw = None
                    raw = self._receive_record(endpoint,
                        client_framer if direction == "client" else server_framer, direction)
                    if raw is None:
                        readable.remove(endpoint)
                        self.mediation["client_eof" if direction == "client" else "backend_eof"] = True
                        if direction == "client":
                            self.relay_pair.shutdown(socket.SHUT_WR)
                        else:
                            frontend.shutdown(socket.SHUT_WR)
                            return
                        continue
                    if direction == "client":
                        self.mediation["client_ingress_records"].append(record_description(raw, include_raw=True))
                        gate.check(raw)
                        self._send(self.relay_pair, raw, "client")
                        gate.forwarded(raw)
                        self.mediation["client_forwarded_records"].append(record_description(raw, include_raw=True))
                        self.mediation["client_forwarded_bytes"] += len(raw)
                        self.mediation["peer_streams_admitted"] = 1
                    else:
                        self.mediation["server_ingress_record_count"] += 1
                        description = record_description(raw, include_raw=False)
                        self.mediation["server_ingress_records"].append(description)
                        self.mediation["server_pending_record"] = description
                        self._send(frontend, raw, "server")
                        self.mediation["server_forwarded_records"].append(record_description(raw, include_raw=False))
                        self.mediation["server_forwarded_bytes"] += len(raw)
                        self.mediation["server_pending_record"] = None
        except gate_module.MediatorViolation as error:
            self.mediation["blocked"] = True
            self.mediation["block_reason"] = error.code
            if direction == "client" and raw is not None:
                index = len(self.mediation["client_ingress_records"]) - 1
                if index >= 0 and self.mediation["client_ingress_records"][index]["raw_hex"] == raw.hex():
                    self.mediation["blocked_record_index"] = index
        except (ValueError, OSError) as error:
            self.mediation["error"] = (str(error)[:160] if isinstance(error, ValueError)
                                       else type(error).__name__)
            if isinstance(error, ValueError) and str(error) == "tls_posture_owner_deadline":
                self.mediation["connection_deadline_expired"] = True
        finally:
            self.mediation["gate_state"] = gate.state
            self.mediation["forwarded_client_hellos"] = gate.forwarded_client_hellos
            if self.frontend is not None:
                _shutdown(self.frontend)
            _shutdown(self.relay_pair)
            self.stop.set()
            self.connected.set()
            with self.condition:
                self.relay_done = True
                self.condition.notify_all()

    def _join(self, deadline):
        for thread in (self.thread, self.peer_thread):
            if thread.ident is not None:
                thread.join(timeout=max(0, deadline - time.monotonic()))
        self.mediation["threads_joined"] = not self.thread.is_alive() and not self.peer_thread.is_alive()
        self.mediation["completed"] = self.mediation["threads_joined"] and self.relay_done and self.peer_done
        if not self.mediation["completed"]:
            raise ValueError("tls_mediated_threads_unfinished")

    def close(self):
        self.cancel_peer.set()
        self.stop.set()
        self.connected.set()
        if self.frontend is not None:
            _shutdown(self.frontend)
        _shutdown(self.relay_pair)
        _shutdown(self.peer_pair)
        self._join(time.monotonic() + 0.5)

    def snapshot(self, minimum_connections, minimum_requests, deadline):
        del minimum_connections, minimum_requests  # Failed attempts are evidence too.
        with self.condition:
            if not self.connections:
                self.stop.set()
                self.connected.set()
            while not (self.relay_done and self.peer_done):
                self.condition.wait(timeout=min(0.05, fixture.remaining(deadline)))
        self._join(deadline)
        # A queued extra TCP connection has already reached the listener. It is
        # refused a peer stream; this never claims that its connect was blocked.
        self.listener.settimeout(min(0.001, fixture.remaining(deadline)))
        try:
            extra, _ = self.listener.accept()
        except socket.timeout:
            pass
        else:
            extra.close()
            self.connections += 1
            self.mediation["extra_frontend_connections_refused"] = 1
        return {"connection_count": self.connections, "request_count": self.requests,
                "diagnostic": self.ledger, "mediation": self.mediation}


class MediatedOwner(fixture.owner.Owner):
    def read_request(self, source):
        request = fixture.read_request(source)
        if request["deadline"] - time.monotonic() > OWNER_SECONDS:
            raise ValueError("tls_mediated_owner_deadline")
        return request

    def create_service(self, request, listener):
        self.service = Service(request, listener)
        return self.service

    def run(self):
        self.service = None
        try:
            return super().run()
        finally:
            if self.service is not None:
                self.service.close()


def main():
    return MediatedOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
