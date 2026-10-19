"""One-use bounded mediator over borrowed listener and handed private socket.

The service creates no sockets, enters no namespaces and opens no files. Its
budget object is the trusted role-bound owner channel; failure cannot replenish
reservations. Native status and parsing are deliberately outside this recorder.
"""

import errno
import hashlib
import select
import socket
import time

from . import name_tls_wire as wire
from .http_headers_parser import parse_http_headers

LIMITS = {"dns": (512, 4096), "http": (256, 2048), "tls": (8192, 16384)}


class Service:
    """An action's recorder; the persistent frontend retains the listener."""

    def __init__(self, operation, listener, daemon_socket, *, configuration, case, deadline, budget,
                 second_observation=False, clock=time.monotonic):
        row = wire.selection(configuration, case)
        if (operation not in LIMITS or type(second_observation) is not bool
                or second_observation and (operation != "dns" or case != "N1")
                or not callable(clock) or deadline <= clock()):
            raise ValueError("name_tls_recorder_configuration")
        for method in ("connection", "request", "before_write", "after_write", "observe_dns", "finish"):
            if not callable(getattr(budget, method, None)):
                raise ValueError("name_tls_recorder_budget")
        self.operation, self.configuration, self.case = operation, configuration, case
        self.listener, self.daemon, self.budget = listener, daemon_socket, budget
        self.deadline, self.clock, self.second_observation = deadline, clock, second_observation
        self.endpoint = (row[0], row[1]) if operation == "dns" else (row[2], row[3] if operation == "http" else row[5])
        self.request_cap, self.response_cap = LIMITS[operation]
        self.client, self.active, self.done, self.reason = None, None, False, None
        self.reserved = self.validated = self.connect_started = self.connected = False
        self.client_eof = self.daemon_eof = self.response_complete = False
        self.daemon_write_closed = False
        self.client_pending, self.server_pending = bytearray(), bytearray()
        self.to_daemon, self.to_client = bytearray(), bytearray()
        self.raw = {key: bytearray() for key in ("request", "delivered_request", "original_response",
                                                "proposed_response", "delivered_response")}
        self.client_hello, self.server_plaintext, self.server_records = None, bytearray(), bytearray()
        self.server_hello_validated = False
        self.client_records = self.daemon_records = self.ccs_client = self.ccs_server = 0
        self.client_encrypted = self.server_encrypted = False
        self.client_terminal_alert = False
        self.server_encrypted_delivery_end = None
        self.accepted_connections = self.operation_count = self.daemon_connects = 0
        self.delivery_unknown = False
        self.chunks, self.next_chunk_at = [], 0.0
        self.listener.setblocking(False)
        self.daemon.setblocking(False)

    def raw_streams(self):
        return {key: bytes(value) for key, value in self.raw.items()}

    def snapshot(self):
        value = {"schema_version": "1", "operation": self.operation, "configuration": self.configuration,
                 "case": self.case, "done": self.done, "reason": self.reason,
                 "accepted_connections": self.accepted_connections, "admitted_connections": int(self.reserved),
                 "operations_validated": self.operation_count, "daemon_connects": self.daemon_connects,
                 "client_records": self.client_records, "daemon_records": self.daemon_records,
                 "request_bytes_delivered": len(self.raw["delivered_request"]),
                 "response_bytes_delivered": len(self.raw["delivered_response"]), "delivery_unknown": self.delivery_unknown,
                 "streams": {key: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                             for key, raw in self.raw.items()}}
        return {**value, "transcript_sha256": wire.semantic_digest(value)}

    def close(self, reason="cancelled"):
        if self.done:
            return
        self.done, self.reason = True, reason
        for stream in (self.client, self.daemon):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    self.delivery_unknown = True
        self.client, self.daemon, self.active = None, None, None
        if self.reserved:
            try:
                self.budget.finish(request_bytes=len(self.raw["delivered_request"]),
                                   response_bytes=len(self.raw["delivered_response"]),
                                   transcript_sha256=self.snapshot()["transcript_sha256"], reason=reason)
            except Exception:
                self.delivery_unknown = True
                if reason == "complete":
                    self.reason = "owner_channel_lost"

    def _accept(self):
        try:
            client, _ = self.listener.accept()
        except BlockingIOError:
            return
        self.accepted_connections += 1
        if self.client is not None or self.accepted_connections != 1:
            client.close()
            raise ValueError("extra_connection")
        client.setblocking(False)
        self.client, self.active = client, {}

    def _admit(self):
        if self.client is not None and not self.reserved:
            self.reserved = bool(self.budget.connection(1))

    def _validate_request(self):
        raw = bytes(self.client_pending)
        if self.operation == "dns":
            if len(raw) < 2:
                return
            expected = 2 + int.from_bytes(raw[:2], "big")
            if expected > self.request_cap:
                raise ValueError("request_limit")
            if len(raw) < expected:
                return
            wire.parse_dns_query(raw)
        elif self.operation == "http":
            expected = wire.http_request(self.configuration, self.case)
            if not expected.startswith(raw):
                raise ValueError("http_request_mismatch")
            if raw != expected:
                return
        else:
            expected = wire.tls_client_hello_length(raw)
            if expected is None or len(raw) < expected:
                return
            wire.validate_tls_client_hello(raw[:expected])
            self.client_hello = raw[:expected]
            self.client_records = 1
            raw = raw[:expected]
        self.budget.request(self.operation)
        self.validated, self.operation_count = True, 1
        self.to_daemon.extend(raw)
        del self.client_pending[:len(raw)]
        self.connect_started, self.daemon_connects = True, 1
        error = self.daemon.connect_ex(self.endpoint)
        if error not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            raise OSError(error, "private_connect_failed")
        self.connected = error == 0
        if self.client_pending:
            self._client_records()

    @staticmethod
    def _record(buffer):
        if len(buffer) < 5:
            return None
        kind, version, size = buffer[0], buffer[1:3], int.from_bytes(buffer[3:5], "big")
        if kind not in (20, 21, 22, 23) or version not in (b"\3\1", b"\3\3") or not 0 < size <= 18432:
            raise ValueError("tls_record_header")
        if len(buffer) < size + 5:
            return None
        raw = bytes(buffer[:size + 5])
        del buffer[:size + 5]
        return kind, raw[5:], raw

    def _client_records(self):
        if self.operation != "tls":
            if self.client_pending:
                raise ValueError("additional_request")
            return
        while True:
            if self.client_terminal_alert and self.client_pending:
                raise ValueError("additional_tls_handshake")
            record = self._record(self.client_pending)
            if record is None:
                return
            kind, body, raw = record
            self.client_records += 1
            if self.client_records > 32:
                raise ValueError("tls_record_count")
            if kind == 20 and body == b"\1" and not self.ccs_client and not self.client_encrypted:
                self.ccs_client = 1
            elif (raw == wire.tls_verification_alert(self.case) and not self.client_encrypted
                    and self.server_hello_validated and self.server_encrypted_delivery_end is not None
                    and len(self.raw["delivered_response"]) >= self.server_encrypted_delivery_end):
                self.client_terminal_alert = True
            elif kind == 23 and len(body) >= 17 and wire.tls_verification_alert(self.case) is None:
                self.client_encrypted = True
            else:
                raise ValueError("additional_tls_handshake")
            self.to_daemon.extend(raw)

    def _read_client(self):
        chunk = self.client.recv(min(4096, self.request_cap - len(self.raw["request"]) + 1))
        if not chunk:
            self.client_eof = True
            if self.client_pending or not self.validated:
                raise ValueError("incomplete_request")
            if (self.operation == "tls" and wire.tls_verification_alert(self.case) is not None
                    and not self.client_terminal_alert):
                raise ValueError("incomplete_verification_alert")
            return
        if len(self.raw["request"]) + len(chunk) > self.request_cap:
            raise ValueError("request_limit")
        self.raw["request"].extend(chunk)
        self.client_pending.extend(chunk)
        if not self.validated:
            self._validate_request()
        else:
            self._client_records()

    def _queue_response(self, raw):
        if len(self.raw["proposed_response"]) + len(raw) > self.response_cap:
            raise ValueError("response_limit")
        self.raw["proposed_response"].extend(raw)
        self.to_client.extend(raw)

    def _server_tls_records(self):
        while True:
            record = self._record(self.server_pending)
            if record is None:
                return
            kind, body, raw = record
            self.daemon_records += 1
            if self.daemon_records > 32:
                raise ValueError("tls_record_count")
            if not self.server_hello_validated:
                if self.case == "N16" and self.daemon_records == 1 and kind == 21 and body == b"\2F":
                    self.server_hello_validated = True
                    self._queue_response(raw)
                    continue
                if kind != 22:
                    raise ValueError("tls_missing_server_hello")
                self.server_plaintext.extend(body)
                self.server_records.extend(raw)
                if len(self.server_plaintext) < 4:
                    continue
                length = 4 + int.from_bytes(self.server_plaintext[1:4], "big")
                if length > self.response_cap:
                    raise ValueError("tls_server_hello_limit")
                if len(self.server_plaintext) < length:
                    continue
                wire.validate_tls_server_hello(bytes(self.server_plaintext), self.client_hello)
                self.server_hello_validated = True
                self._queue_response(bytes(self.server_records))
            elif kind == 20 and body == b"\1" and not self.ccs_server and not self.server_encrypted:
                self.ccs_server = 1
                self._queue_response(raw)
            elif kind == 23 and len(body) >= 17 and self.case != "N16":
                self.server_encrypted = True
                if self.server_encrypted_delivery_end is None:
                    self.server_encrypted_delivery_end = len(self.raw["proposed_response"]) + len(raw)
                self._queue_response(raw)
            else:
                raise ValueError("additional_server_handshake")

    def _complete_dns(self, *, eof=False):
        raw = bytes(self.server_pending)
        if len(raw) < 2:
            if eof:
                raise ValueError("incomplete_dns_response")
            return
        length = 2 + int.from_bytes(raw[:2], "big")
        if length > self.response_cap:
            raise ValueError("response_limit")
        if len(raw) < length:
            if eof:
                raise ValueError("incomplete_dns_response")
            return
        request = bytes(self.raw["request"])
        wire.parse_dns_response(raw, request)
        # A second frame can arrive in a later TCP read. The sole query is
        # half-closed below; require the daemon's EOF before releasing any
        # response bytes or making an owner observation.
        if not eof:
            return
        response = wire.transformed_dns_response(self.configuration, self.case, request, raw,
                                                second_observation=self.second_observation)
        self.server_pending.clear()
        self.response_complete = True
        if self.case == "R2":
            self.chunks = [response[:1], response[1:2], response[2:13], response[13:]]
            self.next_chunk_at = self.clock()
        else:
            self._queue_response(response)

    def _read_daemon(self):
        chunk = self.daemon.recv(min(4096, self.response_cap - len(self.raw["original_response"]) + 1))
        if not chunk:
            self.daemon_eof = True
            if self.operation == "http":
                raw = bytes(self.server_pending)
                parse_http_headers(raw)
                if len(raw.partition(b"\r\n\r\n")[0]) + 4 > 1024:
                    raise ValueError("http_header_limit")
                self.server_pending.clear()
                self._queue_response(raw)
                self.response_complete = True
            elif self.operation == "dns":
                self._complete_dns(eof=True)
            elif self.operation == "tls":
                if self.server_pending or not self.server_hello_validated:
                    raise ValueError("incomplete_tls_response")
                self.response_complete = True
            return
        if len(self.raw["original_response"]) + len(chunk) > self.response_cap:
            raise ValueError("response_limit")
        if self.response_complete:
            raise ValueError("additional_response")
        self.raw["original_response"].extend(chunk)
        self.server_pending.extend(chunk)
        if self.operation == "dns":
            self._complete_dns()
        elif self.operation == "tls":
            self._server_tls_records()

    def _write(self, stream, pending, direction, raw_key):
        if not pending:
            return
        self.budget.before_write(self.active, direction, len(pending))
        count = stream.send(pending)
        if count <= 0:
            raise OSError("zero_write")
        self.raw[raw_key].extend(pending[:count])
        del pending[:count]
        self.budget.after_write(self.active, direction, count)
        if direction == "response" and not pending and self.chunks:
            self.next_chunk_at = self.clock() + .005

    def tick(self):
        if self.done:
            return
        try:
            if self.clock() >= self.deadline:
                self.close("timeout")
                return
            self._accept()
            self._admit()
            if not self.reserved:
                return
            if self.chunks and not self.to_client and self.clock() >= self.next_chunk_at:
                self._queue_response(self.chunks.pop(0))
            readers = ([self.client] if not self.client_eof else [])
            if self.connected and not self.daemon_eof:
                readers.append(self.daemon)
            writers = ([self.daemon] if self.connect_started and (not self.connected or self.to_daemon) else [])
            if self.to_client:
                writers.append(self.client)
            readable, writable, _ = select.select(readers, writers, [], 0)
            if self.daemon in writable:
                if not self.connected:
                    error = self.daemon.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if error:
                        raise OSError(error, "private_connect_failed")
                    self.connected = True
                self._write(self.daemon, self.to_daemon, "request", "delivered_request")
            if self.client in readable:
                self._read_client()
            if self.daemon in readable:
                self._read_daemon()
            if self.client in writable:
                self._write(self.client, self.to_client, "response", "delivered_response")
            if (self.connected and not self.daemon_write_closed and not self.to_daemon
                    and (self.client_eof or self.operation == "dns" and self.validated)):
                try:
                    self.daemon.shutdown(socket.SHUT_WR)
                except OSError:
                    if self.operation == "dns":
                        raise
                self.daemon_write_closed = True
            verification_complete = (self.operation != "tls" or wire.tls_verification_alert(self.case) is None
                                     or self.client_terminal_alert and self.client_eof and self.daemon_eof)
            if (self.response_complete and not self.to_client and not self.chunks and not self.to_daemon
                    and verification_complete):
                if self.operation == "dns" and self.case != "N8":
                    request, original, delivered = (bytes(self.raw[k]) for k in ("request", "original_response", "delivered_response"))
                    self.budget.observe_dns(wire.parse_dns_response(delivered, request),
                                            request_sha256=hashlib.sha256(request).hexdigest(),
                                            original_sha256=hashlib.sha256(original).hexdigest(),
                                            delivered_sha256=hashlib.sha256(delivered).hexdigest())
                self.close("complete")
        except BlockingIOError:
            return
        except (ValueError, OSError) as error:
            reason = str(error) if isinstance(error, ValueError) else "io_failure"
            self.close(reason if len(reason) <= 64 else "protocol_refused")
        except Exception:
            self.delivery_unknown = True
            self.close("owner_channel_lost")
