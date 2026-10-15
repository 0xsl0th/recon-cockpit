"""Closed, single-process stock HTTP transport recorder; no launch authority.

The namespace owner supplies the listener and explicitly arms a short action
window after authorization. This module creates only the fixed private Unix
connection, never a process, thread, target address or arbitrary request.
"""

import copy
import errno
import json
import math
import select
import socket
import struct
import time


CONFIGURATIONS = {"A": ("10.77.0.10", 8080, "/harbordesk/portal.html"),
                  "B": ("172.23.0.10", 18080, "/portal/index.html")}
CASES = ("O1", "O2", "O3", "O4", "O5", "O6", "R1", "R2", "N1", "N2", "N3", "N4", "N5")
PRIVATE_PATH = "/peer/nginx.sock"
MAX_EVENTS = 64
MAX_LEDGER_BYTES = 1024 * 1024
POLL_SECONDS = 0.01


def _selection(configuration, case):
    if type(configuration) is not str or configuration not in CONFIGURATIONS or type(case) is not str or case not in CASES:
        raise ValueError("invalid_stock_recorder_selection")
    return configuration, case


def request_bytes(configuration, case):
    _selection(configuration, case)
    if case in ("O5", "O6"):
        return b"GET / HTTP/1.0\r\n\r\n"
    target, port, path = CONFIGURATIONS[configuration]
    return f"GET {path} HTTP/1.1\r\nHost: {target}:{port}\r\nConnection: close\r\n\r\n".encode("ascii")


def _private_connection():
    daemon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    daemon.setblocking(False)
    try:
        result = daemon.connect_ex(PRIVATE_PATH)
        if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            raise OSError(result, "stock private daemon unavailable")
        return daemon
    except BaseException:
        daemon.close()
        raise


def _response(raw, maximum):
    """Validate a complete bounded daemon reply before fault injection."""
    if type(raw) is not bytes or not raw or len(raw) > maximum or b"\r\n\r\n" not in raw:
        raise ValueError("invalid_stock_daemon_response")
    header, body = raw.split(b"\r\n\r\n", 1)
    lines = header.split(b"\r\n")
    status = lines[0].split(b" ", 2)
    if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or status[1] not in (b"200", b"302", b"404"):
        raise ValueError("invalid_stock_daemon_status")
    lengths = []
    for line in lines[1:]:
        if b":" not in line or line[:1] in (b" ", b"\t"):
            raise ValueError("invalid_stock_daemon_header")
        name, value = line.split(b":", 1)
        if name.lower() == b"transfer-encoding":
            raise ValueError("unsupported_stock_daemon_encoding")
        if name.lower() == b"content-length":
            value = value.strip()
            if not value.isdigit() or len(value) > 5:
                raise ValueError("invalid_stock_daemon_length")
            lengths.append(int(value))
    if lengths != [len(body)] or not body:
        raise ValueError("invalid_stock_daemon_body")
    return len(header) + 4, len(body)


def transform_response(case, raw):
    """Return bounded write chunks, delays and disposition for a real reply."""
    _selection("A", case)
    boundary, length = _response(raw, 4096 if case in ("O5", "O6") else 2049)
    if case == "R2":
        if length < 2:
            raise ValueError("stock_fragment_body_too_short")
        points = (0, 1, boundary - 2, boundary + length // 2, len(raw))
        return [raw[points[i]:points[i + 1]] for i in range(4)], 0.005, "fragmented"
    if case == "N1":
        return [raw[:-1]], 0.0, "truncated_body"
    if case == "N2":
        return [raw[:1]], 0.0, "reset_before_header"
    if case == "N3":
        return [], 0.0, "withheld_until_deadline"
    if case == "N4":
        if len(raw) >= 2049:
            raise ValueError("stock_overflow_requires_smaller_original")
        return [raw + b"X" * (2049 - len(raw))], 0.0, "overflow_2049"
    if case == "N5":
        changed = raw[:boundary - 2] + b"Content-Length: " + str(length + 1).encode("ascii") + b"\r\n" + raw[boundary - 2:]
        if len(changed) > 2049:
            raise ValueError("stock_duplicate_header_limit")
        return [changed], 0.0, "conflicting_content_length"
    return [raw], 0.0, "unchanged"


_COUNTERS = ("connections_attempted", "connections_admitted", "connections_denied", "requests_validated",
             "requests_delivered", "request_bytes_received", "request_bytes_delivered", "daemon_connections",
             "daemon_response_bytes", "client_response_bytes")
_REASONS = {"running", "closed", "action_deadline", "owner_deadline", "cancelled", "event_limit", "io_failure",
            "daemon_response_invalid", "daemon_response_limit", "fragment_write_partial"}
_EVENT_KINDS = {"attempt", "admit", "deny", "empty", "received", "forwarded", "daemon_received", "validated", "delivered", "daemon_response", "transform", "complete"}
_EVENT_REASONS = {"", "not_armed", "connection_limit", "request_limit", "request_mismatch", "request_incomplete",
                  "extra_request_bytes", "empty_header_request", "unchanged", "fragmented", "truncated_body",
                  "reset_before_header", "withheld_until_deadline", "overflow_2049", "conflicting_content_length"}


def validate_snapshot(value, *, configuration=None, case=None):
    if type(value) is not dict:
        raise ValueError("invalid_stock_recorder_snapshot")
    keys = {"schema_version", "configuration", "case", "armed", "finalized", "terminal_reason", "pending_connections",
            "active_connections", "original_response_hex", "transformed_response_hex", "admissions_elapsed_ms", "events", "writes", *_COUNTERS}
    if set(value) != keys or value["schema_version"] != "1":
        raise ValueError("invalid_stock_recorder_snapshot")
    selected, selected_case = _selection(value["configuration"], value["case"])
    if configuration is not None and selected != configuration or case is not None and selected_case != case:
        raise ValueError("stock_recorder_selection_mismatch")
    nmap = selected_case in ("O5", "O6")
    maximum = 4096 if nmap else 2049
    for key in (*_COUNTERS, "pending_connections", "active_connections"):
        if type(value[key]) is not int or not 0 <= value[key] <= 65536:
            raise ValueError("invalid_stock_recorder_counter")
    if (value["active_connections"] > 1 or value["pending_connections"] > 3
            or value["connections_attempted"] > MAX_EVENTS or value["connections_admitted"] > (3 if nmap else 1)
            or value["connections_denied"] > value["connections_attempted"]
            or value["connections_admitted"] > value["connections_attempted"]
            or not 0 <= value["requests_delivered"] <= value["requests_validated"] <= 1
            or not value["requests_delivered"] <= value["daemon_connections"] <= value["requests_validated"]
            or value["request_bytes_delivered"] > len(request_bytes(selected, selected_case))
            or value["daemon_response_bytes"] > maximum or value["client_response_bytes"] > maximum):
        raise ValueError("stock_recorder_budget_mismatch")
    if value["requests_delivered"] and value["request_bytes_delivered"] != len(request_bytes(selected, selected_case)):
        raise ValueError("stock_recorder_delivery_mismatch")
    for key in ("armed", "finalized"):
        if type(value[key]) is not bool:
            raise ValueError("invalid_stock_recorder_flag")
    if not value["armed"] and (value["connections_admitted"] or value["requests_validated"] or value["daemon_response_bytes"]):
        raise ValueError("stock_recorder_unarmed_activity")
    if type(value["terminal_reason"]) is not str or value["terminal_reason"] not in _REASONS:
        raise ValueError("invalid_stock_recorder_reason")
    if value["finalized"] != (value["terminal_reason"] != "running") or value["finalized"] and (value["pending_connections"] or value["active_connections"]):
        raise ValueError("stock_recorder_finalization_mismatch")
    streams = []
    for key in ("original_response_hex", "transformed_response_hex"):
        raw = value[key]
        if type(raw) is not str or len(raw) > 2 * maximum or len(raw) % 2 or any(c not in "0123456789abcdef" for c in raw):
            raise ValueError("invalid_stock_recorder_stream")
        streams.append(bytes.fromhex(raw))
    if len(streams[0]) != value["daemon_response_bytes"] or len(streams[1]) < value["client_response_bytes"]:
        raise ValueError("stock_recorder_stream_mismatch")
    admissions = value["admissions_elapsed_ms"]
    if (type(admissions) is not list or len(admissions) != value["connections_admitted"]
            or any(type(n) is not int or not 0 <= n <= 60000 for n in admissions)
            or any(b - a < 249 for a, b in zip(admissions, admissions[1:]))):
        raise ValueError("stock_recorder_rate_mismatch")
    for key in ("events", "writes"):
        rows = value[key]
        if type(rows) is not list or len(rows) > MAX_EVENTS:
            raise ValueError("stock_recorder_ledger_limit")
        for row in rows:
            expected = {"kind", "elapsed_ms", "connection", "bytes", "reason"} if key == "events" else {"offset", "bytes", "elapsed_ms"}
            if type(row) is not dict or set(row) != expected:
                raise ValueError("invalid_stock_recorder_event")
            for field in expected - {"kind", "reason"}:
                if type(row[field]) is not int or not 0 <= row[field] <= 65536:
                    raise ValueError("invalid_stock_recorder_event_counter")
            if key == "events" and (type(row["kind"]) is not str or row["kind"] not in _EVENT_KINDS or type(row["reason"]) is not str or row["reason"] not in _EVENT_REASONS):
                raise ValueError("invalid_stock_recorder_event_kind")
    offset = 0
    for write in value["writes"]:
        if write["offset"] != offset or not write["bytes"]:
            raise ValueError("stock_recorder_write_mismatch")
        offset += write["bytes"]
    if offset != value["client_response_bytes"]:
        raise ValueError("stock_recorder_write_mismatch")
    # Events and aggregate counters are independently serialized representations
    # of the same bounded exchanges; removing either must invalidate replay.
    events = value["events"]
    terminal_limit = value["terminal_reason"] == "event_limit"
    for kind, counter in (("attempt", "connections_attempted"), ("admit", "connections_admitted"),
                          ("deny", "connections_denied"), ("validated", "requests_validated"), ("delivered", "requests_delivered")):
        count = sum(row["kind"] == kind for row in events)
        if value[counter] != count and not (terminal_limit and value[counter] == count + 1):
            raise ValueError("stock_recorder_event_counter_mismatch")
    for kind, counter in (("received", "request_bytes_received"), ("forwarded", "request_bytes_delivered"),
                          ("daemon_received", "daemon_response_bytes")):
        count = sum(row["bytes"] for row in events if row["kind"] == kind)
        if value[counter] != count and not (terminal_limit and count <= value[counter] <= count + maximum + 1):
            raise ValueError("stock_recorder_event_byte_mismatch")
    attempts = [row["connection"] for row in events if row["kind"] == "attempt"]
    admits = [row["connection"] for row in events if row["kind"] == "admit"]
    if attempts != list(range(1, len(attempts) + 1)) or len(set(admits)) != len(admits) or not set(admits) <= set(attempts):
        raise ValueError("stock_recorder_connection_event_mismatch")
    if not terminal_limit and [row["elapsed_ms"] for row in events if row["kind"] == "admit"] != admissions:
        raise ValueError("stock_recorder_admission_event_mismatch")
    for row in events:
        if row["kind"] != "attempt" and row["connection"] not in attempts:
            raise ValueError("stock_recorder_unknown_connection_event")
        if row["kind"] not in ("attempt", "deny") and row["connection"] not in admits:
            raise ValueError("stock_recorder_unadmitted_event")
        if row["kind"] in ("validated", "delivered") and row["bytes"] != len(request_bytes(selected, selected_case)):
            raise ValueError("stock_recorder_request_event_mismatch")
        if row["kind"] == "daemon_response" and row["bytes"] != value["daemon_response_bytes"]:
            raise ValueError("stock_recorder_response_event_mismatch")
        if row["kind"] == "complete" and row["bytes"] != value["client_response_bytes"]:
            raise ValueError("stock_recorder_completion_event_mismatch")
    if any(row["kind"] == "transform" for row in value["events"]):
        expected, _, _ = transform_response(selected_case, streams[0])
        if streams[1] != b"".join(expected):
            raise ValueError("stock_recorder_transform_mismatch")
    if len(json.dumps(value, sort_keys=True, separators=(",", ":"))) > MAX_LEDGER_BYTES:
        raise ValueError("stock_recorder_ledger_limit")
    return copy.deepcopy(value)


class Service:
    """Owner-driven nonblocking recorder, with at most one admitted connection."""

    def __init__(self, configuration, case, listener, *, daemon_path=PRIVATE_PATH, deadline):
        _selection(configuration, case)
        now = time.monotonic()
        if (daemon_path != PRIVATE_PATH or type(deadline) not in (float, int) or not math.isfinite(deadline)
                or not 0 < deadline - now <= 60 or not isinstance(listener, socket.socket)
                or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM):
            raise ValueError("invalid_stock_recorder_startup")
        self.configuration, self.case, self.listener = configuration, case, listener
        self.deadline, self.started = deadline, now
        self.action_deadline = None
        self.expected = request_bytes(configuration, case)
        self.nmap = case in ("O5", "O6")
        self.maximum = 4096 if self.nmap else 2049
        self.maximum_connections = 3 if self.nmap else 1
        self.pending, self.active = [], None
        self.last_admission = None
        self.ledger = {"schema_version": "1", "configuration": configuration, "case": case, "armed": False,
            "finalized": False, "terminal_reason": "running", "pending_connections": 0, "active_connections": 0,
            "original_response_hex": "", "transformed_response_hex": "", "admissions_elapsed_ms": [], "events": [], "writes": [],
            **dict.fromkeys(_COUNTERS, 0)}
        listener.setblocking(False)

    def arm(self, action_deadline):
        now = time.monotonic()
        if (self.ledger["armed"] or self.ledger["finalized"] or type(action_deadline) not in (float, int)
                or not math.isfinite(action_deadline) or not 0 < action_deadline - now <= (5 if self.nmap else 1)
                or action_deadline > self.deadline):
            raise ValueError("invalid_stock_recorder_arm")
        self.action_deadline = action_deadline
        self.ledger["armed"] = True

    def _ms(self, *, now=None):
        now = time.monotonic() if now is None else now
        return max(0, min(60000, int((now - self.started) * 1000)))

    def _event(self, kind, connection=0, size=0, reason="", *, now=None):
        if len(self.ledger["events"]) >= MAX_EVENTS:
            self.close("event_limit")
            return False
        self.ledger["events"].append({"kind": kind, "elapsed_ms": self._ms(now=now), "connection": connection, "bytes": size, "reason": reason})
        return True

    def _bytes_event(self, active, kind, size):
        """Aggregate one count row per connection/direction, never payload text."""
        if not size:
            return True
        key = kind + "_event_index"
        if key not in active:
            active[key] = len(self.ledger["events"])
            return self._event(kind, active["id"], size)
        self.ledger["events"][active[key]]["bytes"] += size
        return True

    def _finish_active(self, *, reset=False):
        active, self.active = self.active, None
        if active is not None:
            failure = None
            for key in ("daemon", "socket"):
                channel = active.get(key)
                if channel is not None:
                    if key == "socket" and reset:
                        try:
                            channel.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                        except OSError as exc:
                            failure = exc
                    channel.close()
            if failure is not None:
                raise failure

    def _deny_active(self, reason):
        self.ledger["connections_denied"] += 1
        self._event("deny", self.active["id"], reason=reason)
        self._finish_active()

    def close(self, reason="closed"):
        if type(reason) is not str or reason not in _REASONS - {"running"}:
            raise ValueError("invalid_stock_recorder_close")
        if not self.ledger["finalized"]:
            self.ledger["finalized"] = True
            self.ledger["terminal_reason"] = reason
            self._finish_active()
            for channel, _ in self.pending:
                channel.close()
            self.pending.clear()
            self.listener.close()

    def snapshot(self):
        result = dict(self.ledger, pending_connections=len(self.pending), active_connections=int(self.active is not None))
        return validate_snapshot(result)

    def _accept(self):
        # One accept per owner tick prevents an unbounded readiness drain.
        try:
            channel, _ = self.listener.accept()
        except BlockingIOError:
            return
        channel.setblocking(False)
        self.ledger["connections_attempted"] += 1
        number = self.ledger["connections_attempted"]
        if not self._event("attempt", number):
            channel.close()
            return
        reason = ("not_armed" if not self.ledger["armed"] else "request_limit" if self.ledger["requests_validated"]
                  else "connection_limit" if self.ledger["connections_admitted"] + len(self.pending) >= self.maximum_connections else "")
        if reason:
            self.ledger["connections_denied"] += 1
            self._event("deny", number, reason=reason)
            channel.close()
        else:
            self.pending.append((channel, number))

    def _admit(self):
        now = time.monotonic()
        if self.active is not None or not self.pending or self.last_admission is not None and now - self.last_admission < 0.25:
            return
        channel, number = self.pending.pop(0)
        if self.ledger["requests_validated"]:
            self.ledger["connections_denied"] += 1
            self._event("deny", number, reason="request_limit")
            channel.close()
            return
        self.active = {"socket": channel, "id": number, "stage": "request", "raw": bytearray(), "daemon": None,
                       "request_sent": 0, "response": bytearray(), "peer_eof": False, "chunks": [], "offset": 0,
                       "chunk_index": 0, "next_write": 0, "delay": 0, "disposition": ""}
        self.last_admission = now
        self.ledger["connections_admitted"] += 1
        # The rate state and both serialized admission records describe one instant.
        self.ledger["admissions_elapsed_ms"].append(self._ms(now=now))
        self._event("admit", number, now=now)

    def _read_client(self):
        active = self.active
        try:
            part = active["socket"].recv(len(self.expected) + 1)
        except ConnectionResetError:
            if active["stage"] == "request" and not active["raw"] and self.nmap:
                self._event("empty", active["id"])
                self._finish_active()
                return
            raise
        if active["stage"] != "request":
            if part:
                self.ledger["request_bytes_received"] += len(part)
                if not self._bytes_event(active, "received", len(part)):
                    return
                self._deny_active("extra_request_bytes")
            else:
                active["peer_eof"] = True
            return
        self.ledger["request_bytes_received"] += len(part)
        if not self._bytes_event(active, "received", len(part)):
            return
        active["raw"].extend(part)
        raw = bytes(active["raw"])
        if not part:
            if not raw and self.nmap:
                self._event("empty", active["id"])
                self._finish_active()
            else:
                self._deny_active("request_incomplete" if raw else "empty_header_request")
            return
        if len(raw) > len(self.expected) or not self.expected.startswith(raw):
            self._deny_active("request_mismatch")
            return
        if raw == self.expected:
            self.ledger["requests_validated"] += 1
            if not self._event("validated", active["id"], len(raw)):
                return
            active["daemon"] = self._connect_daemon()
            self.ledger["daemon_connections"] += 1
            active["stage"] = "connect"

    def _connect_daemon(self):
        """Diagnostic transport stays fixed; production overrides this boundary."""
        return _private_connection()

    def _write_daemon(self):
        active = self.active
        if active["stage"] == "connect":
            error = active["daemon"].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if error:
                raise OSError(error, "stock private daemon connect failed")
            active["stage"] = "send_request"
        count = active["daemon"].send(self.expected[active["request_sent"]:])
        if count <= 0:
            raise OSError("stock daemon write closed")
        active["request_sent"] += count
        self.ledger["request_bytes_delivered"] += count
        if not self._bytes_event(active, "forwarded", count):
            return
        if active["request_sent"] == len(self.expected):
            self.ledger["requests_delivered"] += 1
            active["stage"] = "read_response"
            self._event("delivered", active["id"], len(self.expected))

    def _read_daemon(self):
        active = self.active
        part = active["daemon"].recv(self.maximum + 1 - len(active["response"]))
        if len(active["response"]) + len(part) > self.maximum:
            self.close("daemon_response_limit")
            return
        active["response"].extend(part)
        self.ledger["daemon_response_bytes"] = len(active["response"])
        self.ledger["original_response_hex"] = active["response"].hex()
        if not self._bytes_event(active, "daemon_received", len(part)):
            return
        if part:
            return
        active["daemon"].close()
        active["daemon"] = None
        try:
            chunks, delay, disposition = transform_response(self.case, bytes(active["response"]))
        except ValueError:
            self.close("daemon_response_invalid")
            return
        self.ledger["transformed_response_hex"] = b"".join(chunks).hex()
        if not self._event("daemon_response", active["id"], len(active["response"])):
            return
        if not self._event("transform", active["id"], sum(map(len, chunks)), disposition):
            return
        active.update(chunks=chunks, delay=delay, disposition=disposition,
                      stage="send_response" if chunks else "withhold")

    def _write_client(self):
        active = self.active
        chunk = active["chunks"][active["chunk_index"]]
        count = active["socket"].send(chunk[active["offset"]:])
        if count <= 0:
            raise OSError("stock client write closed")
        self.ledger["writes"].append({"offset": self.ledger["client_response_bytes"], "bytes": count, "elapsed_ms": self._ms()})
        self.ledger["client_response_bytes"] += count
        active["offset"] += count
        if len(self.ledger["writes"]) >= MAX_EVENTS:
            self.close("event_limit")
            return
        if active["offset"] != len(chunk):
            if self.case == "R2":
                self.close("fragment_write_partial")
            return
        active["chunk_index"] += 1
        active["offset"] = 0
        active["next_write"] = time.monotonic() + active["delay"]
        if active["chunk_index"] == len(active["chunks"]):
            self._event("complete", active["id"], self.ledger["client_response_bytes"])
            self._finish_active(reset=self.case == "N2")

    def tick(self, timeout=POLL_SECONDS):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= POLL_SECONDS:
            raise ValueError("invalid_stock_recorder_poll")
        if self.ledger["finalized"]:
            return
        now = time.monotonic()
        if now >= self.deadline or self.action_deadline is not None and now >= self.action_deadline:
            self.close("owner_deadline" if now >= self.deadline else "action_deadline")
            return
        self._admit()
        if self.ledger["finalized"]:
            return
        reads, writes = [self.listener], []
        active = self.active
        if active is not None:
            if not active["peer_eof"]:
                reads.append(active["socket"])
            if active["stage"] in ("connect", "send_request"):
                writes.append(active["daemon"])
            elif active["stage"] == "read_response":
                reads.append(active["daemon"])
            elif active["stage"] == "send_response" and now >= active["next_write"]:
                writes.append(active["socket"])
        remaining = min(self.deadline, self.action_deadline or self.deadline) - now
        try:
            readable, writable, _ = select.select(reads, writes, [], min(timeout, max(0, remaining)))
            # Time may have elapsed while waiting; never send after expiry.
            if time.monotonic() >= min(self.deadline, self.action_deadline or self.deadline):
                self.close("owner_deadline" if time.monotonic() >= self.deadline else "action_deadline")
                return
            if active is not None and active["socket"] in readable:
                self._read_client()
            if self.active is active and active is not None:
                if active["daemon"] is not None and active["daemon"] in writable:
                    self._write_daemon()
                elif active["daemon"] is not None and active["daemon"] in readable:
                    self._read_daemon()
                elif active["socket"] in writable:
                    self._write_client()
            if not self.ledger["finalized"] and self.listener in readable:
                self._accept()
        except BlockingIOError:
            return
        except OSError:
            self.close("io_failure")
