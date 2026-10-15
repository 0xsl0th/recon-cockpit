"""Owner-driven, bounded plaintext SSH mediator; this module grants no authority.

Only the owner supplies a connected daemon channel after admission. The owner
must synchronously reap that instance in the finalizer before another admission.
No address discovery, process creation, thread or authentication occurs here.
"""

import copy
import json
import math
import select
import socket
import time

try:
    from . import stock_ssh_packets as packets
except ImportError:  # Reviewed standalone owner namespace mount.
    import stock_ssh_packets as packets


CONFIGURATIONS = {"A": ("10.77.0.20", 2222), "B": ("172.23.0.20", 12222)}
CASES = ("O1", "O2", "R1", "R2", "N1", "N2", "N3", "N4", "N5", "N6")
NMAP_CASES = ("O1", "N1")
POLL_SECONDS = .01
MAX_CONNECTION_ATTEMPTS = 16
MAX_WRITES = 64
MAX_LEDGER_BYTES = 256 * 1024
_STREAMS = ("received_client_hex", "forwarded_client_hex", "original_daemon_hex",
            "proposed_response_hex", "delivered_response_hex")
_COUNTERS = ("connections_attempted", "connections_admitted", "connections_denied", "daemon_connections",
             "client_bytes_received", "client_bytes_forwarded", "daemon_bytes_received", "client_bytes_delivered",
             "client_packets_forwarded", "server_key_replies_forwarded")
_TERMINALS = {"running", "closed", "cancelled", "owner_deadline", "action_deadline", "io_failure",
              "client_limit", "response_limit", "daemon_response_invalid", "instance_cleanup_failed", "ledger_limit",
              "fragment_write_partial"}
_REASONS = {"", "not_armed", "connection_limit", "client_limit", "client_message_invalid", "extra_client_bytes",
            "client_incomplete", "client_closed", "empty_probe", "instance_failure", "server_incomplete",
            "complete", "deadline", "closed", "daemon_response_invalid", "response_limit", "io_failure"}


def _selection(configuration, case):
    if (type(configuration) is not str or configuration not in CONFIGURATIONS
            or type(case) is not str or case not in CASES):
        raise ValueError("invalid_stock_ssh_recorder_selection")
    return configuration, case


def _hex(raw, maximum):
    if (type(raw) is not str or len(raw) > maximum * 2 or len(raw) % 2
            or any(c not in "0123456789abcdef" for c in raw)):
        raise ValueError("invalid_stock_ssh_recorder_stream")
    return bytes.fromhex(raw)


def validate_snapshot(value, *, configuration=None, case=None):
    """Recompute counters and transformations; saved evidence grants no action."""
    fields = {"schema_version", "configuration", "case", "armed", "finalized", "terminal_reason",
              "active_connections", "pending_connections", "admissions_elapsed_ms", "connections", *_COUNTERS}
    if type(value) is not dict or set(value) != fields or value["schema_version"] != "1":
        raise ValueError("invalid_stock_ssh_recorder_snapshot")
    selected, selected_case = _selection(value["configuration"], value["case"])
    if configuration is not None and selected != configuration or case is not None and selected_case != case:
        raise ValueError("stock_ssh_recorder_selection_mismatch")
    nmap = selected_case in NMAP_CASES
    request_cap, response_cap, connections_cap = (0, 255, 3) if nmap else (8192, 8192, 1)
    for key in ("armed", "finalized"):
        if type(value[key]) is not bool:
            raise ValueError("invalid_stock_ssh_recorder_flag")
    if (type(value["terminal_reason"]) is not str or value["terminal_reason"] not in _TERMINALS
            or value["finalized"] != (value["terminal_reason"] != "running")):
        raise ValueError("invalid_stock_ssh_recorder_terminal")
    for key in (*_COUNTERS, "active_connections", "pending_connections"):
        if type(value[key]) is not int or not 0 <= value[key] <= 65536:
            raise ValueError("invalid_stock_ssh_recorder_counter")
    if (value["active_connections"] > 1 or value["pending_connections"] > connections_cap
            or value["finalized"] and (value["active_connections"] or value["pending_connections"])
            or value["connections_admitted"] > connections_cap
            or value["client_bytes_received"] > request_cap + 1
            or value["client_bytes_forwarded"] > request_cap
            or value["daemon_bytes_received"] > response_cap + 1
            or value["client_bytes_delivered"] > response_cap
            or value["client_packets_forwarded"] > (0 if nmap else 2)
            or value["server_key_replies_forwarded"] > (0 if nmap else 1)):
        raise ValueError("stock_ssh_recorder_budget_mismatch")
    rows, admissions = value["connections"], value["admissions_elapsed_ms"]
    if (type(rows) is not list or len(rows) > MAX_CONNECTION_ATTEMPTS
            or len(rows) != value["connections_attempted"] or type(admissions) is not list
            or len(admissions) != value["connections_admitted"]
            or any(type(n) is not int or not 0 <= n <= 60000 for n in admissions)
            or any(b - a < 249 for a, b in zip(admissions, admissions[1:]))):
        raise ValueError("stock_ssh_recorder_connection_mismatch")
    totals = dict.fromkeys(_COUNTERS, 0)
    admitted_times = []
    statuses = []
    for number, row in enumerate(rows, 1):
        expected = {"id", "admitted", "daemon_connected", "admitted_ms", "status", "reason",
                    "client_messages", "server_messages", "transforms", "writes", *_STREAMS}
        if type(row) is not dict or set(row) != expected or type(row["id"]) is not int or row["id"] != number:
            raise ValueError("invalid_stock_ssh_recorder_connection")
        if (type(row["admitted"]) is not bool or type(row["daemon_connected"]) is not bool
                or type(row["admitted_ms"]) is not int or not -1 <= row["admitted_ms"] <= 60000
                or type(row["status"]) is not str or row["status"] not in ("pending", "active", "denied", "finished")
                or type(row["reason"]) is not str or row["reason"] not in _REASONS):
            raise ValueError("invalid_stock_ssh_recorder_connection_state")
        statuses.append(row["status"])
        if row["admitted"]:
            admitted_times.append(row["admitted_ms"])
            if row["admitted_ms"] < 0 or row["status"] == "pending":
                raise ValueError("invalid_stock_ssh_recorder_admission")
        elif row["admitted_ms"] != -1 or row["daemon_connected"] or row["status"] in ("active", "finished"):
            raise ValueError("invalid_stock_ssh_recorder_admission")
        streams = {key: _hex(row[key], 8193 if key == "proposed_response_hex" else
                    request_cap + 1 if key == "received_client_hex" else
                    request_cap if key == "forwarded_client_hex" else
                    response_cap + 1 if key == "original_daemon_hex" else response_cap) for key in _STREAMS}
        if not row["admitted"] and any(streams.values()):
            raise ValueError("stock_ssh_recorder_unadmitted_data")
        received, forwarded = streams["received_client_hex"], streams["forwarded_client_hex"]
        original, proposed, delivered = (streams[key] for key in
            ("original_daemon_hex", "proposed_response_hex", "delivered_response_hex"))
        if not received.startswith(forwarded) or not proposed.startswith(delivered):
            raise ValueError("stock_ssh_recorder_stream_mismatch")
        if not row["daemon_connected"] and (forwarded or original or proposed or delivered):
            raise ValueError("stock_ssh_recorder_unconnected_data")
        for key, stages, source in (("client_messages", ("identification", "kexinit", "dh_init"), received),
                                    ("server_messages", ("identification", "kexinit", "key_reply"), original)):
            messages = row[key]
            if type(messages) is not list or len(messages) > (1 if nmap and key == "server_messages" else 0 if nmap else 3):
                raise ValueError("stock_ssh_recorder_message_limit")
            offset = 0
            for index, item in enumerate(messages):
                if (type(item) is not dict or set(item) != {"stage", "offset", "bytes"}
                        or item["stage"] != stages[index] or type(item["offset"]) is not int
                        or item["offset"] != offset or type(item["bytes"]) is not int or item["bytes"] < 1
                        or offset + item["bytes"] > len(source)):
                    raise ValueError("stock_ssh_recorder_message_mismatch")
                packets.validate_message(item["stage"], source[offset:offset + item["bytes"]], selected,
                                         selected_case, server=key == "server_messages")
                offset += item["bytes"]
            if key == "client_messages":
                if len(forwarded) > offset:
                    raise ValueError("stock_ssh_recorder_unvalidated_forward")
                totals["client_packets_forwarded"] += sum(item["stage"] != "identification"
                    and item["offset"] + item["bytes"] <= len(forwarded) for item in messages)
        transformations = row["transforms"]
        if type(transformations) is not list or len(transformations) != len(row["server_messages"]):
            raise ValueError("invalid_stock_ssh_recorder_transform")
        compiled, planned_writes = b"", []
        for item, message in zip(transformations, row["server_messages"]):
            if type(item) is not dict or set(item) != {"stage", "source_offset", "source_bytes", "output_hex", "disposition"}:
                raise ValueError("invalid_stock_ssh_recorder_transform")
            start, size, stage = message["offset"], message["bytes"], message["stage"]
            chunks, _, reason = packets.transform(stage, original[start:start + size], selected, selected_case)
            changed = b"".join(chunks)
            if (item["stage"] != stage or type(item["source_offset"]) is not int or item["source_offset"] != start
                    or type(item["source_bytes"]) is not int or item["source_bytes"] != size
                    or item["output_hex"] != changed.hex() or item["disposition"] != reason):
                raise ValueError("stock_ssh_recorder_transform_mismatch")
            compiled += changed
            planned_writes.extend(len(chunk) for chunk in chunks)
            if stage == "key_reply" and len(delivered) >= len(compiled):
                totals["server_key_replies_forwarded"] += 1
        if compiled != proposed:
            raise ValueError("stock_ssh_recorder_transform_stream_mismatch")
        writes = row["writes"]
        if type(writes) is not list or len(writes) > MAX_WRITES:
            raise ValueError("stock_ssh_recorder_write_limit")
        offsets = {"client": 0, "daemon": 0}
        for write in writes:
            if (type(write) is not dict or set(write) != {"direction", "offset", "bytes", "elapsed_ms"}
                    or write["direction"] not in offsets
                    or any(type(write[k]) is not int for k in ("offset", "bytes", "elapsed_ms"))
                    or write["offset"] != offsets[write["direction"]] or not 1 <= write["bytes"] <= 8192
                    or not 0 <= write["elapsed_ms"] <= 60000):
                raise ValueError("invalid_stock_ssh_recorder_write")
            offsets[write["direction"]] += write["bytes"]
        if offsets != {"client": len(delivered), "daemon": len(forwarded)}:
            raise ValueError("stock_ssh_recorder_write_mismatch")
        if selected_case == "R2":
            client_writes = [write for write in writes if write["direction"] == "client"]
            sizes = [write["bytes"] for write in client_writes]
            if (len(sizes) > len(planned_writes)
                    or any(actual != planned for actual, planned in zip(sizes[:-1], planned_writes))
                    or sizes and sizes[-1] > planned_writes[len(sizes) - 1]
                    or sizes and sizes[-1] != planned_writes[len(sizes) - 1]
                    and value["terminal_reason"] != "fragment_write_partial"
                    or any(b["elapsed_ms"] - a["elapsed_ms"] < 4 for a, b in zip(client_writes, client_writes[1:]))):
                raise ValueError("stock_ssh_recorder_fragment_mismatch")
        totals["connections_attempted"] += 1
        totals["connections_admitted"] += row["admitted"]
        totals["connections_denied"] += row["status"] == "denied"
        totals["daemon_connections"] += row["daemon_connected"]
        for field, raw in (("client_bytes_received", received), ("client_bytes_forwarded", forwarded),
                           ("daemon_bytes_received", original), ("client_bytes_delivered", delivered)):
            totals[field] += len(raw)
    if (any(value[key] != total for key, total in totals.items()) or admissions != admitted_times
            or statuses.count("active") != value["active_connections"]
            or statuses.count("pending") != value["pending_connections"]
            or not value["armed"] and value["connections_admitted"]
            or len(json.dumps(value, sort_keys=True, separators=(",", ":"))) > MAX_LEDGER_BYTES):
        raise ValueError("stock_ssh_recorder_ledger_mismatch")
    return copy.deepcopy(value)


class Service:
    """One nonblocking active channel; aggregate limits survive all instances."""

    def __init__(self, configuration, case, listener, *, deadline, connection_factory, connection_finalizer):
        _selection(configuration, case)
        now = time.monotonic()
        if (type(deadline) not in (float, int) or not math.isfinite(deadline) or not 0 < deadline - now <= 60
                or not isinstance(listener, socket.socket) or listener.family != socket.AF_INET
                or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM
                or listener.getsockname() != CONFIGURATIONS[configuration]
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                or not callable(connection_factory) or not callable(connection_finalizer)):
            raise ValueError("invalid_stock_ssh_recorder_startup")
        self.configuration, self.case, self.listener = configuration, case, listener
        self.deadline, self.started, self.action_deadline = deadline, now, None
        self.connection_factory, self.connection_finalizer = connection_factory, connection_finalizer
        self.nmap = case in NMAP_CASES
        self.request_cap, self.response_cap, self.connection_cap = (0, 255, 3) if self.nmap else (8192, 8192, 1)
        self.pending, self.active, self.last_admission = [], None, None
        self.ledger = {"schema_version": "1", "configuration": configuration, "case": case,
            "armed": False, "finalized": False, "terminal_reason": "running", "active_connections": 0,
            "pending_connections": 0, "admissions_elapsed_ms": [], "connections": [], **dict.fromkeys(_COUNTERS, 0)}
        self.listener.setblocking(False)

    def _ms(self):
        return max(0, min(60000, int((time.monotonic() - self.started) * 1000)))

    def arm(self, action_deadline):
        if (self.ledger["armed"] or self.ledger["finalized"] or type(action_deadline) not in (float, int)
                or not math.isfinite(action_deadline) or not 0 < action_deadline - time.monotonic() <= 5
                or action_deadline > self.deadline):
            raise ValueError("invalid_stock_ssh_recorder_arm")
        self.action_deadline = action_deadline
        self.ledger["armed"] = True

    def _finish_daemon(self, active):
        channel, active["daemon"] = active["daemon"], None
        if channel is not None:
            channel.close()
        if active["needs_finalizer"]:
            active["needs_finalizer"] = False
            try:
                self.connection_finalizer(active["row"]["id"])
            except Exception:
                active["cleanup_failed"] = True
                raise

    def _finish(self, reason, *, denied=False):
        active, self.active = self.active, None
        if active is None:
            return
        active["socket"].close()
        active["row"].update(status="denied" if denied else "finished", reason=reason)
        if denied:
            self.ledger["connections_denied"] += 1
        try:
            self._finish_daemon(active)
        except Exception:
            self.ledger["terminal_reason"] = "instance_cleanup_failed"
            self.close("instance_cleanup_failed")

    def close(self, reason="closed"):
        if type(reason) is not str or reason not in _TERMINALS - {"running"}:
            raise ValueError("invalid_stock_ssh_recorder_close")
        if self.ledger["finalized"]:
            return
        self.ledger.update(finalized=True, terminal_reason=reason)
        active = self.active
        self._finish("deadline" if reason in ("owner_deadline", "action_deadline") else
                     reason if reason in _REASONS else "closed")
        if active is not None and active.get("cleanup_failed"):
            self.ledger["terminal_reason"] = "instance_cleanup_failed"
        for channel, row in self.pending:
            channel.close()
            row.update(status="denied", reason="closed")
            self.ledger["connections_denied"] += 1
        self.pending.clear()
        self.listener.close()

    def snapshot(self):
        return validate_snapshot(dict(self.ledger, active_connections=int(self.active is not None),
                                      pending_connections=len(self.pending)))

    def _accept(self):
        if len(self.ledger["connections"]) >= MAX_CONNECTION_ATTEMPTS:
            self.close("ledger_limit")
            return
        channel, _ = self.listener.accept()
        channel.setblocking(False)
        row = {"id": len(self.ledger["connections"]) + 1, "admitted": False, "daemon_connected": False,
            "admitted_ms": -1, "status": "pending", "reason": "", "client_messages": [], "server_messages": [],
            "transforms": [], "writes": [], **dict.fromkeys(_STREAMS, "")}
        self.ledger["connections"].append(row)
        self.ledger["connections_attempted"] += 1
        reason = "not_armed" if not self.ledger["armed"] else "connection_limit" if (
            self.ledger["connections_admitted"] + len(self.pending) >= self.connection_cap) else ""
        if reason:
            channel.close()
            row.update(status="denied", reason=reason)
            self.ledger["connections_denied"] += 1
        else:
            self.pending.append((channel, row))

    def _admit(self):
        now = time.monotonic()
        if self.active is not None or not self.pending or self.last_admission is not None and now - self.last_admission < .25:
            return
        channel, row = self.pending.pop(0)
        row.update(admitted=True, admitted_ms=self._ms(), status="active")
        self.ledger["connections_admitted"] += 1
        self.ledger["admissions_elapsed_ms"].append(row["admitted_ms"])
        self.last_admission = now
        active = self.active = {"socket": channel, "row": row, "daemon": None, "needs_finalizer": True,
            "client_buffer": bytearray(), "server_buffer": bytearray(), "to_daemon": bytearray(),
            "chunks": [], "chunk_offset": 0, "next_write": now, "delay": 0,
            "finish_after_write": False, "withhold": False, "client_eof": False}
        try:
            daemon = self.connection_factory(row["id"], self.action_deadline)
            if (not isinstance(daemon, socket.socket) or daemon.type & socket.SOCK_STREAM != socket.SOCK_STREAM
                    or daemon is channel or daemon is self.listener):
                raise ValueError("invalid_owned_ssh_channel")
            daemon.getpeername()  # Unconnected channels cannot become authority.
            daemon.setblocking(False)
            active["daemon"] = daemon
            row["daemon_connected"] = True
            self.ledger["daemon_connections"] += 1
        except Exception:
            self._finish("instance_failure", denied=True)
            self.close("io_failure")

    @staticmethod
    def _next_message(buffer, stage):
        if stage == "identification":
            end = buffer.find(b"\n") + 1
            if end:
                return bytes(buffer[:end])
            if len(buffer) >= packets.MAX_IDENTIFICATION:
                raise ValueError("ssh_identification_limit")
            return None
        size = packets.packet_size(buffer)
        return bytes(buffer[:size]) if size is not None and len(buffer) >= size else None

    def _read_client(self):
        active, row = self.active, self.active["row"]
        remaining = self.request_cap + 1 - self.ledger["client_bytes_received"]
        try:
            part = active["socket"].recv(max(1, remaining))
        except ConnectionResetError:
            self._finish("empty_probe" if self.nmap and not row["received_client_hex"] else "client_closed")
            return
        if not part:
            active["client_eof"] = True
            if self.nmap:
                self._finish("empty_probe" if not row["delivered_response_hex"] else "client_closed")
            elif not active["finish_after_write"]:
                self._finish("client_incomplete" if active["client_buffer"] else "client_closed")
            return
        row["received_client_hex"] += part.hex()
        self.ledger["client_bytes_received"] += len(part)
        if self.ledger["client_bytes_received"] > self.request_cap:
            self._finish("client_limit", denied=True)
            self.close("client_limit")
            return
        active["client_buffer"].extend(part)
        while active["client_buffer"]:
            index = len(row["client_messages"])
            if index >= 3:
                self._finish("extra_client_bytes", denied=True)
                return
            stage = ("identification", "kexinit", "dh_init")[index]
            try:
                message = self._next_message(active["client_buffer"], stage)
                if message is None:
                    return
                packets.validate_message(stage, message, self.configuration, self.case, server=False)
                if stage == "dh_init" and len(row["server_messages"]) < 2:
                    raise ValueError("ssh_dh_before_server_kexinit")
            except ValueError:
                self._finish("client_message_invalid", denied=True)
                return
            offset = sum(item["bytes"] for item in row["client_messages"])
            row["client_messages"].append({"stage": stage, "offset": offset, "bytes": len(message)})
            del active["client_buffer"][:len(message)]
            active["to_daemon"].extend(message)

    def _read_daemon(self):
        active, row = self.active, self.active["row"]
        remaining = self.response_cap + 1 - self.ledger["daemon_bytes_received"]
        part = active["daemon"].recv(max(1, remaining))
        if not part:
            self._finish("server_incomplete")
            return
        row["original_daemon_hex"] += part.hex()
        self.ledger["daemon_bytes_received"] += len(part)
        if self.ledger["daemon_bytes_received"] > self.response_cap:
            self.close("response_limit")
            return
        active["server_buffer"].extend(part)
        while active["server_buffer"] and not active["finish_after_write"] and not active["withhold"]:
            index = len(row["server_messages"])
            stage = ("identification", "kexinit", "key_reply")[index]
            try:
                message = self._next_message(active["server_buffer"], stage)
                if message is None:
                    return
                if stage == "kexinit" and not row["forwarded_client_hex"]:
                    raise ValueError("server_kexinit_before_client_identification")
                if stage == "key_reply" and self.ledger["client_packets_forwarded"] != 2:
                    raise ValueError("server_reply_before_client_dh")
                chunks, delay, disposition = packets.transform(stage, message, self.configuration, self.case)
            except ValueError:
                self.close("daemon_response_invalid")
                return
            offset = sum(item["bytes"] for item in row["server_messages"])
            row["server_messages"].append({"stage": stage, "offset": offset, "bytes": len(message)})
            transformed = b"".join(chunks)
            row["transforms"].append({"stage": stage, "source_offset": offset, "source_bytes": len(message),
                                      "output_hex": transformed.hex(), "disposition": disposition})
            row["proposed_response_hex"] += transformed.hex()
            del active["server_buffer"][:len(message)]
            if sum(len(bytes.fromhex(item["proposed_response_hex"])) for item in self.ledger["connections"]) > self.response_cap:
                self.close("response_limit")
                return
            active["chunks"].extend(chunks)
            active["delay"] = delay
            active["withhold"] = disposition == "withheld_until_deadline"
            active["finish_after_write"] = self.nmap or stage == "key_reply" or disposition == "unsupported_host_key_algorithm"
            if active["finish_after_write"] or active["withhold"]:
                self._finish_daemon(active)
                # Received server tail (including coalesced NEWKEYS) remains in
                # original_daemon_hex; none enters the delivery stream.
                return

    def _write(self, direction):
        active, row = self.active, self.active["row"]
        if len(row["writes"]) >= MAX_WRITES:
            self.close("ledger_limit")
            return
        if direction == "daemon":
            offered = bytes(active["to_daemon"])
            channel, stream, counter = active["daemon"], "forwarded_client_hex", "client_bytes_forwarded"
        else:
            offered = active["chunks"][0][active["chunk_offset"]:]
            channel, stream, counter = active["socket"], "delivered_response_hex", "client_bytes_delivered"
        count = channel.send(offered)
        if count <= 0:
            raise OSError("ssh_channel_closed")
        row["writes"].append({"direction": direction, "offset": len(row[stream]) // 2,
                              "bytes": count, "elapsed_ms": self._ms()})
        row[stream] += offered[:count].hex()
        self.ledger[counter] += count
        if direction == "client" and self.case == "R2" and count != len(offered):
            self.close("fragment_write_partial")
            return
        if direction == "daemon":
            del active["to_daemon"][:count]
            self.ledger["client_packets_forwarded"] = sum(item["stage"] != "identification"
                and item["offset"] + item["bytes"] <= len(row[stream]) // 2 for item in row["client_messages"])
        else:
            active["chunk_offset"] += count
            if active["chunk_offset"] == len(active["chunks"][0]):
                active["chunks"].pop(0)
                active["chunk_offset"] = 0
                active["next_write"] = time.monotonic() + active["delay"]
            if not active["chunks"] and active["finish_after_write"]:
                if row["server_messages"][-1]["stage"] == "key_reply":
                    self.ledger["server_key_replies_forwarded"] += 1
                self._finish("complete")

    def tick(self, timeout=POLL_SECONDS):
        if type(timeout) not in (float, int) or not math.isfinite(timeout) or not 0 <= timeout <= POLL_SECONDS:
            raise ValueError("invalid_stock_ssh_recorder_poll")
        if self.ledger["finalized"]:
            return
        end = min(self.deadline, self.action_deadline or self.deadline)
        if time.monotonic() >= end:
            self.close("owner_deadline" if time.monotonic() >= self.deadline else "action_deadline")
            return
        self._admit()
        if self.ledger["finalized"]:
            return
        reads, writes, active = [self.listener], [], self.active
        if active is not None:
            if not active["client_eof"]:
                reads.append(active["socket"])
            if active["daemon"] is not None:
                reads.append(active["daemon"])
                if active["to_daemon"]:
                    writes.append(active["daemon"])
            if active["chunks"] and time.monotonic() >= active["next_write"]:
                writes.append(active["socket"])
        try:
            ready, writable, _ = select.select(reads, writes, [], min(timeout, max(0, end - time.monotonic())))
            if time.monotonic() >= end:
                self.close("owner_deadline" if time.monotonic() >= self.deadline else "action_deadline")
                return
            # Consume prohibited client data before any queued bytes can pass.
            if active is not None and active["socket"] in ready:
                self._read_client()
            if self.active is active and active is not None and active["daemon"] is not None:
                if active["daemon"] in writable:
                    self._write("daemon")
                if self.active is active and active["daemon"] in ready:
                    self._read_daemon()
            if self.active is active and active is not None and active["socket"] in writable:
                self._write("client")
            if not self.ledger["finalized"] and self.listener in ready:
                self._accept()
        except BlockingIOError:
            return
        except (OSError, ValueError):
            self.close("io_failure")
