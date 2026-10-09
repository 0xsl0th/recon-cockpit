"""Disconnected owner for the unaccepted T02 native feasibility experiment.

This is not an adapter or permission source. In particular, observing a second
ClientHello proves that the proposed one-ClientHello boundary failed; it does
not establish that the extra message was blocked. The server's deliberately
public synthetic key is never an input to the tool runtime.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import ssl
import threading
import time
import warnings

if __package__:
    from . import network_tools_fixture as public
    from . import tls_posture_hello as hello
    from . import network_tools_tls_certificate_material as material
    from . import owned_lab_worker as owner
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    public = _load("t02_public_fixture", "network_tools_fixture.py")
    hello = _load("t02_hello_grammar", "tls_posture_hello.py")
    material = _load("t02_owner_material", "network_tools_tls_certificate_material.py")
    owner = _load("t02_owner_lifecycle", "owned_lab_worker.py")


VERSIONS = {"tls1": (0x0301, ssl.TLSVersion.TLSv1, 0xC009),
            "tls1_1": (0x0302, ssl.TLSVersion.TLSv1_1, 0xC009),
            "tls1_2": (0x0303, ssl.TLSVersion.TLSv1_2, 0xC02B),
            "tls1_3": (0x0304, ssl.TLSVersion.TLSv1_3, 0x1302)}
CASES = ("modern", "legacy", "reject", "hrr")
MAX_DIRECTION_BYTES = 32768
MAX_RECORDS = 32
MAX_RECORD_PAYLOAD = 18432
MAX_CLIENT_HELLO = hello.MAX_CLIENT_HELLO
MAX_MESSAGES = 64
COOKIE = hello.COOKIE
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def remaining(deadline):
    left = deadline - time.monotonic()
    if not math.isfinite(left) or left <= 0:
        raise ValueError("tls_posture_owner_deadline")
    return left


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("tls_posture_owner_request")
    value = json.loads(raw, object_pairs_hook=owner._unique)
    if (type(value) is not dict or set(value) != {"case", "version", "deadline", "host_namespaces"}
            or type(value["case"]) is not str or value["case"] not in CASES
            or type(value["version"]) is not str or value["version"] not in VERSIONS
            or (value["case"] == "hrr" and value["version"] != "tls1_3")
            or type(value["deadline"]) not in {int, float}
            or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("tls_posture_owner_request")
    return value


_Reader = hello._Reader
validate_client_hello = hello.validate_client_hello


def hello_retry_request(hello):
    # RFC 8446 4.1.3/4.1.4: ServerHello layout, special random, echoed
    # legacy_session_id, original offered suite and supported_versions.
    # Section 4.2.2 allows cookie-only HRR and defines its uint16 vector.
    # https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.4
    # https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.2
    session = bytes.fromhex(hello["session_id_hex"])
    cookie = len(COOKIE).to_bytes(2, "big") + COOKIE
    extensions = b"\0\x2b\0\2\3\4" + b"\0\x2c" + len(cookie).to_bytes(2, "big") + cookie
    body = b"\3\3" + HRR_RANDOM + bytes([len(session)]) + session + b"\x13\2\0" + len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\2" + len(body).to_bytes(3, "big") + body
    return b"\x16\3\3" + len(handshake).to_bytes(2, "big") + handshake


def new_ledger(case, version):
    return {"case": case, "expected_version": version, "completed": False, "error": None,
            "handshake_completed": False, "clean_close": False, "negotiated_version": None,
            "cipher": None, "application_bytes": 0, "client_hellos": 0,
            "received_bytes": 0, "sent_bytes": 0, "received_records": [], "sent_records": [],
            "handshake_messages": [], "alerts": [], "hrr_sent": False,
            "server_close_notify_record": None}


class RecordIO:
    """Read exact records and account every byte before parsing/forwarding it."""
    def __init__(self, connection, deadline, ledger, *, cancel_event=None):
        self.connection, self.deadline, self.ledger = connection, deadline, ledger
        self.cancel_event = cancel_event

    def _check_cancelled(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ValueError("tls_posture_owner_cancelled")

    def _read(self, size):
        if self.ledger["received_bytes"] + size > MAX_DIRECTION_BYTES:
            raise ValueError("tls_posture_owner_byte_cap")
        raw = bytearray()
        while len(raw) < size:
            self._check_cancelled()
            self.connection.settimeout(min(0.05 if self.cancel_event is not None else 1,
                                           remaining(self.deadline)))
            try:
                chunk = self.connection.recv(size - len(raw))
            except socket.timeout:
                if self.cancel_event is None:
                    raise
                continue
            if not chunk:
                raise ValueError("tls_posture_owner_eof")
            self.ledger["received_bytes"] += len(chunk)
            if self.ledger["received_bytes"] > MAX_DIRECTION_BYTES:
                raise ValueError("tls_posture_owner_byte_cap")
            raw.extend(chunk)
        return bytes(raw)

    def _record(self, direction, raw):
        records = self.ledger[direction + "_records"]
        if len(records) >= MAX_RECORDS:
            raise ValueError("tls_posture_owner_record_cap")
        if (len(raw) < 6 or raw[0] not in (20, 21, 22, 23)
                or raw[1:3] not in (b"\3\1", b"\3\2", b"\3\3")
                or not 1 <= int.from_bytes(raw[3:5], "big") <= MAX_RECORD_PAYLOAD
                or int.from_bytes(raw[3:5], "big") != len(raw) - 5):
            raise ValueError("tls_posture_owner_record")
        records.append({"type": raw[0], "version": raw[1:3].hex(),
                        "payload_length": len(raw) - 5, "raw_hex": raw.hex()})

    def receive(self):
        if len(self.ledger["received_records"]) >= MAX_RECORDS:
            raise ValueError("tls_posture_owner_record_cap")
        header = self._read(5)
        size = int.from_bytes(header[3:5], "big")
        if not 1 <= size <= MAX_RECORD_PAYLOAD or self.ledger["received_bytes"] + size > MAX_DIRECTION_BYTES:
            raise ValueError("tls_posture_owner_byte_cap")
        raw = header + self._read(size)
        self._record("received", raw)
        return raw

    def send(self, raw):
        offset = 0
        while offset < len(raw):
            self._check_cancelled()
            if len(raw) - offset < 5:
                raise ValueError("tls_posture_owner_record")
            size = int.from_bytes(raw[offset + 3:offset + 5], "big") + 5
            record = raw[offset:offset + size]
            if self.ledger["sent_bytes"] + len(record) > MAX_DIRECTION_BYTES:
                raise ValueError("tls_posture_owner_byte_cap")
            self._record("sent", record)
            if self.cancel_event is None:
                self.connection.settimeout(min(1, remaining(self.deadline)))
                self.connection.sendall(record)
            else:
                sent = 0
                while sent < len(record):
                    self._check_cancelled()
                    self.connection.settimeout(min(0.05, remaining(self.deadline)))
                    try:
                        size_sent = self.connection.send(record[sent:])
                    except socket.timeout:
                        continue
                    if size_sent <= 0:
                        raise ValueError("tls_posture_owner_eof")
                    sent += size_sent
            self.ledger["sent_bytes"] += len(record)
            offset += size


def tls_context(case, ledger):
    certificate = material.certificate_for_case("tls-cert-ok")
    if hashlib.sha256(certificate).hexdigest() != public.TLS_CERTIFICATE_CERT_SHA256["tls-cert-ok"]:
        raise ValueError("tls_posture_owner_material")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    legacy = case == "legacy"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = ssl.TLSVersion.TLSv1 if legacy else ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ciphers("ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0"
                        if legacy else "ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=2")
    context.set_ecdh_curve("prime256v1")
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET | ssl.OP_NO_RENEGOTIATION
    context.num_tickets = 0
    context.sni_callback = lambda connection, name, ctx: None if name == public.TLS_NAME else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    def observe(connection, direction, protocol, content, message_type, data):
        if int(content) == 22:
            if len(ledger["handshake_messages"]) >= MAX_MESSAGES:
                raise ValueError("tls_posture_owner_message_cap")
            ledger["handshake_messages"].append({"direction": direction, "type": int(message_type),
                                                   "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            if direction == "read" and int(message_type) == 1:
                ledger["client_hellos"] = sum(item["direction"] == "read" and item["type"] == 1
                                              for item in ledger["handshake_messages"])
        elif int(content) == 21:
            if len(data) != 2 or len(ledger["alerts"]) >= 8:
                raise ValueError("tls_posture_owner_alert_cap")
            ledger["alerts"].append({"direction": direction, "type": data[0], "description": data[1]})
    context._msg_callback = observe
    descriptors = []
    try:
        for name, raw in (("t02-public-cert", certificate), ("t02-public-owner-key", material.SERVER_KEY_PEM)):
            descriptor = os.memfd_create(name, os.MFD_CLOEXEC)
            descriptors.append(descriptor)
            if os.write(descriptor, raw) != len(raw):
                raise ValueError("tls_posture_owner_material")
        context.load_cert_chain(*(f"/proc/self/fd/{descriptor}" for descriptor in descriptors))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    return context


def serve(connection, *, case, version, deadline, context, ledger, on_request, cancel_event=None):
    if case not in CASES or version not in VERSIONS or (case == "hrr" and version != "tls1_3"):
        raise ValueError("tls_posture_owner_case")
    remaining(deadline)
    records = RecordIO(connection, deadline, ledger, cancel_event=cancel_event)
    initial = records.receive()
    hello = validate_client_hello(initial, version)
    ledger["client_hellos"] = 1
    on_request()
    def manual_message(direction, raw):
        ledger["handshake_messages"].append({"direction": direction, "type": raw[5],
                                               "length": len(raw) - 5,
                                               "sha256": hashlib.sha256(raw[5:]).hexdigest()})
    if case == "reject" or (case == "modern" and version in ("tls1", "tls1_1")):
        manual_message("read", initial)
        records.send(b"\x15\3\3\0\2\2\x46")
        ledger["alerts"].append({"direction": "write", "type": 2, "description": 70})
        return
    if case == "hrr":
        manual_message("read", initial)
        retry_request = hello_retry_request(hello)
        records.send(retry_request)
        manual_message("write", retry_request)
        ledger["hrr_sent"] = True
        second = records.receive()
        if second == b"\x14\3\3\0\1\1":
            second = records.receive()  # One TLS 1.3 compatibility CCS, never a retry allowance.
        if second[0] == 22 and second[5] == 1:
            ledger["client_hellos"] = 2
        second_hello = validate_client_hello(second, version, retry=True)
        if any(second_hello[key] != hello[key] for key in ("version", "session_id_hex", "cipher", "random_hex")):
            raise ValueError("tls_posture_owner_retry_mismatch")
        manual_message("read", second)
        ledger["client_hellos"] = 2
        raise ValueError("tls_posture_extra_client_hello_observed_not_blocked")
    inbound, outbound = ssl.MemoryBIO(), ssl.MemoryBIO()
    secured = context.wrap_bio(inbound, outbound, server_side=True)
    inbound.write(initial)

    def flush():
        pending = outbound.read()
        if pending:
            records.send(pending)

    def drive(operation):
        for _ in range(MAX_RECORDS):
            remaining(deadline)
            try:
                result = operation()
                flush()
                return result
            except ssl.SSLWantReadError:
                flush()
                inbound.write(records.receive())
            except ssl.SSLWantWriteError:
                flush()
            except ssl.SSLError:
                flush()
                raise
        raise ValueError("tls_posture_owner_operation_cap")

    drive(secured.do_handshake)
    ledger["handshake_completed"] = True
    ledger["negotiated_version"] = secured.version()
    ledger["cipher"] = secured.cipher()[0]
    if secured.version() != {"tls1": "TLSv1", "tls1_1": "TLSv1.1", "tls1_2": "TLSv1.2", "tls1_3": "TLSv1.3"}[version]:
        raise ValueError("tls_posture_owner_negotiated_version")
    data = drive(lambda: secured.read(1))
    ledger["application_bytes"] += len(data)
    if data:
        raise ValueError("tls_posture_owner_application_data")
    close_record_index = len(ledger["sent_records"])
    close_alert_index = len(ledger["alerts"])
    drive(secured.unwrap)
    ledger["clean_close"] = True
    # Bind the final wire record to the real SSLObject close operation, rather
    # than guessing from ciphertext size. A CLI with stdin EOF may already have
    # exited and never read this reply; its trace must disclose that distinction.
    if (len(ledger["sent_records"]) != close_record_index + 1
            or ledger["alerts"][close_alert_index:] != [{"direction": "write", "type": 1, "description": 0}]):
        raise ValueError("tls_posture_owner_close_record_association")
    close_record = ledger["sent_records"][close_record_index]
    ledger["server_close_notify_record"] = {
        "sent_record_index": close_record_index,
        "raw_sha256": hashlib.sha256(bytes.fromhex(close_record["raw_hex"])).hexdigest(),
        "payload_length": close_record["payload_length"],
    }
    if sum(item["direction"] == "read" and item["type"] == 1 for item in ledger["handshake_messages"]) != 1:
        raise ValueError("tls_posture_extra_client_hello_observed_not_blocked")


class Service:
    def __init__(self, request, listener):
        self.request, self.listener = request, listener
        self.condition = threading.Condition()
        self.connections, self.requests = 0, 0
        self.ledger = new_ledger(request["case"], request["version"])
        self.context = tls_context(request["case"], self.ledger)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _progress(self):
        with self.condition:
            self.requests += 1
            self.condition.notify_all()

    def _serve(self):
        try:
            connection, _ = self.listener.accept()
            with self.condition:
                self.connections += 1
            with connection:
                serve(connection, case=self.request["case"], version=self.request["version"],
                      deadline=self.request["deadline"], context=self.context, ledger=self.ledger,
                      on_request=self._progress)
        except (ValueError, OSError) as error:
            self.ledger["error"] = (str(error)[:160] if isinstance(error, ValueError)
                                    else type(error).__name__)
        finally:
            with self.condition:
                self.ledger["completed"] = True
                self.condition.notify_all()

    def snapshot(self, minimum_connections, minimum_requests, deadline):
        with self.condition:
            if not self.connections and not minimum_connections and not minimum_requests:
                return {"connection_count": 0, "request_count": 0, "diagnostic": self.ledger}
            while not self.ledger["completed"]:
                self.condition.wait(timeout=min(0.05, remaining(deadline)))
            # The parent asks only after its client exits. Detect any queued
            # extra connection; accepting it here is evidence of a boundary
            # failure, never a claim that the extra connect was blocked.
            self.listener.settimeout(min(0.001, remaining(deadline)))
            try:
                extra, _ = self.listener.accept()
            except socket.timeout:
                pass
            else:
                extra.close()
                self.connections += 1
                self.ledger["error"] = "tls_posture_extra_connection_observed_not_blocked"
            # A failed parse is evidence too: do not wait forever for progress it
            # deliberately did not acknowledge. The parent checks denominators.
            return {"connection_count": self.connections, "request_count": self.requests,
                    "diagnostic": self.ledger}


class DiagnosticOwner(owner.Owner):
    def read_request(self, source):
        return read_request(source)

    def create_service(self, request, listener):
        return Service(request, listener)


def main():
    return DiagnosticOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
