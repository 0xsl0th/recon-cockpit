"""Finite record gate for the owned T02 transport experiment.

This module has no socket, TLS engine or authority. The caller supplies the
reviewed first-ClientHello validator and forwards only records accepted here.
Encrypted record shapes are bounded opaque data, not authenticated semantic
claims. In particular this gate does not decrypt application traffic.
"""

CLIENT_MAX_BYTES = 8192
CLIENT_MAX_RECORDS = 8
SERVER_MAX_BYTES = 32768
SERVER_MAX_RECORDS = 32
MAX_RECORD_PAYLOAD = 18432
MAX_CLIENT_HELLO = 4096
VERSIONS = ("tls1", "tls1_1", "tls1_2", "tls1_3")
_RECORD_VERSIONS = (b"\x03\x01", b"\x03\x02", b"\x03\x03")
_SELECTED = {"tls1": b"\x03\x01", "tls1_1": b"\x03\x02",
             "tls1_2": b"\x03\x03", "tls1_3": b"\x03\x03"}
_FINISHED_LENGTH = {"tls1": 52, "tls1_1": 68, "tls1_2": 40, "tls1_3": 69}
_CLOSE_LENGTH = {"tls1": 36, "tls1_1": 52, "tls1_2": 26, "tls1_3": 19}


class MediatorViolation(ValueError):
    """A stable, non-peer-controlled refusal reason."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _header(raw, maximum):
    if len(raw) < 5:
        raise MediatorViolation("partial_record")
    if raw[0] not in (20, 21, 22, 23) or raw[1:3] not in _RECORD_VERSIONS:
        raise MediatorViolation("invalid_record_header")
    size = int.from_bytes(raw[3:5], "big")
    if not 1 <= size <= maximum:
        raise MediatorViolation("record_payload_limit")
    return size


class RecordFramer:
    """Bound TCP fragmentation without ever exposing partial TLS records.

    A feed that fails returns no records, including any preceding complete
    records in that same feed. They have not been authorized for forwarding.
    The framer becomes terminal on failure. Received bytes count input observed;
    oversized input is counted but never retained in the bounded buffer.
    """

    def __init__(self, *, max_bytes, max_records, max_payload=MAX_RECORD_PAYLOAD):
        if (type(max_bytes) is not int or not 6 <= max_bytes <= SERVER_MAX_BYTES
                or type(max_records) is not int or not 1 <= max_records <= SERVER_MAX_RECORDS
                or type(max_payload) is not int or not 1 <= max_payload <= MAX_RECORD_PAYLOAD):
            raise ValueError("invalid_framer_bounds")
        self.max_bytes, self.max_records, self.max_payload = max_bytes, max_records, max_payload
        self.received_bytes, self.record_count = 0, 0
        self._buffer = bytearray()
        self._blocked = False

    @property
    def pending_bytes(self):
        return len(self._buffer)

    def _refuse(self, code):
        self._blocked = True
        self._buffer.clear()
        raise MediatorViolation(code)

    def feed(self, raw):
        if self._blocked:
            raise MediatorViolation("framer_already_blocked")
        if type(raw) is not bytes:
            self._refuse("invalid_record_input")
        self.received_bytes += len(raw)
        if self.received_bytes > self.max_bytes:
            self._refuse("direction_byte_limit")
        self._buffer.extend(raw)
        records = []
        try:
            while len(self._buffer) >= 5:
                if self.record_count >= self.max_records:
                    self._refuse("direction_record_limit")
                size = _header(self._buffer, self.max_payload) + 5
                if size > self.max_bytes:
                    self._refuse("direction_byte_limit")
                if len(self._buffer) < size:
                    break
                record = bytes(self._buffer[:size])
                del self._buffer[:size]
                self.record_count += 1
                records.append(record)
            if self._buffer and self.record_count >= self.max_records:
                self._refuse("direction_record_limit")
        except MediatorViolation:
            self._blocked = True
            self._buffer.clear()
            raise
        return records

    def finish(self):
        if self._blocked:
            raise MediatorViolation("framer_already_blocked")
        if self._buffer:
            self._refuse("partial_record")


class ClientGate:
    """Validate before send; separately commit only a successfully sent record.

    ``check`` retains one pending exact record but does not advance the sequence
    or forwarding counters. The owner calls ``forwarded`` only after sendall
    succeeds. A partial/failed send requires terminating the trial; counters
    never reinterpret those bytes as a completely forwarded record.
    """

    def __init__(self, version, validate_client_hello):
        if type(version) is not str or version not in VERSIONS or not callable(validate_client_hello):
            raise ValueError("invalid_client_gate")
        self.version = version
        self._validator = validate_client_hello
        self.state = "expect_client_hello"
        self.forwarded_bytes = self.forwarded_records = self.forwarded_client_hellos = 0
        self._pending = None

    def _refuse(self, code):
        self.state = "blocked"
        self._pending = None
        raise MediatorViolation(code)

    def _transition(self, raw):
        if type(raw) is not bytes or len(raw) < 6:
            self._refuse("invalid_record_input")
        try:
            size = _header(raw, MAX_RECORD_PAYLOAD)
        except MediatorViolation as error:
            self._refuse(error.code)
        if size != len(raw) - 5:
            self._refuse("record_length_mismatch")
        if (self.forwarded_bytes + len(raw) > CLIENT_MAX_BYTES
                or self.forwarded_records + 1 > CLIENT_MAX_RECORDS):
            self._refuse("client_forward_limit")
        if self.state == "expect_client_hello":
            if (len(raw) > MAX_CLIENT_HELLO or raw[0] != 22 or raw[1:3] != b"\x03\x01"
                    or raw[5] != 1 or len(raw) < 9
                    or int.from_bytes(raw[6:9], "big") != len(raw) - 9):
                self._refuse("invalid_first_client_hello")
            try:
                self._validator(raw, self.version)
            except (TypeError, ValueError):
                self._refuse("invalid_first_client_hello")
            return "expect_ccs" if self.version == "tls1_3" else "expect_key_exchange"
        # Legacy Finished ciphertext also has outer type22: its first payload
        # byte is opaque, so never mistake it for a plaintext message type.
        encrypted_legacy = self.version != "tls1_3" and self.state == "expect_finished"
        if raw[0] == 22 and raw[5] == 1 and not encrypted_legacy:
            self._refuse("extra_client_hello")
        if raw[1:3] != _SELECTED[self.version]:
            self._refuse("record_version_mismatch")
        if self.state == "expect_key_exchange":
            # One complete ClientKeyExchange carrying one uncompressed P-256
            # point. Extra/coalesced/fragmented handshake messages cannot fit.
            if raw[0] != 22 or size != 70 or raw[5:11] != b"\x10\0\0\x42\x41\x04":
                self._refuse("unexpected_client_record")
            return "expect_ccs"
        if self.state == "expect_ccs":
            if raw[0] != 20 or raw[5:] != b"\x01":
                self._refuse("unexpected_client_record")
            return "expect_finished"
        if self.state == "expect_finished":
            if raw[0] != (23 if self.version == "tls1_3" else 22) or size != _FINISHED_LENGTH[self.version]:
                self._refuse("unexpected_client_record")
            return "expect_close"
        if self.state == "expect_close":
            if raw[0] != (23 if self.version == "tls1_3" else 21) or size != _CLOSE_LENGTH[self.version]:
                self._refuse("unexpected_client_record")
            return "complete"
        self._refuse("extra_client_record")

    def check(self, raw):
        if self.state == "blocked":
            raise MediatorViolation("gate_already_blocked")
        if self._pending is not None:
            if type(raw) is not bytes or raw != self._pending[0]:
                self._refuse("pending_record_changed")
            return
        self._pending = (raw, self._transition(raw))

    def forwarded(self, raw):
        if self.state == "blocked":
            raise MediatorViolation("gate_already_blocked")
        if self._pending is None or type(raw) is not bytes or raw != self._pending[0]:
            self._refuse("unvalidated_forward_commit")
        next_state = self._pending[1]
        self.forwarded_client_hellos += self.state == "expect_client_hello"
        self.forwarded_bytes += len(raw)
        self.forwarded_records += 1
        self.state = next_state
        self._pending = None
