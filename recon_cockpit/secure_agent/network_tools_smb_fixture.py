"""Finite genuine SMB2_02 / anonymous srvsvc enumeration fixture.

Only IPC$/srvsvc exists. This is neither a filesystem server nor a general SMB,
NTLM or RPC implementation. Public synthetic metadata has no credential/trust
meaning. Each connection permits one level-1 NetrShareEnum and bounded cleanup.
"""

import struct
import time
from uuid import UUID

MAX_FRAME = 8192
MAX_MESSAGES = 24
FILE_ID = b"HarborDeskPipe01"
SRVS = UUID("4b324fc8-1670-01d3-1278-5a47bf6ee188").bytes_le + struct.pack("<I", 3)
NDR = UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le + struct.pack("<I", 2)
NTLM_OID = bytes.fromhex("2b06010401823702020a")


def _u16(raw, offset=0):
    return struct.unpack_from("<H", raw, offset)[0]


def _u32(raw, offset=0):
    return struct.unpack_from("<I", raw, offset)[0]


def _asn(tag, body):
    if len(body) > 2048:
        raise ValueError("smb_fixture_token_limit")
    length = bytes([len(body)]) if len(body) < 128 else b"\x82" + struct.pack("!H", len(body))
    return bytes([tag]) + length + body


def _spnego_init():
    return _asn(0x60, _asn(6, bytes.fromhex("2b0601050502"))
                + _asn(0xa0, _asn(0x30, _asn(0xa0, _asn(0x30, _asn(6, NTLM_OID))))))


def _spnego_reply(token=None):
    fields = _asn(0xa0, _asn(10, b"\x00" if token is None else b"\x01"))
    if token is not None:
        fields += _asn(0xa1, _asn(6, NTLM_OID)) + _asn(0xa2, _asn(4, token))
    return _asn(0xa1, _asn(0x30, fields))


def _ntlm_token(blob):
    """Accept just the finite ASN.1 wrappers carrying one NTLM token."""
    if blob.startswith(b"NTLMSSP\x00"):
        return blob
    tokens = []
    def walk(raw, depth=0):
        if depth > 8:
            raise ValueError("smb_fixture_token_depth")
        offset = 0
        while offset < len(raw):
            if offset + 2 > len(raw):
                raise ValueError("smb_fixture_token_length")
            tag, length = raw[offset:offset + 2]
            offset += 2
            if length & 0x80:
                count = length & 0x7f
                if not 1 <= count <= 2 or offset + count > len(raw):
                    raise ValueError("smb_fixture_token_length")
                length = int.from_bytes(raw[offset:offset + count], "big")
                offset += count
            if offset + length > len(raw):
                raise ValueError("smb_fixture_token_length")
            body = raw[offset:offset + length]
            offset += length
            if tag == 4 and body.startswith(b"NTLMSSP\x00"):
                tokens.append(body)
            elif tag in (0x60, 0x30, 0xa0, 0xa1, 0xa2):
                walk(body, depth + 1)
            elif tag not in (6, 10):
                raise ValueError("smb_fixture_token_type")
    walk(blob)
    if len(tokens) != 1:
        raise ValueError("smb_fixture_ntlm_only")
    return tokens[0]


def _challenge():
    # Public fixed challenge for an anonymous-only exchange, not authentication.
    target = "HARBORDESK".encode("utf-16le")
    info = struct.pack("<HH", 1, len(target)) + target + b"\x00" * 4
    flags = 0x00888205  # Unicode, NTLM, target server/info, extended session security.
    return (b"NTLMSSP\x00" + struct.pack("<IHHII", 2, len(target), len(target), 48, flags)
            + b"PUBLIC00" + b"\x00" * 8 + struct.pack("<HHI", len(info), len(info), 48 + len(target))
            + target + info)


def _anonymous(token):
    if len(token) < 64 or token[:12] != b"NTLMSSP\x00\x03\x00\x00\x00":
        raise ValueError("smb_fixture_anonymous_only")
    fields = []
    for offset in (12, 20, 28, 36, 44, 52):
        size, maximum, start = struct.unpack_from("<HHI", token, offset)
        if size > maximum or start + size > len(token):
            raise ValueError("smb_fixture_auth_length")
        fields.append(token[start:start + size])
    lm, nt, domain, user, workstation, session_key = fields
    if lm not in (b"", b"\x00") or nt or domain or user or session_key or len(workstation) > 64:
        raise ValueError("smb_fixture_credentials_forbidden")


def _slice(raw, offset, length, *, minimum):
    if not minimum <= offset <= len(raw) or not 0 <= length <= MAX_FRAME or offset + length > len(raw):
        raise ValueError("smb_fixture_buffer_limit")
    return raw[offset:offset + length]


def _unicode(raw):
    if len(raw) % 2 or len(raw) > 256:
        raise ValueError("smb_fixture_name_limit")
    return raw.decode("utf-16le", errors="strict")


def _ndr_string(value):
    raw = (value + "\x00").encode("utf-16le")
    count = len(raw) // 2
    result = struct.pack("<III", count, 0, count) + raw
    return result + b"\x00" * (-len(result) % 4)


def share_response(shares, *, denied=False):
    """NDR32 level-1 SHARE_ENUM_STRUCT; only supplied public fixture rows."""
    if denied:
        return struct.pack("<IIIIIIII", 1, 1, 1, 0, 0, 0, 0, 5)
    if len(shares) > 2:
        raise ValueError("smb_fixture_share_limit")
    count = len(shares)
    result = struct.pack("<IIIIII", 1, 1, 1, count, 2, count)
    result += b"".join(struct.pack("<III", 3 + 2 * i, kind, 4 + 2 * i)
                       for i, (_, kind, _) in enumerate(shares))
    for name, kind, comment in shares:
        if name not in ("PUBLIC", "IPC$") or kind not in (0, 3) or len(comment) > 256:
            raise ValueError("smb_fixture_share_invalid")
        result += _ndr_string(name) + _ndr_string(comment)
    return result + struct.pack("<III", count, 0, 0)


def validate_share_request(stub):
    if len(stub) < 28:
        raise ValueError("smb_fixture_rpc_stub")
    offset = 4
    if _u32(stub):
        maximum, displacement, count = struct.unpack_from("<III", stub, offset)
        offset += 12
        if displacement != 0 or not 1 <= count <= maximum <= 64:
            raise ValueError("smb_fixture_rpc_server")
        server = _unicode(_slice(stub, offset, count * 2, minimum=offset))
        if server not in ("\\\\127.0.0.1\x00", "127.0.0.1\x00", "\x00"):
            raise ValueError("smb_fixture_rpc_server")
        offset = (offset + count * 2 + 3) & ~3
    if len(stub) < offset + 28:
        raise ValueError("smb_fixture_rpc_stub")
    level, tag, container, entries, buffer, preferred, resume = struct.unpack_from("<IIIIIII", stub, offset)
    offset += 28
    if (level != 1 or tag != 1 or not container or entries or buffer
            or preferred not in (0xffffffff, 65536) or (resume and stub[offset:] != b"\x00" * 4)
            or (not resume and offset != len(stub))):
        raise ValueError("smb_fixture_single_level1_enumeration")


def _rpc_packet(kind, call, body):
    return struct.pack("<BBBB4sHHI", 5, 0, kind, 3, b"\x10\x00\x00\x00", len(body) + 16, 0, call) + body


class Exchange:
    def __init__(self, case, shares, on_enumeration):
        self.case, self.shares, self.on_enumeration = case, shares, on_enumeration
        self.phase = "negotiate"
        self.message_id = -1
        self.context_id = None
        self.rpc_calls = set()
        self.enumerated = False
        self.pending = None

    def rpc(self, raw):
        if (len(raw) < 16 or raw[:2] != b"\x05\x00" or raw[3] & ~0x13 or raw[3] & 3 != 3
                or raw[4:8] != b"\x10\x00\x00\x00" or _u16(raw, 8) != len(raw) or _u16(raw, 10)):
            raise ValueError("smb_fixture_rpc_framing")
        call, kind, body = _u32(raw, 12), raw[2], raw[16:]
        if call in self.rpc_calls or len(self.rpc_calls) >= 2:
            raise ValueError("smb_fixture_rpc_replay")
        self.rpc_calls.add(call)
        if kind == 11 and self.context_id is None:
            if len(body) < 12 or not 1 <= body[8] <= 3:
                raise ValueError("smb_fixture_rpc_bind")
            offset, results = 12, []
            for _ in range(body[8]):
                if offset + 24 > len(body):
                    raise ValueError("smb_fixture_rpc_bind")
                context, count, reserved = struct.unpack_from("<HBB", body, offset)
                abstract = body[offset + 4:offset + 24]
                if abstract != SRVS or reserved or not 1 <= count <= 3:
                    raise ValueError("smb_fixture_srvsvc_only")
                offset += 24
                transfers = [_slice(body, offset + i * 20, 20, minimum=offset) for i in range(count)]
                offset += count * 20
                accepted = NDR in transfers and self.context_id is None
                if accepted:
                    self.context_id = context
                results.append(struct.pack("<HH", 0 if accepted else 2, 0 if accepted else 2)
                               + (NDR if accepted else b"\x00" * 20))
            if offset != len(body) or self.context_id is None:
                raise ValueError("smb_fixture_ndr32_only")
            address = b"\\PIPE\\srvsvc\x00"
            response = struct.pack("<HHIH", 4280, 4280, 1, len(address)) + address
            response += b"\x00" * (-len(response) % 4)
            response += bytes([len(results), 0, 0, 0]) + b"".join(results)
            return _rpc_packet(12, call, response)
        if kind != 0 or self.context_id is None or self.enumerated or len(body) < 8:
            raise ValueError("smb_fixture_rpc_operation")
        allocation, context, operation = struct.unpack_from("<IHH", body)
        if context != self.context_id or operation != 15 or allocation != len(body) - 8:
            raise ValueError("smb_fixture_shareenum_only")
        validate_share_request(body[8:])
        self.enumerated = True
        self.on_enumeration()
        response = share_response(self.shares, denied=self.case == "smb-denied")
        return _rpc_packet(2, call, struct.pack("<IHBB", len(response), context, 0, 0) + response)

    def handle(self, raw):
        if (len(raw) < 64 or raw[:4] != b"\xfeSMB" or _u16(raw, 4) != 64
                or _u32(raw, 16) or _u32(raw, 20) or raw[48:64] != b"\x00" * 16):
            raise ValueError("smb_fixture_smb2_unsigned_single_only")
        command, message = _u16(raw, 12), struct.unpack_from("<Q", raw, 24)[0]
        tree, session = _u32(raw, 36), struct.unpack_from("<Q", raw, 40)[0]
        if message <= self.message_id:
            raise ValueError("smb_fixture_message_replay")
        self.message_id = message
        body, status, response_tree, response_session = raw[64:], 0, tree, session
        if self.phase == "negotiate" and command == 0 and tree == session == 0:
            if len(body) != 38 or _u16(body) != 36 or _u16(body, 2) != 1 or _u16(body, 36) != 0x202:
                raise ValueError("smb_fixture_smb202_only")
            token = _spnego_init()
            reply = struct.pack("<HHHH16sIIIIQQHHI", 65, 1, 0x202, 0, b"HarborDeskSMB001!",
                0, MAX_FRAME, MAX_FRAME, MAX_FRAME, 133000000000000000, 133000000000000000, 128, len(token), 0) + token
            self.phase = "session"
        elif self.phase in ("session", "challenge") and command == 1 and tree == 0:
            if len(body) < 24 or _u16(body) != 25 or any(body[16:24]):
                raise ValueError("smb_fixture_session_setup")
            blob = _slice(raw, _u16(body, 12), _u16(body, 14), minimum=88)
            token = _ntlm_token(blob) if blob else b""
            if self.phase == "session" and token[:12] == b"NTLMSSP\x00\x01\x00\x00\x00":
                answer, status, self.phase = _spnego_reply(_challenge()), 0xc0000016, "challenge"
            else:
                if token:
                    _anonymous(token)
                answer, self.phase = _spnego_reply(), "tree"
            response_session = 1
            reply = struct.pack("<HHHH", 9, 2 if status == 0 else 0, 72, len(answer)) + answer
        elif self.phase == "tree" and command == 3 and session == 1 and tree == 0:
            if len(body) < 8 or _u16(body) != 9:
                raise ValueError("smb_fixture_tree_request")
            name = _unicode(_slice(raw, _u16(body, 4), _u16(body, 6), minimum=72))
            if name.upper() != "\\\\127.0.0.1\\IPC$":
                raise ValueError("smb_fixture_ipc_only")
            reply, response_tree, self.phase = struct.pack("<HBBIII", 16, 2, 0, 0, 0, 0x001f01ff), 1, "pipe"
        elif self.phase == "pipe" and command == 5 and tree == session == 1:
            if len(body) < 56 or _u16(body) != 57 or _u32(body, 36) != 1 or _u32(body, 48) or _u32(body, 52):
                raise ValueError("smb_fixture_open_existing_pipe_only")
            name = _unicode(_slice(raw, _u16(body, 44), _u16(body, 46), minimum=120))
            if name.lower() != "srvsvc":
                raise ValueError("smb_fixture_srvsvc_only")
            reply = struct.pack("<HBBI", 89, 0, 0, 1) + b"\x00" * 48 + struct.pack("<II", 0x80, 0) + FILE_ID + b"\x00" * 8
            self.phase = "rpc"
        elif self.phase == "rpc" and tree == session == 1 and command == 11:
            if (len(body) < 56 or _u16(body) != 57 or _u32(body, 4) != 0x0011c017
                    or body[8:24] != FILE_ID or _u32(body, 40) or _u32(body, 48) != 1):
                raise ValueError("smb_fixture_pipe_transceive_only")
            request = _slice(raw, _u32(body, 24), _u32(body, 28), minimum=120)
            result = self.rpc(request)
            if self.enumerated and self.case == "smb-denied":
                # Exercise a genuine denial of the SMB pipe transaction.
                # smbclient may suppress this just like an RPC-level denial;
                # its footer-only result must remain inconclusive.
                status, reply = 0xc0000022, struct.pack("<HBBI", 9, 0, 0, 0) + b"\x00"
            else:
                reply = struct.pack("<HHI", 49, 0, 0x0011c017) + FILE_ID + struct.pack("<IIIIII", 0, 0, 112, len(result), 1, 0) + result
        elif self.phase == "rpc" and tree == session == 1 and command == 9:
            if len(body) < 48 or _u16(body) != 49 or body[16:32] != FILE_ID or any(body[8:16]) or self.pending is not None:
                raise ValueError("smb_fixture_pipe_write_only")
            request = _slice(raw, _u16(body, 2), _u32(body, 4), minimum=112)
            self.pending = self.rpc(request)
            reply = struct.pack("<HHIIHH", 17, 0, len(request), 0, 0, 0)
        elif self.phase == "rpc" and tree == session == 1 and command == 8:
            if (len(body) < 48 or _u16(body) != 49 or body[16:32] != FILE_ID or any(body[8:16])
                    or self.pending is None or _u32(body, 4) < len(self.pending)):
                raise ValueError("smb_fixture_pipe_read_only")
            if self.enumerated and self.case == "smb-denied":
                status, reply = 0xc0000022, struct.pack("<HBBI", 9, 0, 0, 0) + b"\x00"
            else:
                reply = struct.pack("<HBBIII", 17, 80, 0, len(self.pending), 0, 0) + self.pending
            self.pending = None
        elif self.phase == "rpc" and self.enumerated and command == 6 and tree == session == 1:
            if len(body) != 24 or _u16(body) != 24 or body[8:24] != FILE_ID:
                raise ValueError("smb_fixture_close")
            reply, self.phase = struct.pack("<H", 60) + b"\x00" * 58, "disconnect"
        elif self.phase == "disconnect" and command == 4 and tree == session == 1 and body == b"\x04\x00\x00\x00":
            reply, self.phase = body, "logoff"
        elif self.phase == "logoff" and command == 2 and session == 1 and body == b"\x04\x00\x00\x00":
            reply, self.phase = body, "closed"
        else:
            raise ValueError("smb_fixture_operation_forbidden")
        header = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, status, command, 1,
                             1, 0, message, 0, response_tree, response_session, b"\x00" * 16)
        return header + reply


def serve(connection, *, case, shares, deadline, on_enumeration):
    exchange = Exchange(case, shares, on_enumeration)
    def read(count):
        result = bytearray()
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("smb_fixture_deadline")
            connection.settimeout(min(remaining, 2))
            part = connection.recv(count - len(result))
            if not part:
                if not result and exchange.enumerated:
                    return None
                raise ValueError("smb_fixture_incomplete")
            result.extend(part)
        return bytes(result)
    for _ in range(MAX_MESSAGES):
        header = read(4)
        if header is None:
            return
        size = int.from_bytes(header, "big")
        if not 64 <= size <= MAX_FRAME:
            raise ValueError("smb_fixture_frame_limit")
        raw = read(size)
        reply = exchange.handle(raw)
        if exchange.enumerated and case == "smb-stalled":
            time.sleep(max(0, deadline - time.monotonic()))
            return
        if exchange.enumerated and case == "smb-malformed":
            connection.sendall(b"\x00\xff\xff\xff")
            return
        connection.sendall(len(reply).to_bytes(4, "big") + reply)
        if exchange.phase == "closed":
            return
    raise ValueError("smb_fixture_message_limit")
