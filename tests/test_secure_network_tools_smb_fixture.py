"""Wire/state boundaries of the finite anonymous SMB owner, without sockets."""

import io
import struct
import time

import pytest

from recon_cockpit.secure_agent import network_tools_smb_fixture as smb
from recon_cockpit.secure_agent import network_tools_fixture as fixture


def packet(command, body, *, message=0, tree=0, session=0):
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, 0, command, 1,
                       0, 0, message, 123, tree, session, b"\0" * 16) + body


def rpc(kind, body, call=1):
    return struct.pack("<BBBB4sHHI", 5, 0, kind, 3, b"\x10\0\0\0", 16 + len(body), 0, call) + body


def bind():
    return rpc(11, struct.pack("<HHIB3x", 4280, 4280, 0, 1)
               + struct.pack("<HBB", 0, 1, 0) + smb.SRVS + smb.NDR)


def enumeration(*, operation=15, stub=None, call=2):
    if stub is None:
        stub = struct.pack("<IIIIIIII", 0, 1, 1, 1, 0, 0, 0xffffffff, 0)
    return rpc(0, struct.pack("<IHH", len(stub), 0, operation) + stub, call)


def ioctl(body, message):
    request = struct.pack("<HHI", 57, 0, 0x0011c017) + smb.FILE_ID
    request += struct.pack("<IIIIIIII", 120, len(body), 0, 0, 0, 65536, 1, 0)
    return packet(11, request + body, message=message, tree=1, session=1)


def setup_packets():
    negotiate = struct.pack("<HHHHI16sQH", 36, 1, 0, 0, 0, b"\0" * 16, 0, 0x202)
    first = b"NTLMSSP\0" + struct.pack("<II", 1, 0x00088201) + b"\0" * 16
    anonymous = b"NTLMSSP\0" + struct.pack("<I", 3) + b"\0" * 48 + struct.pack("<I", 0x00000801)
    def session(token):
        return struct.pack("<HBBIIHHQ", 25, 0, 0, 0, 0, 88, len(token), 0) + token
    ipc = "\\\\127.0.0.1\\IPC$".encode("utf-16le")
    tree = struct.pack("<HHHH", 9, 0, 72, len(ipc)) + ipc
    create = bytearray(56)
    struct.pack_into("<H", create, 0, 57)
    struct.pack_into("<I", create, 36, 1)
    name = "srvsvc".encode("utf-16le")
    struct.pack_into("<HH", create, 44, 120, len(name))
    return [packet(0, negotiate), packet(1, session(first), message=1),
            packet(1, session(anonymous), message=2, session=1),
            packet(3, tree, message=3, session=1),
            packet(5, bytes(create) + name, message=4, tree=1, session=1)]


def ready(case="smb-ok"):
    counts = []
    exchange = smb.Exchange(case, fixture.smb_shares(case), lambda: counts.append(1))
    for raw in setup_packets():
        exchange.handle(raw)
    exchange.handle(ioctl(bind(), 5))
    return exchange, counts


class Connection:
    def __init__(self, data):
        self.stream, self.sent = io.BytesIO(data), bytearray()
    def settimeout(self, timeout):
        assert 0 < timeout <= 2
    def recv(self, count):
        return self.stream.read(min(count, 3))
    def sendall(self, data):
        self.sent.extend(data)


@pytest.mark.parametrize("case", ["smb-ok", "smb-empty", "smb-injected", "smb-denied"])
def test_anonymous_ipc_wire_exchange_counts_only_one_validated_enumeration(case):
    sequence = setup_packets() + [ioctl(bind(), 5), ioctl(enumeration(), 6)]
    sequence += [packet(6, struct.pack("<HHI", 24, 0, 0) + smb.FILE_ID, message=7, tree=1, session=1),
                 packet(4, b"\x04\0\0\0", message=8, tree=1, session=1),
                 packet(2, b"\x04\0\0\0", message=9, session=1)]
    connection = Connection(b"".join(len(raw).to_bytes(4, "big") + raw for raw in sequence))
    counts = []
    smb.serve(connection, case=case, shares=fixture.smb_shares(case),
              deadline=time.monotonic() + 5, on_enumeration=lambda: counts.append(1))
    assert counts == [1]
    assert (fixture.HOSTILE_NOTE.encode("utf-16le") in connection.sent) is (case == "smb-injected")
    offset, replies = 0, []
    while offset < len(connection.sent):
        count = int.from_bytes(connection.sent[offset:offset + 4], "big")
        replies.append(bytes(connection.sent[offset + 4:offset + 4 + count]))
        offset += count + 4
    assert len(replies) == 10 and offset == len(connection.sent)
    assert struct.unpack_from("<I", replies[6], 8)[0] == (0xc0000022 if case == "smb-denied" else 0)
    assert ("PUBLIC\0".encode("utf-16le") in connection.sent) is (case in {"smb-ok", "smb-injected"})


@pytest.mark.parametrize("case", ["smb-ok", "smb-denied"])
def test_rpc_write_read_uses_only_the_open_pipe_and_consumes_pending_reply(case):
    exchange, counts = ready(case)
    request = enumeration()
    body = struct.pack("<HHIQ", 49, 112, len(request), 0) + smb.FILE_ID + b"\0" * 16 + request
    exchange.handle(packet(9, body, message=6, tree=1, session=1))
    assert counts == [1] and exchange.pending is not None
    read = struct.pack("<HBBIQ", 49, 0, 0, 8192, 0) + smb.FILE_ID + b"\0" * 16
    reply = exchange.handle(packet(8, read, message=7, tree=1, session=1))
    assert struct.unpack_from("<I", reply, 8)[0] == (0xc0000022 if case == "smb-denied" else 0)
    assert exchange.pending is None
    with pytest.raises(ValueError, match="pipe_read_only"):
        exchange.handle(packet(8, read, message=8, tree=1, session=1))
    assert counts == [1]


@pytest.mark.parametrize("field", [12, 20, 28, 36, 52])
def test_credentials_are_rejected_before_tree_connection(field):
    token = bytearray(b"NTLMSSP\0" + struct.pack("<I", 3) + b"\0" * 52)
    struct.pack_into("<HHI", token, field, 2, 2, 64)
    token.extend(b"xx")
    with pytest.raises(ValueError, match="credentials_forbidden"):
        smb._anonymous(bytes(token))


@pytest.mark.parametrize("fault", ["other_share", "other_pipe", "new_dialect", "compound", "signed", "replayed_message"])
def test_unreviewed_smb_operations_cannot_reach_enumeration(fault):
    sequence = setup_packets()
    if fault == "other_share":
        sequence[3] = sequence[3].replace("IPC$".encode("utf-16le"), "DATA".encode("utf-16le"))
    elif fault == "other_pipe":
        sequence[4] = sequence[4].replace("srvsvc".encode("utf-16le"), "samrxx".encode("utf-16le"))
    elif fault == "new_dialect":
        sequence[0] = sequence[0][:-2] + b"\x11\x03"
    else:
        raw = bytearray(sequence[3])
        if fault == "compound": struct.pack_into("<I", raw, 20, 128)
        if fault == "signed": struct.pack_into("<I", raw, 16, 8)
        if fault == "replayed_message": struct.pack_into("<Q", raw, 24, 2)
        sequence[3] = bytes(raw)
    counts = []
    exchange = smb.Exchange("smb-ok", fixture.SMB_SHARES, lambda: counts.append(1))
    with pytest.raises(ValueError):
        for raw in sequence:
            exchange.handle(raw)
    assert counts == []


@pytest.mark.parametrize("fault", ["operation", "wrong_context", "server", "level", "entries", "preferred", "resume", "trailing", "replay"])
def test_only_single_level1_enumeration_of_fixed_server_is_accepted(fault):
    exchange, counts = ready()
    request = bytearray(enumeration())
    if fault == "operation": struct.pack_into("<H", request, 22, 16)
    elif fault == "wrong_context": struct.pack_into("<H", request, 20, 4)
    elif fault == "server":
        name = "\\\\outside\0".encode("utf-16le")
        stub = struct.pack("<IIII", 1, len(name) // 2, 0, len(name) // 2) + name
        stub += b"\0" * (-len(stub) % 4) + struct.pack("<IIIIIII", 1, 1, 1, 0, 0, 0xffffffff, 0)
        request = enumeration(stub=stub)
    elif fault in {"level", "entries", "preferred", "resume"}:
        index = {"level": 28, "entries": 40, "preferred": 48, "resume": 52}[fault]
        struct.pack_into("<I", request, index, 2)
    elif fault == "trailing":
        request = enumeration(stub=enumeration()[24:] + b"\0\0\0\0")
    else:
        exchange.handle(ioctl(bytes(request), 6))
    with pytest.raises(ValueError):
        exchange.handle(ioctl(bytes(request), 7))
    assert counts == ([1] if fault == "replay" else [])


@pytest.mark.parametrize("fault", ["other_interface", "unsupported_transfer", "bind_auth", "duplicate_bind"])
def test_rpc_bind_is_anonymous_srvsvc_ndr32_only(fault):
    exchange = smb.Exchange("smb-ok", fixture.SMB_SHARES, lambda: pytest.fail("enumeration"))
    request = bytearray(bind())
    if fault == "other_interface": request[32:52] = b"x" * 20
    elif fault == "unsupported_transfer": request[-20:] = b"x" * 20
    elif fault == "bind_auth": struct.pack_into("<H", request, 10, 1)
    else: exchange.rpc(bytes(request))
    with pytest.raises(ValueError): exchange.rpc(bytes(request))


@pytest.mark.parametrize("data", [b"", b"\0\0\0\x01x", b"\0\x01\0\0", b"\0\0\0\x40" + b"x" * 63])
def test_frame_bounds_and_incomplete_input_fail_without_progress(data):
    with pytest.raises(ValueError):
        smb.serve(Connection(data), case="smb-ok", shares=fixture.SMB_SHARES,
                  deadline=time.monotonic() + 2, on_enumeration=lambda: pytest.fail("enumeration"))
