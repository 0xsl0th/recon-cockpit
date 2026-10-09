"""Finite synthetic ONC RPC metadata fixture, with no mount or file backend.

Only the owner mounts this module. RPC calls are bounded and validated before
counting the single DUMP/EXPORT operation. Discovery can only name the fixed
synthetic portmapper or MOUNT program; replies remain fixture data and never
become execution authority.
"""

import struct
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    import importlib.util
    from pathlib import Path
    _spec = importlib.util.spec_from_file_location("rpc_public_fixture", Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(fixture)

PORT = fixture.RPC_PORT
MAX_FRAME_BYTES = fixture.RPC_MAX_FRAME_BYTES
MAX_CALLS = fixture.RPC_MAX_CALLS
MAX_CONNECTIONS = fixture.RPC_MAX_CONNECTIONS
REGISTRATIONS = fixture.RPC_REGISTRATIONS
EXPORTS = fixture.NFS_EXPORTS
INJECTED_REGISTRATION = fixture.RPC_INJECTED_REGISTRATION
HOSTILE_GROUP = fixture.NFS_HOSTILE_GROUP


def _words(*values):
    return struct.pack("!" + "I" * len(values), *values)


def _string(value):
    raw = value.encode("ascii")
    return _words(len(raw)) + raw + b"\0" * (-len(raw) % 4)


class Reader:
    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    def word(self):
        if self.offset + 4 > len(self.raw):
            raise ValueError("rpc_fixture_incomplete_word")
        value = struct.unpack_from("!I", self.raw, self.offset)[0]
        self.offset += 4
        return value

    def opaque(self, maximum):
        size = self.word()
        end = self.offset + size
        padded = end + (-size % 4)
        if size > maximum or padded > len(self.raw) or any(self.raw[end:padded]):
            raise ValueError("rpc_fixture_opaque_limit")
        value, self.offset = self.raw[self.offset:end], padded
        return value

    def end(self):
        if self.offset != len(self.raw):
            raise ValueError("rpc_fixture_trailing_bytes")


def _auth(reader):
    flavor, body = reader.word(), reader.opaque(400)
    if flavor == 0:
        if body:
            raise ValueError("rpc_fixture_nonempty_null_auth")
    elif flavor == 1:
        # AUTH_SYS is transport metadata, not a password. Native showmount may
        # emit this from its synthetic namespace identity; never retain it.
        auth = Reader(body)
        auth.word()  # Per-call timestamp does not affect authority.
        if auth.opaque(32) != b"reconlab" or auth.word() != 0 or auth.word() != 0:
            raise ValueError("rpc_fixture_synthetic_identity_only")
        groups = auth.word()
        if groups > 1 or any(auth.word() != 0 for _ in range(groups)):
            raise ValueError("rpc_fixture_synthetic_groups_only")
        auth.end()
    else:
        raise ValueError("rpc_fixture_auth_forbidden")


def read_call(raw):
    if type(raw) is not bytes or not 40 <= len(raw) <= MAX_FRAME_BYTES:
        raise ValueError("rpc_fixture_call_limit")
    reader = Reader(raw)
    xid = reader.word()
    if (reader.word(), reader.word()) != (0, 2):
        raise ValueError("rpc_fixture_call_header")
    program, version, procedure = reader.word(), reader.word(), reader.word()
    _auth(reader)
    if reader.word() != 0 or reader.opaque(0):
        raise ValueError("rpc_fixture_verifier_forbidden")
    return xid, program, version, procedure, reader


def _accepted(xid, body=b"", status=0):
    return _words(xid, 1, 0, 0, 0, status) + body


def _records(case):
    records = () if case == "rpc-empty" else REGISTRATIONS
    if case == "rpc-injected":
        records += (INJECTED_REGISTRATION,)
    return b"".join(_words(1, *record) for record in records) + _words(0)


def _exports(case):
    exports = () if case == "nfs-empty" else EXPORTS
    if case == "nfs-injected":
        exports = ((EXPORTS[0][0], (HOSTILE_GROUP,)), EXPORTS[1])
    return b"".join(_words(1) + _string(path) + b"".join(_words(1) + _string(group)
        for group in groups) + _words(0) for path, groups in exports) + _words(0)


class Exchange:
    def __init__(self, case, on_metadata):
        if case not in ("rpc-ok", "rpc-empty", "rpc-injected", "rpc-malformed", "rpc-stalled",
                        "nfs-ok", "nfs-empty", "nfs-injected", "nfs-malformed", "nfs-stalled", "nfs-redirected"):
            raise ValueError("rpc_fixture_case")
        self.case, self.on_metadata = case, on_metadata
        self.calls = 0
        self.metadata = False
        self.discovery = 0

    def reply(self, raw):
        xid, program, version, procedure, reader = read_call(raw)
        if self.calls >= MAX_CALLS or self.metadata:
            raise ValueError("rpc_fixture_call_count")
        self.calls += 1
        listing = self.case.startswith("rpc-")
        if listing and (program, version, procedure) == (100000, 2, 4):
            if not self.discovery:
                raise ValueError("rpc_fixture_discovery_required")
            reader.end()
            body = _records(self.case)
        elif program == 100000:
            wanted_programs = ((100000, 2),) if listing else ((100005, 1), (100005, 3))
            if self.discovery >= 3:
                raise ValueError("rpc_fixture_discovery_count")
            if (version, procedure) == (2, 3):
                wanted = (reader.word(), reader.word(), reader.word(), reader.word())
                if wanted[:2] not in wanted_programs or wanted[2:] != (6, 0):
                    raise ValueError("rpc_fixture_fixed_mount_discovery")
                reader.end()
                body = _words(112 if self.case == "nfs-redirected" else PORT)
            elif version in (3, 4) and procedure in ((3, 9) if version == 4 else (3,)):
                if (reader.word(), reader.word()) not in wanted_programs:
                    raise ValueError("rpc_fixture_fixed_mount_discovery")
                if reader.opaque(8) != b"tcp":
                    raise ValueError("rpc_fixture_tcp_only")
                # libtirpc may send its fixed rpcbind contact address here.
                if reader.opaque(64) not in (b"", b"127.0.0.1.0.111") or reader.opaque(32) not in (b"", b"libtirpc"):
                    raise ValueError("rpc_fixture_fixed_contact")
                reader.end()
                body = _string("127.0.0.1.0.112" if self.case == "nfs-redirected" else "127.0.0.1.0.111")
            else:
                raise ValueError("rpc_fixture_discovery_only")
            self.discovery += 1
            return _accepted(xid, body)
        elif not listing and program == 100005 and version in (1, 3) and procedure in (0, 5):
            reader.end()
            if not self.discovery or self.case == "nfs-redirected":
                raise ValueError("rpc_fixture_discovery_required")
            if procedure == 0:
                return _accepted(xid)
            body = _exports(self.case)
        else:
            raise ValueError("rpc_fixture_exports_only")
        self.metadata = True
        self.on_metadata()
        if self.case.endswith("-stalled"):
            return None
        if self.case.endswith("-malformed"):
            body = _words(1)  # Incomplete list item cannot establish metadata.
        return _accepted(xid, body)


def _read_exact(connection, count):
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ValueError("rpc_fixture_incomplete_frame")
        data.extend(chunk)
    return bytes(data)


def serve(connection, exchange, deadline):
    for _ in range(MAX_CALLS):
        marker = struct.unpack("!I", _read_exact(connection, 4))[0]
        size = marker & 0x7fffffff
        if not marker & 0x80000000 or not 40 <= size <= MAX_FRAME_BYTES:
            raise ValueError("rpc_fixture_frame_limit")
        response = exchange.reply(_read_exact(connection, size))
        if response is None:
            time.sleep(max(0, min(60, deadline - time.monotonic())))
            return
        connection.sendall(_words(0x80000000 | len(response)) + response)
        if exchange.metadata:
            return
    raise ValueError("rpc_fixture_call_count")


def firewall_rules():
    """One reviewed low-port exception; no caller-selected port or address."""
    return """table inet recon_fixture {
  chain output {
    type filter hook output priority 0; policy drop;
    ip daddr 127.0.0.1 tcp dport 111 ct direction original accept
    ct direction reply ct state established ct original ip daddr 127.0.0.1 ct original proto-dst 111 accept
  }
  chain input {
    type filter hook input priority 0; policy drop;
    ip daddr 127.0.0.1 tcp dport 111 ct direction original accept
    ct direction reply ct state established ct original ip daddr 127.0.0.1 ct original proto-dst 111 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
}
"""
