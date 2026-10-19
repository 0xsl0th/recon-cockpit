"""Fixed injected-peer Linux probes; never native daemon-output evidence.

The outer test creates a fresh disconnected network and seals this helper and
the production sources. This helper creates its finite socket fixture before
dropping capabilities and installing the unchanged recorder syscall filter.
"""

import array
import errno
import hashlib
import ipaddress
import json
import os
import resource
import select
import socket
import struct
import sys
import time

sys.path.insert(0, "/app")

from recon_cockpit.secure_agent import name_tls_frontend_worker as frontend
from recon_cockpit.secure_agent import name_tls_recorder as recorder
from recon_cockpit.secure_agent import name_tls_transport as transport
from recon_cockpit.secure_agent import name_tls_topology as topology
from recon_cockpit.secure_agent import name_tls_wire as wire
from recon_cockpit.secure_agent import worker
from recon_cockpit.secure_agent.name_tls_topology_worker import Netlink, LIBC, CLONE_NEWNET


def dns_exchange(configuration):
    query = struct.pack("!6H", 419, 0, 1, 0, 0, 0) + wire.QUESTION
    response = (struct.pack("!6H", 419, 0x8480, 1, 1, 0, 0) + wire.QUESTION
                + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
                + ipaddress.IPv4Address(wire.ROWS[configuration][2]).packed)
    return len(query).to_bytes(2, "big") + query, len(response).to_bytes(2, "big") + response


def client_hello():
    def vector(raw, width=2):
        return len(raw).to_bytes(width, "big") + raw
    def extension(kind, raw):
        return kind.to_bytes(2, "big") + vector(raw)
    extensions = b"".join((extension(0, vector(b"\0" + vector(b"harbordesk.test"))),
        extension(10, b"\0\2\0\x17"), extension(13, b"\0\2\4\3"), extension(43, b"\2\3\4"),
        extension(51, vector(b"\0\x17" + vector(b"\4" + b"k" * 64)))))
    body = b"\3\3" + b"r" * 32 + b"\0\0\2\x13\2\1\0" + vector(extensions)
    handshake = b"\1" + len(body).to_bytes(3, "big") + body
    return b"\x16\3\1" + vector(handshake)


def wire_case(configuration, case):
    operation, fault = case.split("/", 1)
    request, response = dns_exchange(configuration)
    target = "response"
    if operation == "dns":
        if fault == "wrong_transaction_id": response = response[:2] + b"\0\1" + response[4:]
        elif fault == "changed_question": response = response.replace(b"harbordesk", b"harbordesx", 1)
        elif fault == "compression_pointer_loop":
            offset = 12 + len(wire.QUESTION)
            response = response[:offset + 2] + (0xC000 | offset).to_bytes(2, "big") + response[offset + 4:]
        elif fault == "oversized_tcp_frame": response = b"\xff\xff" + response[2:]
        elif fault == "second_tcp_frame": response += response
        elif fault == "extra_question": response = response[:6] + b"\0\2" + response[8:]
        elif fault == "unexpected_edns_or_trailing_bytes": response += b"\0"
        elif fault == "excess_records_or_invalid_ttl":
            response = response[:8] + b"\0\xff" + response[10:]
        else: raise AssertionError("unknown DNS fixture")
    elif operation == "tls":
        request, response, target = client_hello(), b"", "request"
        if fault == "malformed_or_oversized_record": request = request[:3] + b"\xff\xff" + request[5:]
        elif fault == "changed_clienthello_sni": request = request.replace(b"harbordesk.test", b"harbordesx.test")
        elif fault == "unexpected_version_cipher_or_keyshare": request = request.replace(b"\x13\2", b"\x13\1", 1)
        elif fault == "second_clienthello_or_psk_resumption": request += request
        elif fault == "unexpected_extra_records": request += b"\x16\3\3\0\4\x18\0\0\0"
        else: raise AssertionError("unknown TLS fixture")
    elif operation == "http":
        request, response = wire.http_request(configuration, "O4"), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        if fault == "changed_get_path_or_raw_host": request, target = b"GET /other " + request.split(b" ", 2)[2], "request"
        elif fault == "second_request_or_body": request, target = request + request, "request"
        elif fault == "oversized_response": response = b"HTTP/1.1 200 OK\r\nX-Overflow: " + b"x" * 2048 + b"\r\n\r\n"
        else: raise AssertionError("unknown HTTP fixture")
    else:
        raise AssertionError("unknown operation")
    return operation, request, response, target


class FixtureBudget:
    """Counts fixture calls; it is explicitly not an owner authority witness."""
    def __init__(self, refuse=False):
        self.events, self.refuse = [], refuse
    def connection(self, local_id):
        self.events.append(["connection", local_id])
        return True
    def request(self, operation):
        self.events.append(["request", operation])
        if self.refuse:
            raise ValueError("injected_request_reservation_refusal")
    def before_write(self, active, direction, count): self.events.append(["before_write", direction, count])
    def after_write(self, active, direction, count): self.events.append(["after_write", direction, count])
    def observe_dns(self, *args, **kwargs): raise AssertionError("malformed fixture produced an observation")
    def finish(self, **kwargs): self.events.append(["finish", kwargs])


def network(configuration):
    assert os.getuid() == os.getgid() == 65534
    assert [name for _, name in socket.if_nameindex()] == ["lo"]
    assert LIBC.unshare(CLONE_NEWNET) == 0
    channel = Netlink()
    try:
        channel.up("lo")
        for address in (wire.ROWS[configuration][0], wire.ROWS[configuration][2]):
            channel.address("lo", address, 32)
    finally:
        channel.close()


def listener(endpoint):
    channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    channel.bind(endpoint)
    channel.listen(2)
    channel.setblocking(False)
    return channel


def seal():
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    worker.drop_privileges()
    frontend.socket_filter()


def malformed(configuration, case):
    operation, request, response, target = wire_case(configuration, case)
    return exchange(configuration, operation, request, response, target=target,
                    split_response=case == "dns/second_tcp_frame")


def exchange(configuration, operation, request, response=b"", *, target="request", refuse=False, second=False,
             split_response=False):
    row = wire.ROWS[configuration]
    endpoint = (row[0], row[1]) if operation == "dns" else (row[2], row[3] if operation == "http" else row[5])
    public = listener(("127.0.0.1", 0))
    daemon_listener = listener(endpoint)
    private = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    private.setblocking(False)
    private_identity = transport.socket_identity(private)
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.settimeout(1)
    peer.connect(public.getsockname())
    extra = socket.socket(socket.AF_INET, socket.SOCK_STREAM) if second else None
    budget = FixtureBudget(refuse)
    service = recorder.Service(operation, public, private, configuration=configuration, case="O4",
                               deadline=time.monotonic() + 2, budget=budget)
    seal()
    try:
        if second:
            service.tick()
            assert service.accepted_connections == 1
            extra.settimeout(1)
            extra.connect(public.getsockname())
        else:
            peer.sendall(request)
        accepted, sent, peer_bytes = None, False, bytearray()
        request_seen, tail, tail_at, first_buffered = False, None, None, False
        peer.setblocking(False)
        stop = time.monotonic() + 2
        while not service.done and time.monotonic() < stop:
            service.tick()
            if accepted is None and select.select([daemon_listener], [], [], 0)[0]:
                accepted, _ = daemon_listener.accept()
                accepted.setblocking(False)
            if accepted is not None and not request_seen:
                try: received = accepted.recv(8192)
                except BlockingIOError: received = b""
                if received:
                    assert received == request
                    request_seen = True
                    if split_response:
                        first = 2 + int.from_bytes(response[:2], "big")
                        accepted.sendall(response[:first])
                        tail = response[first:]
                        assert tail
                    elif response:
                        accepted.sendall(response)
                    if not split_response:
                        accepted.shutdown(socket.SHUT_WR)
                        sent = True
            if tail is not None:
                if tail_at is None and len(service.raw["original_response"]) == first:
                    assert not service.done and not service.to_client and not peer_bytes
                    first_buffered = True
                    tail_at = time.monotonic() + .01
                if tail_at is not None and time.monotonic() >= tail_at:
                    assert not service.done and not service.to_client and not peer_bytes
                    accepted.sendall(tail)
                    accepted.shutdown(socket.SHUT_WR)
                    tail, sent = None, True
            try: peer_bytes.extend(peer.recv(8192))
            except (BlockingIOError, ConnectionResetError): pass
            time.sleep(.001)
        assert service.done and service.reason not in ("complete", "timeout", "cancelled"), service.snapshot()
        snapshot = service.snapshot()
        if target == "request" or refuse or second:
            assert snapshot["daemon_connects"] == 0
            assert snapshot["request_bytes_delivered"] == snapshot["response_bytes_delivered"] == 0
            assert accepted is None
        else:
            assert snapshot["request_bytes_delivered"] == len(request)
            assert snapshot["response_bytes_delivered"] == 0
            assert accepted is not None and sent
        assert not peer_bytes
        assert not split_response or first_buffered and sent
        transport.assert_descriptor_copies(private_identity, [])
        return {"recorder": snapshot, "fixture_budget_events": budget.events,
                "daemon_capability_closed": True, "delivered_to_peer": 0,
                "split_response": split_response, "first_frame_buffered_before_tail": first_buffered,
                "injected_request_sha256": hashlib.sha256(request).hexdigest(),
                "injected_response_sha256": hashlib.sha256(response).hexdigest()}
    finally:
        service.close()
        for channel in (public, daemon_listener, peer, extra, accepted):
            if channel is not None: channel.close()


def expect_refusal(call):
    try: call()
    except (ValueError, OSError) as error: return str(error)
    raise AssertionError("invalid descriptor handoff was accepted")


def custody(case):
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    source = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    source.setblocking(False)
    identity = transport.socket_identity(source)
    acquired, duplicate, server, accepted = None, None, None, None
    seen = set()
    expected_cookie = identity["daemon_netns_cookie"] + 1
    try:
        if case == "daemon_socket_must_be_unconnected_at_transfer":
            server = listener(("127.0.0.1", 0))
            source.settimeout(1)
            source.connect(server.getsockname())
            source.setblocking(False)
            accepted, _ = server.accept()
        elif case == "daemon_socket_namespace_swap_rejected":
            expected_cookie = identity["daemon_netns_cookie"]
        elif case == "sender_or_launcher_copy_leak_rejected":
            duplicate = os.dup(source.fileno())
        seal()
        packet = {"operation": "daemon_descriptor", "descriptor": identity}
        if case in ("duplicate_scm_rights_handoff_rejected", "unexpected_export_descriptor_rejected"):
            descriptors = array.array("i", [source.fileno(), source.fileno()])
            sender.sendmsg([transport.encode(packet)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)])
            source.close()
            receive = (lambda: topology.receive_packet(receiver, expected_descriptors=13)) if case.startswith("unexpected") else (
                lambda: transport.receive_packet(receiver, descriptor_required=True))
            error = expect_refusal(receive)
        else:
            transport.send_packet(sender, packet, source.fileno())
            source.close()
            if case == "daemon_descriptor_second_consumption_rejected":
                acquired = frontend.receive_daemon_socket(receiver, identity, seen, expected_cookie)
                transport.send_packet(sender, packet, acquired.fileno())
                acquired.close()
                acquired = None
            error = expect_refusal(lambda: frontend.receive_daemon_socket(receiver, identity, seen, expected_cookie))
        if duplicate is not None:
            os.close(duplicate)
            duplicate = None
        transport.assert_descriptor_copies(identity, [])
        return {"refusal": error, "all_received_copies_closed": True, "identity": identity}
    finally:
        for channel in (sender, receiver, source, acquired, server, accepted):
            if channel is not None: channel.close()
        if duplicate is not None: os.close(duplicate)


def unknown_runtime():
    provider = next(path for path in ("/lib/x86_64-linux-gnu/libseccomp.so.2",
        "/usr/lib/x86_64-linux-gnu/libseccomp.so.2") if os.path.isfile(path))
    with open(provider, "rb") as stream:
        provider_raw = stream.read(1048577)
    assert 0 < len(provider_raw) <= 1048576 and os.path.isfile("/usr/bin/python3")
    seal()
    # These are the exact production frontend post-import file permissions.
    frontend.common.apply_landlock({"/dev/null": 6, "/proc/self/status": 4})
    try:
        descriptor = os.open(provider, os.O_RDONLY | os.O_CLOEXEC)
    except PermissionError as error:
        provider_error = error.errno
    else:
        os.close(descriptor)
        raise AssertionError("unlisted provider remained readable after confinement")
    try:
        os.execve("/usr/bin/python3", ["/usr/bin/python3", "-I", "-S", "-c", "raise SystemExit(99)"], {})
    except PermissionError as error:
        helper_error = error.errno
    else:
        raise AssertionError("unlisted helper executed")
    assert provider_error in (errno.EACCES, errno.EPERM) and helper_error == errno.EPERM
    return {"role": "frontend", "provider_path": provider, "helper_path": "/usr/bin/python3",
            "provider_sha256": hashlib.sha256(provider_raw).hexdigest(),
            "both_paths_existed_before_confinement": True,
            "provider_errno": provider_error, "helper_errno": helper_error}


def overflow():
    seal()
    os.write(1, b"INJECTED_NAME_TLS_OUTPUT\n")
    assert os.read(0, 1) == b"1" and os.read(0, 1) == b""
    for _ in range(128):
        os.write(1, b"o" * 1024)
        os.write(2, b"e" * 1024)
    raise AssertionError("combined output supervisor did not terminate the overflowing fixture")


def main():
    configuration, group, case, host_net = sys.argv[1:]
    assert configuration in ("A", "B") and os.readlink("/proc/self/ns/net") != host_net
    network(configuration)
    if case.endswith("native_stdout_stderr_overflow"):
        overflow()
    if case == "unknown_runtime_provider_or_helper_refused":
        result = unknown_runtime()
    elif group == "malformed_and_bounded_wire":
        result = malformed(configuration, case)
    elif group == "transport_denial":
        operation, fault = case.split("/")
        assert fault == "second_connection"
        result = exchange(configuration, operation, b"", second=True)
    elif case in ("consume_before_request_reservation_rejected", "all_descriptor_copies_closed_after_denial"):
        result = exchange(configuration, "dns", dns_exchange(configuration)[0], refuse=True)
    else:
        result = custody(case)
    print(json.dumps({"schema_version": "1", "configuration": configuration, "group": group, "case": case,
        "test_passed": True, "probe_kind": "isolated_injected_peer", "native_daemon_output_claimed": False,
        "owner_enforcement_claimed": False, "namespace": os.readlink("/proc/self/ns/net"),
        "actual_provider_calls": 0, "actual_cost_microusd": 0, "result": result}, sort_keys=True))


if __name__ == "__main__":
    main()
