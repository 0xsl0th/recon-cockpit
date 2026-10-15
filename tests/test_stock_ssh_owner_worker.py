"""Owner protocol/custody tests; no daemon or confined worker is launched."""

import array
from copy import deepcopy
import errno
import hashlib
import math
import os
from pathlib import Path
import socket
import stat
import sys
import time

import pytest

from recon_cockpit.secure_agent import stock_ssh_owner_worker as owner
from recon_cockpit.secure_agent import stock_ssh_contract as contract


@pytest.fixture(autouse=True)
def portable_kernel_metadata(monkeypatch):
    if sys.platform != "linux":
        # The portable suite tests descriptor transfer and protocol custody,
        # not Linux namespace-cookie/CLOEXEC kernel features. Native Linux
        # acceptance separately checks both; unsupported production hosts refuse.
        monkeypatch.setattr(owner, "RECEIVE_CLOEXEC", 0)
        def identity_for_descriptor(descriptor):
            channel = socket.socket(fileno=os.dup(descriptor))
            try:
                assert channel.family == socket.AF_INET and channel.type == socket.SOCK_STREAM
                return {"inode": 1000 + descriptor, "local": list(channel.getsockname()),
                        "peer": list(channel.getpeername()), "netns_cookie": 23}
            finally:
                channel.close()
        monkeypatch.setattr(owner.custodian, "connected_identity", identity_for_descriptor)


def identity(index=0):
    return {"inode": 2000 + index, "local": ["127.0.0.1", 19022],
            "peer": ["127.0.0.1", 40000 + index], "netns_cookie": 23}


def transport(case="O2"):
    return {"mode": "preconnected-loopback-tcp-descriptor-no-live-listener",
            "pairs": [identity(index) for index in range(3 if case in ("O1", "N1") else 1)],
            "private_listener_closed": True, "exact_established_routes_only": True,
            "setup_exchange_verified": True, "setup_witness_bytes_each_direction": len(owner.PRIVATE_WITNESS)}


def request():
    return {"selection": contract.selection("A", "O2"), "deadline": 105.0,
        "host_namespaces": {key: key + ":[100]" for key in ("user", "net", "mnt", "pid")},
        "runtime_digest": "a" * 64}


def instance():
    return {"operation": "instance", "connection_id": 1, "deadline": 105.0, "descriptor": identity()}


def receipt(metadata):
    ledger = owner.process.ProcessLedger(2)
    ledger.exit(2, 0)
    return {**ledger.receipt(), "descriptor": metadata, "stop_reason": "processes_exited",
            "stderr_base64": "", "stderr_truncated": False, "elapsed_ms": 1}


def test_protocol_codec_rejects_duplicate_keys_and_unknown_top_level():
    value = {"operation": "ready", "sequence": 1}
    assert owner.decode(owner.encode(value)) == value
    for raw in (b'{"sequence":1,"sequence":2}', b'[]', b'null', b'', b'x' * (owner.MAX_PACKET + 1),
                b'{"nested":{"v":1,"v":2}}', b'{"v":NaN}', b'{"v":Infinity}', b'{"v":1e400}', b'{"v":"\xff"}'):
        with pytest.raises(ValueError): owner.decode(raw)
    with pytest.raises(ValueError): owner.encode({"oversized": "x" * owner.MAX_PACKET})
    with pytest.raises(ValueError): owner.encode({"value": float("nan")})


def test_owner_codec_uses_its_declared_bound_for_original_and_transformed_evidence():
    value = {"evidence": "x" * (owner.MAX_PACKET - len(b'{"evidence":""}'))}
    raw = owner.encode(value)
    assert len(raw) == owner.MAX_PACKET and owner.decode(raw) == value
    with pytest.raises(ValueError): owner.decode(raw + b" ")


@pytest.mark.parametrize("fault", ["extra", "selection", "deadline_bool", "expired", "too_long", "nan",
    "digest", "host_namespaces", "host_namespace_type"])
def test_bootstrap_requires_exact_finite_selection_deadline_and_namespace_context(fault):
    value = request()
    if fault == "extra": value["execute"] = True
    elif fault == "selection": value["selection"]["case"] = "O1"
    elif fault == "deadline_bool": value["deadline"] = True
    elif fault == "expired": value["deadline"] = 100
    elif fault == "too_long": value["deadline"] = 161
    elif fault == "nan": value["deadline"] = math.nan
    elif fault == "digest": value["runtime_digest"] = "A" * 64
    elif fault == "host_namespaces": value["host_namespaces"]["user"] = "net:[100]"
    else: value["host_namespaces"]["pid"] = 100
    with pytest.raises(ValueError): owner.request(value, now=100)
    assert owner.request(request(), now=100) == request()


@pytest.mark.parametrize("fault", ["extra", "bool_id", "repeated_id", "exhausted", "deadline_bool",
    "expired", "too_long", "past_owner", "host_descriptor", "inode_bool"])
def test_instance_reservation_refuses_reuse_extra_work_or_host_descriptor(fault):
    value, count, last, end = instance(), 0, 0, 160
    if fault == "extra": value["argv"] = ["/bin/sh"]
    elif fault == "bool_id": value["connection_id"] = True
    elif fault == "repeated_id": last = 1
    elif fault == "exhausted": count = 1
    elif fault == "deadline_bool": value["deadline"] = True
    elif fault == "expired": value["deadline"] = 100
    elif fault == "too_long": value["deadline"] = 105.001
    elif fault == "past_owner": end = 104
    elif fault == "host_descriptor": value["descriptor"]["peer"][0] = "10.77.0.20"
    else: value["descriptor"]["inode"] = True
    with pytest.raises(ValueError): owner.validate_instance_message(value, count=count, last=last,
        selected=contract.selection("A", "O2"), owner_deadline=end, now=100)


def test_nmap_has_three_serial_instances_and_no_renewed_allowance():
    value = instance(); value["connection_id"] = 3
    assert owner.validate_instance_message(value, count=2, last=2, selected=contract.selection("A", "O1"),
                                           owner_deadline=160, now=100) == value
    with pytest.raises(ValueError): owner.validate_instance_message(value, count=3, last=2,
        selected=contract.selection("A", "O1"), owner_deadline=160, now=100)
    assert owner._is_cancel({"operation": "cancel", "connection_id": 3}, 3)
    assert not owner._is_cancel({"operation": "cancel", "connection_id": True}, 1)
    assert not owner._is_cancel({"operation": "cancel", "connection_id": 2}, 3)


@pytest.mark.parametrize("fault", ["extra", "open_listener", "broad_routes", "wrong_count", "same_inode",
    "same_peer", "different_cookie", "different_listener", "host_endpoint", "invalid_port"])
def test_transport_receipt_binds_finite_distinct_connected_pairs(fault):
    value = transport("O1")
    if fault == "extra": value["host_network"] = False
    elif fault == "open_listener": value["private_listener_closed"] = False
    elif fault == "broad_routes": value["exact_established_routes_only"] = 1
    elif fault == "wrong_count": value["pairs"].pop()
    elif fault == "same_inode": value["pairs"][1]["inode"] = value["pairs"][0]["inode"]
    elif fault == "same_peer": value["pairs"][1]["peer"] = value["pairs"][0]["peer"]
    elif fault == "different_cookie": value["pairs"][1]["netns_cookie"] += 1
    elif fault == "different_listener": value["pairs"][1]["local"][1] += 1
    elif fault == "host_endpoint": value["pairs"][1]["local"][0] = "0.0.0.0"
    else: value["pairs"][1]["peer"][1] = 65536
    with pytest.raises(ValueError): owner.validate_private_transport(value, contract.selection("A", "O1"))


def test_firewall_allows_frontend_and_only_established_exact_private_tuples():
    for configuration, target, port in (("A", "10.77.0.20", 2222), ("B", "172.23.0.20", 12222)):
        raw = owner.firewall_rules(configuration, transport("O1")["pairs"])
        assert raw.count("policy drop") == 3
        assert raw.count(f"ip daddr {target} tcp dport {port} ct direction original accept") == 2
        private = [line for line in raw.splitlines() if "ip saddr 127.0.0.1" in line]
        assert len(private) == 12 and all(line.endswith("ct state established accept") for line in private)
        assert all("tcp sport " in line and "tcp dport " in line for line in private)
        assert "ct state established accept\n  " not in "\n".join(line for line in private if "tcp sport" not in line)
        assert "udp" not in raw and "0.0.0.0" not in raw


def test_private_pairs_are_real_connected_tcp_and_listener_is_closed():
    rows = owner.private_pairs(3, time.monotonic() + 3)
    try:
        saved = {"mode": "preconnected-loopback-tcp-descriptor-no-live-listener", "pairs": [row[2] for row in rows],
                 "private_listener_closed": True, "exact_established_routes_only": True,
                 "setup_exchange_verified": True, "setup_witness_bytes_each_direction": len(owner.PRIVATE_WITNESS)}
        owner.verify_private_pairs(rows, time.monotonic() + 2)
        assert owner.validate_private_transport(saved, contract.selection("B", "O1")) == saved
        for client, server, metadata in rows:
            assert owner.custodian.connected_identity(server.fileno()) == metadata
            client.send(b"owned")
            server.settimeout(1); assert server.recv(5) == b"owned"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            assert probe.connect_ex(tuple(rows[0][2]["local"])) == errno.ECONNREFUSED
    finally:
        for client, server, _ in rows: client.close(); server.close()


def test_descriptor_packet_transfers_exactly_one_owned_cloexec_fd():
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    received = None
    try:
        owner.send_packet(sender, {"operation": "instance"}, descriptor)
        value, received = owner.receive_packet(receiver, descriptor_required=True)
        assert value == {"operation": "instance"} and received != descriptor
        if sys.platform == "linux":
            assert not os.get_inheritable(received)
        assert os.fstat(received).st_rdev == os.fstat(descriptor).st_rdev
    finally:
        sender.close(); receiver.close(); os.close(descriptor)
        if received is not None: os.close(received)


def test_setup_rules_bind_both_ports_before_connect_and_final_rules_remove_new():
    routes = []
    def prepare(value):
        routes.extend(value)
        assert all(row["peer"][1] and row["local"][1] for row in value)
        setup = owner._firewall_rules("A", value, setup=True)
        assert setup.count("ct state { new, established }") == 4
    rows = owner.private_pairs(1, time.monotonic() + 3, prepare_transport=prepare)
    try:
        assert routes == [{key: rows[0][2][key] for key in ("local", "peer")}]
        final = owner.firewall_rules("A", [rows[0][2]])
        assert "{ new, established }" not in final
        owner.verify_private_pairs(rows, time.monotonic() + 1)
        for client, server, _ in rows:
            for channel in (client, server):
                with pytest.raises(BlockingIOError): channel.recv(1)
    finally:
        for client, server, _ in rows: client.close(); server.close()


@pytest.mark.parametrize("fault", ["extra_fd", "unexpected_fd", "truncated", "bad_json", "unknown_ancillary"])
def test_rejected_packet_closes_every_received_descriptor(fault):
    descriptors = [os.open("/dev/null", os.O_RDONLY)]
    if fault == "extra_fd": descriptors.append(os.open("/dev/null", os.O_RDONLY))
    payload = array.array("i", descriptors).tobytes()
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, payload)]
    if fault == "unknown_ancillary": ancillary.append((123, 456, b"unknown"))
    class Fake:
        def recvmsg(self, *args):
            return (b'{"a":1,"a":2}' if fault == "bad_json" else b'{}', ancillary,
                    socket.MSG_TRUNC if fault == "truncated" else 0, None)
    with pytest.raises(ValueError): owner.receive_packet(Fake(), descriptor_required=fault != "unexpected_fd")
    for descriptor in descriptors:
        with pytest.raises(OSError) as error: os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


def test_manifest_changed_or_unsealed_mount_fails_before_daemon_work(tmp_path, monkeypatch):
    path = tmp_path / "fixed"; path.write_bytes(b"fixed-image"); path.chmod(0o400)
    manifest = {"files": [{"destination": str(path), "size": len(b"fixed-image"),
                           "sha256": hashlib.sha256(b"fixed-image").hexdigest()}]}
    monkeypatch.setattr(owner.runtime, "validate_manifest", lambda value: value)
    class ReadOnly:
        f_flag = os.ST_RDONLY
    monkeypatch.setattr(owner.os, "statvfs", lambda _: ReadOnly())
    owner.verify_mounted_runtime(manifest)
    path.chmod(0o600); path.write_bytes(b"other-image"); path.chmod(0o400)
    with pytest.raises(ValueError): owner.verify_mounted_runtime(manifest)
    path.chmod(0o600); path.write_bytes(b"fixed-image"); path.chmod(0o400)
    ReadOnly.f_flag = 0
    with pytest.raises(ValueError, match="unsealed"): owner.verify_mounted_runtime(manifest)


def test_instance_channel_transfers_once_closes_local_server_and_reaps_before_reuse(monkeypatch):
    pairs = owner.private_pairs(1, time.monotonic() + 3)
    server_fd = pairs[0][1].fileno()
    events, replies = [], []
    monkeypatch.setattr(owner, "send_packet", lambda channel, message, descriptor=None: events.append((message, descriptor)))
    monkeypatch.setattr(owner, "_wait", lambda *_a, **_k: (replies.pop(0), None))
    monkeypatch.setattr(owner.select, "select", lambda *_: ([object()], [], []))
    channels = owner.InstanceChannels(object(), pairs, time.monotonic() + 60)
    replies.append({"operation": "started", "connection_id": 1})
    client = channels.connect(1, time.monotonic() + 5)
    with pytest.raises(OSError): os.fstat(server_fd)
    with pytest.raises(ValueError): channels.connect(2, time.monotonic() + 5)
    replies.append({"operation": "finished", "connection_id": 1,
                    "receipt": receipt(pairs[0][2])})
    channels.finalize(1)
    assert client.fileno() == -1 and channels.active is None and len(channels.receipts) == 1
    assert events[0][0]["operation"] == "instance" and events[0][1] == server_fd
    with pytest.raises(ValueError): channels.connect(2, time.monotonic() + 5)
    channels.close()


@pytest.mark.parametrize("fault", ["wrong_id", "not_reaped", "changed_descriptor", "bool_id"])
def test_finalizer_refuses_stale_or_unreaped_receipts(monkeypatch, fault):
    pairs = owner.private_pairs(1, time.monotonic() + 3)
    channels = owner.InstanceChannels(object(), pairs, time.monotonic() + 60)
    client, server, metadata = channels.pairs.pop(0); server.close()
    channels.active = (1, client, metadata)
    reply = {"operation": "finished", "connection_id": 1,
             "receipt": receipt(deepcopy(metadata))}
    if fault == "wrong_id": reply["connection_id"] = 2
    elif fault == "bool_id": reply["connection_id"] = True
    elif fault == "not_reaped": reply["receipt"]["all_server_processes_reaped"] = False
    else: reply["receipt"]["descriptor"]["inode"] += 1
    monkeypatch.setattr(owner, "_wait", lambda *_a, **_k: (reply, None))
    monkeypatch.setattr(owner.select, "select", lambda *_: ([object()], [], []))
    with pytest.raises(ValueError): channels.finalize(1)
    assert client.fileno() == -1 and not channels.receipts
