"""Portable hostile-input checks for the fixed routing boundary."""

from copy import deepcopy
import ipaddress
import json
import os
import socket
import struct
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import routing_topology_spec as spec


def network_state(configuration="A"):
    result = {}
    for role in spec.ROLES:
        links = [{"interface": "lo", "index": 1, "peer_index": None, "kind": "loopback", "up": True}]
        if role == "router":
            links += [{"interface": row[1], "index": 10 + index, "peer_index": 2, "kind": "veth", "up": True}
                      for index, row in enumerate(spec.LINKS)]
        else:
            peer = 10 + next(index for index, row in enumerate(spec.LINKS) if row[0] == role)
            links.append({"interface": "eth0", "index": 2, "peer_index": peer, "kind": "veth", "up": True})
        addresses = spec.expected_addresses(role, configuration=configuration)
        routes = [{"table": 254, "destination": destination, "prefix": 32, "gateway": gateway,
                   "interface": interface, "protocol": 4, "scope": 0, "type": 1}
                  for destination, gateway, interface in spec.routes(role, configuration=configuration)]
        for address in addresses:
            if address["prefix"] != 30:
                continue
            network = ipaddress.IPv4Network(address["address"] + "/30", strict=False)
            routes.append({"table": 254, "destination": str(network.network_address), "prefix": 30,
                           "gateway": None, "interface": address["interface"], "protocol": 2, "scope": 253, "type": 1})
        result[role] = {"links": links, "addresses": addresses, "routes": routes, "ipv4_forwarding": role == "router"}
    return result


def metadata(configuration="A"):
    value = {"ready": True, "profile": spec.PROFILE, "topology_sha256": spec.digest(configuration=configuration),
        "user": "user:[20]", "networks": {role: f"net:[{30 + index}]" for index, role in enumerate(spec.ROLES)},
        "owner_namespaces": {"user": "user:[20]", "net": "net:[32]", "mnt": "mnt:[40]", "pid": "pid:[50]"},
        "listeners": {}, "baselines": [], "filtered": [], "bounds": deepcopy(spec.BOUNDS),
        "setup_helpers": 6, "capabilities_dropped": True, "setup_disabled": True,
        "exports": list(spec.EXPORTS), "private_ssh_pairs": [], "private_pairs_drained": True,
        "private_listener_closed": True, "network_state": network_state(configuration),
        "descriptor_custody": {"before_export": 26, "steady": 14}}
    for index, (name, endpoint) in enumerate(spec.endpoints(configuration).items()):
        cookie = 100 if name.startswith("http") else 200 if name.startswith("ssh") else 300
        value["listeners"][name] = {"inode": 1000 + index, "local": list(endpoint), "netns_cookie": cookie}
    for index in range(4):
        front, daemon = ["127.0.0.1", 20000 + index], ["127.0.0.1", 30000]
        value["private_ssh_pairs"].append({
            "frontend": {"inode": 2000 + index * 2, "local": front, "peer": daemon, "netns_cookie": 200},
            "daemon": {"inode": 2001 + index * 2, "local": daemon, "peer": front, "netns_cookie": 200}})
    for client in ("http", "ssh"):
        for endpoint in spec.endpoints(configuration):
            value["baselines"].append({"client": client, "endpoint": endpoint, "connected": True})
            value["filtered"].append({"client": client, "endpoint": endpoint, "connected": client == endpoint})
    return value


def test_saved_metadata_is_detached_and_does_not_restore_descriptors():
    original = metadata()
    validated = spec.validate_metadata(original)
    validated["networks"]["router"] = "net:[999]"
    assert original["networks"]["router"] == "net:[32]"
    assert all(type(value) is not int for value in original["networks"].values())


def test_legacy_topology_commitment_remains_pinned_and_selection_has_no_global_state():
    expected = "c9ef1fb71272e6c757701a6670170b1ca1eb97406268346b394997f27a19513e"
    original = deepcopy(spec.ENDPOINTS)
    assert spec.digest() == spec.digest(configuration="A") == expected
    assert spec.spec() == spec.spec(configuration="A")
    assert spec.digest(configuration="B") != expected
    selected = spec.endpoints("B")
    selected["http"] = ("192.168.1.1", 80)
    assert spec.endpoints("B")["http"] == ("172.23.0.10", 18080)
    assert spec.ENDPOINTS == spec.endpoints() == original
    assert spec.digest() == expected


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_each_topology_keeps_transit_exports_bounds_and_exact_service_routes(configuration):
    value = spec.spec(configuration=configuration)
    targets = spec.endpoints(configuration)
    assert len(value["roles"]) == 5 and len(value["links"]) == 4 and len(spec.EXPORTS) == 18
    assert value["links"] == spec.spec()["links"] and value["bounds"] == spec.BOUNDS
    assert value["bounds"]["setup_helpers_total"] == 6
    assert targets["excluded"] == ("10.77.0.99", 8080)
    expected = (("10.77.0.10", 8080, 8081), ("10.77.0.20", 2222, 2223)) if configuration == "A" else (
        ("172.23.0.10", 18080, 18081), ("172.23.0.20", 12222, 12223))
    for service, (address, port, wrong) in zip(("http", "ssh"), expected, strict=True):
        assert targets[service] == (address, port) and targets[service + "_wrong"] == (address, wrong)
        rules = value["firewalls"][service + "_client"]
        assert f"ip daddr {address} tcp dport {port} " in rules
        assert f"tcp dport {wrong} " not in rules
        assert "10.77.0.99" not in rules
        assert all(row[0] != "0.0.0.0" for row in value["routes"][service + "_client"])
    assert sum(row["connected"] is False for row in metadata(configuration)["filtered"]) == 8


@pytest.mark.parametrize("configuration", (None, True, 1, "C", "a", "A ", {}, []))
def test_configuration_is_closed_before_topology_derivation(configuration):
    for derive in (lambda: spec.endpoints(configuration), lambda: spec.spec(configuration=configuration),
                   lambda: spec.digest(configuration=configuration),
                   lambda: spec.routes("router", configuration=configuration),
                   lambda: spec.firewall_rules("http_client", configuration=configuration),
                   lambda: spec.expected_addresses("http_frontend", configuration=configuration)):
        with pytest.raises(ValueError, match="configuration"):
            derive()


@pytest.mark.parametrize("configuration,other", (("A", "B"), ("B", "A")))
def test_saved_topology_and_closure_cannot_cross_configuration(configuration, other):
    value = metadata(configuration)
    receipt = {"status": "closed", "owner_exited": True, "descriptors_closed": True,
               "namespaces": value["networks"], "topology_sha256": spec.digest(configuration=configuration)}
    assert spec.validate_metadata(value, configuration=configuration) == value
    assert spec.validate_closure(receipt, metadata=value, configuration=configuration) == receipt
    with pytest.raises(ValueError):
        spec.validate_metadata(value, configuration=other)
    with pytest.raises(ValueError):
        spec.validate_network_state(value["network_state"], configuration=other)
    with pytest.raises(ValueError):
        spec.validate_closure(receipt, metadata=value, configuration=other)
    changed = deepcopy(value)
    changed["topology_sha256"] = spec.digest(configuration=other)
    with pytest.raises(ValueError):
        spec.validate_metadata(changed, configuration=other)


@pytest.mark.parametrize("field", ("listeners", "network_state"))
def test_recommitted_b_topology_rejects_a_listener_or_route_evidence(field):
    value = metadata("B")
    value[field] = metadata("A")[field]
    with pytest.raises(ValueError):
        spec.validate_metadata(value, configuration="B")


@pytest.mark.parametrize("deployment", (None, "nginx-A", "nginx-B", "apache-A", "apache-B"))
def test_owner_configuration_and_cleanup_commitment_derive_from_validated_selection(deployment):
    from recon_cockpit.secure_agent.routing_topology import Topology
    from recon_cockpit.secure_agent.routing_contract import selection
    selected = selection(deployment=deployment)
    instance = Topology(None, None, selection=selected, identity={})
    assert instance.configuration == selected["configuration"]
    receipt = instance.close()
    assert spec.validate_closure(receipt, configuration=selected["configuration"]) == receipt
    selected["configuration"] = "A" if selected["configuration"] == "B" else "B"
    with pytest.raises(ValueError):
        Topology(None, None, selection=selected, identity={})


@pytest.mark.parametrize("mutate", [
    lambda v: v.update(profile="host-routed"),
    lambda v: v.update(topology_sha256="0" * 64),
    lambda v: v["networks"].update(ssh_frontend=v["networks"]["http_frontend"]),
    lambda v: v["owner_namespaces"].update(net=v["networks"]["http_client"]),
    lambda v: v["owner_namespaces"].update(user="user:[99]"),
    lambda v: v.update(capabilities_dropped=1),
    lambda v: v.update(setup_disabled=False),
    lambda v: v.update(setup_helpers=7),
    lambda v: v["bounds"].update(steady_processes=True),
    lambda v: v["listeners"]["http"].update(local=["127.0.0.1", 8080]),
    lambda v: v["listeners"]["excluded"].update(netns_cookie=100),
    lambda v: v["listeners"]["http_wrong"].update(netns_cookie=200),
    lambda v: v["listeners"]["ssh"].update(inode=v["listeners"]["http"]["inode"]),
    lambda v: v["baselines"][0].update(connected=False),
    lambda v: v["baselines"][0].update(connected=1),
    lambda v: v["filtered"][2].update(connected=True),
    lambda v: v["exports"].append("host_net"),
    lambda v: v.update(private_pairs_drained=False),
    lambda v: v.update(private_listener_closed=False),
    lambda v: v["descriptor_custody"].update(steady=15),
    lambda v: v["private_ssh_pairs"][0]["daemon"].update(netns_cookie=100),
    lambda v: v["private_ssh_pairs"][1]["frontend"].update(inode=2000),
    lambda v: v["private_ssh_pairs"][0]["frontend"].update(peer=["10.77.0.20", 2222]),
    lambda v: v["private_ssh_pairs"].pop(),
])
def test_metadata_rejects_changed_boundaries_and_fabricated_witnesses(mutate):
    value = metadata()
    mutate(value)
    with pytest.raises(ValueError):
        spec.validate_metadata(value)


def test_closed_receipt_must_match_saved_namespace_identity():
    original = metadata()
    value = {"status": "closed", "owner_exited": True, "descriptors_closed": True,
             "namespaces": original["networks"], "topology_sha256": spec.digest()}
    assert spec.validate_closure(value, metadata=original) == value
    for key in ("owner_exited", "descriptors_closed"):
        changed = {**value, key: False}
        with pytest.raises(ValueError):
            spec.validate_closure(changed, metadata=original)
    changed = deepcopy(value)
    changed["namespaces"]["router"] = "net:[999]"
    with pytest.raises(ValueError):
        spec.validate_closure(changed, metadata=original)


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"nested":{"x":1,"x":2}}', b'{"x":NaN}',
    b'{"x":Infinity}', b'{"x":1e400}', b'{"x":"\xff"}', b'[]',
    b'{"x":' + b'[' * 65 + b'0' + b']' * 65 + b'}',
])
def test_packet_decoder_rejects_ambiguous_or_unbounded_json(raw):
    with pytest.raises(ValueError):
        spec.decode(raw)


def test_packet_limit_exact_and_overflow():
    raw = b'{"x":"' + b'a' * (spec.MAX_PACKET - 8) + b'"}'
    assert len(raw) == spec.MAX_PACKET
    assert len(spec.decode(raw)["x"]) == spec.MAX_PACKET - 8
    with pytest.raises(ValueError):
        spec.decode(raw + b' ')


def test_client_rules_allow_only_its_selected_service():
    for service, other in (("http", "ssh"), ("ssh", "http")):
        rules = spec.firewall_rules(service + "_client")
        assert rules.count(" accept") == 2
        assert rules.count("policy drop") == 3
        assert spec.ENDPOINTS[other][0] not in rules
        assert spec.ENDPOINTS["excluded"][0] not in rules
        assert 'oifname "eth0"' in rules and 'ct direction reply ct state established' in rules


def test_private_pairs_add_only_exact_established_loopback_tuples():
    pairs = metadata()["private_ssh_pairs"]
    final = spec.firewall_rules("ssh_frontend", pairs)
    assert " new" not in final
    assert final.count('iifname "lo"') == 8
    assert final.count('oifname "lo"') == 8
    assert 'tcp sport 20000 tcp dport 30000 ct state established' in final
    assert 'tcp sport 30000 tcp dport 20003 ct state established' in final
    with pytest.raises(ValueError):
        spec.firewall_rules("http_client", pairs)
    routes = [{side: pair[side]["local"] for side in ("frontend", "daemon")} for pair in pairs]
    setup = spec.firewall_rules("ssh_frontend", private_routes=routes, setup=True)
    assert "{ new, established }" in setup
    routes[0]["frontend"] = ["10.77.0.99", 20000]
    with pytest.raises(ValueError):
        spec.firewall_rules("ssh_frontend", private_routes=routes, setup=True)


def test_explicit_routes_have_no_default_or_ambient_destination():
    for role in spec.ROLES:
        for destination, gateway, interface in spec.routes(role):
            assert destination != "0.0.0.0" and gateway.startswith("10.78.0.")
            assert interface in {"eth0", "fh", "fs"}
    with pytest.raises(ValueError):
        spec.routes("host")


@pytest.mark.parametrize("mutate", [
    lambda v: v["http_client"]["links"].append({"interface": "eth1", "index": 3, "peer_index": 4, "kind": "veth", "up": True}),
    lambda v: v["http_client"]["links"][1].update(kind="tun"),
    lambda v: v["http_client"]["links"][1].update(peer_index=99),
    lambda v: v["http_client"]["links"][1].update(up=1),
    lambda v: v["router"]["links"][1].update(peer_index=3),
    lambda v: v["http_frontend"]["addresses"][0].update(prefix=24),
    lambda v: v["ssh_client"].update(ipv4_forwarding=True),
    lambda v: v["router"].update(ipv4_forwarding=False),
    lambda v: v["http_client"]["routes"][0].update(destination="0.0.0.0", prefix=0),
    lambda v: v["http_client"]["routes"][0].update(gateway="192.168.1.1"),
    lambda v: v["http_client"]["routes"][0].update(table=100),
    lambda v: v["http_client"]["routes"][0].update(protocol=True),
    lambda v: v["http_client"]["routes"].pop(0),
    lambda v: v["http_client"]["routes"].append(deepcopy(v["http_client"]["routes"][0])),
])
def test_observed_network_replay_rejects_ambient_or_missing_routes_and_links(mutate):
    value = network_state()
    mutate(value)
    with pytest.raises(ValueError):
        spec.validate_network_state(value)


def test_local_kernel_routes_must_derive_from_fixed_addresses():
    value = network_state()
    local = {"table": 255, "destination": "10.77.0.10", "prefix": 32, "gateway": None,
             "interface": "eth0", "protocol": 2, "scope": 254, "type": 2}
    value["http_frontend"]["routes"].append(local)
    assert spec.validate_network_state(value) == value
    local["destination"] = "192.168.1.1"
    with pytest.raises(ValueError):
        spec.validate_network_state(value)


def test_private_pair_duplicate_tuples_rejected_even_with_distinct_inode_claims():
    value = metadata()
    value["private_ssh_pairs"][1]["frontend"]["local"] = ["127.0.0.1", 20000]
    value["private_ssh_pairs"][1]["daemon"]["peer"] = ["127.0.0.1", 20000]
    with pytest.raises(ValueError, match="tuple_reuse"):
        spec.validate_metadata(value)


requires_seqpacket = pytest.mark.integration


@pytest.fixture(autouse=True)
def local_descriptor_transport(request):
    if request.node.get_closest_marker("integration") is None:
        return
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned Linux descriptor transport")
    assert sys.platform == "linux"


@requires_seqpacket
def test_fragmented_snapshot_exact_limit_and_single_fd_custody():
    from recon_cockpit.secure_agent import routing_topology as transport
    value = {"x": "a" * (spec.MAX_PACKET - 8)}
    errors = []
    with _channel_pair() as channels:
        source = os.open("/dev/null", os.O_RDONLY)
        try:
            def send():
                try:
                    transport.send_packet(channels[0], value, (source,))
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=send)
            thread.start()
            received, descriptors = transport.receive_packet(channels[1], expected_descriptors=1)
            thread.join(3)
            assert not thread.is_alive() and not errors
            try:
                assert received == value
                assert os.fstat(descriptors[0]).st_rdev == os.fstat(source).st_rdev
                assert not os.get_inheritable(descriptors[0])
            finally:
                os.close(descriptors[0])
        finally:
            os.close(source)


class _channel_pair:
    def __enter__(self):
        self.channels = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        return self.channels

    def __exit__(self, *_):
        for channel in self.channels:
            channel.close()


@requires_seqpacket
@pytest.mark.parametrize("total,offset,body", [
    (spec.MAX_PACKET + 1, 0, b"x" * 32756),
    (32768, 0, b"x" * 32756),
    (32769, 1, b"x" * 32756),
    (32769, 0, b"x"),
], ids=("oversize", "unneeded-fragment", "wrong-offset", "short-frame"))
def test_fragment_metadata_rejects_overflow_reordering_or_short_nonfinal_frame(total, offset, body):
    from recon_cockpit.secure_agent import routing_topology as transport
    with _channel_pair() as (sender, receiver):
        sender.sendmsg([struct.pack("!4sII", b"RCT1", total, offset) + body])
        with pytest.raises(ValueError, match="frame_order"):
            transport.receive_packet(receiver)


@requires_seqpacket
def test_fragment_replay_and_midstream_descriptor_import_rejected_without_fd_leak():
    import array
    from recon_cockpit.secure_agent import routing_topology as transport
    first = struct.pack("!4sII", b"RCT1", 32769, 0) + b"x" * 32756
    last = struct.pack("!4sII", b"RCT1", 32769, 32756) + b"x" * 13
    with _channel_pair() as (sender, receiver):
        sender.sendmsg([first])
        sender.sendmsg([first])
        with pytest.raises(ValueError, match="frame_order"):
            transport.receive_packet(receiver)
    with _channel_pair() as (sender, receiver):
        descriptor = os.open("/dev/null", os.O_RDONLY)
        try:
            before = set(os.listdir("/proc/self/fd"))
            sender.sendmsg([first])
            sender.sendmsg([last], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))])
            with pytest.raises(ValueError, match="descriptor_transport"):
                transport.receive_packet(receiver)
            assert set(os.listdir("/proc/self/fd")) == before
        finally:
            os.close(descriptor)


@requires_seqpacket
def test_fragment_transfer_has_one_absolute_deadline():
    from recon_cockpit.secure_agent import routing_topology as transport
    with _channel_pair() as (sender, receiver):
        sender.sendmsg([struct.pack("!4sII", b"RCT1", 32769, 0) + b"x" * 32756])
        with pytest.raises(ValueError, match="transport_deadline"):
            transport.receive_packet(receiver, deadline=time.monotonic() + .01)


@requires_seqpacket
def test_descriptor_inventory_detects_unexpected_inherited_open_file():
    from recon_cockpit.secure_agent.routing_topology_worker import _assert_descriptors
    descriptor = os.open("/dev/null", os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="descriptor_inventory"):
            _assert_descriptors({0, 1, 2}, 3)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("raw", [b"x", struct.pack("=HH", 3, 1),
    struct.pack("=HH", 8, 1) + b"x", struct.pack("=HH", 5, 1) + b"xBAD",
    struct.pack("=HH", 4, 1) * 2])
def test_kernel_observation_rejects_truncated_duplicate_or_nonzero_padding_attributes(raw):
    from recon_cockpit.secure_agent.routing_topology_worker import _attributes
    with pytest.raises(ValueError, match="netlink_attribute"):
        _attributes(raw)


def test_kernel_dump_requires_matching_sequence_and_kernel_sender():
    from recon_cockpit.secure_agent.routing_topology_worker import Netlink
    class Channel:
        def __init__(self, packet, sender):
            self.packet, self.sender = packet, sender
        def sendto(self, raw, destination):
            assert destination == (0, 0)
            return len(raw)
        def recvmsg(self, maximum):
            assert maximum == 65536
            return self.packet, [], 0, self.sender
    done = struct.pack("=IHHII", 20, 3, 2, 1, 0) + bytes(4)
    for packet, sender in ((done, (123, 0)), (done[:8] + struct.pack("=I", 2) + done[12:], (0, 0))):
        connection = Netlink.__new__(Netlink)
        connection.sequence, connection.channel = 0, Channel(packet, sender)
        with pytest.raises(ValueError, match="dump_"):
            connection.dump(18, bytes(16), 16)


@pytest.mark.parametrize("change", [None, "unverified", "socket", "writable", "mutable_mount", "wrong_mapping", "extra"])
def test_import_created_libffi_descriptor_requires_exact_readonly_mapped_image(monkeypatch, change):
    import io
    import stat
    from types import SimpleNamespace
    from recon_cockpit.secure_agent import routing_topology_worker as owner
    path = "/usr/lib/x86_64-linux-gnu/libffi.so.8.2.0"
    closed = []
    with monkeypatch.context() as patch:
        patch.setattr(owner.os, "O_PATH", 0x200000, raising=False)
        patch.setattr(owner, "ENTRY_DESCRIPTORS_VERIFIED", change != "unverified")
        patch.setattr(owner.os, "listdir", lambda _: ["0", "1", "2", "3"] + (["4"] if change == "extra" else []))
        patch.setattr(owner.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_dev=1, st_ino=20))
        patch.setattr(owner.os, "readlink", lambda _: "socket:[99]" if change == "socket" else path)
        patch.setattr(owner.fcntl, "fcntl", lambda *_: os.O_RDWR if change == "writable" else os.O_RDONLY)
        patch.setattr(owner.os, "statvfs", lambda _: SimpleNamespace(f_flag=0 if change == "mutable_mount" else os.ST_RDONLY))
        patch.setattr(owner.os, "close", closed.append)
        patch.setattr("builtins.open", lambda *args, **kwargs: io.StringIO(
            f"1000-2000 r-xp 00000000 00:01 {21 if change == 'wrong_mapping' else 20} {path}\n"))
        if change is None:
            owner._close_import_descriptor()
        else:
            with pytest.raises(ValueError, match="routing_topology_"):
                owner._close_import_descriptor()
    assert closed == ([3] if change is None else [])


@pytest.mark.parametrize("failure", ["descriptor", "channel", "supervisor", "not_reaped"])
def test_cleanup_attempts_all_owned_descriptors_and_reap_even_after_failure(monkeypatch, failure):
    from types import SimpleNamespace
    from recon_cockpit.secure_agent import routing_topology as transport
    calls = []
    def perform(name):
        calls.append(name)
        if name == failure:
            raise OSError("injected close failure")
    instance = transport.Topology(None, None)
    instance._descriptors = {"first": 10, "second": 11}
    instance._channel = SimpleNamespace(close=lambda: perform("channel"))
    instance._supervisor = SimpleNamespace(close=lambda: perform("supervisor"))
    instance._process = SimpleNamespace(poll=lambda: None if failure == "not_reaped" else -9)
    with monkeypatch.context() as patch:
        patch.setattr(transport.os, "close", lambda descriptor: perform("descriptor" if descriptor == 10 else "second"))
        with pytest.raises(ValueError, match="cleanup_failed"):
            instance.close()
    assert calls == ["descriptor", "second", "channel", "supervisor"]
    assert instance._receipt is None
    with pytest.raises(ValueError, match="cleanup_failed"):
        instance.close()
