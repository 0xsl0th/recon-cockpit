"""Portable routed-worker validation; these tests do not establish routing."""

import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import routed_worker as rw
from recon_cockpit.secure_agent.planner import proposal


def request(**changes):
    raw = {"target": "192.0.2.10", "parameters": proposal()["parameters"],
           "host_namespaces": {name: f"{name}:[100]" for name in ("user", "net", "mnt", "pid")},
           "boundary_witnesses": None}
    return json.dumps({**raw, **changes}).encode() + b"\n"


@pytest.mark.parametrize("target", ["127.0.0.1", "0.1.2.3", "169.254.169.254", "224.0.0.1",
                                    "255.255.255.255", "240.0.0.1", "10.0.2.2", "10.0.2.3",
                                    "10.0.2.100", "192.0.2.10/32", "192.0.2.0/24", "::1",
                                    "::ffff:192.0.2.10", "example.com", "192.0.2.010", 3221225994])
def test_routed_target_rejects_aliases_networks_and_transport_destinations(target):
    with pytest.raises(ValueError):
        rw.validate_target(target)


@pytest.mark.parametrize("target", ["192.0.2.10", "10.129.1.10", "172.16.8.50", "198.51.100.20"])
def test_routed_literal_validation_permits_normal_ipv4_without_resolving_it(target):
    assert rw.validate_target(target) == target


@pytest.mark.parametrize("change", [
    {"command": "id"}, {"parameters": {**proposal()["parameters"], "port": True}},
    {"parameters": {**proposal()["parameters"], "headers": {"Host": "other"}}},
    {"parameters": {**proposal()["parameters"], "port": 0}},
    {"parameters": {**proposal()["parameters"], "method": "CONNECT"}},
    {"parameters": {**proposal()["parameters"], "path": "/\r\nHost: other"}},
    {"boundary_witnesses": {}},
    {"boundary_witnesses": {"forbidden_ip": "192.0.2.10", "forbidden_port": 8081}},
    {"boundary_witnesses": {"forbidden_ip": "192.0.2.11", "forbidden_port": 8080}},
    {"boundary_witnesses": {"forbidden_ip": "10.0.2.2", "forbidden_port": 8081}},
])
def test_routed_request_rejects_execution_extensions_and_invalid_witnesses(change):
    with pytest.raises(ValueError):
        rw.validate_request(request(**change))


def test_routed_request_rejects_duplicate_fields_and_oversize_input():
    with pytest.raises(ValueError, match="duplicate"):
        rw.validate_request(request().replace(b'"target":', b'"target": "192.0.2.11", "target":'))
    with pytest.raises(ValueError, match="large"):
        rw.validate_request(b" " * 8193)


@pytest.mark.parametrize("port", [1, 80, 8080, 65535])
def test_routed_remote_ports_do_not_inherit_fixture_listener_port_restrictions(port):
    raw = request(parameters={**proposal()["parameters"], "port": port})
    assert rw.validate_request(raw)["parameters"]["port"] == port


def test_routed_firewall_has_one_original_tuple_and_only_matching_inbound_replies():
    rules = rw.firewall_rules("192.0.2.10", 8080)
    assert rules.count("policy drop") == 3
    accepts = [line.strip() for line in rules.splitlines() if "accept" in line]
    assert accepts == [
        'oifname "tap0" ip daddr 192.0.2.10 tcp dport 8080 ct direction original accept',
        'iifname "tap0" meta l4proto tcp ct direction reply ct state established ct original ip daddr 192.0.2.10 ct original proto-dst 8080 accept',
    ]
    assert "sport" not in rules and "udp" not in rules


@pytest.mark.parametrize("release", [b"", b"GO", b"GO!\n", b"GO \n", b"approve anything\n"])
def test_routed_release_gate_requires_complete_exact_message(release):
    with pytest.raises(RuntimeError):
        rw.await_release(io.BytesIO(release))


def test_routed_request_and_release_are_distinct_bounded_messages():
    channel = io.BytesIO(request() + b"GO\n")
    assert rw.read_request(channel)["target"] == "192.0.2.10"
    rw.await_release(channel)
    with pytest.raises(ValueError):
        rw.read_request(io.BytesIO(request().rstrip()))


def test_direct_routed_worker_invocation_refuses_before_network_setup():
    result = subprocess.run([sys.executable, "-I", "-S", str(Path(rw.__file__))],
                            input=request(), capture_output=True, timeout=3)
    assert result.returncode == 78
    assert result.stdout == b""
    assert result.stderr == b"secure routed setup failed; execution refused\n"
