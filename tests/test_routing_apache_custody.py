"""Apache routing reserves before connect and rejects invalid descriptor custody.

Portable tests use the accepted socket-state double and real budget machine.
Opt-in Linux tests use actual TCP sockets and SCM_RIGHTS inside a fresh owned
network namespace; deployment trials cover the independent native owners.
"""

from copy import deepcopy
from contextlib import contextmanager
import inspect
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_ledger as ledger
from recon_cockpit.secure_agent import routing_frontend_worker as frontend, routing_services as services
from recon_cockpit.secure_agent import stock_http_production_transport as transport
from test_routing_contract import identity
from test_routing_frontend import Wire, install_wire
from test_stock_http_production_owner import private_socket


def arm(owner, selected, selector, sequence, message_sequence):
    digest = contract.digest(contract.action(selected, selector))
    reply = owner.apply({"operation": "ARM", "sequence": message_sequence, "action_sequence": sequence,
        "action_digest": digest, "selector": selector, "runtime_digests": owner.identity["runtimes"][selector]}, role="launcher")
    assert reply["status"] == "ok"
    return digest


def apache_double(private_socket, budget):
    service = frontend.ApacheService.__new__(frontend.ApacheService)
    service.budget = budget
    service._private_socket = service._custody_socket = private_socket
    service._private_identity = {"daemon_netns_cookie": 123, "inode": 456}
    service._descriptor_consumed = False
    return service


def test_global_request_reservation_precedes_the_only_apache_connect(monkeypatch, private_socket):
    selected = contract.selection(deployment="apache-B")
    owner = ledger.Ledger(selected, identity(deployment="apache-B"), started_at=100, clock=lambda: 100)
    digest = arm(owner, selected, "http_headers", 1, 1)
    install_wire(monkeypatch)
    monkeypatch.setattr(frontend.time, "monotonic", lambda: 100)
    budget = frontend.BudgetChannel(Wire(owner, "http_frontend"), "http_frontend", 160)
    budget.bind(1, digest)
    assert budget.connection(1)
    service = apache_double(private_socket, budget)
    actual_connect = private_socket.connect_ex
    def connect(endpoint):
        assert owner.snapshot()["counters"]["http_requests"] == 1
        assert owner.snapshot()["active_connection"]["request_reserved"] is True
        return actual_connect(endpoint)
    private_socket.connect_ex = connect
    assert service._connect_daemon() is private_socket
    assert service._private_socket is None and service._descriptor_consumed
    assert private_socket.calls == [transport.PRIVATE_ENDPOINT]
    with pytest.raises((ValueError, frontend.BudgetRefused)):
        service._connect_daemon()
    assert private_socket.calls == [transport.PRIVATE_ENDPOINT]


def test_cross_action_http_denial_never_consumes_or_connects_apache_socket(monkeypatch, private_socket):
    selected = contract.selection("http_one", deployment="apache-A")
    instant = [100]
    owner = ledger.Ledger(selected, identity("http_one", deployment="apache-A"), started_at=100, clock=lambda: instant[0])
    digest = arm(owner, selected, "http_headers", 1, 1)
    install_wire(monkeypatch)
    monkeypatch.setattr(frontend.time, "monotonic", lambda: instant[0])
    budget = frontend.BudgetChannel(Wire(owner, "http_frontend"), "http_frontend", 160)
    budget.bind(1, digest); assert budget.connection(1); budget.request("http"); budget.finish()
    assert owner.apply({"operation": "FINISH_ACTION", "sequence": 2, "action_sequence": 1,
        "action_digest": digest, "output_bytes": 0}, role="launcher")["status"] == "ok"
    instant[0] += .25
    digest = arm(owner, selected, "http_nmap", 2, 3)
    budget.bind(2, digest); assert budget.connection(1)
    service = apache_double(private_socket, budget)
    with pytest.raises(frontend.BudgetRefused, match="aggregate_http_requests_limit"):
        service._connect_daemon()
    assert private_socket.calls == [] and service._private_socket is private_socket
    assert service._descriptor_consumed is False
    monkeypatch.setattr(transport.Service, "close", lambda *_: None)
    service.close("io_failure")
    assert private_socket.closed and service._private_socket is None
    assert owner.snapshot()["counters"]["http_requests"] == 1


@pytest.mark.parametrize("fault", ("connected", "stale_inode", "stale_cookie", "reused", "packet", "leaked"))
def test_received_apache_capability_closes_on_every_binding_failure(monkeypatch, private_socket, fault):
    expected = {"daemon_netns_cookie": 123, "inode": 456}
    message = {"operation": "apache_descriptor", "descriptor": deepcopy(expected)}
    seen = set()
    if fault == "connected": private_socket.peer = transport.PRIVATE_ENDPOINT
    elif fault == "stale_inode": expected["inode"] += 1
    elif fault == "stale_cookie": expected["daemon_netns_cookie"] += 1
    elif fault == "reused": seen.add((123, 456))
    elif fault == "packet": message["operation"] = "other"
    monkeypatch.setattr(transport, "receive_packet", lambda *_a, **_kw: (message, 33))
    monkeypatch.setattr(transport, "owned_socket", lambda _: private_socket)
    def custody(*_):
        if fault == "leaked": raise ValueError("routing_frontend_apache_descriptor_copy_leaked")
    monkeypatch.setattr(frontend, "assert_descriptor_copies", custody)
    with pytest.raises(ValueError): frontend.receive_apache_socket(None, expected, seen)
    assert private_socket.closed and private_socket.calls == []


@pytest.mark.parametrize("send_failed", (False, True))
def test_launcher_closes_transferred_copy_before_waiting_for_frontend(monkeypatch, send_failed):
    state = {"closed": False}
    private = SimpleNamespace(fileno=lambda: 33, close=lambda: state.update(closed=True))
    owner = services.Services.__new__(services.Services)
    owner.selection = contract.selection(deployment="apache-A")
    owner._check = lambda: None
    target = {"sequence": 0, "channel": object(), "supervisor": object(), "ready": {"role": "http_frontend"}}
    def send(_supervisor, _channel, value, descriptor=None):
        if descriptor is not None and send_failed: raise OSError("closed receiver")
    def receive(*_):
        assert state["closed"]
        return {"sequence": 1, "operation": "start", "recorder": None, "instances": [],
            "reservations": [], "budget_denied": False, "last_budget_reply": None,
            "apache_descriptor_custody": {}}
    monkeypatch.setattr(services, "_send", send)
    monkeypatch.setattr(services, "_receive", receive)
    monkeypatch.setattr(services, "assert_sender_copy_closed", lambda _: None)
    if send_failed:
        with pytest.raises(OSError): owner._command(target, "start", apache_socket=private, apache_descriptor={})
    else:
        owner._command(target, "start", apache_socket=private, apache_descriptor={})
    assert state["closed"]


def _linux_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual Apache routing descriptor custody")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.mark.integration
@pytest.mark.parametrize("fault", ("none", "wrong", "connected", "duplicated", "stale", "reused", "leaked"))
def test_real_linux_apache_descriptor_transfer_and_refusal(fault, tmp_path):
    _linux_only()
    from recon_cockpit.secure_agent.isolation import _runtime_files
    stdlib, files = _runtime_files("/usr/bin/python3", None)
    source = tmp_path / "descriptor_custody.py"
    source.write_text("""import fcntl, os, re, socket, struct, sys
from contextlib import contextmanager
sys.path.insert(0, '/app')
from recon_cockpit.secure_agent import routing_frontend_worker as frontend, routing_services as services
from recon_cockpit.secure_agent import stock_http_production_transport as transport, worker
assert os.readlink('/proc/self/ns/net') != sys.argv[2]
assert socket.if_nameindex() == [(1, 'lo')]
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
    flags = fcntl.ioctl(probe, 0x8913, struct.pack('16sh', b'lo', 0))
    fcntl.ioctl(probe, 0x8914, struct.pack('16sh', b'lo', struct.unpack('16sh', flags[:18])[1] | 1))
worker.drop_privileges()
""" + inspect.getsource(_expect_refusal) + inspect.getsource(_descriptor_case)
        + "\n_descriptor_case(sys.argv[1])\nprint('custody_verified:' + sys.argv[1])\n")
    argv = ["/usr/bin/bwrap", "--unshare-all", "--uid", "0", "--gid", "0",
        "--cap-drop", "ALL", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_SETPCAP",
        "--die-with-parent", "--new-session", "--as-pid-1", "--clearenv",
        "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for original, destination in files:
        argv += ["--ro-bind", original, destination]
    directory = Path(services.__file__).parent
    for name in services.MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    argv += ["--ro-bind", str(source), "/descriptor_custody.py", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/descriptor_custody.py", fault, os.readlink("/proc/self/ns/net")]
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout == ("custody_verified:" + fault + "\n").encode()


@contextmanager
def _expect_refusal(exceptions, match=None):
    try:
        yield
    except exceptions as error:
        if match is not None:
            assert re.search(match, str(error)), str(error)
    else:
        raise AssertionError("invalid descriptor custody was accepted")


def _descriptor_case(fault):
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    source = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    source.setblocking(False)
    expected = transport.socket_identity(source)
    received = duplicate = listener = accepted = replacement = None
    before = None
    try:
        if fault == "wrong":
            replacement = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            replacement.setblocking(False)
            descriptor = replacement.fileno()
        else:
            descriptor = source.fileno()
        if fault == "connected":
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0)); listener.listen(1)
            source.settimeout(1); source.connect(listener.getsockname()); source.setblocking(False)
            accepted, _ = listener.accept()
        if fault == "stale": expected["inode"] += 1
        message = {"operation": "apache_descriptor", "descriptor": expected}
        if fault == "duplicated":
            import array
            sender.sendmsg([transport.encode(message)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                array.array("i", [descriptor, descriptor]))])
        else:
            transport.send_packet(sender, message, descriptor)
            if fault == "reused": transport.send_packet(sender, message, descriptor)
        # Match cross-process custody: close every sender-side description before
        # the receiver inspects its own bounded FD table.
        source.close()
        if replacement is not None: replacement.close()
        before = set(os.listdir("/proc/self/fd"))
        if fault in ("wrong", "connected", "duplicated", "stale"):
            with _expect_refusal((ValueError, OSError)):
                frontend.receive_apache_socket(receiver, expected, set())
            assert set(os.listdir("/proc/self/fd")) == before
        else:
            seen = set()
            received = frontend.receive_apache_socket(receiver, expected, seen)
            assert transport.socket_identity(received) == expected
            if fault == "leaked":
                duplicate = os.dup(received.fileno())
                with _expect_refusal(ValueError, match="copy_leaked"):
                    frontend.assert_descriptor_copies(expected, (received.fileno(),))
                received.close()
                with _expect_refusal(ValueError, match="copy_leaked"):
                    frontend.assert_descriptor_copies(expected, ())
                with _expect_refusal(ValueError, match="copy_leaked"):
                    services.assert_sender_copy_closed(expected)
                os.close(duplicate); duplicate = None
            else:
                received.close()
            frontend.assert_descriptor_copies(expected, ())
            services.assert_sender_copy_closed(expected)
            if fault == "reused":
                with _expect_refusal(ValueError, match="reused"):
                    frontend.receive_apache_socket(receiver, expected, seen)
            assert set(os.listdir("/proc/self/fd")) == before
    finally:
        if duplicate is not None: os.close(duplicate)
        for channel in (received, source, sender, receiver, listener, accepted, replacement):
            if channel is not None: channel.close()
