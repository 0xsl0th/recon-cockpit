"""Closed owner construction and failure custody; no service is started here."""

import array
from copy import deepcopy
import errno
import os
import socket
import stat
from types import SimpleNamespace
from uuid import uuid4

import pytest

from test_stock_http_runtime import fake_runtime, control
from recon_cockpit.secure_agent import stock_http_lab as lab_module
from recon_cockpit.secure_agent import stock_http_owner_worker as worker
from recon_cockpit.secure_agent import stock_http_contract as contract, stock_http_runtime as runtime
from recon_cockpit.secure_agent.session_limits import SessionLimits


def lab(fake_runtime, **options):
    selected = contract.selection("A", "O1")
    return lab_module.StockHttpLab(selected, str(uuid4()), SessionLimits(**contract.limits(selected)),
        runtime={"daemon": runtime.inspect_runtime("A", "O1", control()), "client": None}, **options)


def test_constructing_and_closing_lab_does_not_execute(fake_runtime, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("construction must remain metadata only")
    monkeypatch.setattr(lab_module, "_Supervisor", forbidden)
    selected = lab(fake_runtime)
    assert selected.started is False
    assert selected.runtime["client"] is None
    original = selected.identity
    detached = selected.identity
    detached["configuration"] = "B"
    assert selected.identity == original
    closed = selected.close()
    assert closed["started"] is False
    assert closed["processes_reaped"] is closed["namespace_descriptors_closed"] is True
    assert closed == selected.close()
    with pytest.raises(RuntimeError):
        selected.start(control())


def test_owner_commands_use_separate_private_storage_and_fixed_runtime(fake_runtime, monkeypatch):
    monkeypatch.setattr(lab_module, "_trusted_program", lambda name: "/usr/bin/" + name)
    bootstrap = ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"),
                 ("/usr/sbin/nft", "/usr/sbin/nft"), ("/usr/bin/nsenter", "/usr/bin/nsenter")])
    recorder = lab_module.recorder_command(bootstrap, 20)
    assert recorder.count("--tmpfs") == 2
    assert recorder.count(str(worker.SCRATCH_BYTES)) == 2
    assert "/peer" in recorder and "/scratch" in recorder
    assert "/usr/bin/nsenter" not in recorder
    assert recorder[-1] == "recorder"
    assert "--as-pid-1" in recorder
    manifest = runtime.inspect_runtime("A", "O1", control())
    descriptors = list(range(40, 40 + len(manifest["files"])))
    daemon = lab_module.daemon_command(bootstrap, manifest, descriptors, 32)
    assert daemon[daemon.index("--bind-fd") + 1:daemon.index("--bind-fd") + 3] == ["32", "/scratch"]
    assert "--tmpfs" not in daemon and "/usr/sbin/nft" not in daemon
    assert daemon.count("--ro-bind-data") == len(manifest["files"])
    assert daemon[-1] == "daemon"
    assert "--as-pid-1" in daemon
    for name, value in runtime.spec.NGINX_ENVIRONMENT.items():
        assert any(daemon[index:index + 3] == ["--setenv", name, value] for index in range(len(daemon)))
    with pytest.raises(ValueError, match="snapshot_count"):
        lab_module.daemon_command(bootstrap, manifest, descriptors[:-1], 32)


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_firewall_has_only_selected_endpoint_not_witnesses(configuration):
    rules = worker.firewall_rules(configuration)
    action = runtime.spec.action(configuration, "O1")
    assert rules.count("policy drop") == 3
    assert f'ip daddr {action["target"]} tcp dport {action["parameters"]["port"]}' in rules
    for address, port in runtime.spec.witness_endpoints(configuration):
        assert f"ip daddr {address} tcp dport {port} " not in rules
    assert "slirp" not in rules


@pytest.mark.parametrize("mutation", ("deadline", "boolean_deadline", "configuration", "case", "digest", "extra"))
def test_invalid_owner_request_refused_before_startup(mutation):
    value = {"configuration": "A", "case": "O1", "deadline": 110.0,
             "host_namespaces": {}, "runtime_digest": "a" * 64}
    if mutation == "deadline": value["deadline"] = 200
    elif mutation == "boolean_deadline": value["deadline"] = True
    elif mutation == "configuration": value["configuration"] = "host"
    elif mutation == "case": value["case"] = "arbitrary"
    elif mutation == "digest": value["runtime_digest"] = "z" * 64
    else: value["argv"] = ["sh"]
    with pytest.raises(ValueError):
        worker.request(value, now=100)


def test_daemon_request_requires_exact_selected_runtime(fake_runtime):
    manifest = runtime.inspect_runtime("A", "O1", control())
    value = {"configuration": "A", "case": "O1", "deadline": 110,
        "host_namespaces": {}, "runtime_digest": runtime.manifest_digest(manifest), "manifest": manifest}
    assert worker.request(value, daemon=True, now=100) == value
    changed = deepcopy(value)
    changed["case"] = "O2"
    with pytest.raises(ValueError, match="runtime_changed"):
        worker.request(changed, daemon=True, now=100)


class Call:
    def __init__(self, function):
        self.function = function
    def __call__(self, *args):
        return self.function(*args)


@pytest.mark.parametrize("daemon", (False, True))
def test_seccomp_accepts_pseudo_numbers_and_denies_unreviewed_families(monkeypatch, daemon):
    added, released = [], []
    library = SimpleNamespace(
        seccomp_init=Call(lambda action: 1),
        seccomp_syscall_resolve_name=Call(lambda name: -10060 if name == b"socketcall" else int.from_bytes(name, "little")),
        seccomp_rule_add_array=Call(lambda context, action, number, count, arguments: added.append((number, count)) or 0),
        seccomp_load=Call(lambda context: 0), seccomp_release=Call(released.append))
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *args, **kwargs: library)
    worker.socket_filter(daemon=daemon)
    assert (-10060, 0) in added and released == [1]
    assert (int.from_bytes(b"fork", "little"), 0) in added
    assert ((int.from_bytes(b"execve", "little"), 0) in added) is not daemon


def test_seccomp_unknown_syscall_refuses_and_releases(monkeypatch):
    released = []
    library = SimpleNamespace(seccomp_init=Call(lambda action: 1),
        seccomp_syscall_resolve_name=Call(lambda name: -1), seccomp_rule_add_array=Call(lambda *args: 0),
        seccomp_load=Call(lambda context: 0), seccomp_release=Call(released.append))
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *args, **kwargs: library)
    with pytest.raises(RuntimeError, match="seccomp_rule_failed"):
        worker.socket_filter(daemon=False)
    assert released == [1]


@pytest.mark.parametrize("failure", ("fstatvfs", "unexpected_ancillary", "truncated"))
def test_received_directory_is_closed_on_every_failure(tmp_path, monkeypatch, failure):
    descriptor = os.open(tmp_path, os.O_PATH | os.O_CLOEXEC)
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]).tobytes())]
    if failure == "unexpected_ancillary": ancillary.insert(0, (99, 99, b"bad"))
    selected = lab_module.StockHttpLab.__new__(lab_module.StockHttpLab)
    selected._channel = SimpleNamespace(recvmsg=lambda *args: (b'{"ready":true}', ancillary,
        socket.MSG_CTRUNC if failure == "truncated" else 0, None))
    selected._supervisor = SimpleNamespace(wait_for=lambda predicate: None, fds=set())
    if failure == "fstatvfs":
        def fail(fd):
            raise OSError(errno.EIO, "test")
        monkeypatch.setattr(lab_module.os, "fstatvfs", fail)
    with pytest.raises((OSError, ValueError)):
        selected._receive(directory=True)
    with pytest.raises(OSError) as error:
        os.fstat(descriptor)
    assert error.value.errno == errno.EBADF
    assert selected._supervisor.fds == set()


def test_storage_partition_is_aggregate_not_per_file():
    assert worker.SCRATCH_BYTES + worker.EVIDENCE_BYTES == 1048576
    assert worker.BOUNDS["aggregate_storage_bytes"] == 1048576
    assert worker.BOUNDS["scratch_bytes"] < worker.BOUNDS["aggregate_storage_bytes"]


@pytest.mark.parametrize("size,mode", ((1048576, 0o700), (786432, 0o777), (1048577, 0o700)))
def test_unbounded_or_public_scratch_refused(monkeypatch, size, mode):
    monkeypatch.setattr(worker.os, "stat", lambda path: SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_dev=1))
    monkeypatch.setattr(worker.os, "statvfs", lambda path: SimpleNamespace(f_blocks=size, f_frsize=1))
    with pytest.raises(ValueError, match="scratch_not_bounded"):
        worker.scratch_bound("/scratch")
