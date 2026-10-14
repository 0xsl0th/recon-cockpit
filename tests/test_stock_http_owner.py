"""Closed owner construction and failure custody; no service is started here."""

import array
from copy import deepcopy
import errno
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
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
    assert recorder.count("--tmpfs") == 1
    assert recorder.count(str(worker.SCRATCH_BYTES)) == 1
    assert ["--ro-bind", "/stock-peer", "/peer"] in [recorder[index:index + 3] for index in range(len(recorder))]
    assert "/peer" in recorder and "/scratch" in recorder
    assert "/usr/bin/nsenter" not in recorder
    assert recorder[-1] == "recorder"
    assert "--as-pid-1" in recorder
    manifest = runtime.inspect_runtime("A", "O1", control())
    descriptors = list(range(40, 40 + len(manifest["files"])))
    daemon = lab_module.daemon_command(bootstrap, manifest, descriptors)
    assert daemon[daemon.index("--bind") + 1:daemon.index("--bind") + 3] == ["/stock-peer", "/scratch"]
    assert "--tmpfs" not in daemon and "/usr/sbin/nft" not in daemon
    assert daemon.count("--ro-bind-data") == len(manifest["files"])
    assert daemon[-1] == "daemon"
    assert "--as-pid-1" in daemon
    for name, value in runtime.spec.NGINX_ENVIRONMENT.items():
        assert any(daemon[index:index + 3] == ["--setenv", name, value] for index in range(len(daemon)))
    with pytest.raises(ValueError, match="snapshot_count"):
        lab_module.daemon_command(bootstrap, manifest, descriptors[:-1])


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


@pytest.mark.parametrize("failure", ("unexpected_descriptor", "unexpected_ancillary", "truncated"))
def test_received_directory_is_closed_on_every_failure(tmp_path, monkeypatch, failure):
    descriptor = os.open(tmp_path, os.O_PATH | os.O_CLOEXEC)
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]).tobytes())]
    if failure == "unexpected_ancillary": ancillary.insert(0, (99, 99, b"bad"))
    selected = lab_module.StockHttpLab.__new__(lab_module.StockHttpLab)
    selected._channel = SimpleNamespace(recvmsg=lambda *args: (b'{"ready":true}', ancillary,
        socket.MSG_CTRUNC if failure == "truncated" else 0, None))
    selected._supervisor = SimpleNamespace(wait_for=lambda predicate: None, fds=set())
    with pytest.raises((OSError, ValueError)):
        selected._receive()
    with pytest.raises(OSError) as error:
        os.fstat(descriptor)
    assert error.value.errno == errno.EBADF
    assert selected._supervisor.fds == set()


def test_storage_partition_is_aggregate_not_per_file():
    assert worker.SCRATCH_BYTES + worker.EVIDENCE_BYTES == 1048576
    assert worker.BOUNDS["aggregate_storage_bytes"] == 1048576
    assert worker.BOUNDS["scratch_bytes"] < worker.BOUNDS["aggregate_storage_bytes"]


def test_owner_rejects_inherited_descriptors_before_loading_native_libraries(tmp_path):
    source = Path(worker.__file__).read_text()
    bootstrap = tmp_path / "owner_entry.py"
    bootstrap.write_text(source[:source.index("\nimport array\n")] +
        '\nassert ENTRY_DESCRIPTORS_VERIFIED\nassert "ctypes" not in sys.modules\nprint("verified")\n')
    clean = subprocess.run([sys.executable, "-I", "-S", str(bootstrap)],
        capture_output=True, timeout=5, check=False)
    assert clean.returncode == 0 and clean.stdout == b"verified\n" and clean.stderr == b""
    with bootstrap.open("rb") as inherited:
        refused = subprocess.run([sys.executable, "-I", "-S", str(bootstrap)],
            pass_fds=(inherited.fileno(),), capture_output=True, timeout=5, check=False)
    assert refused.returncode == 78 and refused.stdout == b""
    assert refused.stderr == b"stock_http_owner_refused\n"


@pytest.mark.parametrize("readonly,error", ((True, errno.EROFS), (False, errno.EROFS), (True, errno.EACCES)))
def test_recorder_peer_requires_actual_read_only_mount_and_write_denial(monkeypatch, readonly, error):
    monkeypatch.setattr(worker.os, "statvfs", lambda path: SimpleNamespace(f_flag=os.ST_RDONLY if readonly else 0))
    def denied(*args):
        raise OSError(error, "test")
    monkeypatch.setattr(worker.os, "open", denied)
    if readonly and error == errno.EROFS:
        worker.verify_peer_read_only()
    else:
        with pytest.raises((ValueError, OSError)):
            worker.verify_peer_read_only()


@pytest.mark.parametrize("size,mode", ((1048576, 0o700), (786432, 0o777), (1048577, 0o700)))
def test_unbounded_or_public_scratch_refused(monkeypatch, size, mode):
    monkeypatch.setattr(worker.os, "stat", lambda path: SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_dev=1))
    monkeypatch.setattr(worker.os, "statvfs", lambda path: SimpleNamespace(f_blocks=size, f_frsize=1))
    with pytest.raises(ValueError, match="scratch_not_bounded"):
        worker.scratch_bound("/scratch")


def _native_gate():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned stock HTTP cleanup")
    assert sys.platform == "linux" and os.geteuid() != 0


@contextmanager
def _native_service(tmp_path, case, cancelled):
    from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    from recon_cockpit.secure_agent.stock_http_backend import AuthorizedStockHttpBackend
    from recon_cockpit.secure_agent.stock_http_client_runtime import inspect_client_runtime
    from recon_cockpit.secure_agent.execution import ExecutionControl
    selected = contract.selection("A", case)
    preflight = ExecutionControl(time.monotonic() + 60)
    runtimes = {"daemon": runtime.inspect_runtime("A", case, preflight),
                "client": inspect_client_runtime(selected, preflight)}
    session = str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=False)
    owner = lab_module.StockHttpLab(selected, session, limits, execute=True, runtime=runtimes)
    original = AuthorizedStockHttpBackend(policy, session, limits, owner, execute=True)
    selected_control = ExecutionControl(time.monotonic() + 60, cancelled)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit:
        with LinuxApprovalService(policy, session, launch_witness=True) as approvals:
            with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as launcher:
                yield selected, session, policy, selected_control, audit, approvals, launcher


@pytest.mark.integration
def test_native_cancellation_before_launch_creates_no_owner(tmp_path):
    _native_gate()
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionStopped
    cancelled = threading.Event()
    with _native_service(tmp_path, "O1", cancelled) as (selected, session, policy, control, audit, approvals, launcher):
        cancelled.set()
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        with pytest.raises(ExecutionStopped, match="session_cancelled"):
            controller.submit(contract.action(selected), execute=True, execution_control=control, session_step=1)
        assert not hasattr(launcher, "_process")
        assert launcher.snapshot["executions_reserved"] == 0
        launcher.close()
        assert launcher._closed


@pytest.mark.integration
@pytest.mark.parametrize("stage", ("response", "startup"))
def test_native_cancel_during_response_and_failed_start_reap_all_descendants(tmp_path, monkeypatch, record_property, stage):
    """Private test-copy markers never alter the ordinary compatibility corpus.

    The response marker follows complete response validation in N3 and adds no
    wait. The startup marker inserts a bounded250ms failure window before exec.
    Host observation uses process names only, never a peer/control descriptor.
    """
    _native_gate()
    from recon_cockpit.secure_agent.controller import Controller
    from test_secure_fixture_launcher_linux import instrument, descendants
    from test_secure_owned_launcher_linux import assert_reaped
    marker = "stock-response" if stage == "response" else "stock-startup"
    if stage == "response":
        def transform(source):
            source = source.replace("import time\n", "import time\nimport ctypes\n", 1)
            anchor = '        self.ledger["transformed_response_hex"] = b"".join(chunks).hex()'
            assert source.count(anchor) == 1
            return source.replace(anchor, anchor + '\n        ctypes.CDLL(None).prctl(15, b"stock-response", 0, 0, 0)')
        instrument(tmp_path, monkeypatch, transform, "stock_http_recorder")
    else:
        def transform(source):
            anchor = '    os.execve("/tool/nginx",'
            assert source.count(anchor) == 1
            return source.replace(anchor, '    ctypes.CDLL(None).prctl(15, b"stock-startup", 0, 0, 0)\n'
                '    time.sleep(0.25)\n    raise ValueError("instrumented_startup_failure")\n' + anchor)
        instrument(tmp_path, monkeypatch, transform, "stock_http_owner_worker")
    cancelled = threading.Event()
    observed = set()
    with _native_service(tmp_path, "N3" if stage == "response" else "O1", cancelled) as (
            selected, session, policy, control, audit, approvals, launcher):
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(controller.submit, contract.action(selected), execute=True,
                                  execution_control=control, session_step=1)
            try:
                found = False
                expiry = min(control.deadline, time.monotonic() + 25)
                while time.monotonic() < expiry and not pending.done():
                    process = getattr(launcher, "_process", None)
                    if process is not None:
                        observed.add(process.pid)
                        observed.update(descendants(process.pid))
                    for pid in tuple(observed):
                        try:
                            found |= Path(f"/proc/{pid}/comm").read_text().strip() == marker
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                    if found:
                        break
                    time.sleep(0.005)
                assert found and not pending.done(), "owned instrumented stage was never reached"
                if stage == "response":
                    cancelled.set()
                result = pending.result(timeout=8)
            finally:
                cancelled.set()
            assert result["execution_status"] == ("cancelled" if stage == "response" else "blocked"), result
            assert launcher._closed and launcher._process.poll() is not None
            assert launcher.snapshot["executions_reserved"] == 0  # No result was acknowledged.
        assert_reaped(observed)
    record_property("instrumented_cleanup_stage", stage)
    record_property("all_observed_descendants_reaped", True)
    record_property("native_response_stage_observed", stage == "response")
