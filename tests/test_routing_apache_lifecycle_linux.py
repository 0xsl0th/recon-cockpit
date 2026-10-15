"""Stop real Apache custody before any routed client or request is released.

An instrumented copy pauses only after production verifies the actual daemon
handoff and the frontend's open, unconsumed descriptor. It grants no authority,
changes no protocol reply or bound, and never fabricates a successful result.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_services
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.routing_backend import AuthorizedRoutingBackend
from recon_cockpit.secure_agent.routing_lab import RoutingLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_routing_lifecycle_linux import _assert_pinned_tree_reaped, _save
from test_secure_fixture_launcher_linux import descendants, instrument

pytestmark = pytest.mark.integration
_MARKER = re.compile(r"rf[A-Z2-7]{13}\Z")


def _hold_unconsumed_handoff(source):
    anchor = '''                validate_apache_custody(start_reply["apache_descriptor_custody"], daemon["ready"]["descriptor"],
                    self.topology.identity, closed=False)
'''
    assert source.count(anchor) == 1
    checkpoint = '''                # Test-only observation after the real validated SCM_RIGHTS handoff.
                if self.selection != contract.selection(deployment="apache-B") or selector != "http_headers":
                    raise ValueError("apache_lifecycle_wrong_checkpoint")
                receipt, record = start_reply["apache_descriptor_custody"], start_reply["recorder"]
                if (private_socket.fileno() != -1 or daemon["private_socket"] is not None
                        or receipt["frontend_consumed"] is not False or receipt["frontend_copy_closed"] is not False
                        or record["armed"] is not False or record["finalized"] is not False
                        or any(record[key] for key in ("connections_attempted", "connections_admitted",
                            "daemon_connections", "requests_validated", "request_bytes_delivered", "client_response_bytes"))
                        or start_reply["reservations"] != [] or start_reply["budget_denied"] is not False
                        or start_reply["last_budget_reply"] is not None):
                    raise ValueError("apache_lifecycle_custody_not_unconsumed")
                # /proc comm is observation only: no output enters the launcher
                # protocol, and the marker carries the real socket inode in 15 bytes.
                import ctypes
                marker = b"rf" + base64.b32encode(receipt["descriptor"]["inode"].to_bytes(8, "big")).rstrip(b"=")
                libc = ctypes.CDLL(None, use_errno=True)
                libc.prctl.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
                libc.prctl.restype = ctypes.c_int
                if len(marker) != 15 or libc.prctl(15, marker, 0, 0, 0) != 0:
                    raise ValueError("apache_lifecycle_marker_failed")
                checkpoint_deadline = min(self.control.deadline, time.monotonic() + 10)
                while time.monotonic() < checkpoint_deadline:
                    self._check()
                    time.sleep(.01)
                raise ValueError("apache_lifecycle_checkpoint_not_stopped")
'''
    candidate = source.replace(anchor, anchor + checkpoint)
    compile(candidate, "routing-apache-lifecycle-observer", "exec")
    return candidate


def _wait_for_handoff(launcher, pending):
    expiry = time.monotonic() + 18
    while not pending.done() and time.monotonic() < expiry:
        process = getattr(launcher, "_process", None)
        if process is not None:
            for pid in {process.pid, *descendants(process.pid)}:
                try:
                    name = Path(f"/proc/{pid}/comm").read_text().strip()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if _MARKER.fullmatch(name):
                    inode = int.from_bytes(base64.b32decode(name[2:] + "==="), "big")
                    assert inode > 0
                    return process, pid, inode
        time.sleep(.01)
    pytest.fail("real Apache handoff checkpoint was not observed")


def _pin_handoff_tree(process, checkpoint_pid, inode):
    pins, commands, holders = {}, {}, []
    try:
        for pid in sorted({process.pid, *descendants(process.pid)}):
            pins[pid] = os.pidfd_open(pid)
            commands[pid] = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        assert process.pid in pins and checkpoint_pid in pins
        frontends = [pid for pid, argv in commands.items() if argv[0] == b"/usr/bin/python3"
            and b"/app/recon_cockpit/secure_agent/routing_frontend_worker.py" in argv]
        daemons = [pid for pid, argv in commands.items() if argv[0] == b"/tool/apache2"]
        assert len(frontends) == len(daemons) == 1
        assert not any(argv[0] in (b"/tool/nmap", b"/tool/ssh-keyscan")
            or argv[0] == b"/usr/bin/python3" and b"/app/recon_cockpit/secure_agent/routing_client_worker.py" in argv
            for argv in commands.values())
        # Metadata reads only; no socket or namespace descriptor is imported.
        # The checkpoint remains paused while every owned FD table is inspected.
        for pid in pins:
            entries = list(Path(f"/proc/{pid}/fd").iterdir())
            assert len(entries) <= contract.OWNER_BOUNDS["file_descriptors"]
            for entry in entries:
                try:
                    target = os.readlink(entry)
                except FileNotFoundError:
                    continue
                if target == f"socket:[{inode}]":
                    holders.append({"pid": pid, "fd": int(entry.name)})
        assert len(holders) == 1 and holders[0]["pid"] == frontends[0]
        return pins, {"checkpoint_pid": checkpoint_pid, "frontend_pid": frontends[0],
                      "apache_pid": daemons[0], "descriptor_inode": inode, "descriptor_holders": holders}
    except BaseException:
        for descriptor in pins.values():
            os.close(descriptor)
        raise


@pytest.mark.parametrize("stop", ("cancel", "launcher_death"))
def test_native_stop_reaps_live_unconsumed_apache_handoff(tmp_path, monkeypatch, record_property, stop):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned Apache handoff lifecycle")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(RoutingLab, "start", lambda *_a, **_kw: pytest.fail("host topology fallback"))
    monkeypatch.setattr(AuthorizedRoutingBackend, "run", lambda *_a, **_kw: pytest.fail("host execution fallback"))
    source_path = Path(routing_services.__file__)
    original_source = source_path.read_bytes()
    instrument(tmp_path, monkeypatch, _hold_unconsumed_handoff, "routing_services")
    selected = contract.selection(deployment="apache-B")
    session = str(uuid4())
    cancelled = threading.Event()
    runtime = contract.inspect_runtime(selected, ExecutionControl(time.monotonic() + 60))
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=False)
    metadata = RoutingLab(selected, session, limits, execute=True, runtime=runtime)
    backend = AuthorizedRoutingBackend(policy, session, limits, metadata, execute=True)
    control = ExecutionControl(time.monotonic() + 60, cancelled)
    pins, launcher = {}, None
    audit_path = tmp_path / "audit.jsonl"
    state = {"test_kind": "live_unconsumed_apache_handoff_lifecycle", "stop": stop,
        "selection": selected, "test_passed": False, "useful_actions_completed": 0,
        "personal_approval_claimed": False, "actual_provider_calls": 0, "actual_cost_microusd": 0,
        "source_sha256": hashlib.sha256(original_source).hexdigest(),
        "instrumented_source_sha256": hashlib.sha256((tmp_path / "routing_services.py").read_bytes()).hexdigest()}
    try:
        with LinuxAuditSink(audit_path, launch_witness=True) as audit, \
                LinuxApprovalService(policy, session, launch_witness=True) as approvals:
            with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher, \
                    ThreadPoolExecutor(max_workers=1) as pool:
                controller = Controller(policy, audit, launcher, approvals, session_id=session)
                pending = pool.submit(controller.submit, contract.action(selected, "http_headers"),
                    execute=True, execution_control=control, session_step=1)
                try:
                    process, checkpoint_pid, inode = _wait_for_handoff(launcher, pending)
                    assert not pending.done() and process.poll() is None
                    pins, observation = _pin_handoff_tree(process, checkpoint_pid, inode)
                    state["checkpoint"] = observation
                    state["observed_processes"] = sorted(pins)
                    assert launcher._lab_context is None
                    assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
                    if stop == "cancel":
                        cancelled.set()
                    else:
                        signal.pidfd_send_signal(pins[process.pid], signal.SIGKILL)
                    try:
                        outcome = pending.result(timeout=8)
                    except AuditUnavailable as error:
                        # A dead witness reader can also prevent recording the
                        # refusal. Preserve the exception; invent no tool result.
                        assert str(error) == "audit_unavailable"
                        state["submission_failure"] = {"exception_type": type(error).__name__, "reason": str(error)}
                    else:
                        state["outcome"] = outcome
                        assert outcome["execution_status"] == ("cancelled" if stop == "cancel" else "blocked")
                        assert outcome["untrusted_result"] == {"status": outcome["execution_status"]}
                    closure = launcher.close()
                    state["closure"] = closure
                    assert closure["launcher_cleanup_verified"] is True
                    assert closure["counters_source"] == "last_acknowledged_result"
                    assert closure["connection_count"] == closure["request_count"] == 0
                    assert launcher._closed and launcher._cleanup_verified and process.poll() is not None
                    assert launcher._lab_context is None
                    assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
                    _assert_pinned_tree_reaped(pins)
                    assert all(not Path(f"/proc/{row['pid']}/fd/{row['fd']}").exists()
                               for row in observation["descriptor_holders"])
                    state.update(descriptor_owners_reaped=True, client_execution_started=False,
                                 acknowledged_results=0, process_identities_reaped=len(pins))
                finally:
                    cancelled.set()
                    if not pending.done():
                        try:
                            pending.result(timeout=10)
                        except (AuditUnavailable, RuntimeError, OSError, ValueError):
                            pass
        events = [json.loads(line) for line in audit_path.read_text().splitlines()]
        assert any(row["event_type"] == "execution_started" for row in events)
        assert not any(row["event_type"] == "execution_finished" and row["execution_status"] == "succeeded"
                       for row in events)
        assert source_path.read_bytes() == original_source
        state["test_passed"] = True
        record_property("instrumented_cleanup_checkpoint", "apache-B-transferred-unconsumed")
        record_property("lifecycle_stop", stop)
        record_property("actual_private_descriptor_observed", True)
        record_property("client_execution_started", False)
        record_property("owned_processes_reaped", len(pins))
    finally:
        cancelled.set()
        if launcher is not None and launcher._supervisor is not None:
            state["launcher_diagnostics"] = {name: bytes(raw).decode("utf-8", "replace")
                for name, raw in launcher._supervisor.buffers.items()}
        _save(tmp_path / "apache-handoff-lifecycle.json", state)
        for descriptor in pins.values():
            os.close(descriptor)
