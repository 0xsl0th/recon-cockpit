"""Sixty-two physical gates with explicitly injected peers and output."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import time

import pytest

from recon_cockpit.secure_agent import name_tls_python_runtime as sources
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import _capture_bounded, _runtime_files, _trusted_program

pytestmark = pytest.mark.integration

GATES = json.loads((Path(__file__).parents[1] / "docs/stage3-name-tls-native-gates.json").read_text())["architecture"]
CUSTODY = {"unexpected_export_descriptor_rejected", "duplicate_scm_rights_handoff_rejected",
    "daemon_socket_must_be_unconnected_at_transfer", "daemon_socket_namespace_swap_rejected",
    "consume_before_request_reservation_rejected", "daemon_descriptor_second_consumption_rejected",
    "sender_or_launcher_copy_leak_rejected", "all_descriptor_copies_closed_after_denial"}
CASES = [row for row in GATES if
    row["group"] == "malformed_and_bounded_wire"
    or row["group"] == "transport_denial" and row["case"].endswith("second_connection")
    or row["group"] == "topology_and_descriptor_custody" and row["case"] in CUSTODY
    or row["case"] == "unknown_runtime_provider_or_helper_refused"]
assert len(CASES) == 62 and len({row["id"] for row in CASES}) == 62


@pytest.fixture(scope="module")
def socket_runtime():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual isolated Name/TLS socket gates")
    assert sys.platform == "linux" and os.geteuid() != 0
    control = ExecutionControl(time.monotonic() + 15)
    stdlib, files = _runtime_files("/usr/bin/python3", None, control=control)
    pins = sources.inspect_sources(control)
    return stdlib, files, pins


def _save(path, raw):
    with path.open("wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)


def _helper_snapshot(raw):
    descriptor = os.memfd_create("name-tls-test-helper", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            assert written > 0
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@pytest.mark.parametrize("gate", CASES, ids=[row["id"] for row in CASES])
def test_isolated_name_tls_wire_and_descriptor_gate(gate, socket_runtime, tmp_path, record_property):
    stdlib, files, pins = socket_runtime
    control = ExecutionControl(time.monotonic() + 10)
    descriptors = sources.snapshot_sources({"python_sources": pins}, tuple(sources.DESTINATIONS), control)
    helper = Path(__file__).with_name("name_tls_socket_probe.py").read_bytes()
    helper_fd = _helper_snapshot(helper)
    host_net = os.readlink("/proc/self/ns/net")
    argv = [_trusted_program("bwrap"), "--unshare-all", "--uid", "65534", "--gid", "65534",
        "--cap-drop", "ALL", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_SETPCAP", "--cap-add", "CAP_SYS_ADMIN",
        "--die-with-parent", "--new-session", "--as-pid-1", "--clearenv", "--setenv", "LC_ALL", "C",
        "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        argv += ["--ro-bind", source, destination]
    sources.mount_sources(argv, tuple(sources.DESTINATIONS), descriptors)
    argv += ["--perms", "0444", "--ro-bind-data", str(helper_fd), "/name_tls_socket_probe.py",
             "--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/name_tls_socket_probe.py", gate["configuration"],
             gate["group"], gate["case"], host_net]
    overflow = gate["case"].endswith("native_stdout_stderr_overflow")
    try:
        if overflow:
            from recon_cockpit.secure_agent.name_tls_contract import action_bounds
            from recon_cockpit.secure_agent.routed import _Supervisor, _BudgetExceeded
            maximum = action_bounds(gate["case"].split("/")[0])["output_bytes"]
            supervisor = _Supervisor(8, maximum, control=control)
            process = None
            try:
                process = supervisor.launch("worker", argv, pass_fds=(*descriptors.values(), helper_fd), stdin=subprocess.PIPE)
                supervisor.wait_for(lambda: b"\n" in supervisor.buffers["worker_out"])
                assert bytes(supervisor.buffers["worker_out"]) == b"INJECTED_NAME_TLS_OUTPUT\n"
                process.stdin.write(b"1")
                process.stdin.close()
                with pytest.raises(_BudgetExceeded) as denied:
                    supervisor.wait_for(lambda: process.poll() is not None, worker_may_exit=True)
                assert denied.value.status == "output_limit"
            finally:
                supervisor.close()
            assert process is not None and process.poll() is not None
            stdout, stderr = bytes(supervisor.buffers["worker_out"]), bytes(supervisor.buffers["worker_err"])
            code, reason = process.returncode, "output_limit"
            assert stdout.startswith(b"INJECTED_NAME_TLS_OUTPUT\n") and len(stdout) + len(stderr) <= maximum
        else:
            code, stdout, stderr, reason = _capture_bounded(argv, b"", 8, 65536, control=control,
                pass_fds=(*descriptors.values(), helper_fd))
    finally:
        for descriptor in (*descriptors.values(), helper_fd): os.close(descriptor)
    _save(tmp_path / "probe-stdout.json", stdout)
    _save(tmp_path / "probe-stderr.txt", stderr)
    if overflow:
        receipt = {"configuration": gate["configuration"], "case": gate["case"], "test_passed": True,
            "probe_kind": "isolated_injected_native_output", "native_daemon_output_claimed": False,
            "native_client_output_claimed": False, "owner_enforcement_claimed": False,
            "production_supervisor": "routed._Supervisor", "combined_output_cap": maximum,
            "retained_bytes": len(stdout) + len(stderr), "stop_reason": reason, "process_reaped": True}
    else:
        assert reason is None and code == 0, (reason, code, stderr.decode("utf-8", "replace"))
        assert not stderr and len(stdout) <= 65536
        receipt = json.loads(stdout)
        assert receipt["configuration"] == gate["configuration"] and receipt["case"] == gate["case"]
        assert receipt["group"] == gate["group"] and receipt["test_passed"] is True
        assert receipt["namespace"] != host_net and receipt["probe_kind"] == "isolated_injected_peer"
        assert receipt["native_daemon_output_claimed"] is receipt["owner_enforcement_claimed"] is False
    receipt.update(gate_id=gate["id"], helper_sha256=hashlib.sha256(helper).hexdigest(),
                   production_sources_sha256=sources.source_digest(pins), independent_watchdog_seconds=8)
    _save(tmp_path / "gate-receipt.json", json.dumps(receipt, sort_keys=True).encode("ascii"))
    record_property("gate_id", gate["id"])
    record_property("case_passed", True)
    record_property("helper_sha256", receipt["helper_sha256"])
    record_property("actual_provider_calls", 0)
