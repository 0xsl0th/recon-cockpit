"""Closed client imports, READY/GO deadlines and selected mount/FD custody."""

import hashlib
import os
import signal
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import stock_http_client_runtime as runtime, stock_http_client_worker as worker
from recon_cockpit.secure_agent import stock_http_contract as contract, stock_http_spec as spec
from recon_cockpit.secure_agent import network_tools_runtime as native
from test_secure_network_tools_runtime import manifest
from test_secure_stock_http_authority import envelope, NONCE


@pytest.mark.parametrize("case", ["O1", "O5", "O6"])
def test_actual_confined_module_set_imports_and_verifies_launch_without_repository_fallback(tmp_path, case):
    package = tmp_path / "recon_cockpit" / "secure_agent"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    source = Path(runtime.__file__).parent
    for module in runtime.MODULES:
        shutil.copyfile(source / (module + ".py"), package / (module + ".py"))
    raw = spec.encode(envelope(case=case))
    code = """import hashlib,json,sys
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent import stock_http_client_worker
from recon_cockpit.secure_agent.stock_http_execution import consume_launch
raw=sys.argv[2].encode('ascii')
request,deadline,namespaces,digest=consume_launch(raw,sys.argv[3],hashlib.sha256(raw).hexdigest(),now=100)
assert request['selection']['configuration']=='A' and deadline==150
assert (digest is None)==(request['selection']['case']=='O1')
assert stock_http_client_worker.__file__.startswith(sys.argv[1])
print('closed-import-and-authority-data-ok')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), raw.decode("ascii"), NONCE],
                            capture_output=True, timeout=10, env={"LC_ALL": "C"}, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout == b"closed-import-and-authority-data-ok\n"


@pytest.mark.parametrize("case", spec.CASES)
def test_go_uses_existing_selected_deadline_without_reset_or_budget_extension(case):
    maximum = spec.budgets(case)["tool_timeout_seconds"]
    raw = spec.encode({"nonce": NONCE, "deadline": 100 + maximum})
    assert worker.validate_go(raw, NONCE, 160, case, now=100) == 100 + maximum
    with pytest.raises(ValueError):
        worker.validate_go(raw, NONCE, 160, case, now=100 + maximum)
    with pytest.raises(ValueError):
        worker.validate_go(raw, NONCE, 100 + maximum - .1, case, now=100)


@pytest.mark.parametrize("change", [lambda d: d.update(nonce="b" * 64), lambda d: d.update(deadline=True),
    lambda d: d.update(deadline=100), lambda d: d.update(deadline=101.001), lambda d: d.update(deadline="101"),
    lambda d: d.update(extra=True), lambda d: d.pop("nonce")])
def test_changed_release_cannot_arm_a_new_or_longer_action(change):
    value = {"nonce": NONCE, "deadline": 101}
    change(value)
    with pytest.raises(ValueError):
        worker.validate_go(spec.encode(value), NONCE, 160, "O1", now=100)


@pytest.mark.parametrize("raw", [b"x" * 257, b'{"nonce":"x","deadline":NaN}',
    b'{"nonce":"x","deadline":101,"deadline":100}', b"[]", "not bytes"])
def test_invalid_release_framing_and_json_refused(raw):
    with pytest.raises((ValueError, TypeError)):
        worker.validate_go(raw, NONCE, 160, "O1", now=100)


@pytest.mark.parametrize("case", ["O1", "O5", "O6"])
def test_command_retains_only_selected_snapshots_and_no_private_owner_mount(monkeypatch, case):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    selected = None if case == "O1" else manifest(native.NMAP_SERVICE)
    entries = [] if selected is None else native.runtime_files(selected)
    descriptors = list(range(40, 40 + len(entries)))
    bootstrap = ("/stdlib", [(path, path) for path in ("/usr/bin/python3", "/usr/bin/nmap", "/tool/ssh-keyscan",
        "/usr/bin/nsenter", "/usr/sbin/nft", "/usr/bin/ip", "/usr/sbin/nginx", "/usr/bin/bwrap", "/lib/libc.so")])
    argv = runtime._command(SimpleNamespace(_namespace_fds=(30, 31)), bootstrap, selected, descriptors, "a" * 64, "b" * 64)
    assert argv[:4] == ["/usr/bin/nsenter", "--user=/proc/self/fd/30", "--net=/proc/self/fd/31", "--preserve-credentials"]
    clear_index = argv.index(runtime._CLOSE_EXCEPT)
    assert argv[clear_index + 1] == (",".join(map(str, descriptors)) if descriptors else "0,1,2")
    assert argv[clear_index + 2] == "/usr/bin/bwrap"
    mounted = [argv[i + 1:i + 3] for i, value in enumerate(argv) if value == "--ro-bind"]
    forbidden = {"nmap", "ssh-keyscan", "nsenter", "nft", "ip", "nginx", "bwrap"}
    assert all(Path(source).name not in forbidden for source, _ in mounted)
    assert all(destination not in {"/peer", "/scratch"} for _, destination in mounted)
    assert "--bind" not in argv and "--bind-fd" not in argv and "--tmpfs" not in argv
    data = [argv[i + 1:i + 3] for i, value in enumerate(argv) if value == "--ro-bind-data"]
    assert data == [[str(fd), row["destination"]] for fd, row in zip(descriptors, entries, strict=True)]
    assert "--clearenv" in argv and "--new-session" in argv and "--die-with-parent" in argv
    assert [argv[i + 1:i + 3] for i, value in enumerate(argv) if value == "--setenv"] == [["LC_ALL", "C"], ["MALLOC_ARENA_MAX", "1"]]
    assert argv[-6:] == ["/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_http_client_worker.py", "a" * 64, "b" * 64]


def test_command_rejects_unaccounted_snapshot_descriptors(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    with pytest.raises(ValueError):
        runtime._command(SimpleNamespace(_namespace_fds=(30, 31)), ("/stdlib", []), None, [40], "a" * 64, "b" * 64)


@pytest.mark.parametrize("configuration,case", [("A", "O5"), ("A", "O6"), ("B", "O5"), ("B", "O6")])
def test_native_arguments_change_only_exact_target_port_and_closed_probe_intensity(configuration, case):
    value = envelope(configuration, case)
    from recon_cockpit.secure_agent.stock_http_execution import consume_launch
    raw = spec.encode(value)
    request, *_ = consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)
    argv = worker.argv_for(request)
    expected = list(native.FIXED_ARGV[native.NMAP_SERVICE])
    expected[expected.index("-p") + 1] = str(request["parameters"]["port"])
    expected[expected.index("--version-intensity") + 1] = "1"
    expected[-1] = request["target"]
    assert argv == tuple(expected)
    assert "--script" not in argv and "--version-all" not in argv and "-n" in argv
    assert native.execution_environment(native.NMAP_SERVICE) == {"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1"}


def test_header_runtime_cannot_select_native_program_or_another_profile():
    headers = contract.selection("A", "O1")
    assert runtime.validate_client_runtime(None, headers) is None
    with pytest.raises(ValueError):
        runtime.validate_client_runtime(manifest(native.NMAP_SERVICE), headers)
    with pytest.raises(ValueError):
        runtime.validate_client_runtime(manifest(native.SSH), contract.selection("A", "O5"))


def test_private_descriptor_check_refuses_live_extra_fds_but_tolerates_closed_listing(monkeypatch):
    monkeypatch.setattr(worker.os, "listdir", lambda path: ["0", "1", "2", "9"])
    monkeypatch.setattr(worker.os, "fstat", lambda fd: object())
    with pytest.raises(ValueError, match="inherited_descriptor"):
        worker.private_descriptors()
    def disappeared(_):
        raise OSError("descriptor closed while listing")
    monkeypatch.setattr(worker.os, "fstat", disappeared)
    worker.private_descriptors()


def test_control_pipe_handles_partial_writes_without_losing_packet_bytes(monkeypatch):
    from recon_cockpit.secure_agent.routed import _Supervisor
    read_fd, write_fd = os.pipe()
    original_write = os.write
    monkeypatch.setattr(runtime.os, "write", lambda fd, data: original_write(fd, data[:3]))
    supervisor = _Supervisor(1, 8192)
    try:
        with os.fdopen(write_fd, "wb", buffering=0) as target:
            proc = SimpleNamespace(stdin=target, poll=lambda: None)
            runtime._write_control(proc, b"one complete private packet\n", supervisor)
        assert os.read(read_fd, 1024) == b"one complete private packet\n"
    finally:
        os.close(read_fd)
        supervisor.close()


def test_control_pipe_backpressure_cannot_outlive_supervisor_deadline():
    from recon_cockpit.secure_agent.routed import _Supervisor, _BudgetExceeded
    read_fd, write_fd = os.pipe()
    supervisor = _Supervisor(.02, 8192)
    began = time.monotonic()
    try:
        os.set_blocking(write_fd, False)
        for _ in range(256):
            try:
                os.write(write_fd, b"x" * 4096)
            except BlockingIOError:
                break
        else:
            pytest.fail("test pipe capacity exceeded bounded fill")
        with os.fdopen(write_fd, "wb", buffering=0) as target:
            proc = SimpleNamespace(stdin=target, poll=lambda: None)
            with pytest.raises(_BudgetExceeded, match="timeout"):
                runtime._write_control(proc, b"x" * 32769, supervisor)
        assert time.monotonic() - began < 1
    finally:
        os.close(read_fd)
        supervisor.close()


def test_go_write_respects_action_deadline_even_with_result_drain_time_remaining():
    from recon_cockpit.secure_agent.routed import _Supervisor, _BudgetExceeded
    read_fd, write_fd = os.pipe()
    supervisor = _Supervisor(1, 8192)
    try:
        with os.fdopen(write_fd, "wb", buffering=0) as target:
            proc = SimpleNamespace(stdin=target, poll=lambda: None)
            with pytest.raises(_BudgetExceeded, match="timeout"):
                runtime._write_control(proc, b"go\n", supervisor, deadline=time.monotonic() - 1)
        assert os.read(read_fd, 1024) == b""
    finally:
        os.close(read_fd)
        supervisor.close()


def test_cancelled_control_pipe_never_writes_release_bytes():
    from recon_cockpit.secure_agent.routed import _Supervisor
    from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
    read_fd, write_fd = os.pipe()
    cancelled = threading.Event()
    cancelled.set()
    supervisor = _Supervisor(1, 8192, control=ExecutionControl(time.monotonic() + 1, cancelled=cancelled))
    try:
        with os.fdopen(write_fd, "wb", buffering=0) as target:
            proc = SimpleNamespace(stdin=target, poll=lambda: None)
            with pytest.raises(ExecutionStopped, match="session_cancelled"):
                runtime._write_control(proc, b"go\n", supervisor)
        assert os.read(read_fd, 1024) == b""
    finally:
        os.close(read_fd)
        supervisor.close()


@pytest.mark.parametrize("code,now,reason,expected", [(-signal.SIGALRM, 105, None, "timeout"),
    (128 + signal.SIGALRM, 105, None, "timeout"), (-signal.SIGALRM, 104.99, None, None),
    (1, 105, None, None), (0, 105, None, None), (-signal.SIGALRM, 105, "output_limit", "output_limit")])
def test_native_timer_exit_is_timeout_only_at_the_actual_deadline(code, now, reason, expected):
    assert runtime._native_stop_reason(code, reason, 105, now=now) == expected


@pytest.mark.parametrize("status,count,now,expected", [("failed", 0, 101, "timeout"),
    ("failed", 0, 100.99, "failed"), ("failed", 1, 101, "failed"),
    ("succeeded", 20, 101, "succeeded"), ("timeout", 0, 101, "timeout")])
def test_empty_eof_at_shared_deadline_is_distinct_from_early_failure(monkeypatch, status, count, now, expected):
    monkeypatch.setattr(worker, "probe_headers", lambda request, deadline: {"status": status, "bytes_received": count})
    monkeypatch.setattr(worker.time, "monotonic", lambda: now)
    assert worker.probe_headers_at_deadline({}, 101)["status"] == expected


def header_reply():
    import base64
    raw = b"x" * 2048
    return {"status": "output_limit", "bytes_received": 2048, "truncated": True,
        "boundary_checks": dict.fromkeys(runtime.BOUNDARY_NAMES, True),
        "results": [{"target": "10.77.0.10", "port": 8080, "bytes_received": 2048, "truncated": True,
            "raw_response": base64.b64encode(raw).decode(), "response_sha256": hashlib.sha256(raw).hexdigest()}]}


def test_header_protocol_cap_accounts_for_base64_expansion_without_reducing_raw_capture():
    value = header_reply()
    raw = spec.encode(value)
    assert 2048 < len(raw) < 8192
    assert runtime._header_reply(raw, contract.selection("A", "O1")) == value


@pytest.mark.parametrize("change", [lambda value: value.update(bytes_received=True),
    lambda value: value.update(truncated=False), lambda value: value.update(status="succeeded"),
    lambda value: value["boundary_checks"].update(private_socket_blocked=1),
    lambda value: value["results"][0].update(port=8081),
    lambda value: value["results"][0].update(bytes_received=2047),
    lambda value: value["results"][0].update(response_sha256="0" * 64),
    lambda value: value["results"][0].update(raw_response="")])
def test_header_worker_protocol_cannot_report_inconsistent_capture_or_boundaries(change):
    value = header_reply()
    change(value)
    with pytest.raises(ValueError):
        runtime._header_reply(spec.encode(value), contract.selection("A", "O1"))
