"""Native recorder refusal probes, separate from stock-client compatibility.

Private test copies replace only the final client exec after READY/GO and all
confinement checks. They contact the selected disconnected endpoint and retain
the real stock daemon/custodian. No production command or profile is expanded.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import stock_ssh as diagnostic
from recon_cockpit.secure_agent import stock_ssh_packets as packets
from recon_cockpit.secure_agent import stock_ssh_process as process
from recon_cockpit.secure_agent.stock_ssh_backend import AuthorizedStockSshBackend
from recon_cockpit.secure_agent.stock_ssh_evidence import inspect_trial
from recon_cockpit.secure_agent.stock_ssh_lab import StockSshLab
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from test_secure_fixture_launcher_linux import instrument, descendants
from test_secure_owned_launcher_linux import assert_reaped
from test_stock_ssh_recorder import CLIENT_IDENTIFICATION, kex, dh


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def native_gate():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned SSH recorder budget probes")
    assert sys.platform == "linux" and os.geteuid() != 0


def _probe_source(source, probe):
    anchor = '        os.execve(argv[0], argv, native.execution_environment(manifest["tool_id"]))'
    assert source.count(anchor) == 1
    common = '''        # Instrumented native boundary probe, not a stock client result.
        def connection():
            channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            channel.settimeout(worker._remaining(deadline, 1))
            channel.connect((request["target"], request["parameters"]["port"]))
            return channel
        def exact(channel, size):
            result = b""
            while len(result) < size:
                part = channel.recv(size - len(result))
                if not part:
                    raise RuntimeError("probe_expected_stock_bytes")
                result += part
            return result
        def banner(channel):
            result = b""
            while not result.endswith(b"\\n"):
                result += exact(channel, 1)
                if len(result) > 255:
                    raise RuntimeError("probe_stock_identification_limit")
            if not result.startswith(b"SSH-2.0-OpenSSH_"):
                raise RuntimeError("probe_stock_identification_missing")
        def packet(channel):
            prefix = exact(channel, 4)
            length = int.from_bytes(prefix, "big")
            if not 12 <= length <= 8192:
                raise RuntimeError("probe_stock_packet_limit")
            return prefix + exact(channel, length)
        def denied(channel):
            try:
                if channel.recv(1):
                    raise RuntimeError("probe_forbidden_response_received")
            except ConnectionResetError:
                pass
'''
    if probe in ("fourth_nmap_connection", "second_keyscan_connection"):
        admitted = 3 if probe == "fourth_nmap_connection" else 1
        # No sleeps before the first three attempts: the actual recorder must
        # impose the 250ms spacing, including after each daemon instance exits.
        body = f'''        for index in range({admitted + 1}):
            with connection() as channel:
                if index < {admitted}:
                    banner(channel)
                else:
                    denied(channel)
'''
    elif probe == "nmap_application_byte":
        body = '''        with connection() as channel:
            channel.sendall(b"X")
            try:
                while channel.recv(256):
                    pass
            except ConnectionResetError:
                pass
'''
    elif probe == "wait_for_stop":
        body = '''        with connection() as channel:
            banner(channel)
            if ctypes.CDLL(None).prctl(15, b"ssh-budget-wait", 0, 0, 0) != 0:
                raise RuntimeError("probe_stage_marker_failed")
            time.sleep(10)
            raise RuntimeError("probe_action_deadline_not_enforced")
'''
    elif probe in ("malformed_identification", "oversized_identification"):
        message = b"SSH-1.5-forbidden\r\n" if probe == "malformed_identification" else b"X" * 8193
        body = f'''        with connection() as channel:
            banner(channel)
            channel.sendall({message!r})
            denied(channel)
'''
    else:
        messages = {"newkeys": packets.synthetic_packet(b"\x15"),
                    "userauth": packets.synthetic_packet(b"\x32"),
                    "service_request": packets.synthetic_packet(b"\x05"),
                    "malformed_packet": b"\xff\xff\xff\xff\x04",
                    "extra_kexinit": kex(),
                    "extra_after_dh": dh() + packets.synthetic_packet(b"\x15")}
        message = messages[probe]
        before = ""
        if probe in ("extra_kexinit", "extra_after_dh"):
            before = f'''            channel.sendall({kex()!r})
            if packet(channel)[5] != 20:
                raise RuntimeError("probe_stock_kexinit_missing")
'''
        else:
            # Wait for the daemon's KEXINIT to ensure identification was
            # forwarded before testing the next client message boundary.
            before = '''            if packet(channel)[5] != 20:
                raise RuntimeError("probe_stock_kexinit_missing")
'''
        body = f'''        with connection() as channel:
            banner(channel)
            channel.sendall({CLIENT_IDENTIFICATION!r})
{before}            channel.sendall({message!r})
            denied(channel)
'''
    candidate = source.replace(anchor, common + body + "        return 0")
    compile(candidate, "instrumented-stock-ssh-budget-client.py", "exec")
    return candidate


def _run_probe(tmp_path, monkeypatch, probe):
    case = "O1" if probe in ("fourth_nmap_connection", "nmap_application_byte") else "O2"
    instrument(tmp_path, monkeypatch, lambda source: _probe_source(source, probe), "stock_ssh_client_worker")
    monkeypatch.setattr(StockSshLab, "start", lambda *a, **k: pytest.fail("host owner fallback"))
    monkeypatch.setattr(AuthorizedStockSshBackend, "run", lambda *a, **k: pytest.fail("host tool fallback"))
    directory = tmp_path / "evidence"
    report = diagnostic.run_trial(directory, configuration="A", case=case,
                                  execute=True, unattended_owned_lab_test=True)
    assert report["case_passed"] is False, report
    assert report["native_response_verified"] is False
    assert report["metrics"]["useful_completion"] is False
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    result = json.loads((directory / "result.json").read_bytes())
    assert result["boundary_checks"] and all(result["boundary_checks"].values())
    owner = result["stock_ssh_owner"]
    ledger = owner["recorder"]
    assert ledger["finalized"] and ledger["active_connections"] == ledger["pending_connections"] == 0
    assert result["stock_ssh_closure"]["processes_reaped"] is True
    assert result["stock_ssh_closure"]["namespace_descriptors_closed"] is True
    assert len(owner["instances"]) == ledger["daemon_connections"]
    for instance in owner["instances"]:
        receipt = process.validate_receipt(instance["receipt"])
        assert receipt["all_server_processes_reaped"] is True
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    assert inspect_trial(directory) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    return owner, ledger


@pytest.mark.parametrize("probe", ("fourth_nmap_connection", "second_keyscan_connection"))
def test_native_connection_cap_and_rate_survive_daemon_restarts(tmp_path, monkeypatch, record_property, probe):
    owner, ledger = _run_probe(tmp_path, monkeypatch, probe)
    admitted = 3 if probe == "fourth_nmap_connection" else 1
    assert ledger["connections_attempted"] == admitted + 1
    assert ledger["connections_admitted"] == ledger["daemon_connections"] == admitted
    assert ledger["connections_denied"] == 1
    assert ledger["client_bytes_forwarded"] == ledger["client_packets_forwarded"] == 0
    assert ledger["connections"][-1]["reason"] == "connection_limit"
    assert ledger["connections"][-1]["daemon_connected"] is False
    assert [row["connection_id"] for row in owner["instances"]] == list(range(1, admitted + 1))
    assert all(b - a >= 249 for a, b in zip(ledger["admissions_elapsed_ms"], ledger["admissions_elapsed_ms"][1:]))
    record_property("instrumented_boundary_probe", probe)
    record_property("stock_client_compatibility_claimed", False)
    record_property("actual_stock_instances_reaped", admitted)


@pytest.mark.parametrize("probe", ("nmap_application_byte", "malformed_identification", "oversized_identification",
    "malformed_packet", "newkeys", "userauth", "service_request", "extra_kexinit", "extra_after_dh"))
def test_native_forbidden_client_data_is_recorded_and_never_forwarded(tmp_path, monkeypatch, record_property, probe):
    _, ledger = _run_probe(tmp_path, monkeypatch, probe)
    assert ledger["connections_attempted"] == ledger["connections_admitted"] == ledger["connections_denied"] == 1
    row = ledger["connections"][0]
    assert row["status"] == "denied"
    received, forwarded = bytes.fromhex(row["received_client_hex"]), bytes.fromhex(row["forwarded_client_hex"])
    assert received and received.startswith(forwarded) and len(received) > len(forwarded)
    assert len(received) <= (1 if probe == "nmap_application_byte" else 8193)
    expected = b"" if probe in ("nmap_application_byte", "malformed_identification", "oversized_identification") else CLIENT_IDENTIFICATION
    if probe in ("extra_kexinit", "extra_after_dh"):
        expected += kex()
    assert forwarded == expected
    assert ledger["client_packets_forwarded"] == (1 if probe in ("extra_kexinit", "extra_after_dh") else 0)
    assert ledger["server_key_replies_forwarded"] == 0
    record_property("instrumented_boundary_probe", probe)
    record_property("stock_client_compatibility_claimed", False)
    record_property("forbidden_bytes_forwarded", 0)


@pytest.mark.parametrize("stop", ("cancel", "action_deadline"))
def test_native_stop_after_actual_stock_identification_reaps_every_observed_process(
        tmp_path, monkeypatch, record_property, stop):
    # A private process-name marker appears only after the client has received
    # an actual stock identification through the confined mediator. Monitoring
    # uses host /proc metadata, never a client-visible control capability.
    instrument(tmp_path, monkeypatch, lambda source: _probe_source(source, "wait_for_stop"), "stock_ssh_client_worker")
    monkeypatch.setattr(StockSshLab, "start", lambda *a, **k: pytest.fail("host owner fallback"))
    monkeypatch.setattr(AuthorizedStockSshBackend, "run", lambda *a, **k: pytest.fail("host tool fallback"))
    launchers = []
    original = LinuxFixtureLauncher.__init__
    def remember_launcher(self, *args, **kwargs):
        original(self, *args, **kwargs)
        launchers.append(self)
    monkeypatch.setattr(LinuxFixtureLauncher, "__init__", remember_launcher)
    cancelled, observed = threading.Event(), set()
    directory = tmp_path / "evidence"
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(diagnostic.run_trial, directory, configuration="A", case="O2",
            execute=True, unattended_owned_lab_test=True, cancelled=cancelled)
        try:
            reached, expiry = False, time.monotonic() + 25
            while not pending.done() and time.monotonic() < expiry:
                for launcher in launchers:
                    process_handle = getattr(launcher, "_process", None)
                    if process_handle is not None:
                        observed.add(process_handle.pid)
                        observed.update(descendants(process_handle.pid))
                for pid in tuple(observed):
                    try:
                        reached |= Path(f"/proc/{pid}/comm").read_text().strip() == "ssh-budget-wait"
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                if reached:
                    break
                time.sleep(.005)
            assert reached and not pending.done(), "actual stock identification stage was not observed"
            if stop == "cancel":
                cancelled.set()
            report = pending.result(timeout=10)
        finally:
            cancelled.set()
    assert report["case_passed"] is False and report["metrics"]["useful_completion"] is False
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert len(launchers) == 1 and launchers[0]._closed and launchers[0]._process.poll() is not None
    assert_reaped(observed)
    if stop == "cancel":
        assert report["execution_status"] == "cancelled"
        assert launchers[0].snapshot["executions_reserved"] == 0  # No result acknowledged.
    else:
        result = json.loads((directory / "result.json").read_bytes())
        assert result["status"] == "timeout"
        assert result["boundary_checks"] and all(result["boundary_checks"].values())
        assert 4500 <= result["timing"]["action_elapsed_ms"] <= 6500
        ledger = result["stock_ssh_owner"]["recorder"]
        assert ledger["finalized"] and ledger["active_connections"] == ledger["pending_connections"] == 0
        assert ledger["connections_admitted"] == 1 and ledger["client_bytes_forwarded"] == 0
        assert len(result["stock_ssh_owner"]["instances"]) == 1
        process.validate_receipt(result["stock_ssh_owner"]["instances"][0]["receipt"])
        assert result["stock_ssh_closure"]["processes_reaped"] is True
    assert inspect_trial(directory) == report
    record_property("instrumented_cleanup_stage", stop)
    record_property("actual_stock_identification_observed", True)
    record_property("all_observed_descendants_reaped", True)
