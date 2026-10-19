"""26 owned lifecycle gates using real clocks and only pinned descendant PIDs.

Finite test source variants pause at topology setup or after recorder ARM;
their exact bytes are included in the ordinary sealed runtime source manifest.
No production hook, extra descriptor, target, grant or replacement clock exists.
"""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import os
from pathlib import Path
import select
import signal
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from test_name_tls_linux import NativeSession
from test_secure_fixture_launcher_linux import descendants
from test_secure_owned_launcher_linux import assert_reaped
from name_tls_native_instrument import variant as _variant

pytestmark = pytest.mark.integration
CASES = ("cancel_before_topology", "cancel_during_topology", "cancel_after_valid_dns_binding",
         "dns/cancel_during_action_and_reap", "http/cancel_during_action_and_reap", "tls/cancel_during_action_and_reap",
         "owner_death_during_action", "launcher_death_during_action", "recorder_channel_death_during_action",
         "daemon_death_during_action", "client_death_during_action", "real_owner_60_second_deadline",
         "abrupt_close_last_ack_distinct_from_graceful_final_snapshot")


@pytest.fixture(autouse=True)
def owned_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned name/TLS lifetime gates")
    assert sys.platform == "linux" and os.geteuid() != 0


def _pause_topology(tmp_path, monkeypatch):
    def transform(source):
        original = "        owned = setup(base, configuration=configuration)"
        assert source.count(original) == 1
        return source.replace(original,
            "        with open('/proc/self/comm', 'w', encoding='ascii') as marker:\n"
            "            marker.write('NTLS-TOPO-PAUSE')\n"
            "        time.sleep(2)\n" + original)
    return [_variant(tmp_path, monkeypatch, "name_tls_topology_worker", transform)]


def _pause_action(tmp_path, monkeypatch, operation):
    def frontend(source):
        original = '                if op == "close":'
        assert source.count(original) == 1
        return source.replace(original,
            f'                if op == "arm" and role == {operation + "_frontend"!r}:\n'
            '                    time.sleep(2)\n' + original)
    variants = [_variant(tmp_path, monkeypatch, "name_tls_frontend_worker", frontend)]
    def launcher(source):
        original = "        with _NestedAdmission(config, init['runtime']) as gate, (owned.lab if owned is not None else nullcontext()):"
        assert source.count(original) == 1
        return source.replace(original,
            "        from recon_cockpit.secure_agent.name_tls_services import Services\n"
            "        ordinary_command = Services._command\n"
            "        def paused_command(self, frontend, operation, **fields):\n"
            "            result = ordinary_command(self, frontend, operation, **fields)\n"
            f"            if operation == 'arm' and self.active['slot'] == {('dns_1' if operation == 'dns' else operation)!r}:\n"
            "                with open('/proc/self/comm', 'w', encoding='ascii') as marker:\n"
            "                    marker.write('NTLS-ARM-PAUSE')\n"
            "                time.sleep(2)\n"
            "            return result\n"
            "        Services._command = paused_command\n" + original)
    variants.append(_variant(tmp_path, monkeypatch, "launcher_worker", launcher))
    return variants


def _pin_tree(process):
    pins, rows = {}, {}
    try:
        for pid in sorted({process.pid, *descendants(process.pid)}):
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            pins[pid] = descriptor
            try:
                directory = Path(f"/proc/{pid}")
                rows[pid] = {"cmdline": [part.decode("ascii", "replace") for part in
                                         directory.joinpath("cmdline").read_bytes().split(b"\0") if part],
                             "comm": directory.joinpath("comm").read_text().strip()}
            except FileNotFoundError:
                rows[pid] = {"cmdline": [], "comm": "exited"}
        assert process.pid in pins
        return pins, rows
    except BaseException:
        for descriptor in pins.values():
            os.close(descriptor)
        raise


def _await_phase(session, pending, marker):
    deadline = min(session.control.deadline, time.monotonic() + 15)
    while time.monotonic() < deadline:
        process = getattr(session.backend, "_process", None)
        if process is not None:
            for pid in {process.pid, *descendants(process.pid)}:
                try:
                    if Path(f"/proc/{pid}/comm").read_text().strip() == marker:
                        pins, rows = _pin_tree(process)
                        assert any(row["comm"] == marker for row in rows.values())
                        return pins, rows
                except FileNotFoundError:
                    continue
        if pending.done():
            pytest.fail("owned operation finished before the instrumented phase: " + repr(pending.result()))
        time.sleep(.005)
    pytest.fail("owned lifecycle phase was not observed")


def _worker(rows, module):
    script = "/app/recon_cockpit/secure_agent/" + module + ".py"
    candidates = [pid for pid, row in rows.items() if row["cmdline"] and row["cmdline"][0] == "/usr/bin/python3"
                  and script in row["cmdline"]]
    assert len(candidates) == 1, (module, rows)
    return candidates[0]


def _target(rows, operation, session):
    if operation == "launcher":
        return session.backend._process.pid
    if operation == "owner":
        return _worker(rows, "name_tls_topology_worker")
    if operation in ("daemon", "client"):
        executable = "/tool/dnsmasq" if operation == "daemon" else "/tool/dig"
        candidates = [pid for pid, row in rows.items() if row["cmdline"] and row["cmdline"][0] == executable]
    else:
        script = "/app/recon_cockpit/secure_agent/name_tls_frontend_worker.py"
        port = contract.public.endpoints(session.selected["configuration"])["resolver"]["port"]
        candidates = []
        for pid, row in rows.items():
            if not row["cmdline"] or row["cmdline"][0] != "/usr/bin/python3" or script not in row["cmdline"]:
                continue
            # Fixed DNS listener distinguishes the active recorder from the
            # two other persistent recorders without trusting process names.
            tcp = Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]
            if any(int(line.split()[1].split(":")[1], 16) == port and line.split()[3] == "0A" for line in tcp):
                candidates.append(pid)
    assert len(candidates) == 1, (operation, candidates, rows)
    return candidates[0]


def _reaped(pins):
    poller = select.poll()
    pending = set(pins.values())
    for descriptor in pending:
        poller.register(descriptor, select.POLLIN)
    deadline = time.monotonic() + 3
    while pending and time.monotonic() < deadline:
        for descriptor, flags in poller.poll(50):
            if flags & select.POLLIN:
                pending.discard(descriptor)
                poller.unregister(descriptor)
    assert not pending, "an owned name/TLS process survived cleanup"
    assert_reaped(set(pins))


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", CASES)
def test_native_lifetime_and_physical_cleanup(tmp_path, monkeypatch, record_property, configuration, case):
    cancelled = threading.Event()
    during = "during_action" in case
    operation = case.split("/")[0] if "/" in case else "dns"
    variants = (_pause_topology(tmp_path, monkeypatch) if case == "cancel_during_topology" else
                _pause_action(tmp_path, monkeypatch, operation) if during else [])
    state = {"schema_version": "1", "gate_id": f"architecture/{configuration}/lifetime_and_physical_cleanup/{case}",
             "source_variants": variants, "test_passed": False, "personal_approval_claimed": False,
             "actual_provider_calls": 0}
    pins = {}
    try:
        with NativeSession(tmp_path / "trial", configuration, "O4", evidence=False,
                           require_approval=False, cancelled=cancelled) as session:
            state["identity"] = session.lab.identity
            state["runtime_sources"] = session.manifest["runtime"]["python_sources"]
            if case == "cancel_before_topology":
                cancelled.set()
                with pytest.raises(ExecutionStopped, match="session_cancelled"):
                    session.submit("dns_1")
                assert not hasattr(session.backend, "_process")
                assert session.close_owner()["last_result"] is None
            elif case == "cancel_during_topology" or during:
                if operation in ("http", "tls"):
                    dns = session.submit("dns_1")
                    assert dns["execution_status"] == "succeeded", dns
                    assert dns["untrusted_result"]["name_tls_ledger"]["binding"] is not None
                before = deepcopy(session.backend._lab_context)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(session.submit, "dns_1" if operation == "dns" else operation)
                    pins, rows = _await_phase(session, pending,
                        "NTLS-TOPO-PAUSE" if case == "cancel_during_topology" else "NTLS-ARM-PAUSE")
                    state["observed_processes"] = rows
                    if "cancel" in case:
                        cancelled.set()
                    else:
                        role = case.split("_death")[0]
                        pid = _target(rows, role, session)
                        state["terminated_role"], state["terminated_pid"] = role, pid
                        signal.pidfd_send_signal(pins[pid], signal.SIGKILL)
                    try:
                        outcome = pending.result(timeout=15)
                    except ExecutionStopped as error:
                        assert "cancel" in case and error.reason == "session_cancelled"
                        state["submission_exception"] = error.reason
                    else:
                        assert outcome["execution_status"] != "succeeded", outcome
                        state["outcome"] = outcome
                closure = session.close_owner()
                assert closure["counters_source"] == "last_acknowledged_result"
                # No invented final delivery is substituted for a lost native
                # acknowledgment; retained completed DNS remains independently useful.
                if before is not None:
                    assert closure["last_result"]["connection_count"] >= before["connection_count"]
                state["closure"] = closure
                _reaped(pins)
            else:
                dns = session.submit("dns_1")
                assert dns["execution_status"] == "succeeded", dns
                result = dns["untrusted_result"]
                assert result["name_tls_ledger"]["binding"] is not None
                before = deepcopy(session.backend._lab_context)
                reservations = dict(session.backend.snapshot)
                pins, rows = _pin_tree(session.backend._process)
                state.update(observed_processes=rows, last_acknowledged_result=result,
                             reservations_before_stop=reservations)
                if case == "cancel_after_valid_dns_binding":
                    cancelled.set()
                    with pytest.raises(ExecutionStopped, match="session_cancelled"):
                        session.submit("http")
                elif case == "real_owner_60_second_deadline":
                    owner = _worker(rows, "name_tls_topology_worker")
                    waited = time.monotonic()
                    while time.monotonic() < session.control.deadline + .1:
                        time.sleep(.05)
                    state["real_waited_ms"] = round((time.monotonic() - waited) * 1000)
                    state["owner_elapsed_ms"] = round((time.monotonic() - (session.control.deadline - 60)) * 1000)
                    poller = select.poll()
                    poller.register(pins[owner], select.POLLIN)
                    assert poller.poll(2000), "owner did not exit at its original real deadline"
                    assert 60000 <= state["owner_elapsed_ms"] <= 63000
                    with pytest.raises(ExecutionStopped, match="session_timeout"):
                        session.submit("http")
                else:
                    assert case == "abrupt_close_last_ack_distinct_from_graceful_final_snapshot"
                    signal.pidfd_send_signal(pins[session.backend._process.pid], signal.SIGKILL)
                    session.backend._process.wait(timeout=3)
                closure = session.close_owner()
                assert closure == {"identity": session.lab.identity, "status": "closed",
                    "launcher_cleanup_verified": True, "counters_source": "last_acknowledged_result", "last_result": before}
                assert dict(session.backend.snapshot) == reservations
                assert session.backend.close() == closure
                with pytest.raises(IsolationUnavailable):
                    session.backend.run(parse_action(session.action("http")), session.policy,
                                        control=ExecutionControl(time.monotonic() + 5))
                assert dict(session.backend.snapshot) == reservations
                state["closure"] = closure
                _reaped(pins)
            state["test_passed"] = True
            record_property("gate_id", state["gate_id"])
            record_property("case_passed", True)
    finally:
        for descriptor in pins.values():
            os.close(descriptor)
        with (tmp_path / "lifecycle-observation.json").open("w", encoding="ascii") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(state, stream, sort_keys=True, ensure_ascii=True, allow_nan=False)
