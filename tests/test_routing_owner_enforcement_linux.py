"""Twenty-four pinned probes plus two declared-negative owner-stop regressions.

The test-only private launcher has an independent eighty-second watchdog so it
can observe the unchanged owner's real sixty-second expiry and cleanup.
"""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_ledger as ledger
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import _namespaces
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher

pytestmark = pytest.mark.integration

CASES = (
    "cross_role_spacing", "overlap_concurrency", "aggregate_request_bytes", "aggregate_response_bytes",
    "action_request_bytes", "action_response_bytes", "maximum_output_and_fifth_action", "retained_output_excess",
    "action_deadline", "owner_lifetime", "failed_write_no_refund", "worker_replacement_sequence",
    "changed_selection", "changed_runtime", "changed_action_digest", "wrong_channel_role",
    "message_sequence_replay", "changed_action_sequence", "finished_lease_replay", "channel_continuity_loss",
    "post_terminal_reservation", "bytes_before_kex", "request_replay", "settled_selector_replay",
    "declared_http_negative_stops_owner", "declared_ssh_negative_stops_owner",
)


@pytest.fixture(scope="module")
def owner_probe_runtime():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual isolated routing owner probes")
    assert sys.platform == "linux" and os.geteuid() != 0
    inspected = {}
    def for_profile(profile):
        if profile not in inspected:
            selected = contract.selection(deployment="nginx-A", case_profile=profile)
            control = ExecutionControl(time.monotonic() + 60)
            runtime = contract.inspect_runtime(selected, control)
            # Only reuse the fixed production mount/namespace command construction.
            # No production launcher, witness, tool or daemon execution is replaced.
            launcher = LinuxFixtureLauncher.__new__(LinuxFixtureLauncher)
            launcher._config = {"profile": contract.PROFILE, "case": selected}
            launcher._routing_runtime = runtime
            launcher._witness_source = launcher._approval_source = None
            closure, files = launcher._runtime(control)
            inspected[profile] = launcher, selected, runtime, closure, files
        return inspected[profile]
    return for_profile


def _save(path, data):
    with path.open("wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)


@pytest.mark.parametrize("case", CASES)
def test_native_owner_channel_enforcement(tmp_path, record_property, owner_probe_runtime, case):
    profile = {"declared_http_negative_stops_owner": "http_headers_N1",
               "declared_ssh_negative_stops_owner": "ssh_nmap_N1"}.get(case, "baseline")
    launcher, selected, runtime, closure, files = owner_probe_runtime(profile)
    identity = contract.identity(selected, str(uuid4()), runtime)
    helper = Path(__file__).with_name("routing_owner_probe.py")
    command = launcher._command(closure, files, "instrumented-owner-probe")
    mount_at = command.index("--remount-ro")
    command[mount_at:mount_at] = ["--ro-bind", str(helper), "/routing_owner_probe.py"]
    entry = command.index("/app/recon_cockpit/secure_agent/launcher_worker.py", command.index("--remount-ro"))
    command[entry:] = ["/routing_owner_probe.py", case]
    initial = {"selection": selected, "identity": identity, "runtime": closure,
        "host_namespaces": _namespaces()}
    raw = json.dumps(initial, sort_keys=True, allow_nan=False).encode()
    assert len(raw) <= 131072
    _save(tmp_path / "probe-input.json", raw)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(raw, timeout=80)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=3)
        _save(tmp_path / "probe-stdout.json", stdout)
        _save(tmp_path / "probe-stderr.txt", stderr)
        raise AssertionError("isolated owner probe exceeded independent watchdog") from None
    _save(tmp_path / "probe-stdout.json", stdout)
    _save(tmp_path / "probe-stderr.txt", stderr)
    assert process.returncode == 0, stderr.decode("utf-8", "replace")
    assert len(stdout) <= 524288 and not stderr
    receipt = json.loads(stdout)
    assert receipt["case"] == case and receipt["test_passed"] is True
    assert receipt["selection"] == selected and receipt["identity"] == identity
    assert receipt["daemon_or_native_client_executed"] is False
    assert receipt["claimed_daemon_payload_bytes"] == receipt["actual_provider_calls"] == receipt["actual_cost_microusd"] == 0
    assert receipt["closure"]["owner_exited"] is receipt["closure"]["descriptors_closed"] is True
    assert len(set(receipt["topology"]["networks"].values())) == 5
    for snapshot in receipt["snapshots"]:
        ledger.validate_snapshot(snapshot, selected=selected, identity=identity)
    record_property("case_passed", True)
    record_property("instrumented_owner_probe", case)
    record_property("helper_sha256", hashlib.sha256(helper.read_bytes()).hexdigest())
    record_property("useful_actions_completed", 0)
    record_property("actual_provider_calls", 0)
