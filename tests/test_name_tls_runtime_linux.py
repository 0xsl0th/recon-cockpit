"""Fourteen invalid-claim probes against actual owned descriptors/native images."""

import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent import name_tls_native_runtime as native
from recon_cockpit.secure_agent import name_tls_python_runtime as sources
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import _capture_bounded
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.name_tls_lab import NameTLSLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_name_tls_socket_linux import _helper_snapshot, _save

pytestmark = pytest.mark.integration
GATES = json.loads((Path(__file__).parents[1] / "docs/stage3-name-tls-native-gates.json").read_text())["architecture"]
TOPOLOGY_CASES = {"host_or_other_owner_namespace_rejected", "changed_namespace_uid_mapping_rejected",
                  "listener_endpoint_or_cookie_change_rejected"}
CASES = [row for row in GATES if row["case"] in TOPOLOGY_CASES
         or row["case"].endswith("runtime_inode_or_hash_drift_rejected")]
assert len(CASES) == 14 and len({row["id"] for row in CASES}) == 14


@pytest.fixture(scope="module")
def inspected_native_runtime():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual Name/TLS runtime mutation gates")
    assert sys.platform == "linux" and os.geteuid() != 0
    cache = {}
    def get(configuration):
        if configuration not in cache:
            cache[configuration] = native.inspect_runtime(configuration, "O4", ExecutionControl(time.monotonic() + 15))
        return cache[configuration]
    return get


@pytest.mark.parametrize("gate", CASES, ids=[row["id"] for row in CASES])
def test_live_name_tls_runtime_observation_refuses_injected_claim(gate, inspected_native_runtime, tmp_path, record_property):
    selected = contract.selection(gate["configuration"], "O4")
    runtime = inspected_native_runtime(gate["configuration"])
    session_id = str(uuid4())
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=False)
    metadata = NameTLSLab(selected, session_id, limits, execute=True, runtime=runtime)
    # Only reuse the fixed namespace/mount command builder. This explicitly
    # instrumented helper does not impersonate audit or approval services and
    # never invokes production launcher admission/start methods.
    launcher = LinuxFixtureLauncher.__new__(LinuxFixtureLauncher)
    launcher._config = {"version": "1", "service_id": str(uuid4()), "profile": contract.PROFILE,
        "case": selected, "session_id": session_id, "policy": policy.to_dict(), "limits": asdict(limits),
        "execute": True, "owned_lab": metadata.identity}
    launcher._name_tls_runtime = runtime
    launcher._witness_source = launcher._approval_source = None
    control = ExecutionControl(time.monotonic() + 75)
    closure, files = launcher._runtime(control)
    descriptors = sources.snapshot_sources(runtime, tuple(sources.DESTINATIONS), control)
    helper = Path(__file__).with_name("name_tls_runtime_probe.py").read_bytes()
    helper_fd = _helper_snapshot(helper)
    argv = launcher._command(closure, files, "instrumented-name-tls-runtime", source_descriptors=descriptors)
    mount = argv.index("--remount-ro")
    argv[mount:mount] = ["--perms", "0444", "--ro-bind-data", str(helper_fd), "/name_tls_runtime_probe.py"]
    entry = argv.index("/app/recon_cockpit/secure_agent/launcher_worker.py", argv.index("--remount-ro"))
    argv[entry:] = ["/name_tls_runtime_probe.py"]
    raw = json.dumps({"config": launcher._config, "closure": closure, "gate": gate}, sort_keys=True).encode("ascii")
    assert len(raw) <= 262144
    _save(tmp_path / "probe-input.json", raw)
    try:
        code, stdout, stderr, reason = _capture_bounded(argv, raw, 70, 524288, control=control,
            pass_fds=(*descriptors.values(), helper_fd))
    finally:
        for descriptor in (*descriptors.values(), helper_fd): os.close(descriptor)
    _save(tmp_path / "probe-stdout.json", stdout)
    _save(tmp_path / "probe-stderr.txt", stderr)
    assert reason is None and code == 0 and not stderr, (reason, code, stderr.decode("utf-8", "replace"))
    receipt = json.loads(stdout)
    assert receipt["gate_id"] == gate["id"] and receipt["case_passed"] is True
    assert len(receipt["production_native_operations"]) == 3 and receipt["refusals"]
    assert receipt["closure"]["topology"]["owner_exited"] is True
    receipt.update(helper_sha256=hashlib.sha256(helper).hexdigest(), runtime_sha256=native.runtime_digest(runtime),
                   independent_watchdog_seconds=70)
    _save(tmp_path / "gate-receipt.json", json.dumps(receipt, sort_keys=True).encode("ascii"))
    record_property("gate_id", gate["id"])
    record_property("case_passed", True)
    record_property("helper_sha256", receipt["helper_sha256"])
    record_property("actual_provider_calls", 0)
