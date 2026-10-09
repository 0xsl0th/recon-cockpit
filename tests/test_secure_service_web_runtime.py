"""Independent authority, native-runtime projection and closed-profile regressions."""

from copy import deepcopy
import hashlib
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol as protocol
from recon_cockpit.secure_agent import network_tools_runtime as network, web_tools_runtime as web
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.executor_worker import digest, encode
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.service_web_contract import CASES, LIMITS, OUTPUT_RESERVATIONS, TOOL_IDS, action
from recon_cockpit.secure_agent.service_web_execution import consume_launch
from recon_cockpit.secure_agent.service_web_lab_contract import identity
from recon_cockpit.secure_agent.service_web_runtime import project_closure, validate_manifests


def manifest(tool_id):
    runtime = network if tool_id == TOOL_IDS[0] else web
    entries = [(runtime.EXECUTABLES[tool_id], runtime.FIXED_ARGV[tool_id][0], b"data"),
               ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", b"data")]
    entries.extend(network.compiled_files(tool_id) if runtime is network else (web._compiled(tool_id),))
    return {"version": "1", "profile": runtime.PROFILE, "tool_id": tool_id,
            "executable": runtime.FIXED_ARGV[tool_id][0], "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "files": [{"source": src, "destination": dst, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for src, dst, data in sorted(entries, key=lambda row: row[1])]}


def policy():
    return parse_policy({"schema_version": "1", "policy_version": "test-service-web-v1",
        "allowed_targets": ["127.0.0.1"], "allowed_tools": list(TOOL_IDS),
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 10,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": True, "approval_ttl_seconds": 60})


def configuration(case="vulnerable"):
    return {"version": "1", "service_id": str(uuid4()), "session_id": str(uuid4()),
        "policy": policy().to_dict(), "limits": dict(LIMITS), "execute": True,
        "profile": "owned_service_web_lab", "case": case}


def envelope(step=1, case="vulnerable"):
    selected = parse_action(action(case, step))
    host = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    return {"mode": "owned_service_web_lab", "identity": identity(case, str(uuid4())),
        "namespaces": {name: name + ":[200]" for name in host},
        **({"runtime": manifest(selected.tool_id)} if step < 3 else {}),
        "launch": {"schema_version": "1", "mode": "service_web_owned", "execute": True,
            "session_id": str(uuid4()), "nonce": "a" * 64, "sequence": step,
            "action": selected.to_dict(), "action_digest": selected.digest,
            "policy": policy().to_dict(), "policy_digest": policy().digest,
            "limits": dict(LIMITS), "limits_digest": digest(LIMITS), "deadline": 130,
            "output_reserved_before": OUTPUT_RESERVATIONS[step - 1],
            "output_reserved_after": OUTPUT_RESERVATIONS[step], "host_namespaces": host}}


def verify(value, *, expected_tool=None):
    raw = encode(value)
    return consume_launch(raw, "a" * 64, hashlib.sha256(raw).hexdigest(), now=100,
                          expected_tool=expected_tool)


def recommit(value):
    for field in ("action", "policy", "limits"):
        value["launch"][field + "_digest"] = digest(value["launch"][field])


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("step", (1, 2, 3))
def test_each_committed_step_admits_only_its_fixed_capability(case, step):
    value = envelope(step, case)
    request, deadline, namespaces, runtime_digest = verify(value)
    assert request["tool_id"] == TOOL_IDS[step - 1] and deadline == 130
    assert namespaces == value["namespaces"]
    if step == 3:
        assert runtime_digest is None
    else:
        runtime = network if step == 1 else web
        assert runtime_digest == runtime.manifest_digest(value["runtime"])
    assert admission.profile_allows(parse_action(action(case, step)), configuration(case))


@pytest.mark.parametrize("step", (1, 2, 3))
@pytest.mark.parametrize("fault", ("mode", "inner_mode", "identity", "namespace", "host", "deadline", "nan",
    "sequence", "boolean_sequence", "before", "after", "policy", "action", "timeout", "output", "steps", "lifetime", "aggregate", "execute", "nonce", "unknown"))
def test_fresh_commitments_do_not_bypass_authority(step, fault):
    value = envelope(step)
    launch = value["launch"]
    if fault == "mode": value["mode"] = "owned_network_tools_lab"
    elif fault == "inner_mode": launch["mode"] = "network_tools_owned"
    elif fault == "identity": value["identity"]["spec_sha256"] = "b" * 64
    elif fault == "namespace": value["namespaces"] = dict(launch["host_namespaces"])
    elif fault == "host": launch["host_namespaces"]["mnt"] = "not-a-namespace"
    elif fault == "deadline": launch["deadline"] = 161
    elif fault == "nan": launch["deadline"] = None
    elif fault == "sequence": launch["sequence"] = 3 if step == 1 else 1
    elif fault == "boolean_sequence": launch["sequence"] = True
    elif fault == "before": launch["output_reserved_before"] += 1
    elif fault == "after": launch["output_reserved_after"] -= 1
    elif fault == "policy": launch["policy"]["allowed_tools"] = []
    elif fault == "action":
        launch["action"]["target"] = "127.0.0.2"
        launch["policy"]["allowed_targets"] = ["127.0.0.0/8"]
    elif fault == "timeout": launch["action"]["parameters"]["timeout_seconds"] += 1
    elif fault == "output": launch["action"]["parameters"]["max_output_bytes"] -= 1
    elif fault == "steps": launch["limits"]["max_steps"] = 4
    elif fault == "lifetime": launch["limits"]["max_runtime_seconds"] = 61
    elif fault == "aggregate": launch["limits"]["max_output_bytes"] = 18433
    elif fault == "execute": launch["execute"] = False
    elif fault == "nonce": launch["nonce"] = "b" * 64
    else: value["unknown"] = True
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize("step", (1, 2, 3))
def test_worker_projection_rejects_cross_capability_dispatch(step):
    value = envelope(step)
    for wrong in set(TOOL_IDS) - {TOOL_IDS[step - 1]}:
        with pytest.raises(ValueError):
            verify(value, expected_tool=wrong)
    if step == 3:
        value["runtime"] = manifest(TOOL_IDS[0])
    else:
        value["runtime"] = manifest(TOOL_IDS[1 if step == 1 else 0])
    with pytest.raises(ValueError):
        verify(value)


def test_runtime_closure_requires_exact_two_manifests_and_projects_one():
    closure = {"stdlib": "/usr/lib/python3.13", "files": ["/usr/bin/python3", "/usr/bin/bwrap", "/usr/bin/nsenter", "/usr/sbin/nft"],
               "service_web_runtime": {tool_id: manifest(tool_id) for tool_id in TOOL_IDS[:2]}}
    assert protocol.runtime(closure, owned_lab=True, service_web=True) == closure
    for tool_id, key in ((TOOL_IDS[0], "network_tools_runtime"), (TOOL_IDS[1], "web_tools_runtime")):
        projected = project_closure(closure, tool_id)
        assert set(projected) == {"stdlib", "files", key}
        assert projected[key]["tool_id"] == tool_id
        projected[key]["files"][0]["size"] = 1234
        assert closure["service_web_runtime"][tool_id]["files"][0]["size"] != 1234
    for fault in ("missing", "extra", "swapped", "boolean"):
        changed = deepcopy(closure["service_web_runtime"])
        if fault == "missing": del changed[TOOL_IDS[0]]
        elif fault == "extra": changed["http_headers_v1"] = {}
        elif fault == "swapped": changed[TOOL_IDS[0]] = changed[TOOL_IDS[1]]
        else: changed = True
        with pytest.raises(ValueError): validate_manifests(changed)
    with pytest.raises(ValueError): protocol.runtime(closure, owned_lab=True, service_web=True, network_tools=True)


def test_distinct_resource_tag_cannot_be_substituted_for_existing_profile():
    config = configuration()
    assert protocol.runtime_tag(config, {}) == "service-web-launch-preconditions"
    protocol.validate_runtime_tag("service-web-launch-preconditions", config, {})
    for tag in (None, "web-tools-launch-preconditions", "network-tools-launch-preconditions", "launch-preconditions"):
        with pytest.raises(ValueError): protocol.validate_runtime_tag(tag, config, {})
    with pytest.raises(ValueError):
        protocol.validate_runtime_tag("service-web-launch-preconditions", {"profile": "fixture"}, {})


def test_admission_enforces_order_without_reserving_for_wrong_step():
    config = configuration()
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    sequence = 0
    def admit(step):
        nonlocal sequence
        sequence += 1
        return state.handle({"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
            "sequence": sequence, "operation": "admit", "action": action("vulnerable", step),
            "policy_digest": digest(config["policy"])})
    assert admit(2)["reason"] == "admission_profile_denied"
    assert admit(3)["snapshot"] == {"executions_reserved": 0, "output_bytes_reserved": 0}
    for step in (1, 2, 3):
        accepted = admit(step)
        assert accepted["reason"] is None
        assert accepted["snapshot"] == {"executions_reserved": step, "output_bytes_reserved": OUTPUT_RESERVATIONS[step]}
        refused = admit(step)
        assert refused["reason"] in ("admission_profile_denied", "admission_step_limit")
        assert refused["snapshot"] == accepted["snapshot"]
    for field in LIMITS:
        changed = deepcopy(config)
        changed["limits"][field] += 1
        with pytest.raises(ValueError): admission.configuration(changed)


@pytest.mark.parametrize("step", (1, 2, 3))
def test_launcher_rejects_reordered_requests(step):
    config = configuration()
    for wrong in set((1, 2, 3)) - {step}:
        value = {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
            "sequence": step, "operation": "execute", "action": action("vulnerable", wrong),
            "policy_digest": digest(config["policy"])}
        with pytest.raises(ValueError): protocol.request(value, config, step)


def test_existing_native_execution_dispatch_never_accepts_other_workflow_tool():
    from recon_cockpit.secure_agent.network_tools_execution import consume_launch as consume_network
    from recon_cockpit.secure_agent.web_tools_execution import consume_launch as consume_web
    for step in (1, 2):
        value = envelope(step)
        raw = encode(value)
        good, bad = (consume_network, consume_web) if step == 1 else (consume_web, consume_network)
        assert good(raw, "a" * 64, hashlib.sha256(raw).hexdigest(), now=100)[0]["tool_id"] == TOOL_IDS[step - 1]
        with pytest.raises(ValueError): bad(raw, "a" * 64, hashlib.sha256(raw).hexdigest(), now=100)


def test_backend_rejects_missing_predecessor_before_start_or_reservation(monkeypatch):
    from recon_cockpit.secure_agent.service_web_backend import AuthorizedServiceWebBackend
    from recon_cockpit.secure_agent.service_web_lab import ServiceWebLab
    from recon_cockpit.secure_agent.session_limits import SessionLimits
    session_id = str(uuid4())
    limits = SessionLimits(**LIMITS)
    lab = ServiceWebLab("vulnerable", session_id, limits, execute=True)
    backend = AuthorizedServiceWebBackend(policy(), session_id, limits, lab, execute=True)
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected owner start")
    monkeypatch.setattr(lab, "start", forbidden)
    with pytest.raises(IsolationUnavailable, match="predecessor"):
        backend.run(parse_action(action("vulnerable", 2)), policy(), control=ExecutionControl(time.monotonic() + 30))
    assert dict(backend.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
    assert lab.close()["status"] == "closed"


@pytest.mark.parametrize("runtime,tool_id", ((network, TOOL_IDS[0]), (web, TOOL_IDS[1])))
def test_extra_execution_mounts_are_selected_only_for_new_envelope(monkeypatch, runtime, tool_id):
    from types import SimpleNamespace
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    lab = SimpleNamespace(_namespace_fds=(101, 102))
    pinned = manifest(tool_id)
    descriptors = tuple(range(110, 110 + len(pinned["files"])))
    args = (lab, ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]), pinned,
            descriptors, "a" * 64, "b" * 64)
    accepted = runtime._command(*args)
    selected = runtime._command(*args, service_web=True)
    assert not any("service_web" in value for value in accepted)
    assert "/app/recon_cockpit/secure_agent/service_web_execution.py" in selected
    assert accepted[-2:] == selected[-2:]


@pytest.mark.parametrize("step,restriction", [(step, restriction) for step in (1, 2, 3)
    for restriction in ("tools", "targets", "ports", "methods" if step == 3 else "timeout", "output")])
def test_policy_restrictions_are_enforced_by_both_independent_authorities(step, restriction):
    value = envelope(step)
    bound = value["launch"]["policy"]
    if restriction == "tools": bound["allowed_tools"] = []
    elif restriction == "targets": bound["allowed_targets"] = ["192.0.2.1"]
    elif restriction == "ports": bound["allowed_ports"] = [8081]
    elif restriction == "methods": bound["allowed_methods"] = []
    elif restriction == "timeout":
        bound["max_timeout_seconds"] = value["launch"]["action"]["parameters"]["timeout_seconds"] - 1
    else: bound["max_output_bytes"] = value["launch"]["action"]["parameters"]["max_output_bytes"] - 1
    recommit(value)
    with pytest.raises(ValueError, match="policy_denied"):
        verify(value)
    config = configuration()
    config["policy"] = bound
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    refusal = state.handle({"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
        "sequence": 1, "operation": "admit", "action": value["launch"]["action"],
        "policy_digest": digest(bound)})
    assert refusal["reason"] == "admission_policy_denied"
    assert refusal["snapshot"] == {"executions_reserved": 0, "output_bytes_reserved": 0}


def test_backend_cannot_continue_after_inconclusive_predecessor(monkeypatch):
    from recon_cockpit.secure_agent.service_web_backend import AuthorizedServiceWebBackend
    from recon_cockpit.secure_agent.service_web_lab import ServiceWebLab
    from recon_cockpit.secure_agent.session_limits import SessionLimits
    session_id, limits = str(uuid4()), SessionLimits(**LIMITS)
    lab = ServiceWebLab("vulnerable", session_id, limits, execute=True)
    backend = AuthorizedServiceWebBackend(policy(), session_id, limits, lab, execute=True)
    calls = []
    def incomplete(action, policy, *, control):
        calls.append(action.tool_id)
        backend._sequence += 1
        backend._output += action.parameters.max_output_bytes
        return {"status": "failed", "tool_observation": None}
    monkeypatch.setattr(backend, "_run_native", incomplete)
    control = ExecutionControl(time.monotonic() + 30)
    assert backend.run(parse_action(action("vulnerable", 1)), policy(), control=control)["status"] == "failed"
    with pytest.raises(IsolationUnavailable, match="predecessor"):
        backend.run(parse_action(action("vulnerable", 2)), policy(), control=control)
    assert calls == [TOOL_IDS[0]]
    assert dict(backend.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
    assert lab.close()["status"] == "closed"
