"""Committed native launches independently recheck every scoped authority field."""

from copy import deepcopy
import hashlib
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent.configurable_execution import consume_launch
from recon_cockpit.secure_agent.configurable_lab_contract import identity
from recon_cockpit.secure_agent.executor_worker import digest, encode
from recon_cockpit.secure_agent.models import parse_action
from test_secure_configurable_parser import scope
from test_secure_configurable_runtime import manifests

NONCE = "a" * 64
HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}


def envelope(step=1):
    selected = parse_action(contract.action(scope(), step))
    endpoint = contract.ENDPOINTS[step - 1]
    policy = contract.policy_for_scope(scope())
    value = {"mode": contract.PROFILE, "identity": identity(scope(), endpoint, str(UUID(int=step))),
        "namespaces": {name: name + ":[200]" for name in HOST}, "scope": scope(), "endpoint_id": endpoint,
        "launch": {"schema_version": "1", "mode": contract.PROFILE, "execute": True,
            "session_id": str(UUID(int=876)), "nonce": NONCE, "sequence": step,
            "action": selected.to_dict(), "action_digest": selected.digest,
            "policy": policy.to_dict(), "policy_digest": policy.digest,
            "limits": dict(contract.LIMITS), "limits_digest": digest(contract.LIMITS), "deadline": 130,
            "output_reserved_before": contract.OUTPUT_RESERVATIONS[step - 1],
            "output_reserved_after": contract.OUTPUT_RESERVATIONS[step], "host_namespaces": HOST}}
    if step != 2:
        value["runtime"] = manifests()[selected.tool_id]
    return value


def verify(value, *, nonce=NONCE):
    raw = encode(value)
    return consume_launch(raw, nonce, hashlib.sha256(raw).hexdigest(), now=100)


def recommit(value):
    for field in ("action", "policy", "limits"):
        value["launch"][field + "_digest"] = digest(value["launch"][field])


@pytest.mark.parametrize("step", [1, 2, 3, 4])
def test_each_launch_returns_exact_endpoint_and_separately_pinned_runtime(step):
    value = envelope(step)
    request, deadline, namespaces, runtime_digest = verify(value)
    assert request["target"] == value["launch"]["action"]["target"]
    assert request["parameters"] == value["launch"]["action"]["parameters"]
    assert request["scope"] == scope() and request["verify_boundary"] is True
    assert deadline == 130 and namespaces == value["namespaces"]
    assert (runtime_digest is None) == (step == 2)


@pytest.mark.parametrize("step", [1, 2, 3, 4])
@pytest.mark.parametrize("fault", ["outer_mode", "inner_mode", "scope_path", "scope_target", "endpoint", "identity", "instance",
    "namespace", "namespace_type", "namespace_extra", "deadline", "deadline_bool", "execute", "nonce", "session",
    "sequence", "sequence_bool", "before", "after", "policy_deny", "action_target", "action_port", "action_id",
    "timeout", "output", "steps", "lifetime", "aggregate", "limit_bool", "unknown", "launch_unknown"])
def test_fresh_commitments_cannot_authorize_scope_or_execution_expansion(step, fault):
    value = envelope(step)
    launch = value["launch"]
    if fault == "outer_mode": value["mode"] = "owned_service_web_lab"
    elif fault == "inner_mode": launch["mode"] = "service_web_owned"
    elif fault == "scope_path": value["scope"]["http"]["path"] = "/private"
    elif fault == "scope_target": value["scope"]["ssh"]["target"] = "192.168.99.1"
    elif fault == "endpoint": value["endpoint_id"] = "ssh" if value["endpoint_id"] == "http" else "http"
    elif fault == "identity": value["identity"]["scope_sha256"] = "b" * 64
    elif fault == "instance": value["identity"]["instance_id"] = "bad"
    elif fault == "namespace": value["namespaces"]["net"] = HOST["net"]
    elif fault == "namespace_type": value["namespaces"]["net"] = "user:[200]"
    elif fault == "namespace_extra": value["namespaces"]["fd"] = 9
    elif fault == "deadline": launch["deadline"] = 161
    elif fault == "deadline_bool": launch["deadline"] = True
    elif fault == "execute": launch["execute"] = False
    elif fault == "nonce": launch["nonce"] = "b" * 64
    elif fault == "session": launch["session_id"] = "not-a-session"
    elif fault == "sequence": launch["sequence"] = 2 if step == 1 else 1
    elif fault == "sequence_bool": launch["sequence"] = True
    elif fault == "before": launch["output_reserved_before"] += 1
    elif fault == "after": launch["output_reserved_after"] -= 1
    elif fault == "policy_deny": launch["policy"]["allowed_tools"] = []
    elif fault == "action_target":
        launch["action"]["target"] = "192.168.99.99"
        launch["policy"]["allowed_targets"] = ["192.168.0.0/16"]
    elif fault == "action_port":
        launch["action"]["parameters"]["port"] = 4444
        launch["policy"]["allowed_ports"] = [4444]
    elif fault == "action_id": launch["action"]["action_id"] = str(UUID(int=999))
    elif fault == "timeout": launch["action"]["parameters"]["timeout_seconds"] += 1
    elif fault == "output": launch["action"]["parameters"]["max_output_bytes"] -= 1
    elif fault == "steps": launch["limits"]["max_steps"] = 5
    elif fault == "lifetime": launch["limits"]["max_runtime_seconds"] = 61
    elif fault == "aggregate": launch["limits"]["max_output_bytes"] = 26625
    elif fault == "limit_bool": launch["limits"]["max_steps"] = True
    elif fault == "unknown": value["extra"] = True
    else: launch["extra"] = True
    recommit(value)
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("step", [1, 2, 3, 4])
def test_runtime_profile_is_required_only_for_the_selected_native_tool(step):
    value = envelope(step)
    if step == 2: value["runtime"] = manifests()[contract.NMAP]
    else: value["runtime"] = manifests()[contract.SSH if step in (1, 3) else contract.NMAP]
    with pytest.raises(ValueError): verify(value)
    value = envelope(step)
    if step != 2:
        del value["runtime"]
        with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("digest_value", ["b" * 64, "é" * 64, "A" * 64, None, True])
def test_context_commitment_rejects_substitution_and_noncanonical_digest(digest_value):
    raw = encode(envelope())
    with pytest.raises(ValueError): consume_launch(raw, NONCE, digest_value, now=100)


def test_launch_rejects_duplicate_scope_fields_and_oversized_raw_before_decode():
    raw = encode(envelope())
    raw = b'{"mode":"' + contract.PROFILE.encode() + b'",' + raw[1:]
    with pytest.raises(ValueError): consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)
    raw = b" " * 32769
    with pytest.raises(ValueError): consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)
