"""Explicit codec profile and verified rejection envelopes, with unit doubles."""

import json
import time

import pytest

from recon_cockpit.secure_agent import broker_ipc, openai_isolation
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_isolation import LinuxOpenAIPlanner
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES
from recon_cockpit.secure_agent import web_model_contract as contract
from recon_cockpit.secure_agent.web_assessment_contract import action


def envelope(**changes):
    return {"schema_version": "1", "profile": contract.WEB_MODEL_PROFILE, "output_status": "proposal",
        "proposal": {"schema_version": "1", "action": action("vulnerable", 1), "done": False},
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), **changes}


@pytest.fixture
def codec(monkeypatch):
    planner = LinuxOpenAIPlanner(profile=contract.WEB_MODEL_PROFILE)
    state = {"envelope": envelope(), "calls": []}
    monkeypatch.setattr(planner, "check_available", lambda: None)
    monkeypatch.setattr(planner, "_command", lambda *_: ["fixed-web-model-codec"])
    monkeypatch.setattr(openai_isolation, "_runtime_files", lambda *_a, **_k: ("stdlib", []))
    def supervise(argv, init, exchange, *, control):
        state["calls"].append(json.loads(init))
        return contract.encode(state["envelope"])
    monkeypatch.setattr(broker_ipc, "supervise", supervise)
    return planner, state


def plan(planner):
    return planner.plan(contract.CONFIG, contract.encode({"step": 1, "untrusted_observation": None}),
                        lambda *_a, **_k: pytest.fail("unit supervisor does not call provider"),
                        control=ExecutionControl(time.monotonic() + 10))


def test_web_codec_initialization_and_success_are_explicitly_profile_bound(codec):
    planner, state = codec
    assert json.loads(plan(planner)) == state["envelope"]["proposal"]
    assert state["calls"] == [{"schema_version": "1", "profile": contract.WEB_MODEL_PROFILE,
        "config": {"model": contract.MODEL, "max_output_tokens": 1024},
        "observation": {"step": 1, "untrusted_observation": None}}]
    assert planner.last_error is None
    assert all(planner.boundary_checks.values())


def test_verified_output_rejection_is_distinct_from_sandbox_failure(codec):
    planner, state = codec
    state["envelope"] = envelope(proposal=None, output_status="invalid")
    with pytest.raises(IsolationUnavailable):
        plan(planner)
    assert planner.last_error == "output_invalid"
    assert all(planner.boundary_checks.values())


@pytest.mark.parametrize("changes", [
    {"profile": "legacy-v1"}, {"boundary_checks": {}},
    {"boundary_checks": dict.fromkeys(BOUNDARY_NAMES, 1)}, {"output_status": "refusal"},
    {"proposal": None}, {"extra": True},
])
def test_unverified_parser_envelope_is_not_misreported_as_model_invalid(codec, changes):
    planner, state = codec
    state["envelope"] = envelope(**changes)
    with pytest.raises(IsolationUnavailable):
        plan(planner)
    assert planner.last_error == "isolation_unavailable"
    assert planner.boundary_checks is None


def test_new_profile_adds_only_the_pure_contract_to_existing_fixed_mounts(monkeypatch):
    monkeypatch.setattr(openai_isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(openai_isolation, "_namespaces", lambda: dict.fromkeys(("user", "net", "mnt", "pid"), "ns:[100]"))
    def mounts(profile=None):
        planner = LinuxOpenAIPlanner() if profile is None else LinuxOpenAIPlanner(profile=profile)
        argv = planner._command("/usr/lib/python3.14", [])
        return {argv[i + 2] for i, word in enumerate(argv) if word == "--ro-bind"}
    assert mounts(contract.WEB_MODEL_PROFILE) - mounts() == {"/app/recon_cockpit/secure_agent/web_model_contract.py"}


@pytest.mark.parametrize("profile", [None, [], "unreviewed", "owned-nmap-http-v1"])
def test_unreviewed_codec_profiles_refuse(profile):
    with pytest.raises(ValueError, match="invalid_openai_profile"):
        LinuxOpenAIPlanner(profile=profile)
