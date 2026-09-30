"""Portable closed-profile and lifecycle tests; kernel evidence is separate."""

import hashlib
import io
import json
import threading
import time

import pytest

from recon_cockpit.secure_agent import assessment_planning_contract as planning
from recon_cockpit.secure_agent import assessment_planning_tls_contract as contract
from recon_cockpit.secure_agent import provider_contract, provider_lab, provider_lab_worker, provider_worker
from recon_cockpit.secure_agent.assessment_planning_transport import LinuxOwnedPlanningTransport
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.openai_protocol import build_request
from test_secure_assessment_planning_contract import candidate, source
from test_secure_provider_worker import CREDENTIAL, Connection, launch


RUN_ID = "a" * 32


def configuration(**changes):
    return {"case": "a", "scenario": "success", "run_id": RUN_ID, **changes}


@pytest.mark.parametrize("case", tuple("abcdef"))
@pytest.mark.parametrize("step", (1, 2, 3))
@pytest.mark.parametrize("owned_lab", (False, True))
def test_tls_profile_exactly_matches_reviewed_mock_release(case, step, owned_lab):
    released = planning.release_observation(case, candidate(case, step, owned_lab=owned_lab),
                                           source(step, body="private body must stay local"))
    raw = contract.canonical_request(case, step, owned_lab=owned_lab)
    assert raw == build_request(planning.CONFIG, released)
    assert contract.request_details(raw, case=case) == {"case": case, "step": step, "owned_lab": owned_lab}
    with pytest.raises(provider_contract.ProviderError, match="provider_invalid_request"):
        provider_contract.validate_request(raw)
    response = contract.response_body(raw, configuration(case=case))
    assert response == planning.replies(case, run_id=RUN_ID)[step - 1].body


@pytest.mark.parametrize("scenario", tuple(set(planning.SCENARIOS) - {"malformed", "slow", "http_error"}))
def test_owned_usage_and_proposal_fixtures_preserve_mock_meanings(scenario):
    body = contract.response_body(contract.canonical_request("a", 1), configuration(scenario=scenario))
    assert body == planning.replies("a", scenario, run_id=RUN_ID)[0].body


@pytest.mark.parametrize("mutation", ["raw_body", "rationale", "model", "target", "card", "case",
                                     "extra", "whitespace", "duplicate", "legacy", "type"])
def test_wire_release_rejects_every_unreviewed_byte(mutation):
    raw = contract.canonical_request("a", 1)
    value = json.loads(raw)
    if mutation in {"raw_body", "rationale", "target", "card", "case"}:
        observation = json.loads(value["input"][1]["content"][0]["text"])
        descriptor = json.loads(observation["untrusted_observation"]["body"])
        if mutation == "raw_body":
            descriptor["private_response"] = "body-canary"
        elif mutation == "rationale":
            descriptor["candidate"]["action"]["rationale"] = "secret"
        elif mutation == "target":
            descriptor["candidate"]["action"]["target"] = "203.0.113.99"
        elif mutation == "card":
            descriptor["workflow_card"]["sha256"] = "a" * 64
        else:
            descriptor["case"] = "b"
        observation["untrusted_observation"]["body"] = planning.encode(descriptor).decode()
        value["input"][1]["content"][0]["text"] = planning.encode(observation).decode()
        raw = planning.encode(value)
    elif mutation == "model":
        value["model"] = "real-model"
        raw = planning.encode(value)
    elif mutation == "extra":
        value["url"] = "https://example.invalid"
        raw = planning.encode(value)
    elif mutation == "whitespace":
        raw += b" "
    elif mutation == "duplicate":
        raw = b'{"model":"other",' + raw[1:]
    elif mutation == "legacy":
        raw = provider_contract.build_request(b'{"step":1,"untrusted_observation":null}')
    else:
        raw = bytearray(raw)
    with pytest.raises(ValueError, match="planning_transport_invalid_request"):
        contract.request_details(raw, case="a")


@pytest.mark.parametrize("changes", [dict(case="z"), dict(case=True), dict(scenario="live"),
    dict(run_id="fixture"), dict(run_id="b" * 33), dict(run_id=True), dict(url="http://external")])
def test_configuration_has_no_live_or_arbitrary_endpoint_escape(changes):
    with pytest.raises(ValueError, match="planning_transport_invalid_configuration"):
        contract.context(configuration(**changes))


def test_new_worker_and_owner_profiles_cannot_be_selected_through_old_entrypoints():
    data = launch()
    request = contract.canonical_request("a", 1)
    data.update(request=request.decode(), planning=configuration(), planning_request_digest=hashlib.sha256(request).hexdigest())
    raw = planning.encode(data)
    digest = hashlib.sha256(raw).hexdigest()
    assert provider_worker.validate_launch(raw, digest, planning=True) == data
    with pytest.raises(ValueError, match="provider_invalid_launch"):
        provider_worker.validate_launch(raw, digest)
    owner = {"scenario": "success", "credential": data["credential"], "host_namespaces": data["host_namespaces"],
             "deadline": time.monotonic() + 30, "planning": configuration(),
             "planning_request_digest": data["planning_request_digest"]}
    raw = planning.encode(owner) + b"\n"
    assert provider_lab_worker.read_request(io.BytesIO(raw), planning=True) == owner
    with pytest.raises(ValueError, match="invalid_provider_owner_request"):
        provider_lab_worker.read_request(io.BytesIO(raw))


@pytest.mark.parametrize("step,owned_lab", [(1, False), (2, False), (1, True)])
def test_server_and_worker_bind_selected_request_not_just_allowlisted_case(step, owned_lab):
    selected = contract.canonical_request("a", 1)
    request = contract.canonical_request("a", step, owned_lab=owned_lab)
    expected = hashlib.sha256(selected).hexdigest()
    wire = (f"POST /v1/responses HTTP/1.1\r\nHost: provider.owned.invalid:8443\r\n"
            f"Authorization: Bearer {CREDENTIAL}\r\nContent-Type: application/json\r\n"
            f"Accept: application/json\r\nConnection: close\r\nContent-Length: {len(request)}\r\n\r\n"
            ).encode() + request
    data = {**launch(), "request": request.decode(), "planning": configuration(), "planning_request_digest": expected}
    raw = planning.encode(data)
    calls = (
        lambda: provider_lab_worker._http_request(Connection(wire), CREDENTIAL,
                    planning=configuration(), request_digest=expected),
        lambda: provider_worker.validate_launch(raw, hashlib.sha256(raw).hexdigest(), planning=True),
    )
    for call in calls:
        if request == selected:
            call()
        else:
            with pytest.raises(ValueError, match="planning_transport_request_mismatch"):
                call()


def test_transport_configuration_and_construction_are_inert(monkeypatch):
    monkeypatch.setattr(provider_lab.tempfile, "TemporaryDirectory", lambda **_: pytest.fail("construction I/O"))
    transport = LinuxOwnedPlanningTransport("a", run_id=RUN_ID)
    assert (transport.case, transport.scenario, transport.run_id, transport.last_receipt) == ("a", "success", RUN_ID, None)
    for field in ("case", "scenario", "run_id"):
        with pytest.raises(AttributeError):
            setattr(transport, field, "other")


@pytest.fixture
def runtime(monkeypatch):
    calls = []
    def exchange(self, request, *, control, context_digest, planning):
        calls.append((request, control, context_digest, planning, self.scenario))
        self._last_receipt = {"status": "ok"}
        return {"body": b"owned", "receipt": self.last_receipt}
    monkeypatch.setattr(provider_lab.LinuxOwnedProviderTransport, "_exchange_profile", exchange)
    return calls


def test_transport_accepts_only_three_ordered_calls_and_applies_scenario_once(runtime):
    transport = LinuxOwnedPlanningTransport("a", "refusal", run_id=RUN_ID)
    control = ExecutionControl(time.monotonic() + 30)
    for step in (1, 2, 3):
        transport.exchange(contract.canonical_request("a", step), control=control, context_digest="b" * 64)
    assert [item[3]["scenario"] for item in runtime] == ["refusal", "success", "success"]
    assert all(item[1] is control for item in runtime)
    receipt = transport.last_receipt
    receipt["status"] = "changed"
    assert transport.last_receipt == {"status": "ok"}
    with pytest.raises(RuntimeError, match="planning_transport_closed"):
        transport.exchange(contract.canonical_request("a", 3), control=control, context_digest="b" * 64)
    assert len(runtime) == 3


@pytest.mark.parametrize("change", ["repeat", "skip", "case", "backend", "control", "deadline"])
def test_invalid_followup_permanently_closes_without_another_exchange(runtime, change):
    transport = LinuxOwnedPlanningTransport("a", run_id=RUN_ID)
    control = ExecutionControl(time.monotonic() + 30)
    transport.exchange(contract.canonical_request("a", 1), control=control, context_digest="b" * 64)
    raw = contract.canonical_request("a", 1 if change == "repeat" else 3 if change == "skip" else 2,
                                     owned_lab=change == "backend")
    if change == "case":
        raw = contract.canonical_request("b", 2)
    if change == "control":
        control = ExecutionControl(control.deadline)
    if change == "deadline":
        object.__setattr__(control, "deadline", control.deadline + 1)
    with pytest.raises(ValueError):
        transport.exchange(raw, control=control, context_digest="b" * 64)
    with pytest.raises(RuntimeError, match="planning_transport_closed"):
        transport.exchange(raw, control=control, context_digest="b" * 64)
    assert len(runtime) == 1


@pytest.mark.parametrize("control", [None, ExecutionControl(200, clock=lambda: 100),
                                     ExecutionControl(time.monotonic() - 1)])
def test_invalid_or_expired_control_prevents_runtime(runtime, control):
    with pytest.raises((ValueError, ExecutionStopped)):
        LinuxOwnedPlanningTransport("a", run_id=RUN_ID).exchange(
            contract.canonical_request("a", 1), control=control, context_digest="b" * 64)
    assert not runtime


def test_followup_cancellation_never_reuses_previous_success_receipt(runtime):
    stopped = threading.Event()
    control = ExecutionControl(time.monotonic() + 30, cancelled=stopped)
    transport = LinuxOwnedPlanningTransport("a", run_id=RUN_ID)
    transport.exchange(contract.canonical_request("a", 1), control=control, context_digest="b" * 64)
    assert transport.last_receipt == {"status": "ok"}
    stopped.set()
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        transport.exchange(contract.canonical_request("a", 2), control=control, context_digest="c" * 64)
    assert transport.last_receipt is None and len(runtime) == 1


def test_runtime_failure_closes_transport_and_leaves_cleanup_receipt(monkeypatch):
    transport = LinuxOwnedPlanningTransport("a", run_id=RUN_ID)
    monkeypatch.setattr(provider_lab.LinuxFixtureBackend, "check_available", lambda self: (_ for _ in ()).throw(OSError("private")))
    control = ExecutionControl(time.monotonic() + 30)
    with pytest.raises(provider_contract.ProviderError, match="provider_transport_failed"):
        transport.exchange(contract.canonical_request("a", 1), control=control, context_digest="b" * 64)
    assert transport.last_receipt["cleanup"] == {"owner_reaped": True, "worker_reaped": True}
    with pytest.raises(RuntimeError, match="planning_transport_closed"):
        transport.exchange(contract.canonical_request("a", 1), control=control, context_digest="b" * 64)
