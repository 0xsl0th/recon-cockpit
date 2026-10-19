"""Portable authority/state tests; these make no native execution claim."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent import name_tls_public as public
from recon_cockpit.secure_agent import name_tls_ledger as ledger_module
from recon_cockpit.secure_agent import name_tls_spec as preparation
from recon_cockpit.secure_agent import launch_admission
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.tool_adapters import ADAPTERS, NAME_TLS_CANDIDATES

SESSION = "00000000-0000-0000-0000-000000000001"
OWNER = "00000000-0000-0000-0000-000000000002"
ROOT = Path(__file__).resolve().parents[1]


def setup(case="O4", configuration="A", order="default"):
    selected = contract.selection(configuration, case, order)
    owner = contract.identity(selected, SESSION, "a" * 64, owner_id=OWNER)
    return selected, owner


def semantic(configuration="A", ttl=60, address=None):
    return {"schema_version": "1", "question": {"name": public.DNS_NAME, "class": 1, "type": 1},
            "transaction_id": 1234, "flags": 0x8400,
            "records": [{"section": "answer", "name": public.DNS_NAME, "type": 1, "class": 1,
                         "ttl": ttl, "data": address or public.endpoints(configuration)["http"]["target"]}]}


class Harness:
    def __init__(self, case="O4", configuration="A", order="default"):
        self.selected, self.identity = setup(case, configuration, order)
        self.clock = 0.0
        self.ledger = ledger_module.Ledger(self.selected, self.identity, started_at=0, clock=lambda: self.clock)
        self.sequences = dict.fromkeys(ledger_module.ROLES, 0)
        self.action = None
        self.action_sequence = 0
        self.messages = []
        self.lease = None

    def send(self, operation, role="launcher", **extras):
        self.sequences[role] += 1
        message = {"operation": operation, "sequence": self.sequences[role],
                   "action_sequence": self.action_sequence,
                   "action_digest": contract.digest(self.action or self.selected),
                   "owner_identity_sha256": self.identity["owner_identity_sha256"], **extras}
        reply = self.ledger.apply(message, role=role)
        ledger_module.validate_reply(reply, message, role=role)
        self.messages.append({"role": role, "message": deepcopy(message), "reply": deepcopy(reply)})
        return reply

    def arm(self, slot):
        self.action_sequence += 1
        self.action = (contract.dns_action(self.selected, self.identity, slot) if slot.startswith("dns_") else
                       contract.service_action(self.selected, self.identity, slot, self.ledger.snapshot()["binding"]))
        return self.send("ARM", slot=slot, action=self.action)

    def connection(self):
        slot = self.action["parameters"]["operation_slot"]
        role = contract.selector_role(slot)
        reply = self.send("RESERVE_CONNECTION", role, local_id=1)
        if reply["status"] == "ok":
            self.lease = reply["lease"]
        return reply

    def reserve(self, op=None, request=40, response=80):
        slot = self.action["parameters"]["operation_slot"]
        role = contract.selector_role(slot)
        assert self.send("RESERVE_OPERATION", role, lease=self.lease, kind=op or contract.operation(slot))["status"] == "ok"
        for direction, count in (("request", request), ("response", response)):
            assert self.send("RESERVE_BYTES", role, lease=self.lease, direction=direction, bytes=count)["status"] == "ok"

    def finish_connection(self, request=40, response=80):
        return self.send("FINISH_CONNECTION", contract.selector_role(self.action["parameters"]["operation_slot"]),
                         lease=self.lease, delivered_request_bytes=request, delivered_response_bytes=response,
                         transcript_sha256="c" * 64)

    def finish(self, observation=None, success=True, output=100):
        return self.send("FINISH_ACTION", output_bytes=output, native_success=success,
                         observation=observation, parsed_result_sha256="d" * 64, native_result_sha256="e" * 64)

    def dns(self, slot="dns_1", answer=None):
        assert self.arm(slot)["status"] == "ok"
        assert self.connection()["status"] == "ok"
        self.reserve()
        answer = answer or semantic(self.selected["configuration"], 1 if self.selected["case"] == "N14" else 60)
        assert self.send("OBSERVE_DNS", "dns_frontend", lease=self.lease, semantic=answer,
                         request_sha256="1" * 64, original_answer_sha256="2" * 64,
                         delivered_answer_sha256="3" * 64, response_bytes=80)["status"] == "ok"
        assert self.ledger.snapshot()["binding"] is None
        assert self.finish_connection()["status"] == "ok"
        return self.finish(answer)


@pytest.mark.parametrize("configuration,case", preparation.TRIALS)
def test_key_free_public_constants_match_all_prepared_selections(configuration, case):
    assert public.endpoints(configuration) == preparation.endpoints(configuration)
    assert public.request_bytes(configuration, case) == preparation.request_bytes(configuration, case)
    assert public.dns_argv(configuration, case) == preparation.dns_argv(configuration, case)
    assert public.tls_argv(configuration, case) == preparation.tls_argv(configuration, case)
    assert public.PREPARATION_DIGESTS[configuration + "/" + case] == preparation.selection_digest(configuration, case)
    assert contract.validate_selection(contract.selection(configuration, case))["case"] == case


def test_contract_pins_preparation_full_native_contract_and_inventory():
    assert hashlib.sha256((ROOT / "docs/stage3-name-tls-native.md").read_bytes()).hexdigest() == public.NATIVE_CONTRACT_SHA256
    assert hashlib.sha256((ROOT / "docs/stage3-name-tls-native-gates.json").read_bytes()).hexdigest() == public.NATIVE_GATES_SHA256
    assert hashlib.sha256(preparation.TLS_CERTIFICATE_CA_PEM).hexdigest() == public.PUBLIC_CA_SHA256


def test_public_and_contract_imports_never_load_fixture_server_key_modules():
    script = """
import sys
sys.path.insert(0, sys.argv[1])
from recon_cockpit.secure_agent import name_tls_public, name_tls_contract
assert not any('network_tools_fixture' in name or 'certificate_material' in name or name.endswith('name_tls_spec') for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script, str(ROOT)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_all_52_accepted_adapter_descriptors_are_byte_identical():
    old = {key: value.to_dict() for key, value in ADAPTERS.items() if key not in NAME_TLS_CANDIDATES}
    assert len(old) == 52
    raw = json.dumps(old, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(raw).hexdigest() == "832de08fd51a31161cb70217d6235417b6cfaedfe791d246e7f3d174b6290b03"


@pytest.mark.parametrize("field,value", [("owner_id", "invalid"), ("session_id", "invalid"),
    ("selection_sha256", "a" * 63), ("runtime_identity_sha256", "G" * 64),
    ("owner_identity_sha256", None), ("port", True), ("timeout_seconds", 4),
    ("max_output_bytes", 8193), ("configuration", "C"), ("case", "N17"),
    ("operation_slot", "dns_2"), ("question_name", "other.harbordesk.test."),
    ("question_class", "CH"), ("question_type", "AAAA")])
def test_strict_dns_parameters_cannot_expand_scope(field, value):
    selected, owner = setup()
    action = contract.dns_action(selected, owner)
    action["parameters"][field] = value
    with pytest.raises(ValueError):
        parse_action(action)


@pytest.mark.parametrize("slot", ["http", "tls"])
def test_service_approval_parameters_literally_include_live_binding_commitments(slot):
    h = Harness()
    h.dns()
    binding = h.ledger.snapshot()["binding"]
    action = contract.service_action(h.selected, h.identity, slot, binding)
    parsed = parse_action(action)
    assert contract.validate_action(parsed, h.selected, h.identity, binding) == action
    from recon_cockpit.secure_agent.graphical_approval_view import review_text
    review = review_text(parsed, contract.policy_for_selection(h.selected), SESSION)
    for field in ("session_id", "owner_id", "owner_identity_sha256", "runtime_identity_sha256",
                  "selection_sha256", "binding_sha256", "observation_sha256", "observed_answer_sha256",
                  "observed_ttl_seconds", "observed_at_us", "expires_at_us", "canonical_name"):
        assert field in review and str(action["parameters"][field]) in review
    assert ("host" if slot == "http" else "sni") in review
    assert "rationale" not in action["parameters"]


def test_admission_checks_selected_static_scope_and_session_without_minting_live_binding():
    h = Harness()
    action = parse_action(contract.dns_action(h.selected, h.identity))
    config = {"version": "1", "service_id": OWNER, "session_id": SESSION,
              "policy": contract.policy_for_selection(h.selected).to_dict(), "limits": contract.limits(h.selected),
              "execute": True, "profile": contract.PROFILE, "case": h.selected}
    assert launch_admission.configuration(config) == config
    assert launch_admission.profile_allows(action, config)
    assert h.ledger.snapshot()["binding"] is None and h.ledger.snapshot()["counters"]["actions"] == 0
    config["session_id"] = OWNER
    assert not launch_admission.profile_allows(action, config)


@pytest.mark.parametrize("configuration", ["A", "B"])
@pytest.mark.parametrize("order", ["default", "tls_first"])
def test_owner_requires_separate_arm_and_preserves_aggregate_across_three_operations(configuration, order):
    h = Harness(configuration=configuration, order=order)
    assert h.dns()["binding"] is not None
    for slot in contract.operation_plan(h.selected)[1:]:
        h.clock += 0.3
        assert h.arm(slot)["status"] == "ok"
        assert h.connection()["status"] == "ok"
        h.reserve()
        h.finish_connection()
        assert h.finish()["status"] == "ok"
    snapshot = h.ledger.snapshot()
    assert snapshot["terminal"] and snapshot["terminal_reason"] == "completed"
    assert snapshot["counters"] == {"actions": 3, "connections": 3, "dns_queries": 1,
        "http_requests": 1, "tls_handshakes": 1, "request_bytes": 120, "response_bytes": 240,
        "output_bytes": 18432}
    assert ledger_module.validate_snapshot(snapshot, messages=h.messages) == snapshot


def test_changed_second_dns_invalidates_earlier_binding_at_arm_even_before_new_answer():
    h = Harness(case="N1")
    h.dns()
    previous = h.ledger.snapshot()["binding"]
    stale = contract.service_action(h.selected, h.identity, "http", previous)
    h.clock = 0.3
    assert h.arm("dns_2")["status"] == "ok"
    assert h.ledger.snapshot()["binding"] is None
    with pytest.raises(ValueError):
        contract.validate_action(stale, h.selected, h.identity, h.ledger.snapshot()["binding"])
    assert h.ledger.snapshot()["observation_generation"] == 2


def test_negative_tls_dns_prerequisite_does_not_stop_before_tls():
    h = Harness(case="N11")
    h.dns()
    assert not h.ledger.terminal
    h.clock = 0.3
    assert h.arm("tls")["status"] == "ok"
    h.connection()
    h.reserve()
    h.finish_connection()
    assert h.finish(success=False)["status"] == "ok"
    assert h.ledger.snapshot()["terminal_reason"] == "declared_negative_completed"


def test_owner_generated_ttl_expiry_is_rechecked_before_service_plan_admission():
    h = Harness(case="N14")
    h.dns()
    assert h.ledger.snapshot()["binding"]["expires_at_us"] == 1000000
    h.clock = 1.01
    reply = h.arm("http")
    assert reply["status"] == "denied" and reply["reason"] == "binding_expired"
    assert h.ledger.snapshot()["counters"]["connections"] == 1


def test_binding_cannot_come_from_native_parser_without_independent_recorded_dns():
    h = Harness()
    h.arm("dns_1")
    h.connection()
    h.reserve()
    h.finish_connection()
    reply = h.finish(semantic())
    assert reply["status"] == "denied" and reply["reason"] == "dns_native_wire_disagreement"
    assert h.ledger.snapshot()["binding"] is None


@pytest.mark.parametrize("mutation", ["answer", "ttl", "id", "flags"])
def test_native_and_independent_dns_observations_must_match_exactly(mutation):
    h = Harness()
    h.arm("dns_1")
    h.connection()
    h.reserve()
    answer = semantic()
    h.send("OBSERVE_DNS", "dns_frontend", lease=h.lease, semantic=answer,
           request_sha256="1"*64, original_answer_sha256="2"*64,
           delivered_answer_sha256="3"*64, response_bytes=80)
    h.finish_connection()
    if mutation == "answer":
        answer["records"][0]["data"] = "10.77.0.99"
    elif mutation == "ttl":
        answer["records"][0]["ttl"] = 59
    elif mutation == "id":
        answer["transaction_id"] += 1
    else:
        answer["flags"] ^= 128
    assert h.finish(answer)["reason"] == "dns_native_wire_disagreement"
    assert h.ledger.snapshot()["binding"] is None


def test_short_delivery_does_not_create_binding_or_refund_reservations():
    h = Harness()
    h.arm("dns_1")
    h.connection()
    h.reserve()
    answer = semantic()
    h.send("OBSERVE_DNS", "dns_frontend", lease=h.lease, semantic=answer,
           request_sha256="1"*64, original_answer_sha256="2"*64,
           delivered_answer_sha256="3"*64, response_bytes=80)
    h.finish_connection(response=79)
    assert h.finish(answer)["reason"] == "dns_delivery_incomplete"
    assert h.ledger.snapshot()["counters"]["response_bytes"] == 80
    assert h.ledger.snapshot()["binding"] is None


def test_channel_role_and_sequence_are_not_caller_selected_or_replayable():
    h = Harness()
    h.arm("dns_1")
    reply = h.send("RESERVE_CONNECTION", "http_frontend", local_id=1)
    assert reply["reason"] == "action_role_changed"
    assert h.ledger.snapshot()["counters"]["connections"] == 0
    h = Harness()
    h.arm("dns_1")
    message = h.messages[0]["message"]
    reply = h.ledger.apply(message, role="launcher")
    assert reply["reason"] == "message_sequence_changed"
    assert h.ledger.snapshot()["counters"]["actions"] == 1


def test_cross_operation_spacing_wait_preserves_owner_counters():
    h = Harness()
    h.dns()
    h.arm("http")
    before = h.ledger.snapshot()["counters"]
    reply = h.connection()
    assert reply["status"] == "wait" and reply["retry_after_ms"] == 250
    assert h.ledger.snapshot()["counters"] == before
    h.clock = 0.25
    assert h.connection()["status"] == "ok"


@pytest.mark.parametrize("direction,cap", [("request", 512), ("response", 4096)])
def test_reserved_bytes_are_charged_before_delivery_and_overflow_is_refused(direction, cap):
    h = Harness()
    h.arm("dns_1")
    h.connection()
    h.send("RESERVE_OPERATION", "dns_frontend", lease=h.lease, kind="dns")
    assert h.send("RESERVE_BYTES", "dns_frontend", lease=h.lease, direction=direction, bytes=cap)["status"] == "ok"
    assert h.ledger.snapshot()["active_connection"]["delivered_" + direction + "_bytes"] is None
    reply = h.send("RESERVE_BYTES", "dns_frontend", lease=h.lease, direction=direction, bytes=1)
    assert reply["reason"] == "action_" + direction + "_bytes_limit"
    assert h.ledger.snapshot()["counters"][direction + "_bytes"] == cap
    h.finish_connection(request=0, response=0)
    assert h.ledger.snapshot()["counters"][direction + "_bytes"] == cap


def test_action_deadline_and_cleanup_preserve_original_terminal_reason():
    h = Harness()
    h.arm("dns_1")
    h.connection()
    h.reserve()
    h.clock = 10.1
    assert not h.ledger.check_deadline()
    assert h.ledger.snapshot()["terminal_reason"] == "action_deadline"
    h.finish_connection()
    h.finish(success=False)
    assert h.ledger.snapshot()["terminal_reason"] == "action_deadline"
    assert ledger_module.validate_snapshot(h.ledger.snapshot(), messages=h.messages) == h.ledger.snapshot()


@pytest.mark.parametrize("mutation", ["counter", "binding", "event", "reply", "message", "missing_message"])
def test_immutable_saved_ledger_replay_rejects_artifact_tampering(mutation):
    h = Harness()
    h.dns()
    snapshot, messages = h.ledger.snapshot(), deepcopy(h.messages)
    if mutation == "counter":
        snapshot["counters"]["connections"] = 0
    elif mutation == "binding":
        snapshot["binding"]["observed_at_us"] += 1
    elif mutation == "event":
        snapshot["events"][0]["elapsed_us"] += 1
    elif mutation == "reply":
        messages[0]["reply"]["snapshot_sha256"] = "0" * 64
    elif mutation == "message":
        messages[0]["message"]["action"]["parameters"]["owner_id"] = SESSION
    else:
        messages.pop()
    with pytest.raises(ValueError):
        ledger_module.validate_snapshot(snapshot, messages=messages)


def test_no_snapshot_restore_constructor_and_transcript_is_mandatory_for_inspection():
    h = Harness()
    with pytest.raises(TypeError):
        ledger_module.Ledger(h.selected, h.identity, snapshot=h.ledger.snapshot())
    with pytest.raises(TypeError):
        ledger_module.validate_snapshot(h.ledger.snapshot())
