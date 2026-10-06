"""Deterministic proposals for the four declared owned endpoint actions."""

from dataclasses import dataclass
import hashlib
import json
import threading
from uuid import UUID

from . import configurable_contract as contract
from .models import load_json, parse_action
from .configurable_scope import validate_scope


def card_identity(scope):
    return {"id": contract.WORKFLOW, "version": "1", "sha256": hashlib.sha256(
        contract.encode(contract.capability_descriptor(scope))).hexdigest()}


@dataclass(frozen=True, slots=True)
class Decision:
    step: int
    reason: str
    done: bool
    encoded_action: bytes | None

    @property
    def action(self):
        return None if self.encoded_action is None else json.loads(self.encoded_action)

    def to_dict(self):
        return {"step": self.step, "reason": self.reason, "done": self.done,
                "action_digest": None if self.action is None else parse_action(self.action).digest}


def decide(scope, step, records, observation):
    if type(step) is not int or not 1 <= step <= 4 or type(records) is not list:
        raise ValueError("invalid_configurable_workflow_step")
    if type(observation) is not bytes or len(observation) > 8192:
        raise ValueError("invalid_configurable_observation")
    frame = load_json(observation)
    if (set(frame) != {"step", "untrusted_observation"} or type(frame["step"]) is not int
            or frame["step"] != step or (step == 1 and frame["untrusted_observation"] is not None)):
        raise ValueError("invalid_configurable_observation")
    if not records:
        from .session import _observation
        expected = _observation(step, None if step == 1 else
            {"execution_status": "dry_run", "untrusted_result": {}})
        if observation != expected:
            raise ValueError("configurable_authority_observation_changed")
    if records and (type(records[-1]) is not dict
            or records[-1].get("authority_observation_sha256") != hashlib.sha256(observation).hexdigest()):
        raise ValueError("configurable_authority_observation_changed")
    return expected_decision(scope, step, records)


def expected_decision(scope, step, records):
    scope = validate_scope(scope)
    if type(step) is not int or not 1 <= step <= 4 or type(records) is not list:
        raise ValueError("invalid_configurable_workflow_step")
    if len(records) != step - 1:
        return Decision(step, "complete_predecessor_missing", True, None)
    for index, record in enumerate(records, start=1):
        try:
            if type(record) is not dict or type(record.get("observation")) is not dict:
                raise ValueError("invalid_predecessor")
            normalized = contract.observation(scope, index, {"status": "succeeded", "truncated": False,
                "tool_observation": record["observation"].get("details")})
            valid = (record.get("action") == contract.action(scope, index)
                and record.get("status") == "succeeded" and normalized["classification"] == "observed"
                and record["observation"] == normalized
                and (index not in (1, 3) or contract.predecessor_gate(scope, index, normalized)))
        except (ValueError, TypeError, KeyError):
            valid = False
        if not valid:
            return Decision(step, "complete_predecessor_missing", True, None)
    return Decision(step, "declared_endpoint_metadata", step == 4, contract.encode(contract.action(scope, step)))


class ConfigurableProvider:
    name = "deterministic-configurable-owned-http-ssh"
    boundary_checks = None

    def __init__(self, scope, evidence):
        self.scope = validate_scope(scope)
        if self.scope != validate_scope(evidence._manifest["scope"]):
            raise ValueError("configurable_provider_scope_mismatch")
        self._evidence, self._next_step = evidence, 1
        self._session_id, self._closed = None, False
        self._lock = threading.Lock()

    def bind_session(self, session_id):
        if (self._closed or self._session_id is not None or type(session_id) is not str
                or str(UUID(session_id)) != session_id or session_id != self._evidence._manifest["session_id"]):
            raise ValueError("invalid_configurable_provider_binding")
        self._session_id = session_id

    def close(self):
        self._closed = True

    def propose(self, observation, *, control):
        if not self._lock.acquire(blocking=False):
            raise ValueError("configurable_provider_already_running")
        try:
            control.check()
            if (self._closed or self._session_id is None or self.scope != self._evidence._manifest["scope"]
                    or self._session_id != self._evidence._manifest["session_id"]):
                raise ValueError("configurable_provider_closed")
            decision = self._evidence.record_decision(self._next_step, observation)
            self._next_step += 1
            self._closed = decision.done
            return contract.encode({"schema_version": "1", "action": decision.action, "done": decision.done})
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()
