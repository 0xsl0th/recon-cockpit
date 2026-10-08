"""One deterministic reviewed action per tool trial; no cross-tool planning."""

from dataclasses import dataclass
import hashlib
import json
import threading

from . import network_tools_contract as contract
from .models import load_json, parse_action
from .http_headers_workflow import _uuid


def card(case=None):
    if case is not None and (type(case) is not str or case not in contract.B1_CASES + contract.B2_CASES + contract.B3_CASES + contract.B4_CASES + contract.B5_CASES + contract.B6_CASES + contract.B7_CASES + contract.B8_CASES + contract.C1_CASES + contract.C2_CASES + contract.C3_CASES + contract.C4_CASES + contract.C5_CASES + contract.C6_CASES + contract.C7_CASES + contract.C8_CASES + contract.C9_CASES + contract.C10_CASES + contract.C11_CASES + contract.C12_CASES + contract.C13_CASES + contract.C14_CASES):
        raise ValueError("invalid_network_tools_case")
    version = "22" if case in contract.C14_CASES else "21" if case in contract.C13_CASES else "20" if case in contract.C12_CASES else "19" if case in contract.C11_CASES else "18" if case in contract.C10_CASES else "17" if case in contract.C9_CASES else "16" if case in contract.C8_CASES else "15" if case in contract.C7_CASES else "14" if case in contract.C6_CASES else "13" if case in contract.C5_CASES else "12" if case in contract.C4_CASES else "11" if case in contract.C3_CASES else "10" if case in contract.C2_CASES else "9" if case in contract.C1_CASES else "8" if case in contract.B8_CASES else "7" if case in contract.B7_CASES else "6" if case in contract.B6_CASES else "5" if case in contract.B5_CASES else "4" if case in contract.B4_CASES else "3" if case in contract.B3_CASES else "2" if case in contract.B2_CASES else "1"
    cases = contract.C14_CASES if version == "22" else contract.C13_CASES if version == "21" else contract.C12_CASES if version == "20" else contract.C11_CASES if version == "19" else contract.C10_CASES if version == "18" else contract.C9_CASES if version == "17" else contract.C8_CASES if version == "16" else contract.C7_CASES if version == "15" else contract.C6_CASES if version == "14" else contract.C5_CASES if version == "13" else contract.C4_CASES if version == "12" else contract.C3_CASES if version == "11" else contract.C2_CASES if version == "10" else contract.C1_CASES if version == "9" else contract.B8_CASES if version == "8" else contract.B7_CASES if version == "7" else contract.B6_CASES if version == "6" else contract.B5_CASES if version == "5" else contract.B4_CASES if version == "4" else contract.B3_CASES if version == "3" else contract.B2_CASES if version == "2" else contract.B1_CASES
    return {
        "schema_version": "1", "workflow_id": contract.WORKFLOW, "workflow_version": version,
        "planning": "deterministic_offline_single_tool", "live_calls_enabled": False,
        "scope": {"target": "127.0.0.1", "port": 111 if version == "4" else 8080, "owned_lab_only": True},
        "limits": dict(contract.LIMITS),
        "action_digests": {case: [parse_action(contract.action(case, 1)).digest]
                           for case in cases},
    }


def card_identity(case=None):
    selected = card(case)
    return {"id": contract.WORKFLOW, "version": selected["workflow_version"],
            "sha256": hashlib.sha256(contract.encode(selected)).hexdigest()}


@dataclass(frozen=True, slots=True)
class ToolDecision:
    step: int
    decision_kind: str
    reason: str
    _action: bytes | None = None
    _references: tuple = ()
    done: bool = True
    _case: str | None = None

    @property
    def action(self):
        return None if self._action is None else json.loads(self._action)

    def to_dict(self):
        identity = card_identity(self._case)
        return {
            "schema_version": "1", "workflow_id": contract.WORKFLOW,
            "workflow_version": identity["version"], "workflow_digest": identity["sha256"],
            "decision_kind": self.decision_kind, "step": self.step, "reason": self.reason,
            "action_digest": None if self._action is None else parse_action(self.action).digest,
            "predecessors": [{"execution_id": execution, "observation_id": observation}
                             for execution, observation in self._references],
        }


def decide(case, step, records, observation):
    if type(case) is not str or case not in contract.CASES or type(step) is not int or step != 1:
        raise ValueError("invalid_network_tool_step")
    if (type(records) not in (tuple, list) or records
            or type(observation) is not bytes
            or observation != contract.encode({"step": 1, "untrusted_observation": None})):
        return ToolDecision(1, "stop", "invalid_initial_tool_context", _case=case)
    return ToolDecision(1, "propose", "single_scoped_tool_trial",
                        contract.encode(contract.action(case, 1)), _case=case)


def terminal_decision(case, records, summary):
    expected = parse_action(contract.action(case, 1))
    step = summary["steps_attempted"] + 1
    if summary["mode"] == "dry_run":
        return ToolDecision(step, "stop", "dry_run_has_no_execution_evidence", _case=case)
    if summary["session_status"] != "completed":
        return ToolDecision(step, "stop", "session_stopped", _case=case)
    if type(records) not in (list, tuple) or len(records) != 1:
        return ToolDecision(step, "stop", "tool_evidence_missing", _case=case)
    row = records[0]
    if (type(row) is not dict or type(row.get("session_step")) is not int or row["session_step"] != 1
            or not _uuid(row.get("execution_id")) or not _uuid(row.get("observation_id"))
            or row.get("action_digest") != expected.digest
            or row.get("action") != {k: v for k, v in expected.to_dict().items() if k != "rationale"}
            or row.get("execution_status") != "succeeded"):
        return ToolDecision(step, "stop", "tool_execution_not_succeeded", _case=case)
    reason = "tool_evidence_inconclusive"
    observation = row.get("observation")
    try:
        if (type(observation) is dict and observation == contract.classify_tool(
                expected.tool_id, observation.get("details"))):
            reason = observation["reason"]
    except (ValueError, TypeError, KeyError):
        pass
    return ToolDecision(step, "stop", reason,
                        _references=((row["execution_id"], row["observation_id"]),), _case=case)


class NetworkToolsProvider:
    name = "deterministic-owned-single-network-tool"
    boundary_checks = None

    def __init__(self, case, evidence):
        contract.action(case, 1)
        self.case, self._evidence = case, evidence
        self._lock = threading.Lock()
        self._session_id = None
        self._closed = False

    def bind_session(self, session_id):
        with self._lock:
            if self._closed or self._session_id is not None or not _uuid(session_id):
                raise ValueError("invalid_network_tool_provider_binding")
            self._session_id = session_id

    def close(self):
        with self._lock:
            self._closed = True

    def propose(self, observation, *, control):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("network_tool_provider_already_running")
        try:
            control.check()
            if self._closed or self._session_id is None:
                raise RuntimeError("network_tool_provider_closed")
            if (type(observation) is not bytes or len(observation) > 8192
                    or load_json(observation) != {"step": 1, "untrusted_observation": None}):
                raise ValueError("invalid_network_tool_observation")
            decision = self._evidence.record_decision(1, observation)
            control.check()
            return contract.encode({"schema_version": "1", "action": decision.action, "done": True})
        finally:
            self._closed = True
            self._lock.release()
