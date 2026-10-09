"""Deterministic HTTP header observations; response content never changes scope."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import threading
from uuid import UUID

from . import http_headers_contract as contract
from .http_headers_contract import CASES
from .models import load_json, parse_action
from .nmap_parser import PARSER_VERSION


def card():
    return {
        "schema_version": "1", "workflow_id": contract.WORKFLOW, "workflow_version": "1",
        "planning": "deterministic_offline", "live_calls_enabled": False,
        "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
        "limits": dict(contract.LIMITS),
        "steps": [
            {"step": 1, "tool_id": contract.TOOL_ID, "requires": []},
            {"step": 2, "tool_id": contract.HTTP_TOOL_ID, "requires": ["nmap_reachable"]},
        ],
        "action_digests": {case: [parse_action(contract.action(case, step)).digest
                                 for step in (1, 2)] for case in CASES},
    }


def card_identity():
    return {"id": contract.WORKFLOW, "version": "1",
            "sha256": hashlib.sha256(contract.encode(card())).hexdigest()}


@dataclass(frozen=True, slots=True)
class WorkflowDecision:
    step: int
    decision_kind: str
    reason: str
    done: bool
    _action: bytes | None
    _references: tuple

    @property
    def action(self):
        return None if self._action is None else json.loads(self._action)

    def to_dict(self):
        return {
            "schema_version": "1", "workflow_id": contract.WORKFLOW,
            "workflow_version": "1", "workflow_digest": card_identity()["sha256"],
            "decision_kind": self.decision_kind, "step": self.step, "reason": self.reason,
            "action_digest": None if self._action is None else parse_action(self.action).digest,
            "predecessors": [{"execution_id": execution, "observation_id": observation}
                             for execution, observation in self._references],
        }


def _uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _references(records):
    if type(records) not in (list, tuple) or len(records) > 2:
        return ()
    return tuple((row["execution_id"], row.get("observation_id")) for row in records
                 if type(row) is dict and _uuid(row.get("execution_id"))
                 and (row.get("observation_id") is None or _uuid(row["observation_id"])))


def _stop(step, reason, records):
    return WorkflowDecision(step, "stop", reason, True, None, _references(records))


def _matches(case, step, record):
    expected = contract.action(case, step)
    return (
        type(record) is dict and type(record.get("session_step")) is int
        and record["session_step"] == step and _uuid(record.get("execution_id"))
        and _uuid(record.get("observation_id"))
        and record.get("action_digest") == parse_action(expected).digest
        and record.get("action") == {key: value for key, value in expected.items() if key != "rationale"}
    )


def _gate(case, step, observation):
    expected = {"parser_version": PARSER_VERSION, "kind": "nmap_discovery",
                "classification": "reachable", "reason": "nmap_tcp_port_reachable",
                "followup_path": None}
    return step == 1 and type(observation) is dict and observation == expected


def decide(case, step, records, observation):
    if type(case) is not str or case not in CASES or type(step) is not int or step not in (1, 2):
        raise ValueError("invalid_http_headers_workflow_step")
    if type(records) not in (list, tuple) or len(records) != step - 1:
        return _stop(step, "predecessor_evidence_missing", records)
    for index, record in enumerate(records, start=1):
        if not _matches(case, index, record):
            return _stop(step, "predecessor_evidence_invalid", records)
        if record.get("execution_status") != "succeeded":
            return _stop(step, "predecessor_execution_not_succeeded", records)
        if not _gate(case, index, record.get("observation")):
            return _stop(step, "nmap_reachability_not_established", records)
    if (len({row["execution_id"] for row in records}) != len(records)
            or len({row["observation_id"] for row in records}) != len(records)):
        return _stop(step, "predecessor_evidence_invalid", records)
    if records and (type(observation) is not bytes or len(observation) > 8192
                    or records[-1].get("authority_observation_sha256") != hashlib.sha256(observation).hexdigest()):
        return _stop(step, "authority_observation_mismatch", records)
    return WorkflowDecision(step, "propose", (
        "initial_scoped_nmap_discovery", "nmap_reachability_observed",
    )[step - 1], step == 2, contract.encode(contract.action(case, step)), _references(records))


def terminal_decision(case, records, summary):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_assessment_case")
    step = summary["steps_attempted"] + 1
    if summary["mode"] == "dry_run":
        return _stop(step, "dry_run_has_no_execution_evidence", records)
    if summary["session_status"] != "completed":
        return _stop(step, "session_stopped", records)
    if (type(records) not in (list, tuple) or len(records) != 2
            or any(not _matches(case, index, row) or row.get("execution_status") != "succeeded"
                   for index, row in enumerate(records, start=1))
            or len({row["execution_id"] for row in records}) != len(records)
            or len({row["observation_id"] for row in records}) != len(records)
            or not _gate(case, 1, records[0].get("observation"))):
        return _stop(step, "discovery_or_execution_evidence_missing", records)
    observation = records[1].get("observation")
    reason = "http_header_evidence_invalid"
    try:
        if (type(observation) is dict
                and observation == contract.classify_headers(observation.get("headers"))
                and observation["classification"] in ("gaps_observed", "no_gaps_observed")):
            reason = observation["reason"]
    except (ValueError, TypeError, KeyError):
        pass
    return _stop(step, reason, records)


class HTTPHeadersProvider:
    """Trusted deterministic proposal source; no model client or provider calls."""

    name = "deterministic-owned-http-headers-assessment"
    boundary_checks = None

    def __init__(self, case, evidence):
        if type(case) is not str or case not in CASES:
            raise ValueError("invalid_assessment_case")
        self.case, self._evidence = case, evidence
        self._lock = threading.Lock()
        self._session_id = None
        self._next_step = 1
        self._closed = False

    def bind_session(self, session_id):
        with self._lock:
            if self._session_id is not None or self._closed or not _uuid(session_id):
                raise ValueError("invalid_http_headers_provider_binding")
            self._session_id = session_id

    def close(self):
        with self._lock:
            self._closed = True

    def propose(self, observation, *, control):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("http_headers_provider_already_running")
        try:
            control.check()
            if self._closed or self._session_id is None:
                raise RuntimeError("http_headers_provider_closed")
            if type(observation) is not bytes or len(observation) > 8192:
                raise ValueError("invalid_http_headers_observation")
            frame = load_json(observation)
            if (set(frame) != {"step", "untrusted_observation"}
                    or type(frame["step"]) is not int or frame["step"] != self._next_step
                    or (self._next_step == 1 and frame["untrusted_observation"] is not None)):
                raise ValueError("invalid_http_headers_observation")
            decision = self._evidence.record_decision(self._next_step, observation)
            self._next_step += 1
            control.check()
            self._closed = decision.done
            return contract.encode({"schema_version": "1", "action": decision.action, "done": decision.done})
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()
