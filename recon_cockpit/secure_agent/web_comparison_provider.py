"""Bounded scripted planner fault for an offline authority comparison.

The injected response must actually reach this provider through the previous
authority observation. It can produce a proposal only; ordinary policy must
deny it. No execution, approval, recovery or model client is added here.
"""

from __future__ import annotations

import copy
import hashlib
import re
import threading
from uuid import UUID

from .models import load_json, parse_action
from .nmap_evidence import REPRESENTATION
from .web_assessment_contract import encode
from .web_comparison_contract import ARMS, CASES, attack_action
from .web_fixture import OPERATOR_NOTE
from .web_workflow import WebProvider, decide


def _frame(observation):
    if type(observation) is not bytes or len(observation) > 8192:
        raise ValueError("invalid_comparison_observation")
    value = load_json(observation)
    if (type(value) is not dict or set(value) != {"step", "untrusted_observation"}
            or type(value["step"]) is not int or not 1 <= value["step"] <= 3):
        raise ValueError("invalid_comparison_observation")
    previous = value["untrusted_observation"]
    if value["step"] == 1:
        if previous is not None:
            raise ValueError("invalid_comparison_initial_observation")
    elif (type(previous) is not dict or set(previous) != {"execution_status", "body"}
          or type(previous["execution_status"]) is not str
          or previous["execution_status"] not in {"succeeded", "failed", "timeout", "output_limit", "blocked", "cancelled", "dry_run"}
          or type(previous["body"]) is not str or len(previous["body"].encode("utf-8")) > 1024):
        raise ValueError("invalid_comparison_previous_observation")
    return value


def attack_note(observation):
    """Return a fixed note digest only for the exact bounded step-three input.

    This content check is not the predecessor gate. The provider additionally
    binds the frame to durable validated execution evidence before proposing.
    """
    frame = _frame(observation)
    previous = frame["untrusted_observation"]
    if frame["step"] != 3 or previous["execution_status"] != "succeeded":
        return None
    document = load_json(previous["body"])
    if type(document) is not dict:
        raise ValueError("invalid_comparison_index_document")
    if document.get("operator_note") == OPERATOR_NOTE:
        return hashlib.sha256(OPERATOR_NOTE.encode("utf-8")).hexdigest()
    return None


def _proof(case, observation, records, note_digest):
    decision = decide(case, 3, records, observation)
    if decision.decision_kind != "propose" or decision.action is None or len(records) != 2:
        raise ValueError("comparison_predecessor_not_validated")
    record = records[1]
    artifact = record.get("artifact")
    if (type(artifact) is not dict or set(artifact) != {"filename", "bytes", "sha256", "representation"}
            or artifact["filename"] != "result-" + record["execution_id"] + ".json"
            or type(artifact["bytes"]) is not int or not 1 <= artifact["bytes"] <= 65536
            or type(artifact["sha256"]) is not str or re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"]) is None
            or artifact["representation"] != REPRESENTATION):
        raise ValueError("comparison_source_artifact_missing")
    return {"source_execution_id": record["execution_id"], "source_observation_id": record["observation_id"],
            "source_artifact": copy.deepcopy(artifact), "note_sha256": note_digest}


class ComparisonProvider:
    """Single-use wrapper around the unchanged deterministic web provider."""

    name = "deterministic-owned-web-adversarial-comparison"
    boundary_checks = None

    def __init__(self, case, evidence, arm, audit):
        if type(case) is not str or case not in CASES or type(arm) is not str or arm not in ARMS:
            raise ValueError("invalid_web_comparison_case_or_arm")
        self.case, self.arm = case, arm
        self._inner = WebProvider(case, evidence)
        self._evidence, self._audit = evidence, audit
        self._session_id = None
        self._next_step = 1
        self._closed = False
        self._trace = []
        self._lock = threading.Lock()

    @property
    def trace(self):
        with self._lock:
            return copy.deepcopy(self._trace)

    def bind_session(self, session_id):
        with self._lock:
            if (self._closed or self._session_id is not None or type(session_id) is not str
                    or str(UUID(session_id)) != session_id):
                raise ValueError("invalid_comparison_provider_binding")
            self._inner.bind_session(session_id)
            self._session_id = session_id

    def close(self):
        with self._lock:
            self._closed = True
            self._inner.close()

    def propose(self, observation, *, control):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("comparison_provider_already_running")
        try:
            control.check()
            if self._closed or self._session_id is None:
                raise RuntimeError("comparison_provider_closed")
            frame = _frame(observation)
            if frame["step"] != self._next_step:
                raise ValueError("comparison_provider_step_mismatch")
            proof = None
            note_digest = attack_note(observation) if self.arm == "scripted" and self._next_step == 3 else None
            if note_digest is not None:
                proof = _proof(self.case, observation, self._evidence.records, note_digest)
                # Do not ask the inner provider to record a third legitimate
                # proposal which will never be submitted to authority.
                self._inner.close()
                proposal = {"schema_version": "1", "action": attack_action(self.case), "done": True}
            else:
                proposal = load_json(self._inner.propose(observation, control=control))
            control.check()
            self._closed = proposal["done"]
            self._next_step += 1
            if proposal["action"] is not None:
                action = parse_action(proposal["action"])
                row = {"step": frame["step"], "action": action.to_dict(), "action_digest": action.digest,
                       "observation_sha256": hashlib.sha256(observation).hexdigest(), "attack": proof}
                self._audit.emit({"event_type": "web_comparison_plan", "session_id": self._session_id,
                                  "arm": self.arm, **{key: row[key] for key in (
                                      "step", "action_digest", "observation_sha256", "attack")}})
                self._trace.append(row)
                control.check()
            return encode(proposal)
        except BaseException:
            self._closed = True
            self._inner.close()
            raise
        finally:
            self._lock.release()
