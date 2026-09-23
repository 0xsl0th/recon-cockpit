"""Fixed owned-fixture assessment; synthetic candidates gated by host evidence."""

from __future__ import annotations

import hashlib
import json
import threading

from .assessment_contract import CASES, assessment_action, diagnostics_path
from .models import load_json, parse_action
from .openai_broker import BrokerLimits, OfflineReply, OfflineTransport
from .openai_fixtures import _response
from .openai_protocol import OpenAIConfig
from .openai_provider import OfflineOpenAIProvider
from .session_protocol import _plan


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


class AssessmentProvider:
    """One deterministic two-GET workflow, never a live/adaptive model provider.

    An actual complete discovery record authorizes considering the second fixed
    candidate. It supplies no policy or launch authority. Every returned action
    still crosses the coordinator and the usual controller checks.
    """

    name = "deterministic-http-fixture-assessment"

    def _candidate_plans(self, case):
        return tuple({"schema_version": "1", "action": assessment_action(case, step),
                      "done": step == 2} for step in (1, 2))

    def __init__(self, case, audit, evidence):
        if type(case) is not str or case not in CASES:
            raise ValueError("invalid_assessment_case")
        self.case = case
        self._evidence = evidence
        self._plans = self._candidate_plans(case)
        replies = tuple(OfflineReply(200, _encode(_response(plan))) for plan in self._plans)
        self._offline = OfflineOpenAIProvider(
            OpenAIConfig("offline-fixture-http-assessment"), audit, OfflineTransport(replies),
            BrokerLimits(max_calls=len(self._plans), max_reserved_output_tokens=1024 * len(self._plans),
                         max_request_bytes=16384 * len(self._plans)),
        )
        self._lock = threading.Lock()
        self._bound = False
        self._closed = False
        self._next_step = 1

    @property
    def broker(self):
        return self._offline.broker

    @property
    def boundary_checks(self):
        return self._offline.boundary_checks

    def bind_session(self, session_id):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("assessment_already_running")
        try:
            self._offline.bind_session(session_id)
            self._bound = True
        finally:
            self._lock.release()

    def _discovery_complete(self, observation):
        records = self._evidence.records
        if type(records) not in (list, tuple) or len(records) != 1:
            return False
        record = records[0]
        if type(record) is not dict:
            return False
        expected = self._plans[0]["action"]
        safe_action = {key: value for key, value in expected.items() if key != "rationale"}
        parsed = record.get("observation")
        return (type(record.get("session_step")) is int and record["session_step"] == 1
                and record.get("execution_status") == "succeeded"
                and record.get("action_digest") == parse_action(expected).digest
                and record.get("action") == safe_action
                and type(parsed) is dict and parsed.get("classification") == "discovered"
                and parsed.get("followup_path") == diagnostics_path(self.case)
                and record.get("authority_observation_sha256") == hashlib.sha256(observation).hexdigest())

    def _select_plan(self, step, observation):
        if step > 1 and not self._discovery_complete(observation):
            return {"schema_version": "1", "action": None, "done": True}
        return self._plans[step - 1]

    def propose(self, observation, *, control):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("assessment_already_running")
        try:
            control.check()
            if not self._bound or self._closed:
                raise RuntimeError("assessment_provider_closed")
            if type(observation) is not bytes or len(observation) > 8192:
                raise ValueError("invalid_assessment_observation")
            value = load_json(observation)
            if (set(value) != {"step", "untrusted_observation"}
                    or type(value["step"]) is not int or value["step"] != self._next_step
                    or (self._next_step == 1 and value["untrusted_observation"] is not None)):
                raise ValueError("invalid_assessment_observation")
            step = self._next_step
            self._next_step += 1
            plan = self._select_plan(step, observation)
            control.check()
            if plan["action"] is None:
                self._closed = True
                return _encode(plan)
            raw = self._offline.propose(observation, control=control)
            control.check()
            # A compromised response decoder cannot substitute another target,
            # path, allowance, action identity or workflow-completion signal.
            if type(raw) is not bytes or len(raw) > 16384 or _encode(_plan(raw)) != _encode(plan):
                raise ValueError("assessment_candidate_mismatch")
            if plan["done"]:
                self._closed = True
            return raw
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()


class DiscoveryAssessmentProvider(AssessmentProvider):
    """One TCP attempt gates HTTP consideration; HTTP evidence gates validation."""

    name = "deterministic-discovery-http-fixture-assessment"

    def _candidate_plans(self, case):
        from .discovery_contract import discovery_action

        return tuple({"schema_version": "1", "action": discovery_action(case, step),
                      "done": step == 3} for step in (1, 2, 3))

    def _discovery_complete(self, observation):
        from .discovery_contract import PARSER_VERSION

        records = self._evidence.records
        # propose has already advanced _next_step. Every completed predecessor
        # must still match the fixed workflow before another exchange is made.
        count = self._next_step - 2
        if type(records) not in (list, tuple) or len(records) != count or count not in (1, 2):
            return False
        for index, record in enumerate(records):
            expected = self._plans[index]["action"]
            safe = {key: value for key, value in expected.items() if key != "rationale"}
            if (type(record) is not dict or type(record.get("session_step")) is not int
                    or record["session_step"] != index + 1
                    or record.get("execution_status") != "succeeded"
                    or record.get("action_digest") != parse_action(expected).digest
                    or record.get("action") != safe):
                return False
            parsed = record.get("observation")
            if index == 0:
                if parsed != {"parser_version": PARSER_VERSION, "kind": "tcp_discovery",
                              "classification": "reachable", "reason": "tcp_port_reachable",
                              "followup_path": None}:
                    return False
            elif (type(parsed) is not dict or parsed.get("classification") != "discovered"
                  or parsed.get("followup_path") != diagnostics_path(self.case)):
                return False
        return records[-1].get("authority_observation_sha256") == hashlib.sha256(observation).hexdigest()


class WorkflowAssessmentProvider(AssessmentProvider):
    """One reviewed card chooses proposals; the authority still grants execution."""

    name = "deterministic-owned-workflow-assessment"

    def _candidate_plans(self, case):
        from .discovery_contract import discovery_action
        from .workflow import card

        return tuple({"schema_version": "1", "action": discovery_action(case, step["step"]),
                      "done": step["done"]} for step in card()["steps"])

    def _select_plan(self, step, observation):
        # This host-owned sink invokes the engine and durably records its exact
        # decision before any broker exchange. Failure poisons the provider and
        # propagates through the authority's audit-failure path.
        decision = self._evidence.record_decision(step, observation)
        plan = {"schema_version": "1", "action": decision.action, "done": decision.done}
        if decision.action is not None and _encode(plan) != _encode(self._plans[step - 1]):
            raise ValueError("workflow_candidate_mismatch")
        return plan
