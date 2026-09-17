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

    def __init__(self, case, audit, evidence):
        if type(case) is not str or case not in CASES:
            raise ValueError("invalid_assessment_case")
        self.case = case
        self._evidence = evidence
        self._plans = tuple({"schema_version": "1", "action": assessment_action(case, step),
                             "done": step == 2} for step in (1, 2))
        replies = tuple(OfflineReply(200, _encode(_response(plan))) for plan in self._plans)
        self._offline = OfflineOpenAIProvider(
            OpenAIConfig("offline-fixture-http-assessment"), audit, OfflineTransport(replies),
            BrokerLimits(max_calls=2, max_reserved_output_tokens=2048, max_request_bytes=32768),
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
            if step == 2 and not self._discovery_complete(observation):
                self._closed = True
                return _encode({"schema_version": "1", "action": None, "done": True})
            raw = self._offline.propose(observation, control=control)
            control.check()
            # A compromised response decoder cannot substitute another target,
            # path, allowance, action identity or workflow-completion signal.
            if type(raw) is not bytes or len(raw) > 16384 or _encode(_plan(raw)) != _encode(self._plans[step - 1]):
                raise ValueError("assessment_candidate_mismatch")
            if step == 2:
                self._closed = True
            return raw
        except BaseException:
            self._closed = True
            raise
        finally:
            self._lock.release()
