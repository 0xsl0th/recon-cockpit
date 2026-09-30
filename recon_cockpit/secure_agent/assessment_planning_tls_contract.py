"""Closed owned TLS planning fixtures, with no live configuration or imports."""

from __future__ import annotations

import hashlib
import hmac
import re

from . import assessment_planning_contract as planning
from .assessment_contract import CASES
from .discovery_contract import discovery_action
from .openai_protocol import build_request
from .provider_contract import SCENARIOS as TRANSPORT_SCENARIOS
from .workflow import card_identity


PROFILE = "owned-assessment-planning-tls-v1"
SCENARIOS = tuple(sorted(set(planning.SCENARIOS) | TRANSPORT_SCENARIOS))


def context(value):
    if (type(value) is not dict or set(value) != {"case", "scenario", "run_id"}
            or type(value["case"]) is not str or value["case"] not in CASES
            or type(value["scenario"]) is not str or value["scenario"] not in SCENARIOS
            or type(value["run_id"]) is not str or re.fullmatch(r"[a-f0-9]{32}", value["run_id"]) is None):
        raise ValueError("planning_transport_invalid_configuration")
    return dict(value)


def transport_scenario(scenario):
    if type(scenario) is not str or scenario not in SCENARIOS:
        raise ValueError("planning_transport_invalid_configuration")
    if scenario == "http_error":
        return "rate_limit"
    return scenario if scenario in TRANSPORT_SCENARIOS else "success"


def canonical_request(case, step, *, owned_lab=False):
    """Reconstruct only one of the reviewed 36 repository-authored releases."""
    if (type(case) is not str or case not in CASES or type(step) is not int
            or step not in (1, 2, 3) or type(owned_lab) is not bool):
        raise ValueError("planning_transport_invalid_request")
    action = discovery_action(case, step)
    descriptor = {"profile": planning.PROFILE, "case": case,
                  "workflow_card": card_identity(owned_lab=owned_lab),
                  "candidate": {"schema_version": "1", "done": step == 3,
                      "action": {key: value for key, value in action.items() if key != "rationale"}}}
    released = planning.encode({"step": step, "untrusted_observation": {
        "execution_status": "planning", "body": planning.encode(descriptor).decode("ascii")}})
    return build_request(planning.CONFIG, released)


def request_details(raw, *, case=None):
    if (type(raw) is not bytes or not 1 <= len(raw) <= planning.INPUT_LIMIT
            or case is not None and (type(case) is not str or case not in CASES)):
        raise ValueError("planning_transport_invalid_request")
    for candidate in CASES if case is None else (case,):
        for owned_lab in (False, True):
            for step in (1, 2, 3):
                if raw == canonical_request(candidate, step, owned_lab=owned_lab):
                    return {"case": candidate, "step": step, "owned_lab": owned_lab}
    raise ValueError("planning_transport_invalid_request")


def verify_request_digest(raw, expected):
    if (type(raw) is not bytes or type(expected) is not str or re.fullmatch(r"[a-f0-9]{64}", expected) is None
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected)):
        raise ValueError("planning_transport_request_mismatch")


def response_body(request, configuration):
    """Synthetic usage and proposal; the owner independently checks the release."""
    configuration = context(configuration)
    details = request_details(request, case=configuration["case"])
    case, step = details["case"], details["step"]
    scenario = configuration["scenario"]
    action = discovery_action(case, step)
    if scenario == "substituted_action":
        action["target"] = "203.0.113.99"
    proposal = {"schema_version": "1", "action": action, "done": step == 3}
    value = {"object": "response", "id": f"resp_owned_{configuration['run_id']}_{case}_{step}",
             "model": planning.MODEL, "status": "completed", "service_tier": "simulation",
             "error": None, "incomplete_details": None,
             "output": [{"type": "message", "role": "assistant", "status": "completed",
                         "content": [{"type": "output_text", "text": planning.encode(proposal).decode("ascii")}]}],
             "usage": {"input_tokens": 512, "output_tokens": 128, "total_tokens": 640,
                       "input_tokens_details": {"cached_tokens": 0},
                       "output_tokens_details": {"reasoning_tokens": 0}}}
    if scenario == "refusal":
        value["output"][0]["content"] = [{"type": "refusal", "refusal": "Owned synthetic refusal"}]
    elif scenario == "missing_usage":
        value.pop("usage")
    elif scenario == "unknown_usage":
        value["usage"]["input_tokens_details"]["unpriced_tokens"] = 1
    elif scenario == "usage_overrun":
        value["usage"].update(input_tokens=planning.INPUT_LIMIT + 1, output_tokens=planning.OUTPUT_LIMIT + 1,
                              total_tokens=planning.INPUT_LIMIT + planning.OUTPUT_LIMIT + 2)
    return planning.encode(value)
