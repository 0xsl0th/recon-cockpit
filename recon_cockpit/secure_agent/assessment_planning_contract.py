"""Closed assessment-planning transcript for owned, strictly offline simulation.

The price, model and usage are synthetic fixture data. This module supplies no
live configuration, transport, credential lookup or evidence-based finding.
"""

from __future__ import annotations

import hashlib
import json
import re

from .assessment_contract import CASES
from .cost_contract import CostError, PriceCard, TokenUsage
from .discovery_contract import discovery_action
from .models import parse_action
from .openai_broker import OfflineReply
from .openai_protocol import OpenAIConfig, MAX_RESPONSE_BYTES, _decode_object, _observation
from .workflow import WorkflowDecision, card, card_identity


PROFILE = "owned-assessment-planning-v1"
MODEL = "owned-assessment-planning-mock-v1"
# This simulation ceiling covers the complete bounded request byte allowance;
# it is not a tokenizer estimate or an approved real-provider context limit.
INPUT_LIMIT = 16384
OUTPUT_LIMIT = 1024
CONFIG = OpenAIConfig(MODEL, OUTPUT_LIMIT)
PRICE = PriceCard("owned-mock", MODEL, "simulation-v1", 1_000_000, 250_000, 2_000_000, 10)
DEFAULT_BUDGET_MICROUSD = 3 * PRICE.ceiling(INPUT_LIMIT, OUTPUT_LIMIT)
SCENARIOS = ("success", "refusal", "substituted_action", "missing_usage", "unknown_usage",
             "usage_overrun", "malformed", "http_error", "slow")
_RESPONSE_FIELDS = frozenset({"object", "id", "model", "status", "service_tier", "error",
                              "incomplete_details", "output", "usage"})


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def release_observation(case, decision, observation):
    """Release only the repository candidate after the durable workflow gate.

    The caller must first obtain this decision from EvidenceStore.record_decision,
    which checks the source feedback against saved evidence. This additional
    closed check cannot replace that gate or establish evidence by itself.
    No source response body, rationale or evidence identifier enters the result.
    """
    try:
        if (type(case) is not str or case not in CASES or type(decision) is not WorkflowDecision
                or type(decision.step) is not int or decision.step not in (1, 2, 3)
                or type(decision.workflow_version) is not str or decision.workflow_version not in {"1", "2"}):
            raise ValueError
        source = json.loads(_observation(observation))
        feedback = source["untrusted_observation"]
        if (source["step"] != decision.step or (decision.step == 1) != (feedback is None)
                or feedback is not None and feedback["execution_status"] != "succeeded"):
            raise ValueError
        owned_lab = decision.workflow_version == "2"
        identity = card_identity(owned_lab=owned_lab)
        node = card(owned_lab=owned_lab)["steps"][decision.step - 1]
        action = discovery_action(case, decision.step)
        if (decision.decision_kind != "propose" or decision.reason != node["reason"]
                or type(decision.done) is not bool or decision.done is not node["done"]
                or decision.workflow_digest != identity["sha256"]
                or decision.action_digest != parse_action(action).digest
                or encode(decision.action) != encode(action)):
            raise ValueError
        descriptor = {"profile": PROFILE, "case": case, "workflow_card": identity,
                      "candidate": {"schema_version": "1", "done": node["done"],
                                    "action": {key: value for key, value in action.items() if key != "rationale"}}}
        released = encode({"step": decision.step, "untrusted_observation": {
            "execution_status": "planning", "body": encode(descriptor).decode("ascii")}})
        # Keep the existing isolated parser's schema and size ceiling unchanged.
        _observation(released)
        return released
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, UnicodeError):
        raise ValueError("planning_release_invalid") from None


def replies(case, scenario="success", *, run_id="fixture"):
    """Return a finite synthetic transcript, never a transport implementation.

    The fixed default is convenient for pure fixtures. An adapter supplies a
    fresh UUID hex value for distinct sessions sharing one monetary ledger.
    Every adversarial scenario changes the first reply only; there is no retry.
    """
    if (type(case) is not str or case not in CASES or type(scenario) is not str or scenario not in SCENARIOS
            or type(run_id) is not str or re.fullmatch(r"fixture|[a-f0-9]{32}", run_id) is None):
        raise ValueError("planning_fixture_invalid")
    result = []
    for step in (1, 2, 3):
        plan = {"schema_version": "1", "action": discovery_action(case, step), "done": step == 3}
        if step == 1 and scenario == "substituted_action":
            plan["action"]["target"] = "203.0.113.99"
        value = {"object": "response", "id": f"resp_owned_{run_id}_{case}_{step}", "model": MODEL,
                 "status": "completed", "service_tier": "simulation", "error": None,
                 "incomplete_details": None, "output": [{"type": "message", "role": "assistant",
                 "status": "completed", "content": [{"type": "output_text", "text": encode(plan).decode("ascii")}]}],
                 "usage": {"input_tokens": 512, "output_tokens": 128, "total_tokens": 640,
                           "input_tokens_details": {"cached_tokens": 0},
                           "output_tokens_details": {"reasoning_tokens": 0}}}
        if step == 1:
            if scenario == "refusal":
                value["output"][0]["content"] = [{"type": "refusal", "refusal": "Owned synthetic refusal"}]
            elif scenario == "missing_usage":
                value.pop("usage")
            elif scenario == "unknown_usage":
                value["usage"]["input_tokens_details"]["unpriced_tokens"] = 1
            elif scenario == "usage_overrun":
                value["usage"].update(input_tokens=INPUT_LIMIT + 1, output_tokens=OUTPUT_LIMIT + 1,
                                      total_tokens=INPUT_LIMIT + OUTPUT_LIMIT + 2)
        body = b'{"object":' if step == 1 and scenario == "malformed" else encode(value)
        result.append(OfflineReply(429 if step == 1 and scenario == "http_error" else 200, body,
                                   delay_seconds=30 if step == 1 and scenario == "slow" else 0))
    return tuple(result)


def usage(raw):
    """Recognize only the synthetic transcript's fully priced final usage.

    This does not validate or authorize the proposal. Recognized overruns and
    rejected output must be settled before rejecting the proposal. Unrecognized
    or absent usage raises, so a dispatched attempt retains its reservation.
    """
    try:
        value = _decode_object(raw, MAX_RESPONSE_BYTES)
        if (set(value) != _RESPONSE_FIELDS or value["object"] != "response" or value["model"] != MODEL
                or value["status"] not in {"completed", "incomplete"} or value["service_tier"] != "simulation"
                or type(value["id"]) is not str
                or re.fullmatch(r"resp_owned_(?:fixture|[a-f0-9]{32})_[a-f]_[1-3]", value["id"]) is None):
            raise ValueError
        data = value["usage"]
        if type(data) is not dict or set(data) != {"input_tokens", "output_tokens", "total_tokens",
                                                 "input_tokens_details", "output_tokens_details"}:
            raise ValueError
        inputs, outputs = data["input_tokens_details"], data["output_tokens_details"]
        if (type(inputs) is not dict or set(inputs) != {"cached_tokens"}
                or type(outputs) is not dict or set(outputs) != {"reasoning_tokens"}
                or type(outputs["reasoning_tokens"]) is not int or outputs["reasoning_tokens"] != 0):
            raise ValueError
        recognized = TokenUsage(data["input_tokens"], data["output_tokens"], inputs["cached_tokens"])
        if type(data["total_tokens"]) is not int or data["total_tokens"] != recognized.input_tokens + recognized.output_tokens:
            raise ValueError
        return recognized, "simulation-response-" + hashlib.sha256(value["id"].encode("ascii")).hexdigest()
    except (CostError, ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        raise ValueError("planning_usage_unrecognized") from None
