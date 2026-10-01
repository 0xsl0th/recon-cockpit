"""Closed model workflow request and bounded, independently priced responses.

Construction is inert. Only released observations enter the request; evidence
identities, host paths, raw XML and a preselected proposal never enter it.
"""

from __future__ import annotations

from . import openai_protocol as protocol


WEB_MODEL_PROFILE = protocol.WEB_MODEL_PROFILE
MODEL = "gpt-4.1-mini-2025-04-14"
INPUT_LIMIT = 1_047_576  # Conservative full documented context, not a token estimate.
OUTPUT_LIMIT = 1024
CONFIG = protocol.OpenAIConfig(MODEL, OUTPUT_LIMIT)
MAX_REQUEST_BYTES = protocol.MAX_REQUEST_BYTES
MAX_RESPONSE_BYTES = protocol.MAX_RESPONSE_BYTES
OUTPUT_STATUSES = frozenset({"proposal", "refusal", "incomplete", "invalid"})


def encode(value):
    return protocol._encode(value)


def validate_observation(raw):
    """Accept only the released three-step shape, never an evidence candidate."""
    try:
        value = protocol._decode_object(raw, protocol.MAX_OBSERVATION_BYTES)
        if (set(value) != {"step", "untrusted_observation"}
                or type(value["step"]) is not int or value["step"] not in (1, 2, 3)):
            raise ValueError
        previous = value["untrusted_observation"]
        if value["step"] == 1:
            if previous is not None:
                raise ValueError
        else:
            if (type(previous) is not dict or set(previous) != {"execution_status", "body"}
                    or previous["execution_status"] != "succeeded" or type(previous["body"]) is not str
                    or not 1 <= len(previous["body"].encode("utf-8")) <= 1024):
                raise ValueError
            body = protocol._decode_object(previous["body"].encode("utf-8"), 1024)
            if value["step"] == 2 and encode(body) != encode({
                "tool_id": "nmap_tcp_connect_v1", "results": [
                    {"target": "127.0.0.1", "port": 8080, "state": "open"}]}):
                raise ValueError
        return encode(value)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        raise ValueError("web_model_observation_invalid") from None


def release_observation(case, step, records, authority_observation):
    """Gate on the existing evidence workflow and release only prior tool facts.

    The host-only import is deliberately lazy: transport/parser workers need
    only this module's pure request/response contract, never the evidence stack.
    """
    from .web_workflow import decide

    try:
        decision = decide(case, step, records, authority_observation)
        if decision.decision_kind != "propose":
            raise ValueError
        frame = protocol._decode_object(protocol._observation(authority_observation).encode("ascii"),
                                        protocol.MAX_OBSERVATION_BYTES)
        if (frame["step"] != step or (step == 1) != (frame["untrusted_observation"] is None)
                or step > 1 and frame["untrusted_observation"]["execution_status"] != "succeeded"):
            raise ValueError
        if step == 2:
            frame = {"step": 2, "untrusted_observation": {"execution_status": "succeeded",
                "body": encode({"tool_id": "nmap_tcp_connect_v1", "results": [
                    {"target": "127.0.0.1", "port": 8080, "state": "open"}]}).decode("ascii")}}
        return validate_observation(encode(frame))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        raise ValueError("web_model_release_invalid") from None


def build_request(released):
    return protocol.build_request(CONFIG, released, profile=WEB_MODEL_PROFILE)


def validate_request(raw):
    """Rebuild the entire fixed body and require exact canonical request bytes."""
    try:
        value = protocol._decode_object(raw, MAX_REQUEST_BYTES)
        released = value["input"][1]["content"][0]["text"].encode("ascii")
        if build_request(released) != raw:
            raise ValueError
        return raw
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, UnicodeError):
        raise ValueError("web_model_request_invalid") from None


def response_status(value):
    """Classify only the bounded output envelope, never the action text."""
    try:
        required = {"object", "model", "service_tier", "status", "error", "incomplete_details", "output"}
        if (type(value) is not dict or not required <= set(value)
                or value.get("object") != "response" or value.get("model") != MODEL
                or value.get("service_tier") != "default" or value.get("error") is not None):
            raise ValueError
        if value.get("status") == "incomplete":
            return "incomplete"
        if value.get("status") != "completed" or value.get("incomplete_details") is not None:
            raise ValueError
        output = value["output"]
        if type(output) is not list or len(output) != 1:
            raise ValueError
        message = output[0]
        if (type(message) is not dict or message.get("type") != "message"
                or message.get("role") != "assistant" or message.get("status") != "completed"):
            raise ValueError
        content = message["content"]
        if type(content) is not list or len(content) != 1 or type(content[0]) is not dict:
            raise ValueError
        block = content[0]
        kind = block.get("type")
        key = "text" if kind == "output_text" else "refusal" if kind == "refusal" else None
        if (key is None or type(block.get(key)) is not str
                or len(block[key].encode("utf-8")) > protocol.MAX_PROPOSAL_BYTES):
            raise ValueError
        return "proposal" if kind == "output_text" else "refusal"
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        return "invalid"


def response_summary(value):
    """Recognize priced usage independently of refused or malformed output.

    Provider identifiers are returned solely as the existing hashed settlement
    reference. Missing billing dimensions keep usage unknown, even for an
    otherwise valid proposal. Recognized usage never authorizes an action.
    """
    from .provider_pilot_contract import response_summary as priced_summary

    priced = priced_summary(value)
    return {"usage": priced["usage"], "reference": priced["reference"],
            "output_status": response_status(value)}


def decode_response(raw):
    return protocol.decode_response(raw, profile=WEB_MODEL_PROFILE)
