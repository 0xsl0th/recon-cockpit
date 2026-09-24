"""Bounded repository-owned lab identity and continuity evidence.

The deterministic scenario is the seed. Identity describes one disposable
runtime; it is neither an attachment token nor permission to launch anything.
"""

from __future__ import annotations

import copy
import hashlib
import json
from uuid import UUID

from .assessment_contract import CASES, FIXTURE_MARKER


LAB_ID = "owned-http-assessment-lab"
LAB_VERSION = "1"
BACKEND = "linux-authorized-owned-lab-executor-v1"


def capability_descriptor():
    from .discovery_contract import capability_descriptor as discovery_descriptor

    value = discovery_descriptor()
    value["workflow_id"] = "owned-lab-workflow-assessment-v1"
    value["capabilities"][0]["isolation"] = BACKEND
    value["capabilities"][1]["isolation"]["executor"] = BACKEND
    value["owned_lab"] = {"id": LAB_ID, "version": LAB_VERSION,
                          "lifetime": "authority_session", "resume": False}
    return value


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def spec(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_owned_lab_scenario")
    return {
        "id": LAB_ID, "version": LAB_VERSION, "scenario": case,
        "fixture_marker": FIXTURE_MARKER,
        "topology": [{"service_id": "assessment-http", "target": "127.0.0.1",
                      "port": 8080, "protocol": "http-over-tcp"}],
        "lifetime": "authority_session", "reset": "destroy_and_create_new_instance",
        "counter_semantics": "last_acknowledged_service_totals",
        "external_egress": False, "resume": False,
    }


def identity(case, instance_id):
    definition = spec(case)
    if type(instance_id) is not str or str(UUID(instance_id)) != instance_id:
        raise ValueError("invalid_owned_lab_instance")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "spec_sha256": hashlib.sha256(_encode(definition)).hexdigest(),
            "instance_id": instance_id}


def validate_identity(value, *, case=None):
    if type(value) is not dict or set(value) != {"id", "version", "scenario", "spec_sha256", "instance_id"}:
        raise ValueError("invalid_owned_lab_identity")
    expected = identity(value["scenario"], value["instance_id"])
    if _encode(value) != _encode(expected) or (case is not None and value["scenario"] != case):
        raise ValueError("invalid_owned_lab_identity")
    return copy.deepcopy(expected)


def validate_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or any(type(value[key]) is not int or not 0 <= value[key] <= 16
                   for key in ("connection_count", "request_count"))
            or value["request_count"] > value["connection_count"]):
        raise ValueError("invalid_owned_lab_context")
    return copy.deepcopy(value)


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    if type(result) is not dict or result.get("backend") != BACKEND:
        raise ValueError("invalid_owned_lab_result")
    context = validate_context(result.get("owned_lab"), expected)
    before = {"connection_count": 0, "request_count": 0} if previous is None else validate_context(previous, expected)
    connections = context["connection_count"] - before["connection_count"]
    requests = context["request_count"] - before["request_count"]
    if (tool_id not in {"tcp_connect", "http_probe"} or not 0 <= connections <= 1
            or not 0 <= requests <= (1 if tool_id == "http_probe" else 0)
            or (execution_status == "succeeded" and (connections != 1 or requests != (tool_id == "http_probe")))):
        raise ValueError("owned_lab_continuity_mismatch")
    return context


def validate_closure(value, expected, *, previous=None):
    """Bind verified process destruction to the last acknowledged observation.

    The trusted lifecycle owner produces the receipt only after successful
    teardown. Counts retain its last checked service acknowledgement; they are
    not a final post-destruction sample and may undercount incomplete actions.
    An expired control is never replaced just to obtain another observation.
    """
    if type(value) is not dict or set(value) != {"identity", "status", "connection_count", "request_count"} or value["status"] != "closed":
        raise ValueError("invalid_owned_lab_closure")
    context = validate_context({key: item for key, item in value.items() if key != "status"}, expected)
    before = {"identity": expected, "connection_count": 0, "request_count": 0} if previous is None else previous
    if context != validate_context(before, expected):
        raise ValueError("owned_lab_closure_mismatch")
    return copy.deepcopy(value)
