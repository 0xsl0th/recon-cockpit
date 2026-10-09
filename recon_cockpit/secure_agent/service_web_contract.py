"""Three fixed existing capabilities in a separately reviewed owned workflow.

Evidence permits a proposal, never authority. The original single-tool actions,
runtime profiles and parsers retain their own limits and serialized contracts.
"""

from __future__ import annotations

import json
from uuid import NAMESPACE_URL, uuid5

from .models import Action, parse_action
from .tool_adapters import (NMAP_SERVICE_TOOL_ID, FFUF_TOOL_ID, HTTP_HEADERS_TOOL_ID,
                            NMAP_SERVICE_PARAMETERS, FFUF_PARAMETERS, HTTP_HEADERS_PARAMETERS,
                            get_adapter)
from .service_web_lab_contract import (BACKEND, CASES, validate_identity,
                                       validate_context, validate_closure)


PROFILE = "owned_service_web_lab"
WORKFLOW = "owned-service-web-assessment-v1"
TOOL_ID = NMAP_SERVICE_TOOL_ID
DISCOVERY_TOOL_ID = FFUF_TOOL_ID
HTTP_TOOL_ID = HTTP_HEADERS_TOOL_ID
TOOL_IDS = (TOOL_ID, DISCOVERY_TOOL_ID, HTTP_TOOL_ID)
LIMITS = {"max_steps": 3, "max_runtime_seconds": 60, "max_output_bytes": 18432}
PARAMETERS = {TOOL_ID: dict(NMAP_SERVICE_PARAMETERS), DISCOVERY_TOOL_ID: dict(FFUF_PARAMETERS),
              HTTP_TOOL_ID: dict(HTTP_HEADERS_PARAMETERS)}
OUTPUT_RESERVATIONS = (0, 8192, 16384, 18432)
REQUEST_TOTALS = (0, 1, 9, 10)
PARSER_VERSIONS = {tool_id: get_adapter(tool_id).parser_version for tool_id in TOOL_IDS}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def action_step(tool_id):
    if type(tool_id) is not str or tool_id not in TOOL_IDS:
        raise ValueError("invalid_service_web_tool")
    return TOOL_IDS.index(tool_id) + 1


def action(case, step):
    if (type(case) is not str or case not in CASES or type(step) is not int
            or step not in (1, 2, 3)):
        raise ValueError("invalid_service_web_step")
    tool_id = TOOL_IDS[step - 1]
    return parse_action({"schema_version": "1",
        "action_id": str(uuid5(NAMESPACE_URL, WORKFLOW + ":" + case + ":" + str(step))),
        "tool_id": tool_id, "target": "127.0.0.1", "parameters": dict(PARAMETERS[tool_id]),
        "rationale": "DETERMINISTIC OWNED SERVICE WEB WORKFLOW: observe the fixed scoped service and portal."}).to_dict()


def profile_allows(value, case):
    return (type(value) is Action and type(case) is str and case in CASES
            and value.target == "127.0.0.1" and value.tool_id in TOOL_IDS
            and value.parameters.to_dict() == PARAMETERS[value.tool_id])


def capability_descriptor():
    from .web_tools_fixture import HTTP_BASE, WORDS

    return {"schema_version": "1", "workflow_id": WORKFLOW,
        "capabilities": [get_adapter(tool_id).to_dict() for tool_id in TOOL_IDS],
        "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
        "limits": dict(LIMITS), "live_calls_enabled": False,
        "planning": "deterministic_offline",
        "steps": [{"step": step, "tool_id": tool_id, "parameters": dict(PARAMETERS[tool_id])}
                  for step, tool_id in enumerate(TOOL_IDS, start=1)],
        "service_probes": ["NULL", "GetRequest"],
        "discovery_paths": [HTTP_BASE + word for word in WORDS],
        "header_path": PARAMETERS[HTTP_TOOL_ID]["path"],
        "parser_versions": dict(PARSER_VERSIONS),
        "followup_selection": "fixed_portal_only_after_complete_reviewed_predecessor_evidence",
        "arbitrary_metadata_followup": False}


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    """Bind each result to the same lab and its finite ordered query budget."""
    expected = validate_identity(expected)
    step = action_step(tool_id)
    if (type(result) is not dict or result.get("backend") != BACKEND
            or execution_status not in ("succeeded", "failed", "timeout", "output_limit")
            or result.get("status") != execution_status):
        raise ValueError("invalid_service_web_result")
    context = validate_context(result.get("owned_lab"), expected)
    if previous is None:
        if step != 1:
            raise ValueError("service_web_predecessor_context_missing")
        before = {"identity": expected, "connection_count": 0, "request_count": 0}
    else:
        if step == 1:
            raise ValueError("service_web_initial_context_replayed")
        before = validate_context(previous, expected)
        if (before["request_count"] != REQUEST_TOTALS[step - 1]
                or not REQUEST_TOTALS[step - 1] + 1 <= before["connection_count"]
                       <= REQUEST_TOTALS[step - 1] + 2):
            raise ValueError("service_web_predecessor_context_invalid")
    requests = context["request_count"] - before["request_count"]
    connections = context["connection_count"] - before["connection_count"]
    maximum = REQUEST_TOTALS[step] - REQUEST_TOTALS[step - 1]
    if (not 0 <= requests <= maximum or not requests <= connections <= (3 if step == 1 else maximum)
            or context["request_count"] > REQUEST_TOTALS[step]):
        raise ValueError("service_web_result_continuity_mismatch")
    complete = (execution_status == "succeeded" and (
        tool_id == HTTP_TOOL_ID or result.get("tool_observation") is not None))
    if complete and (requests != maximum or (step == 1 and connections not in (2, 3))):
        raise ValueError("service_web_complete_request_count_mismatch")
    return context


def parse_observation(value, result, *, execution_status):
    """Use unchanged observations; raw replay remains the separate evidence gate."""
    tool_id = value.get("tool_id") if type(value) is dict else None
    if tool_id == TOOL_ID:
        from .network_tools_contract import parse_observation as parse
    elif tool_id == DISCOVERY_TOOL_ID:
        from .web_tools_contract import parse_observation as parse
    elif tool_id == HTTP_TOOL_ID:
        from .http_headers_contract import parse_observation as parse
    else:
        raise ValueError("invalid_service_web_observation_tool")
    return parse(value, result, execution_status=execution_status)


def predecessor_gate(step, observation):
    """Accept only complete typed observations for the next fixed proposal."""
    if type(step) is not int or step not in (1, 2) or type(observation) is not dict:
        return False
    try:
        if step == 1:
            from .network_tools_contract import classify_tool

            details = observation.get("details")
            return (observation == classify_tool(TOOL_ID, details)
                    and details["identification"] == "identified"
                    and details["service"]["name"] == "http")
        from .web_tools_contract import classify_tool

        details = observation.get("details")
        return (observation == classify_tool(DISCOVERY_TOOL_ID, details)
                and details["coverage"] == "complete" and details["baseline"] == "not_found"
                and any(row["path"] == PARAMETERS[HTTP_TOOL_ID]["path"] and row["status_code"] == 200
                        for row in details["responses"]))
    except (ValueError, TypeError, KeyError):
        return False


def terminal_header_reason(observation):
    from .http_headers_contract import classify_headers

    try:
        if (type(observation) is dict and observation == classify_headers(observation.get("headers"))
                and observation["classification"] in ("gaps_observed", "no_gaps_observed")):
            return observation["reason"]
    except (ValueError, TypeError, KeyError):
        pass
    return "http_header_evidence_invalid"
