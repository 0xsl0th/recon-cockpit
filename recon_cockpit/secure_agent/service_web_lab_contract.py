"""Identity and finite continuity for the persistent owned service/web fixture."""

from __future__ import annotations

import copy
import hashlib
import json
from uuid import UUID

from .http_headers_fixture import PORTAL_PATH
from .service_web_fixture import (
    CASES, FIXTURE_MARKER, FFUF_PATHS, MAX_CONNECTIONS, MAX_REQUESTS, wire_response,
)


LAB_ID = "harbordesk-owned-service-web-lab"
LAB_VERSION = "1"
BACKEND = "linux-authorized-owned-service-web-executor-v1"


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def spec(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_service_web_lab_scenario")
    routes = [{"phase": phase, "method": "GET", "path": path,
               "response_sha256": hashlib.sha256(wire_response(case, phase, path)).hexdigest()}
              for phase, paths in (("nmap", ("/",)), ("ffuf", FFUF_PATHS), ("headers", (PORTAL_PATH,)))
              for path in paths]
    return {
        "id": LAB_ID, "version": LAB_VERSION, "scenario": case,
        "fixture_marker": FIXTURE_MARKER,
        "topology": [{"service_id": "harbordesk-service-web", "target": "127.0.0.1",
                      "port": 8080, "protocol": "http-over-tcp"}],
        "routes": routes, "data": "seeded_synthetic_http_only",
        "phase_order": ["nmap", "ffuf", "headers"],
        "nmap_empty_connections": {"minimum": 1, "maximum": 2},
        "ffuf_path_order": "each_fixed_path_once",
        "max_connections": MAX_CONNECTIONS, "max_requests": MAX_REQUESTS,
        "lifetime": "authority_session", "reset": "destroy_and_create_new_instance",
        "counter_semantics": "last_acknowledged_service_totals",
        "connection_evidence": "accepted_connections_lower_bound",
        "external_egress": False, "resume": False,
    }


def identity(case, instance_id):
    definition = spec(case)
    try:
        valid = type(instance_id) is str and str(UUID(instance_id)) == instance_id
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("invalid_service_web_lab_instance")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "spec_sha256": hashlib.sha256(_encode(definition)).hexdigest(),
            "instance_id": instance_id}


def validate_identity(value, *, case=None):
    if type(value) is not dict or set(value) != {"id", "version", "scenario", "spec_sha256", "instance_id"}:
        raise ValueError("invalid_service_web_lab_identity")
    expected = identity(value["scenario"], value["instance_id"])
    if _encode(value) != _encode(expected) or (case is not None and value["scenario"] != case):
        raise ValueError("invalid_service_web_lab_identity")
    return copy.deepcopy(expected)


def validate_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or type(value["connection_count"]) is not int
            or not 0 <= value["connection_count"] <= MAX_CONNECTIONS
            or type(value["request_count"]) is not int
            or not 0 <= value["request_count"] <= MAX_REQUESTS
            or value["request_count"] > value["connection_count"]):
        raise ValueError("invalid_service_web_lab_context")
    return copy.deepcopy(value)


def validate_closure(value, expected, *, previous=None):
    """Destruction acknowledges the same totals; it cannot add evidence or work."""
    if (type(value) is not dict or set(value) != {"identity", "status", "connection_count", "request_count"}
            or value["status"] != "closed"):
        raise ValueError("invalid_service_web_lab_closure")
    context = validate_context({key: item for key, item in value.items() if key != "status"}, expected)
    before = {"identity": expected, "connection_count": 0, "request_count": 0} if previous is None else previous
    if context != validate_context(before, expected):
        raise ValueError("service_web_lab_closure_mismatch")
    return copy.deepcopy(value)
