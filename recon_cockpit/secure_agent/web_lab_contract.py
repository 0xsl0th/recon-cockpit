"""Identity and continuity for the separate resettable HarborDesk lab profile.

The scenario and reviewed response bytes form its deterministic seed. An
identity records a disposable instance; it cannot attach to or resume one.
"""

from __future__ import annotations

import copy
import hashlib
import json
from uuid import UUID

from .web_fixture import (CASES, VARIANTS, DIAGNOSTICS_PATH, FIXTURE_MARKER,
                          INDEX_PATH, MAX_BODY_BYTES, response)


LAB_ID = "harbordesk-owned-web-lab"
LAB_VERSION = "1"
BACKEND = "linux-authorized-owned-web-lab-executor-v1"


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def spec(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_web_lab_scenario")
    routes = []
    for path in (INDEX_PATH, DIAGNOSTICS_PATH):
        status, body, headers = response(case, path)
        routes.append({"method": "GET", "path": path, "status": status,
                       "body_sha256": hashlib.sha256(body).hexdigest(),
                       "headers_sha256": hashlib.sha256(headers).hexdigest(),
                       "max_body_bytes": MAX_BODY_BYTES})
    return {
        "id": LAB_ID, "version": LAB_VERSION, "scenario": case,
        "fixture_marker": FIXTURE_MARKER,
        "topology": [{"service_id": "harbordesk-http", "target": "127.0.0.1",
                      "port": 8080, "protocol": "http-over-tcp"}],
        "routes": routes, "data": "seeded_synthetic_metadata_only",
        "lifetime": "authority_session", "reset": "destroy_and_create_new_instance",
        "counter_semantics": "last_acknowledged_service_totals",
        "connection_evidence": "accepted_connections_lower_bound",
        "external_egress": False, "resume": False,
    }


def identity(case, instance_id):
    definition = spec(case)
    if type(instance_id) is not str or str(UUID(instance_id)) != instance_id:
        raise ValueError("invalid_web_lab_instance")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "spec_sha256": hashlib.sha256(_encode(definition)).hexdigest(),
            "instance_id": instance_id}


def validate_identity(value, *, case=None):
    if type(value) is not dict or set(value) != {"id", "version", "scenario", "spec_sha256", "instance_id"}:
        raise ValueError("invalid_web_lab_identity")
    expected = identity(value["scenario"], value["instance_id"])
    if _encode(value) != _encode(expected) or (case is not None and value["scenario"] != case):
        raise ValueError("invalid_web_lab_identity")
    return copy.deepcopy(expected)


def validate_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or any(type(value[key]) is not int or not 0 <= value[key] <= 16
                   for key in ("connection_count", "request_count"))
            or value["request_count"] > value["connection_count"]):
        raise ValueError("invalid_web_lab_context")
    return copy.deepcopy(value)


def validate_closure(value, expected, *, previous=None):
    """Accept only destruction plus the last acknowledged totals, not new work."""
    if (type(value) is not dict or set(value) != {"identity", "status", "connection_count", "request_count"}
            or value["status"] != "closed"):
        raise ValueError("invalid_web_lab_closure")
    context = validate_context({key: item for key, item in value.items() if key != "status"}, expected)
    before = {"identity": expected, "connection_count": 0, "request_count": 0} if previous is None else previous
    if context != validate_context(before, expected):
        raise ValueError("web_lab_closure_mismatch")
    return copy.deepcopy(value)
