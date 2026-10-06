"""Bounded identities and continuity for two isolated declared endpoint fixtures."""

import copy
import hashlib
import json
import re
from uuid import UUID

from .configurable_scope import endpoint, scope_digest, validate_scope, witness_addresses

LAB_ID = "owned-configurable-endpoint-lab"
ASSESSMENT_ID = "owned-configurable-assessment-lab"
LAB_VERSION = "1"
MAX_CONNECTIONS = {"http": 4, "ssh": 3}
MAX_REQUESTS = 2


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def spec(scope, endpoint_name):
    scope = validate_scope(scope)
    selected = endpoint(scope, endpoint_name)
    from . import http_headers_fixture as headers, network_tools_fixture as network
    return {"id": LAB_ID, "version": LAB_VERSION, "scope_sha256": scope_digest(scope),
        "endpoint": endpoint_name, "service": selected,
        "witnesses": [list(pair) for pair in witness_addresses(scope, endpoint_name)],
        "data": "public_synthetic_fixture_only", "external_egress": False, "resume": False,
        "topology": "one_disconnected_namespace_per_endpoint",
        "lifetime": "authority_session", "max_connections": MAX_CONNECTIONS[endpoint_name],
        "max_requests": MAX_REQUESTS, "counter_semantics": "last_acknowledged_service_totals",
        "phases": ["nmap_service", "http_headers" if endpoint_name == "http" else "ssh_host_key"],
        "nmap_response_sha256": hashlib.sha256(network.NMAP_SERVICE_HTTP if endpoint_name == "http"
                                                 else network.NMAP_SERVICE_SSH).hexdigest(),
        "followup_public_material_sha256": hashlib.sha256(headers.PORTAL_BODY + headers.BASE_HEADERS).hexdigest()
            if endpoint_name == "http" else hashlib.sha256(network.SSH_PUBLIC_BLOB).hexdigest(),
        "authentication": False, "shell": False, "real_credentials": False}


def identity(scope, endpoint_name, instance_id):
    selected = endpoint(scope, endpoint_name)
    try:
        valid = type(instance_id) is str and str(UUID(instance_id)) == instance_id
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("invalid_configurable_lab_instance")
    return {"id": LAB_ID, "version": LAB_VERSION, "scope_sha256": scope_digest(scope),
        "endpoint": endpoint_name, "target": selected["target"], "port": selected["port"],
        "spec_sha256": hashlib.sha256(_encode(spec(scope, endpoint_name))).hexdigest(),
        "instance_id": instance_id}


def validate_identity(value, *, scope=None, endpoint_name=None):
    if (type(value) is not dict or set(value) != {"id", "version", "scope_sha256", "endpoint",
            "target", "port", "spec_sha256", "instance_id"}
            or value["id"] != LAB_ID or value["version"] != LAB_VERSION
            or type(value["endpoint"]) is not str or value["endpoint"] not in MAX_CONNECTIONS
            or (endpoint_name is not None and value["endpoint"] != endpoint_name)
            or any(type(value[key]) is not str or not re.fullmatch(r"[a-f0-9]{64}", value[key])
                   for key in ("scope_sha256", "spec_sha256"))):
        raise ValueError("invalid_configurable_lab_identity")
    try:
        valid = type(value["instance_id"]) is str and str(UUID(value["instance_id"])) == value["instance_id"]
    except (ValueError, TypeError, AttributeError):
        valid = False
    # Validate endpoint syntax using the same full scope validator, even when
    # only matching a previously trusted identity rather than reconstructing it.
    validate_scope({"schema_version": "1", "scope_id": "identity-validation",
        "http": {"target": value["target"], "port": value["port"], "path": "/"},
        "ssh": {"target": value["target"], "port": 1024 if value["port"] != 1024 else 1025}})
    if not valid or (scope is not None and value != identity(scope, value["endpoint"], value["instance_id"])):
        raise ValueError("invalid_configurable_lab_identity")
    return copy.deepcopy(value)


def validate_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or type(value["connection_count"]) is not int
            or not 0 <= value["connection_count"] <= MAX_CONNECTIONS[expected["endpoint"]]
            or type(value["request_count"]) is not int
            or not 0 <= value["request_count"] <= MAX_REQUESTS
            or value["request_count"] > value["connection_count"]):
        raise ValueError("invalid_configurable_lab_context")
    return copy.deepcopy(value)


def validate_closure(value, expected, *, previous=None):
    if (type(value) is not dict or set(value) != {"identity", "status", "connection_count", "request_count"}
            or value["status"] != "closed"):
        raise ValueError("invalid_configurable_lab_closure")
    context = validate_context({key: item for key, item in value.items() if key != "status"}, expected)
    before = {"identity": expected, "connection_count": 0, "request_count": 0} if previous is None else previous
    if context != validate_context(before, expected):
        raise ValueError("configurable_lab_closure_mismatch")
    return copy.deepcopy(value)


def assessment_identity(scope, endpoints):
    scope = validate_scope(scope)
    if type(endpoints) is not dict or set(endpoints) != {"http", "ssh"}:
        raise ValueError("invalid_configurable_assessment_endpoints")
    fixed = {name: validate_identity(endpoints[name], scope=scope, endpoint_name=name) for name in ("http", "ssh")}
    if fixed["http"]["instance_id"] == fixed["ssh"]["instance_id"]:
        raise ValueError("configurable_endpoint_instances_must_differ")
    return {"id": ASSESSMENT_ID, "version": LAB_VERSION, "scope": scope,
            "scope_sha256": scope_digest(scope), "endpoints": fixed}


def validate_assessment_identity(value, *, scope=None):
    if (type(value) is not dict or set(value) != {"id", "version", "scope", "scope_sha256", "endpoints"}
            or value != assessment_identity(value["scope"], value["endpoints"])
            or (scope is not None and value["scope"] != validate_scope(scope))):
        raise ValueError("invalid_configurable_assessment_identity")
    return copy.deepcopy(value)


def validate_assessment_closure(value, expected, *, previous=None):
    expected = validate_assessment_identity(expected)
    if previous is not None and type(previous) is dict and set(previous) == {"identity", "step", "endpoints"}:
        if (previous["identity"] != expected or type(previous["step"]) is not int
                or not 0 <= previous["step"] <= 4):
            raise ValueError("invalid_configurable_assessment_previous")
        previous = previous["endpoints"]
    if (type(value) is not dict or set(value) != {"identity", "status", "endpoints"}
            or value["status"] != "closed" or value["identity"] != expected
            or type(value["endpoints"]) is not dict or set(value["endpoints"]) != {"http", "ssh"}
            or (previous is not None and (type(previous) is not dict or set(previous) != {"http", "ssh"}))):
        raise ValueError("invalid_configurable_assessment_closure")
    for name in ("http", "ssh"):
        validate_closure(value["endpoints"][name], expected["endpoints"][name],
                         previous=None if previous is None else previous[name])
    return copy.deepcopy(value)
