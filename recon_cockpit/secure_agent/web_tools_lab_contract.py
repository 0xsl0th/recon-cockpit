"""Pure identity and continuity for independent owned web-tool actions."""

import copy
import hashlib
import json
from uuid import UUID

from .web_tools_fixture import (CASES, CA_PEM, FIXTURE_MARKER, HTTP_BASE, PATH_WORDLIST_BYTES,
                                PORTAL_PATH, TLS_NAME, WORDS, SERVER_CERT_SHA256,
                                UNTRUSTED_SERVER_CERT_SHA256, tool_for_case, wire_response)

LAB_ID = "harbordesk-owned-web-tools-lab"
LAB_VERSION = "1"
BACKEND = "linux-authorized-owned-web-tools-executor-v1"


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def spec(case):
    tool = tool_for_case(case)
    paths = (PORTAL_PATH,) if case.startswith("curl-") else tuple(HTTP_BASE + word for word in WORDS)
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": FIXTURE_MARKER, "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080,
                          "protocol": "https" if case.startswith("curl-") else "http"}],
            "tls_name": TLS_NAME if case.startswith("curl-") else None,
            "ca_sha256": hashlib.sha256(CA_PEM).hexdigest() if case.startswith("curl-") else None,
            "certificate": "untrusted" if case == "curl-untrusted" else "trusted" if case.startswith("curl-") else None,
            "certificate_sha256": (UNTRUSTED_SERVER_CERT_SHA256 if case == "curl-untrusted"
                                   else SERVER_CERT_SHA256 if case.startswith("curl-") else None),
            "wordlist_sha256": hashlib.sha256(PATH_WORDLIST_BYTES).hexdigest() if case.startswith("ffuf-") else None,
            "routes": [{"method": "GET", "path": path, "wire_sha256": hashlib.sha256(wire_response(case, path)).hexdigest()}
                       for path in paths],
            "behavior": "stall_after_request" if case.endswith("-stalled") else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "connection_evidence": "accepted_connections_lower_bound"}


def identity(case, instance_id):
    definition = spec(case)
    if type(instance_id) is not str or str(UUID(instance_id)) != instance_id:
        raise ValueError("invalid_web_tools_lab_instance")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "instance_id": instance_id, "spec_sha256": hashlib.sha256(_encode(definition)).hexdigest()}


def validate_identity(value, *, case=None):
    if type(value) is not dict or set(value) != {"id", "version", "scenario", "instance_id", "spec_sha256"}:
        raise ValueError("invalid_web_tools_lab_identity")
    expected = identity(value["scenario"], value["instance_id"])
    if value != expected or (case is not None and value["scenario"] != case):
        raise ValueError("invalid_web_tools_lab_identity")
    return copy.deepcopy(expected)


def validate_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or any(type(value[k]) is not int or not 0 <= value[k] <= 16 for k in ("connection_count", "request_count"))
            or value["request_count"] > value["connection_count"]):
        raise ValueError("invalid_web_tools_lab_context")
    return copy.deepcopy(value)


def validate_closure(value, expected, *, previous=None):
    if (type(value) is not dict or set(value) != {"identity", "status", "connection_count", "request_count"}
            or value["status"] != "closed"):
        raise ValueError("invalid_web_tools_lab_closure")
    context = validate_context({k: v for k, v in value.items() if k != "status"}, expected)
    before = {"identity": expected, "connection_count": 0, "request_count": 0} if previous is None else previous
    if context != validate_context(before, expected):
        raise ValueError("web_tools_lab_closure_mismatch")
    return copy.deepcopy(value)
