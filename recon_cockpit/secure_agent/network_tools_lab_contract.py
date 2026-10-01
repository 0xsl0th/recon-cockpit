"""Identity and continuity for the fixed disconnected DNS/TLS fixtures."""

import copy
import hashlib
import json
from uuid import UUID

from .network_tools_fixture import (CASES, CA_PEM, FIXTURE_MARKER, QUERY_NAME, TLS_NAME,
    SERVER_CERT_SHA256, UNTRUSTED_SERVER_CERT_SHA256, TLS_MALFORMED_BYTES,
    dns_query, dns_response, tool_for_case)

LAB_ID = "harbordesk-owned-network-tools-lab"
LAB_VERSION = "1"
BACKEND = "linux-authorized-owned-network-tools-executor-v1"


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def spec(case):
    tool = tool_for_case(case)
    dns = case.startswith("dig-")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
        "fixture_marker": FIXTURE_MARKER, "tool_id": tool,
        "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "dns_tcp" if dns else "tls"}],
        "query": {"name": QUERY_NAME, "type": "A", "class": "IN", "recursion": False} if dns else None,
        "response_sha256": hashlib.sha256(dns_response(case, dns_query())).hexdigest() if dns else None,
        "dns_transaction_id": "copied_from_validated_question" if dns else None,
        "tls_name": None if dns else TLS_NAME,
        "tls_protocol": None if dns else "TLSv1.3",
        "ca_sha256": None if dns else hashlib.sha256(CA_PEM).hexdigest(),
        "certificate_sha256": None if dns else (UNTRUSTED_SERVER_CERT_SHA256
            if case == "openssl-untrusted" else SERVER_CERT_SHA256),
        "malformed_tls_sha256": hashlib.sha256(TLS_MALFORMED_BYTES).hexdigest() if case == "openssl-malformed" else None,
        "behavior": "stall_before_response" if case.endswith("-stalled") else "fixed_response",
        "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
        "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
        "counter_semantics": "last_acknowledged_service_totals",
        "request_count_means": "validated_dns_questions" if dns else "server_completed_tls_handshakes",
        "application_payloads": "fixed_dns_question" if dns else "none",
        "connection_evidence": "accepted_connections_lower_bound"}


def identity(case, instance_id):
    definition = spec(case)
    if type(instance_id) is not str or str(UUID(instance_id)) != instance_id:
        raise ValueError("invalid_network_tools_lab_instance")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case, "instance_id": instance_id,
            "spec_sha256": hashlib.sha256(_encode(definition)).hexdigest()}


def validate_identity(value, *, case=None):
    if type(value) is not dict or set(value) != {"id", "version", "scenario", "instance_id", "spec_sha256"}:
        raise ValueError("invalid_network_tools_lab_identity")
    expected = identity(value["scenario"], value["instance_id"])
    if value != expected or (case is not None and value["scenario"] != case):
        raise ValueError("invalid_network_tools_lab_identity")
    return copy.deepcopy(expected)


def validate_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or any(type(value[k]) is not int or not 0 <= value[k] <= 1 for k in ("connection_count", "request_count"))
            or value["request_count"] > value["connection_count"]):
        raise ValueError("invalid_network_tools_lab_context")
    return copy.deepcopy(value)


def validate_closure(value, expected, *, previous=None):
    if (type(value) is not dict or set(value) != {"identity", "status", "connection_count", "request_count"}
            or value["status"] != "closed"):
        raise ValueError("invalid_network_tools_lab_closure")
    context = validate_context({k: v for k, v in value.items() if k != "status"}, expected)
    before = {"identity": expected, "connection_count": 0, "request_count": 0} if previous is None else previous
    if context != validate_context(before, expected):
        raise ValueError("network_tools_lab_closure_mismatch")
    return copy.deepcopy(value)
