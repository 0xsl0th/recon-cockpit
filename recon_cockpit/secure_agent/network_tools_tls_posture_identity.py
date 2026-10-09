"""Pure authority identity for the fixed owned TLS posture candidate profiles."""

import copy
import hashlib
import json
import re
from uuid import UUID

from .network_tools_tls_posture_spec import case_parts, tool_for_case, MAX_OWNER_BYTES

LAB_ID = "harbordesk-owned-network-tools-lab"
LAB_VERSION = "1"


def spec(case):
    version, variant = case_parts(case)
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
        "fixture_marker": "recon-harbordesk-tls-posture-v1", "tool_id": tool_for_case(case),
        "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "tls"}],
        "tls_version": version, "behavior": variant,
        "ca_sha256": "617015dc0014927cacb2c334ed861b091ea4846b2461540aa4aac3fa2138b84d",
        "max_connections": 1, "max_requests": 1,
        "connection_evidence": "accepted_connections_lower_bound_plus_one_refused_sample",
        "request_count_means": "validated_first_client_hello_at_owned_peer",
        "counter_semantics": "last_acknowledged_service_totals",
        "mediator": "complete_client_record_before_private_peer_forwarding_v1",
        "owner_private_peer": "unnamed_socketpair", "max_client_bytes": 8192,
        "max_client_records": 8, "max_server_bytes": 32768, "max_server_records": 32,
        "max_owner_receipt_bytes": MAX_OWNER_BYTES, "max_session_seconds": 30,
        "max_connection_seconds": 5, "max_output_bytes": 8192,
        "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
        "reset": "destroy_and_create_new_instance", "external_egress": False,
        "resume": False, "credentials": False, "application_payloads": False,
        "followup": False, "vulnerability_claim": False,
        "encrypted_record_semantics_enforced": False}


def identity(case, instance_id):
    definition = spec(case)
    if type(instance_id) is not str or str(UUID(instance_id)) != instance_id:
        raise ValueError("invalid_tls_posture_lab_instance")
    raw = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "instance_id": instance_id, "spec_sha256": hashlib.sha256(raw).hexdigest()}


def validate_identity(value, *, case=None):
    if type(value) is not dict or set(value) != {"id", "version", "scenario", "instance_id", "spec_sha256"}:
        raise ValueError("invalid_tls_posture_lab_identity")
    expected = identity(value["scenario"], value["instance_id"])
    if value != expected or case is not None and value["scenario"] != case:
        raise ValueError("invalid_tls_posture_lab_identity")
    return expected


def validate_counter_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or type(value["connection_count"]) is not int or not 0 <= value["connection_count"] <= 2
            or type(value["request_count"]) is not int or not 0 <= value["request_count"] <= 1
            or value["request_count"] > value["connection_count"]):
        raise ValueError("invalid_tls_posture_lab_context")
    return copy.deepcopy(value)


def validate_context(value, expected):
    if (type(value) is not dict
            or set(value) != {"identity", "connection_count", "request_count", "tls_posture_owner_sha256"}
            or type(value["tls_posture_owner_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", value["tls_posture_owner_sha256"]) is None):
        raise ValueError("invalid_tls_posture_lab_context")
    validate_counter_context({key: item for key, item in value.items()
                              if key != "tls_posture_owner_sha256"}, expected)
    return copy.deepcopy(value)
