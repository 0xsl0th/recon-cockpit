"""Authority identity for the fixed owned twelve-path HTTP hierarchy fixture."""

import copy
import hashlib
import json
import re
from uuid import UUID

from .network_tools_web_hierarchy_spec import (
    case_parts, tool_for_case, MAX_OWNER_BYTES, MAX_CONNECTIONS, PATHS, PREFIXES, WORDLIST,
)

LAB_ID = "harbordesk-owned-network-tools-lab"
LAB_VERSION = "1"

# Compiled public wire commitments keep the client/inspector identity pure.
# Focused tests compare every entry with the actual owner fixture bytes.
_RESPONSE_HASHES = {'nested': {'/harbordesk/index.html': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
            '/harbordesk/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/docs/index.html': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
            '/harbordesk/docs/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/docs/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/docs/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/api/index.html': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/api/status': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
            '/harbordesk/api/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
            '/harbordesk/api/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1'},
 'empty': {'/harbordesk/index.html': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/docs/index.html': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/docs/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/docs/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/docs/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/api/index.html': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/api/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/api/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
           '/harbordesk/api/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1'},
 'wildcard': {'/harbordesk/index.html': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/status': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/missing-control-a': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/missing-control-b': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/docs/index.html': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/docs/status': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/docs/missing-control-a': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/docs/missing-control-b': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/api/index.html': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/api/status': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/api/missing-control-a': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6',
              '/harbordesk/api/missing-control-b': '3ce33a1e1a27a0886458002f33ab1500531733d66f88fccb41541295a197d5d6'},
 'mixed-controls': {'/harbordesk/index.html': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
                    '/harbordesk/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
                    '/harbordesk/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
                    '/harbordesk/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
                    '/harbordesk/docs/index.html': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
                    '/harbordesk/docs/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
                    '/harbordesk/docs/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
                    '/harbordesk/docs/missing-control-b': '850c12aa7dd419ca907288cea166bf980dd5073d3da15ed8601736f3d729e95b',
                    '/harbordesk/api/index.html': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
                    '/harbordesk/api/status': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
                    '/harbordesk/api/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
                    '/harbordesk/api/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1'},
 'redirect': {'/harbordesk/index.html': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
              '/harbordesk/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/docs/index.html': '2ca80f10c6b71466b7ee85e5a3a743ceae918ce82b00e39ad87f2838382fb64d',
              '/harbordesk/docs/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/docs/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/docs/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/api/index.html': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/api/status': '8d01250eb25e48a25b6cd2348b517e2000b587812438819ec22e36122d4a3825',
              '/harbordesk/api/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
              '/harbordesk/api/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1'},
 'hostile': {'/harbordesk/index.html': '55005a551466d31cadc872e91fb7fe24b2f49ee654c29aa6fbd14e421d1456d9',
             '/harbordesk/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/docs/index.html': '55005a551466d31cadc872e91fb7fe24b2f49ee654c29aa6fbd14e421d1456d9',
             '/harbordesk/docs/status': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/docs/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/docs/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/api/index.html': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/api/status': '55005a551466d31cadc872e91fb7fe24b2f49ee654c29aa6fbd14e421d1456d9',
             '/harbordesk/api/missing-control-a': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1',
             '/harbordesk/api/missing-control-b': '3415194fe9fb643e0d761a918de9d509997dc984439ab172900693d1bdf9a4f1'},
 'stalled': {'/harbordesk/index.html': None,
             '/harbordesk/status': None,
             '/harbordesk/missing-control-a': None,
             '/harbordesk/missing-control-b': None,
             '/harbordesk/docs/index.html': None,
             '/harbordesk/docs/status': None,
             '/harbordesk/docs/missing-control-a': None,
             '/harbordesk/docs/missing-control-b': None,
             '/harbordesk/api/index.html': None,
             '/harbordesk/api/status': None,
             '/harbordesk/api/missing-control-a': None,
             '/harbordesk/api/missing-control-b': None}}


def spec(case):
    variant = case_parts(case)
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
        "fixture_marker": "recon-harbordesk-web-hierarchy-v1", "tool_id": tool_for_case(case),
        "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "http"}],
        "behavior": variant, "method": "GET", "paths": list(PATHS), "prefixes": list(PREFIXES),
        "wordlist_sha256": hashlib.sha256(WORDLIST).hexdigest(),
        "responses": dict(_RESPONSE_HASHES[variant]),
        "max_connections": MAX_CONNECTIONS, "max_requests": len(PATHS), "max_active_requests": 1,
        "max_recorded_request_attempts": MAX_CONNECTIONS,
        "connection_evidence": "accepted_connections_lower_bound_with_bounded_request_ledger",
        "request_count_means": "recorded_request_attempts_including_invalid_or_duplicate_paths",
        "counter_semantics": "last_acknowledged_service_totals",
        "owner_snapshot": "single_sequence_1_original_management_line",
        "max_request_bytes": 1024, "max_response_bytes": 1024,
        "max_owner_receipt_bytes": MAX_OWNER_BYTES, "max_session_seconds": 60,
        "max_client_seconds": 10, "max_output_bytes": 8192,
        "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
        "reset": "destroy_and_create_new_instance", "external_egress": False,
        "resume": False, "credentials": False, "redirects": False,
        "recursion": False, "followup": False, "vulnerability_claim": False}


def identity(case, instance_id):
    definition = spec(case)
    if type(instance_id) is not str or str(UUID(instance_id)) != instance_id:
        raise ValueError("invalid_web_hierarchy_lab_instance")
    raw = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "instance_id": instance_id, "spec_sha256": hashlib.sha256(raw).hexdigest()}


def validate_identity(value, *, case=None):
    if type(value) is not dict or set(value) != {"id", "version", "scenario", "instance_id", "spec_sha256"}:
        raise ValueError("invalid_web_hierarchy_lab_identity")
    expected = identity(value["scenario"], value["instance_id"])
    if value != expected or case is not None and value["scenario"] != case:
        raise ValueError("invalid_web_hierarchy_lab_identity")
    return expected


def validate_counter_context(value, expected):
    expected = validate_identity(expected)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or type(value["connection_count"]) is not int
            or not 0 <= value["connection_count"] <= MAX_CONNECTIONS
            or type(value["request_count"]) is not int
            or not 0 <= value["request_count"] <= value["connection_count"]):
        raise ValueError("invalid_web_hierarchy_lab_context")
    return copy.deepcopy(value)


def validate_context(value, expected):
    if (type(value) is not dict
            or set(value) != {"identity", "connection_count", "request_count", "web_hierarchy_owner_sha256"}
            or type(value["web_hierarchy_owner_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", value["web_hierarchy_owner_sha256"]) is None):
        raise ValueError("invalid_web_hierarchy_lab_context")
    validate_counter_context({key: item for key, item in value.items()
                              if key != "web_hierarchy_owner_sha256"}, expected)
    return copy.deepcopy(value)
