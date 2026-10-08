"""Fixed single-action network-tool contracts; observations confer no authority."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from uuid import NAMESPACE_URL, uuid5

from .assessment_contract import _ACTION_FIELDS
from .models import Action, parse_action
from .tool_adapters import (DIG_TOOL_ID, OPENSSL_TOOL_ID, DIG_PARAMETERS, OPENSSL_PARAMETERS,
                            SSH_TOOL_ID, LDAP_TOOL_ID, SSH_PARAMETERS, LDAP_PARAMETERS,
                            SMB_TOOL_ID, SMB_PARAMETERS, RPCINFO_TOOL_ID, SHOWMOUNT_TOOL_ID,
                            RPCINFO_PARAMETERS, SHOWMOUNT_PARAMETERS,
                            FTP_TOOL_ID, SMTP_TOOL_ID, FTP_PARAMETERS, SMTP_PARAMETERS,
                            HTTP_OPTIONS_TOOL_ID, HTTP_OPTIONS_PARAMETERS, DOCKER_PING_TOOL_ID, DOCKER_VERSION_TOOL_ID, WINRM_TOOL_ID,
                            DOCKER_PING_PARAMETERS, DOCKER_VERSION_PARAMETERS, WINRM_PARAMETERS,
                            NMAP_SERVICE_TOOL_ID, NMAP_SERVICE_PARAMETERS, KERBRUTE_TOOL_ID, KERBRUTE_PARAMETERS,
                            SSH_ALGORITHMS_TOOL_ID, SSH_ALGORITHMS_PARAMETERS, SNMP_NEXT_TOOL_ID, SNMP_NEXT_PARAMETERS, REDIS_TOOL_ID, REDIS_PARAMETERS, SNMP_TOOL_ID, SNMP_PARAMETERS,
                            POSTGRESQL_TLS_TOOL_ID, POSTGRESQL_TLS_PARAMETERS, MYSQL_TLS_TOOL_ID, MYSQL_TLS_PARAMETERS,
                            WHATWEB_TOOL_ID, WHATWEB_PARAMETERS, DIG_SRV_TOOL_ID, DIG_SRV_PARAMETERS, DIG_NSID_TOOL_ID, DIG_NSID_PARAMETERS, DIG_AXFR_TOOL_ID, DIG_AXFR_PARAMETERS, RDP_TOOL_ID, RDP_PARAMETERS, SMB2_TOOL_ID, SMB2_PARAMETERS,
                            SMTP_TLS_TOOL_ID, SMTP_TLS_PARAMETERS, LDAP_TLS_TOOL_ID, LDAP_TLS_PARAMETERS, FTP_TLS_TOOL_ID, FTP_TLS_PARAMETERS, NETWORK_TOOLS_LIMITS, get_adapter)
from .tool_adapters import TLS_CERTIFICATE_TOOL_ID, TLS_CERTIFICATE_PARAMETERS
from .network_tools_fixture import (TLS_CERTIFICATE_CASES, TLS_CERTIFICATE_SUCCESS_CASES,
    TLS_CERTIFICATE_COMPLETE_CASES, TLS_CERTIFICATE_CA_PEM)
from .network_tools_lab_contract import (BACKEND, CASES, validate_closure, validate_context,
                                     validate_identity)
from .network_tools_fixture import (QUERY_NAME, TLS_NAME, CA_PEM, tool_for_case, REDIS_SNMP_CASES,
    DATABASE_TLS_CASES, DATABASE_TLS_SUCCESS_CASES, WHATWEB_CASES, WHATWEB_SUCCESS_CASES,
    WHATWEB_PATH, WHATWEB_PLUGINS, DNS_SRV_CASES, DNS_SRV_SUCCESS_CASES, DNS_SRV_QUERY_NAME, RDP_CASES, RDP_SUCCESS_CASES, SMB2_CASES, SMB2_SUCCESS_CASES, SMTP_TLS_CASES, SMTP_TLS_SUCCESS_CASES, SMTP_TLS_COMPLETE_CASES,
    LDAP_TLS_CASES, LDAP_TLS_SUCCESS_CASES, LDAP_TLS_COMPLETE_CASES, LDAP_TLS_REQUEST,
    FTP_TLS_CASES, FTP_TLS_SUCCESS_CASES, FTP_TLS_COMPLETE_CASES, FTP_TLS_AUTH,
    SSH_ALGORITHMS_CASES, SSH_ALGORITHMS_SUCCESS_CASES,
    SNMP_NEXT_CASES, SNMP_NEXT_SUCCESS_CASES, SNMP_NEXT_SEED_OID,
    HTTP_OPTIONS_CASES, HTTP_OPTIONS_SUCCESS_CASES, HTTP_OPTIONS_PATH, HTTP_OPTIONS_USER_AGENT,
    DNS_NSID_CASES, DNS_NSID_SUCCESS_CASES, DNS_NSID_QUERY_NAME, DNS_NSID_MAX_NSID_BYTES, DNS_AXFR_CASES, DNS_AXFR_SUCCESS_CASES)


TOOL_ID = DIG_TOOL_ID
PROFILE = "owned_network_tools_lab"
WORKFLOW = "owned-network-tool-assessment-v1"
LIMITS = dict(NETWORK_TOOLS_LIMITS)
PARAMETERS = {DIG_TOOL_ID: dict(DIG_PARAMETERS), OPENSSL_TOOL_ID: dict(OPENSSL_PARAMETERS)}
PARAMETERS.update({SSH_TOOL_ID: dict(SSH_PARAMETERS), LDAP_TOOL_ID: dict(LDAP_PARAMETERS)})
PARAMETERS[SMB_TOOL_ID] = dict(SMB_PARAMETERS)
PARAMETERS.update({RPCINFO_TOOL_ID: dict(RPCINFO_PARAMETERS), SHOWMOUNT_TOOL_ID: dict(SHOWMOUNT_PARAMETERS)})
PARAMETERS.update({FTP_TOOL_ID: dict(FTP_PARAMETERS), SMTP_TOOL_ID: dict(SMTP_PARAMETERS)})
PARAMETERS.update({DOCKER_PING_TOOL_ID: dict(DOCKER_PING_PARAMETERS),
                   DOCKER_VERSION_TOOL_ID: dict(DOCKER_VERSION_PARAMETERS), WINRM_TOOL_ID: dict(WINRM_PARAMETERS)})
PARAMETERS[NMAP_SERVICE_TOOL_ID] = dict(NMAP_SERVICE_PARAMETERS)
PARAMETERS[KERBRUTE_TOOL_ID] = dict(KERBRUTE_PARAMETERS)
PARAMETERS.update({REDIS_TOOL_ID: dict(REDIS_PARAMETERS), SNMP_TOOL_ID: dict(SNMP_PARAMETERS)})
PARAMETERS.update({POSTGRESQL_TLS_TOOL_ID: dict(POSTGRESQL_TLS_PARAMETERS), MYSQL_TLS_TOOL_ID: dict(MYSQL_TLS_PARAMETERS)})
PARAMETERS[WHATWEB_TOOL_ID] = dict(WHATWEB_PARAMETERS)
PARAMETERS[DIG_SRV_TOOL_ID] = dict(DIG_SRV_PARAMETERS)
PARAMETERS[DIG_NSID_TOOL_ID] = dict(DIG_NSID_PARAMETERS)
PARAMETERS[DIG_AXFR_TOOL_ID] = dict(DIG_AXFR_PARAMETERS)
PARAMETERS[RDP_TOOL_ID] = dict(RDP_PARAMETERS)
PARAMETERS[SMB2_TOOL_ID] = dict(SMB2_PARAMETERS)
PARAMETERS[SMTP_TLS_TOOL_ID] = dict(SMTP_TLS_PARAMETERS)
PARAMETERS[LDAP_TLS_TOOL_ID] = dict(LDAP_TLS_PARAMETERS)
PARAMETERS[FTP_TLS_TOOL_ID] = dict(FTP_TLS_PARAMETERS)
PARSER_VERSIONS = {DIG_TOOL_ID: "dig-dns-text-v1", OPENSSL_TOOL_ID: "openssl-tls-brief-v1",
    SSH_TOOL_ID: "ssh-keyscan-rsa-v1", LDAP_TOOL_ID: "ldap-rootdse-ldif-v1", SMB_TOOL_ID: "smb-share-list-v1",
    RPCINFO_TOOL_ID: "rpcinfo-dump-v1", SHOWMOUNT_TOOL_ID: "showmount-exports-v1",
    FTP_TOOL_ID: "curl-ftp-list-v1", SMTP_TOOL_ID: "curl-smtp-capabilities-v1", DOCKER_PING_TOOL_ID: "curl-docker-ping-v1",
    DOCKER_VERSION_TOOL_ID: "curl-docker-version-v1", WINRM_TOOL_ID: "curl-winrm-metadata-v1", NMAP_SERVICE_TOOL_ID: "nmap-service-xml-v1", KERBRUTE_TOOL_ID: "kerbrute-userenum-text-v1",
    REDIS_TOOL_ID: "redis-info-server-v1", SNMP_TOOL_ID: "snmp-system-text-v1",
    POSTGRESQL_TLS_TOOL_ID: "postgresql-tls-brief-v1", MYSQL_TLS_TOOL_ID: "mysql-tls-brief-v1",
    WHATWEB_TOOL_ID: "whatweb-json-v1", DIG_SRV_TOOL_ID: "dig-dns-srv-text-v1", DIG_NSID_TOOL_ID: "dig-dns-nsid-text-v1", DIG_AXFR_TOOL_ID: "dig-dns-axfr-text-v1", RDP_TOOL_ID: "rdp-initial-negotiation-v1", SMB2_TOOL_ID: "smb2-negotiate-metadata-v1", SMTP_TLS_TOOL_ID: "smtp-starttls-brief-v1", LDAP_TLS_TOOL_ID: "ldap-starttls-brief-v1", FTP_TLS_TOOL_ID: "ftp-starttls-brief-v1"}
B1_CASES = ("dig-ok", "dig-nxdomain", "dig-injected", "dig-malformed", "dig-stalled",
            "openssl-ok", "openssl-untrusted", "openssl-malformed", "openssl-stalled")
B2_CASES = ("ssh-ok", "ssh-malformed", "ssh-stalled", "ssh-injected",
            "ldap-ok", "ldap-empty", "ldap-referral", "ldap-malformed", "ldap-stalled", "ldap-injected")
B3_CASES = ("smb-ok", "smb-empty", "smb-denied", "smb-injected", "smb-malformed", "smb-stalled")
B4_CASES = ("rpc-ok", "rpc-empty", "rpc-injected", "rpc-malformed", "rpc-stalled",
            "nfs-ok", "nfs-empty", "nfs-injected", "nfs-malformed", "nfs-stalled", "nfs-redirected")
B5_CASES = ("ftp-ok", "ftp-empty", "ftp-denied", "ftp-injected", "ftp-malformed", "ftp-stalled",
            "ftp-passive-ip", "ftp-passive-port", "smtp-ok", "smtp-empty", "smtp-injected",
            "smtp-malformed", "smtp-rejected", "smtp-stalled")
B6_CASES = tuple("docker-ping-" + suffix for suffix in ("ok", "unavailable", "injected", "malformed", "stalled", "redirect-ip", "redirect-port")) + tuple(
    "docker-version-" + suffix for suffix in ("ok", "empty", "injected", "malformed", "stalled", "redirect-ip", "redirect-port")) + tuple(
    "winrm-" + suffix for suffix in ("ok", "no-auth", "injected", "malformed", "stalled", "redirect-ip", "redirect-port"))
B7_CASES = tuple("nmap-service-" + suffix for suffix in ("http", "ssh", "unknown", "injected", "malformed", "stalled"))
B8_CASES = tuple("kerberos-" + suffix for suffix in ("ok", "empty", "denied", "injected", "spoof", "malformed", "stalled"))
C1_CASES = REDIS_SNMP_CASES
C2_CASES = DATABASE_TLS_CASES
C3_CASES = WHATWEB_CASES
C4_CASES = DNS_SRV_CASES
C5_CASES = RDP_CASES
C6_CASES = SMB2_CASES
C7_CASES = SMTP_TLS_CASES
C8_CASES = LDAP_TLS_CASES
C9_CASES = FTP_TLS_CASES
C10_CASES = DNS_NSID_CASES
C11_CASES = DNS_AXFR_CASES
C12_CASES = HTTP_OPTIONS_CASES
C15_CASES = TLS_CERTIFICATE_CASES
PARAMETERS[TLS_CERTIFICATE_TOOL_ID] = dict(TLS_CERTIFICATE_PARAMETERS)
PARSER_VERSIONS[TLS_CERTIFICATE_TOOL_ID] = "openssl-peer-certificate-v1"
C14_CASES = SSH_ALGORITHMS_CASES
PARAMETERS[SSH_ALGORITHMS_TOOL_ID] = dict(SSH_ALGORITHMS_PARAMETERS)
PARSER_VERSIONS[SSH_ALGORITHMS_TOOL_ID] = "ssh-kexinit-wire-v1"
C13_CASES = SNMP_NEXT_CASES
PARAMETERS[SNMP_NEXT_TOOL_ID] = dict(SNMP_NEXT_PARAMETERS)
PARSER_VERSIONS[SNMP_NEXT_TOOL_ID] = "snmp-interface-next-text-v1"
PARAMETERS[HTTP_OPTIONS_TOOL_ID] = dict(HTTP_OPTIONS_PARAMETERS)
PARSER_VERSIONS[HTTP_OPTIONS_TOOL_ID] = "curl-http-options-v1"
BOUNDARY_FIELDS = frozenset({"forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked",
    "capabilities_dropped", "no_new_privs", "root_read_only", "process_creation_blocked",
    "raw_sockets_blocked", "landlock_applied", "python_unreadable"})


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def parser_version(tool_id):
    if type(tool_id) is not str or tool_id not in PARSER_VERSIONS:
        raise ValueError("unsupported_network_tool")
    return PARSER_VERSIONS[tool_id]


def action(case, step=1):
    if type(step) is not int or step != 1:
        raise ValueError("invalid_network_tools_step")
    tool_id = tool_for_case(case)
    return parse_action({"schema_version": "1", "action_id": str(uuid5(NAMESPACE_URL, WORKFLOW + ":" + case)),
        "tool_id": tool_id, "target": "127.0.0.1", "parameters": dict(PARAMETERS[tool_id]),
        "rationale": "DETERMINISTIC OWNED NETWORK TOOL: execute one fixed scoped tool profile."}).to_dict()


def profile_allows(value, case):
    return (type(value) is Action and type(case) is str and case in CASES
            and value.target == "127.0.0.1" and value.tool_id == tool_for_case(case)
            and value.parameters.to_dict() == PARAMETERS[value.tool_id])


def capability_descriptor(case=None):
    if case is not None and (type(case) is not str or case not in B1_CASES + B2_CASES + B3_CASES + B4_CASES + B5_CASES + B6_CASES + B7_CASES + B8_CASES + C1_CASES + C2_CASES + C3_CASES + C4_CASES + C5_CASES + C6_CASES + C7_CASES + C8_CASES + C9_CASES + C10_CASES + C11_CASES + C12_CASES + C13_CASES + C14_CASES + C15_CASES):
        raise ValueError("invalid_network_tools_case")
    if case in C15_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(TLS_CERTIFICATE_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "tls_certificate": {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "server_name": TLS_NAME, "ca_sha256": hashlib.sha256(TLS_CERTIFICATE_CA_PEM).hexdigest(),
                "max_connections": 1, "max_requests": 1, "max_leaf_der_bytes": 4096,
                "max_extensions": 16, "max_subject_alt_names": 8, "max_summary_bytes": 3072,
                "trust_and_hostname_verification": True, "owner_clean_tls_close_required": True,
                "application_requests": False, "credentials": False, "client_certificate": False,
                "authentication": False, "revocation_checked": False, "ocsp": False, "aia_fetch": False,
                "dns_resolution": False, "cipher_sweep": False, "retries": False,
                "session_resumption": False, "response_directed_followup": False},
            "result_semantics": "certificate_metadata_from_fixture_verified_tls",
            "parser_versions": {TLS_CERTIFICATE_TOOL_ID: PARSER_VERSIONS[TLS_CERTIFICATE_TOOL_ID]}}
    if case in C14_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(SSH_ALGORITHMS_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "ssh_algorithms": {"protocol": "2.0", "operation": "identification_and_kexinit_advertisements",
                "max_connections": 1, "max_requests": 1, "random_cookie_bytes": 16,
                "client_write_half_close_before_response": True, "max_identification_bytes": 255,
                "max_packet_length": 4096, "max_capture_bytes": 4355,
                "key_exchange_completion": False, "authentication": False, "session": False,
                "credentials": False, "known_hosts": False, "nse": False, "udp": False,
                "retries": False, "response_directed_followup": False, "service_identity_verified": False},
            "result_semantics": "untrusted_ssh_algorithm_advertisements",
            "parser_versions": {SSH_ALGORITHMS_TOOL_ID: PARSER_VERSIONS[SSH_ALGORITHMS_TOOL_ID]}}
    if case in C13_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(SNMP_NEXT_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "snmp_next": {"version": "2c", "transport": "tcp", "operation": "GetNextRequest",
                "seed_oid": SNMP_NEXT_SEED_OID, "max_connections": 1, "max_requests": 1,
                "max_bindings": 1, "community_is_public_synthetic_data": True,
                "walk": False, "getbulk": False, "set": False, "udp": False,
                "retries": False, "correction_resubmission": False, "real_credentials": False,
                "mib_imports": False, "response_directed_followup": False,
                "service_identity_verified": False, "interface_inventory_complete": False},
            "result_semantics": "untrusted_snmp_successor_metadata",
            "parser_versions": {SNMP_NEXT_TOOL_ID: PARSER_VERSIONS[SNMP_NEXT_TOOL_ID]}}
    if case in C12_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(HTTP_OPTIONS_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "http_request": {"method": "OPTIONS", "path": HTTP_OPTIONS_PATH,
                "version": "HTTP/1.1", "user_agent": HTTP_OPTIONS_USER_AGENT,
                "max_connections": 1, "max_requests": 1, "redirects": False,
                "retries": False, "authentication": False, "credentials": False,
                "cookies": False, "proxy": False, "request_body": False,
                "advertised_method_execution": False, "response_directed_followup": False,
                "service_identity_verified": False},
            "result_semantics": "untrusted_http_options_metadata",
            "parser_versions": {HTTP_OPTIONS_TOOL_ID: PARSER_VERSIONS[HTTP_OPTIONS_TOOL_ID]}}
    if case in C11_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(DIG_AXFR_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "dns_question": {"name": "harbordesk.test.", "type": "AXFR", "class": "IN", "transport": "tcp",
                "max_connections": 1, "max_requests": 1, "max_accepted_messages": 4,
                "max_accepted_answer_records": 16, "matching_soa_boundaries_required": True,
                "record_types": ["SOA", "NS", "A", "TXT"],
                "count_limits_enforced_by": "fixture_and_independent_parser",
                "native_frame_record_limit": False, "recursion": False, "udp": False,
                "edns": False, "cookies": False, "edns_negotiation": False,
                "malformed_recovery": False, "retries": False, "search": False,
                "preliminary_soa_query": False, "response_directed_followup": False,
                "service_identity_verified": False},
            "result_semantics": "untrusted_dns_zone_transfer_metadata",
            "parser_versions": {DIG_AXFR_TOOL_ID: PARSER_VERSIONS[DIG_AXFR_TOOL_ID]}}
    if case in C10_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(DIG_NSID_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "dns_question": {"name": DNS_NSID_QUERY_NAME, "type": "A", "class": "IN", "transport": "tcp",
                "recursion": False, "edns_version": 0, "advertised_udp_size": 1232,
                "options": [{"code": 3, "bytes": 0}], "max_nsid_bytes": DNS_NSID_MAX_NSID_BYTES,
                "max_connections": 1, "max_requests": 1, "udp": False, "cookies": False,
                "edns_negotiation": False, "malformed_recovery": False, "retries": False,
                "search": False, "zone_transfer": False, "response_directed_followup": False,
                "service_identity_verified": False, "nsid_encoding": "opaque_lowercase_hex"},
            "result_semantics": "untrusted_dns_server_metadata",
            "parser_versions": {DIG_NSID_TOOL_ID: PARSER_VERSIONS[DIG_NSID_TOOL_ID]}}
    if case in C9_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(FTP_TLS_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "ftp_starttls": {"request_sha256": hashlib.sha256(FTP_TLS_AUTH).hexdigest(),
                "request_bytes": len(FTP_TLS_AUTH), "max_commands": 1,
                "max_connections": 1, "max_requests": 1, "tls_name": TLS_NAME,
                "tls_protocol": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(),
                "authentication": False, "client_credentials": False, "login": False,
                "data_connection": False, "listing": False, "file_transfer": False, "pbsz_prot": False,
                "tls_application_requests": False, "plaintext_session": False, "retries": False,
                "client_validates_ftp_reply_codes": False, "auth_reply_retained": False,
                "full_ftp_dialogue_retained": False, "fragmented_ready_reply_may_fail": True,
                "service_identity_claim": False, "useful_result_requires_owner_clean_close": True},
            "result_semantics": "verified_tls_handshake_only",
            "parser_versions": {FTP_TLS_TOOL_ID: PARSER_VERSIONS[FTP_TLS_TOOL_ID]}}
    if case in C8_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(LDAP_TLS_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "ldap_starttls": {"request_sha256": hashlib.sha256(LDAP_TLS_REQUEST).hexdigest(),
                "request_bytes": len(LDAP_TLS_REQUEST), "message_id": 1, "request_oid": "1.3.6.1.4.1.1466.20037",
                "max_connections": 1, "max_requests": 1, "tls_name": TLS_NAME,
                "tls_protocol": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(),
                "bind": False, "search": False, "authentication": False,
                "client_credentials": False, "referral_following": False,
                "tls_application_requests": False, "plaintext_session": False, "retries": False,
                "ldap_response_validation_claim": False, "service_identity_claim": False,
                "client_matches_response_message_id": False, "complete_ldap_response_retained": False,
                "fragmented_response_may_fail": True, "useful_result_requires_owner_clean_close": True},
            "result_semantics": "verified_tls_handshake_only",
            "parser_versions": {LDAP_TLS_TOOL_ID: PARSER_VERSIONS[LDAP_TLS_TOOL_ID]}}
    if case in C7_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(SMTP_TLS_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "smtp_starttls": {"ehlo_name": TLS_NAME, "commands": ["EHLO harbordesk.test", "STARTTLS"],
                "max_connections": 1, "max_commands": 2, "tls_name": TLS_NAME,
                "tls_protocol": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(),
                "authentication": False, "mail": False, "recipient_probing": False,
                "client_credentials": False, "tls_application_requests": False, "plaintext_session": False,
                "retries": False, "smtp_dialogue_validation_claim": False, "service_identity_claim": False,
                "client_attempts_starttls_without_advertisement": True,
                "client_does_not_validate_ready_status": True, "fragmented_ready_may_fail": True,
                "full_plaintext_dialogue_retained": False, "useful_result_requires_owner_clean_close": True},
            "result_semantics": "verified_tls_handshake_only",
            "parser_versions": {SMTP_TLS_TOOL_ID: PARSER_VERSIONS[SMTP_TLS_TOOL_ID]}}
    if case in C6_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(SMB2_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "smb2_negotiation": {"offered_dialects": [0x0210, 0x0302], "client_capabilities": 0,
                "max_connections": 1, "max_requests": 1, "request_bytes": 108,
                "max_response_bytes": 4100, "max_opaque_buffer_bytes": 256,
                "write_half_close_before_response": True, "read_one_frame_only": True,
                "opaque_peer_bytes_retained_in_raw_evidence": True, "token_interpretation": False,
                "session_setup": False, "authentication": False, "ntlm_exchange": False,
                "share_access": False, "retries": False, "signing_enforcement_verified": False,
                "verified_service_identity": False, "exhaustive_capability_enumeration": False},
            "result_semantics": "untrusted_smb2_negotiation_metadata",
            "parser_versions": {SMB2_TOOL_ID: PARSER_VERSIONS[SMB2_TOOL_ID]}}
    if case in C5_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(RDP_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "rdp_negotiation": {"offered_protocols": ["tls"], "max_connections": 1,
                "max_requests": 1, "request_bytes": 19, "max_response_bytes": 19,
                "write_half_close_before_response": True, "read_one_frame_only": True,
                "trailing_data_inspected": False, "security_handshake": False,
                "authentication": False, "ntlm_collection": False, "remote_session": False,
                "cookies_or_routing_tokens": False, "retries": False,
                "verified_service_identity": False, "all_protocol_support_enumerated": False},
            "result_semantics": "untrusted_rdp_negotiation_metadata",
            "parser_versions": {RDP_TOOL_ID: PARSER_VERSIONS[RDP_TOOL_ID]}}
    if case in C4_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(DIG_SRV_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "dns_question": {"name": DNS_SRV_QUERY_NAME, "type": "SRV", "transport": "tcp",
                "recursion": False, "max_connections": 1, "max_questions": 1,
                "max_records": 4, "search": False, "zone_transfer": False,
                "retries": False, "advertised_target_resolution": False,
                "advertised_endpoint_followup": False, "verified_service_identity": False},
            "result_semantics": "untrusted_dns_service_metadata",
            "parser_versions": {DIG_SRV_TOOL_ID: PARSER_VERSIONS[DIG_SRV_TOOL_ID]}}
    if case in C3_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(WHATWEB_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "http_fingerprint": {"method": "GET", "path": WHATWEB_PATH,
                "plugins": list(WHATWEB_PLUGINS), "aggression": 1, "max_connections": 1,
                "max_requests": 1, "max_response_bytes": 8192, "redirects": False,
                "retries": False, "authentication": False, "cookies": False,
                "javascript_execution": False, "metadata_followup": False,
                "caller_plugins_or_templates": False, "verified_product_identity": False,
                "empty_hints_mean": "no_match_from_five_passive_plugins"},
            "result_semantics": "untrusted_application_hints",
            "parser_versions": {WHATWEB_TOOL_ID: PARSER_VERSIONS[WHATWEB_TOOL_ID]}}
    if case in C2_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(tool).to_dict() for tool in (POSTGRESQL_TLS_TOOL_ID, MYSQL_TLS_TOOL_ID)],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "database_tls": {"profiles": ["postgresql", "mysql"], "pre_authentication": True,
                "name": TLS_NAME, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(), "max_connections": 1,
                "database_login": False, "sql": False, "application_requests": False,
                "plaintext_downgrade": False, "version_or_readiness_claim": False,
                "mysql_fragmented_greeting_may_be_inconclusive": True},
            "parser_versions": {tool: PARSER_VERSIONS[tool] for tool in (POSTGRESQL_TLS_TOOL_ID, MYSQL_TLS_TOOL_ID)}}
    if case in C1_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(tool).to_dict() for tool in (REDIS_TOOL_ID, SNMP_TOOL_ID)],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "redis": {"protocol": "RESP2", "command": ["INFO", "server"],
                "authentication": False, "key_access": False, "writes": False,
                "cluster_redirects": False, "metadata_followup": False},
            "snmp": {"version": "2c", "transport": "tcp", "operation": "GetRequest",
                "oids": [".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"],
                "community": "public_synthetic_fixture_only", "max_requests": 1,
                "retries": 0, "correction_resubmission": False, "walk": False, "set": False,
                "host_config_or_mibs": False, "udp": False, "metadata_followup": False},
            "result_semantics": "untrusted_service_report",
            "parser_versions": {tool: PARSER_VERSIONS[tool] for tool in (REDIS_TOOL_ID, SNMP_TOOL_ID)}}
    if case in B8_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(KERBRUTE_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "kerberos": {"realm": "HARBORDESK.TEST", "principals": ["fixture-a", "fixture-b"],
                "max_requests": 2, "threads": 1, "transport": "tcp_after_udp_denied_by_seccomp",
                "operation": "initial_as_req_without_preauth", "passwords": False, "spraying": False,
                "tickets": False, "authentication_verified": False, "results": "tool_report_only",
                "unknown_report_can_be_spoofed_by_error_text": True, "metadata_followup": False},
            "parser_versions": {KERBRUTE_TOOL_ID: PARSER_VERSIONS[KERBRUTE_TOOL_ID]}}
    if case in B7_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(NMAP_SERVICE_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "service_probes": {"transport": "tcp", "scan": "connect", "dns": False,
                "probes": ["NULL", "GetRequest"], "http_request": "GET / HTTP/1.0\r\n\r\n",
                "compiled_data_only": True, "nse": "pinned_noop_entrypoint", "scripts": False,
                "authentication": False, "metadata_followup": False,
                "unidentified_means": "no_match_from_finite_reviewed_probes"},
            "parser_versions": {NMAP_SERVICE_TOOL_ID: PARSER_VERSIONS[NMAP_SERVICE_TOOL_ID]}}
    if case in B6_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(tool).to_dict() for tool in (DOCKER_PING_TOOL_ID, DOCKER_VERSION_TOOL_ID, WINRM_TOOL_ID)],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "http": {"method": "GET", "paths": {DOCKER_PING_TOOL_ID: "/_ping",
                DOCKER_VERSION_TOOL_ID: "/version", WINRM_TOOL_ID: "/wsman"}, "redirects": False,
                "authentication": False, "metadata_followup": False},
            "docker": {"advertised_metadata_only": True, "daemon_identity_verified": False, "daemon_control": False},
            "winrm": {"advertised_schemes_only": True, "service_identity_verified": False,
                "authentication_verified": False, "wsman_operations": False},
            "parser_versions": {tool: PARSER_VERSIONS[tool] for tool in (DOCKER_PING_TOOL_ID, DOCKER_VERSION_TOOL_ID, WINRM_TOOL_ID)}}
    if case in B5_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(tool).to_dict() for tool in (FTP_TOOL_ID, SMTP_TOOL_ID)],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "ftp": {"operation": "NLST", "login": "fixed_anonymous", "file_transfer": False,
                "control_endpoint": "127.0.0.1:8080", "data_endpoint": "127.0.0.1:8080",
                "metadata_followup": False},
            "smtp": {"operation": "EHLO", "authentication": False, "mail_submission": False,
                "capabilities": "advertised_only"},
            "parser_versions": {tool: PARSER_VERSIONS[tool] for tool in (FTP_TOOL_ID, SMTP_TOOL_ID)}}
    if case in B4_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(tool).to_dict() for tool in (RPCINFO_TOOL_ID, SHOWMOUNT_TOOL_ID)],
            "scope": {"target": "127.0.0.1", "port": 111, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "rpc": {"operation": "registration_dump", "transport": "tcp", "metadata_followup": False},
            "nfs": {"operation": "export_list", "discovery_endpoint": "127.0.0.1:111",
                "export_endpoint": "127.0.0.1:111", "mounts": False, "file_access": False},
            "parser_versions": {tool: PARSER_VERSIONS[tool] for tool in (RPCINFO_TOOL_ID, SHOWMOUNT_TOOL_ID)}}
    if case in B3_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(SMB_TOOL_ID).to_dict()],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "smb": {"operation": "anonymous_share_listing", "file_share_access": False,
                "comments": "discarded", "metadata_followup": False},
            "parser_versions": {SMB_TOOL_ID: PARSER_VERSIONS[SMB_TOOL_ID]}}
    if case in B2_CASES:
        return {"schema_version": "1", "workflow_id": WORKFLOW,
            "capabilities": [get_adapter(tool).to_dict() for tool in (SSH_TOOL_ID, LDAP_TOOL_ID)],
            "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
            "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
            "ssh": {"key_type": "ssh-rsa", "key_bits": 2048, "authentication": False, "trust": "unverified"},
            "ldap": {"base_dn": "", "scope": "base", "filter": "(objectClass=*)", "bind": "anonymous",
                "attributes": ["namingContexts", "supportedLDAPVersion", "supportedSASLMechanisms", "vendorName"],
                "referrals": "not_followed"},
            "parser_versions": {tool: PARSER_VERSIONS[tool] for tool in (SSH_TOOL_ID, LDAP_TOOL_ID)}}
    # Preserve the accepted B1 descriptor byte-for-byte for saved evidence.
    return {"schema_version": "1", "workflow_id": WORKFLOW,
        "capabilities": [get_adapter(tool).to_dict() for tool in (DIG_TOOL_ID, OPENSSL_TOOL_ID)],
        "scope": {"target": "127.0.0.1", "port": 8080, "owned_lab_only": True},
        "limits": dict(LIMITS), "live_calls_enabled": False, "planning": "deterministic_offline",
        "dns_question": {"name": QUERY_NAME, "type": "A", "transport": "tcp", "recursion": False},
        "tls": {"name": TLS_NAME, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(), "application_requests": False},
        "parser_versions": {tool: PARSER_VERSIONS[tool] for tool in (DIG_TOOL_ID, OPENSSL_TOOL_ID)}}


def validate_result_context(result, expected, *, previous=None, tool_id, execution_status):
    expected = validate_identity(expected)
    if (type(result) is not dict or result.get("backend") != BACKEND
            or tool_id != tool_for_case(expected["scenario"])):
        raise ValueError("invalid_network_tools_lab_result")
    context = validate_context(result.get("owned_lab"), expected)
    before = {"connection_count": 0, "request_count": 0} if previous is None else validate_context(previous, expected)
    connections = context["connection_count"] - before["connection_count"]
    requests = context["request_count"] - before["request_count"]
    request_limit = 2 if expected["scenario"] in B8_CASES else 1
    connection_limit = (2 if expected["scenario"] in B8_CASES else 3 if expected["scenario"] in B7_CASES else 4 if expected["scenario"] in B4_CASES else
                        2 if (expected["scenario"].startswith("ftp-") and expected["scenario"] not in C9_CASES) else 1)
    if (not 0 <= connections <= connection_limit or not 0 <= requests <= request_limit
            or (expected["scenario"] in {"openssl-untrusted", "openssl-malformed", "openssl-stalled",
                                         "ssh-malformed", "ssh-stalled", "ftp-denied",
                                         "ftp-passive-ip", "ftp-passive-port"} and requests != 0)
            or ((expected["scenario"].startswith("ftp-") and expected["scenario"] not in C9_CASES) and result.get("tool_observation") is not None
                and connections != 2)
            or (expected["scenario"] in C2_CASES and expected["scenario"] not in DATABASE_TLS_SUCCESS_CASES and requests != 0)
            or (expected["scenario"] in C2_CASES and result.get("tool_observation") is not None and connections != 1)
            or (expected["scenario"] in C1_CASES and result.get("tool_observation") is not None and connections != 1)
            or (expected["scenario"] in C3_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in WHATWEB_SUCCESS_CASES))
            or (expected["scenario"] in C4_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in DNS_SRV_SUCCESS_CASES))
            or (expected["scenario"] in C5_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in RDP_SUCCESS_CASES))
            or (expected["scenario"] in C15_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in TLS_CERTIFICATE_SUCCESS_CASES))
            or (expected["scenario"] in C14_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in SSH_ALGORITHMS_SUCCESS_CASES))
            or (expected["scenario"] in C13_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in SNMP_NEXT_SUCCESS_CASES))
            or (expected["scenario"] in C12_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in HTTP_OPTIONS_SUCCESS_CASES))
            or (expected["scenario"] in C11_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in DNS_AXFR_SUCCESS_CASES))
            or (expected["scenario"] in C10_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in DNS_NSID_SUCCESS_CASES))
            or (expected["scenario"] in C9_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in FTP_TLS_SUCCESS_CASES))
            or (expected["scenario"] in C8_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in LDAP_TLS_SUCCESS_CASES))
            or (expected["scenario"] in C7_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in SMTP_TLS_SUCCESS_CASES))
            or (expected["scenario"] in C6_CASES and result.get("tool_observation") is not None
                and (connections != 1 or expected["scenario"] not in SMB2_SUCCESS_CASES))
            or (expected["scenario"] in B7_CASES and result.get("tool_observation") is not None and connections < 2)
            or (execution_status == "succeeded" and result.get("tool_observation") is not None and requests != request_limit)):
        raise ValueError("network_tools_request_continuity_mismatch")
    return context


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_tool_result(result, *, tool_id, execution_status, runtime_sha256=None):
    """Check bounded capture/provenance; replay parsing is a separate boundary."""
    version = parser_version(tool_id)
    core = {k: v for k, v in result.items() if k not in {"backend", "owned_lab"}} if type(result) is dict else result
    if (type(core) is not dict or set(core) != {"status", "results", "raw_output_base64", "raw_stderr_base64",
            "bytes_received", "truncated", "provenance", "boundary_checks", "tool_observation"}
            or type(execution_status) is not str or execution_status not in {"succeeded", "failed", "timeout", "output_limit"}
            or core["status"] != execution_status or core["results"] != []
            or type(core["results"]) is not list or type(core["bytes_received"]) is not int
            or not 0 <= core["bytes_received"] <= PARAMETERS[tool_id]["max_output_bytes"]
            or type(core["truncated"]) is not bool or core["truncated"] != (execution_status == "output_limit")):
        raise ValueError("invalid_network_tool_result")
    checks = core["boundary_checks"]
    if type(checks) is not dict or set(checks) != BOUNDARY_FIELDS or any(v is not True for v in checks.values()):
        raise ValueError("invalid_network_tool_boundary_checks")
    decoded = []
    try:
        for field in ("raw_output_base64", "raw_stderr_base64"):
            encoded = core[field]
            if type(encoded) is not str or len(encoded) > 10924:
                raise ValueError("invalid_network_tool_capture")
            raw = base64.b64decode(encoded, validate=True)
            if base64.b64encode(raw).decode("ascii") != encoded:
                raise ValueError("invalid_network_tool_capture")
            decoded.append(raw)
    except (ValueError, TypeError):
        raise ValueError("invalid_network_tool_capture") from None
    output, stderr = decoded
    if len(output) + len(stderr) != core["bytes_received"]:
        raise ValueError("invalid_network_tool_capture_size")
    provenance = core["provenance"]
    if (type(provenance) is not dict or set(provenance) != {"runtime_sha256", "runtime_manifest", "output_sha256",
            "stderr_sha256", "parser_version", "exit_code", "stop_reason"}
            or not _digest(provenance["runtime_sha256"])
            or (runtime_sha256 is not None and provenance["runtime_sha256"] != runtime_sha256)
            or provenance["output_sha256"] != hashlib.sha256(output).hexdigest()
            or provenance["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
            or provenance["parser_version"] != version or type(provenance["exit_code"]) is not int
            or not -255 <= provenance["exit_code"] <= 255
            or provenance["stop_reason"] not in (None, "timeout", "output_limit")
            or (execution_status == "succeeded" and (provenance["exit_code"] != 0 or provenance["stop_reason"] is not None))
            or (execution_status == "failed" and (provenance["exit_code"] == 0 or provenance["stop_reason"] is not None))
            or (execution_status in {"timeout", "output_limit"} and provenance["stop_reason"] != execution_status)):
        raise ValueError("invalid_network_tool_provenance")
    from .network_tools_runtime import manifest_digest
    manifest = provenance["runtime_manifest"]
    if manifest_digest(manifest) != provenance["runtime_sha256"] or manifest.get("tool_id") != tool_id:
        raise ValueError("invalid_network_tool_runtime")
    if core["tool_observation"] is not None:
        if execution_status != "succeeded" or core["truncated"] or not (output or stderr):
            raise ValueError("failed_network_tool_has_observation")
        from .network_tools_parser import validate_result
        validate_result(tool_id, core["tool_observation"])
    return output, stderr


def _observation(tool_id, classification, reason, details=None):
    return {"parser_version": parser_version(tool_id), "kind": "network_tool", "tool_id": tool_id,
            "classification": classification, "reason": reason, "followup_path": None, "details": details}


def classify_tool(tool_id, normalized):
    from .network_tools_parser import validate_result
    normalized = validate_result(tool_id, normalized)
    if tool_id == TLS_CERTIFICATE_TOOL_ID:
        return _observation(tool_id, "tls_peer_certificate_observed", "tls_peer_certificate_observed", normalized)
    if tool_id == SSH_ALGORITHMS_TOOL_ID:
        return _observation(tool_id, "ssh_algorithm_advertisements_observed", "ssh_algorithm_advertisements_observed", normalized)
    if tool_id == SNMP_NEXT_TOOL_ID:
        return _observation(tool_id, "snmp_interface_next_observed", "snmp_interface_next_observed", normalized)
    if tool_id == HTTP_OPTIONS_TOOL_ID:
        return _observation(tool_id, "http_options_observed", "http_options_observed", normalized)
    if tool_id == DIG_AXFR_TOOL_ID:
        reason = "dns_axfr_completed" if normalized["transfer_complete"] else "dns_axfr_refused"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == DIG_NSID_TOOL_ID:
        reason = ("dns_nsid_absent" if not normalized["nsid_present"]
            else "dns_nsid_empty" if normalized["nsid_bytes"] == 0 else "dns_nsid_observed")
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == FTP_TLS_TOOL_ID:
        return _observation(tool_id, "ftp_tls_verified", "ftp_tls_verified", normalized)
    if tool_id == LDAP_TLS_TOOL_ID:
        return _observation(tool_id, "ldap_tls_verified", "ldap_tls_verified", normalized)
    if tool_id == SMTP_TLS_TOOL_ID:
        return _observation(tool_id, "smtp_tls_verified", "smtp_tls_verified", normalized)
    if tool_id == SMB2_TOOL_ID:
        reason = "smb2_dialect_selected" if normalized["response_type"] == "selection" else "smb2_negotiation_refused"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == RDP_TOOL_ID:
        reason = {"selection": "rdp_protocol_selected", "legacy": "rdp_legacy_confirmation",
                  "failure": "rdp_negotiation_failure"}[normalized["response_type"]]
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == DIG_SRV_TOOL_ID:
        reason = ("dns_srv_name_not_found" if normalized["status"] == "NXDOMAIN"
            else "dns_srv_no_data" if not normalized["records"]
            else "dns_srv_service_unavailable" if normalized["records"][0]["target"] == "."
            else "dns_srv_observed")
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == WHATWEB_TOOL_ID:
        reason = "http_fingerprint_observed" if normalized["hints"] else "http_fingerprint_no_hints"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id in (POSTGRESQL_TLS_TOOL_ID, MYSQL_TLS_TOOL_ID):
        return _observation(tool_id, "database_tls_verified", "database_tls_verified", normalized)
    if tool_id == REDIS_TOOL_ID:
        return _observation(tool_id, "redis_server_info_observed", "redis_server_info_observed", normalized)
    if tool_id == SNMP_TOOL_ID:
        return _observation(tool_id, "snmp_system_metadata_observed", "snmp_system_metadata_observed", normalized)
    if tool_id == KERBRUTE_TOOL_ID:
        return _observation(tool_id, "kerberos_principal_reports_observed", "kerberos_principal_reports_observed", normalized)
    if tool_id == NMAP_SERVICE_TOOL_ID:
        reason = "nmap_service_identified" if normalized["identification"] == "identified" else "nmap_service_unidentified"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == DOCKER_PING_TOOL_ID:
        return _observation(tool_id, "docker_ping_observed", "docker_ping_observed", normalized)
    if tool_id == DOCKER_VERSION_TOOL_ID:
        reason = "docker_version_metadata_observed" if normalized["metadata"] else "docker_no_version_metadata_observed"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == WINRM_TOOL_ID:
        reason = "winrm_auth_schemes_observed" if normalized["auth_schemes"] else "winrm_no_auth_schemes_observed"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == FTP_TOOL_ID:
        reason = "ftp_names_observed" if normalized["entries"] else "ftp_empty_listing_observed"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == SMTP_TOOL_ID:
        reason = "smtp_capabilities_observed" if normalized["capabilities"] else "smtp_no_extensions_observed"
        return _observation(tool_id, reason, reason, normalized)
    if tool_id == RPCINFO_TOOL_ID:
        present = bool(normalized["registrations"])
        return _observation(tool_id, "rpc_registrations_observed" if present else "rpc_empty_registrations_observed",
            "rpc_registrations_observed" if present else "rpc_empty_registrations_observed", normalized)
    if tool_id == SHOWMOUNT_TOOL_ID:
        present = bool(normalized["exports"])
        return _observation(tool_id, "nfs_exports_observed" if present else "nfs_empty_exports_observed",
            "nfs_exports_observed" if present else "nfs_empty_exports_observed", normalized)
    if tool_id == OPENSSL_TOOL_ID:
        return _observation(tool_id, "handshake_verified", "tls_handshake_verified", normalized)
    if tool_id == SSH_TOOL_ID:
        return _observation(tool_id, "host_key_observed", "ssh_host_key_observed", normalized)
    if tool_id == LDAP_TOOL_ID:
        present = any(normalized[field] for field in ("naming_contexts", "supported_ldap_versions",
            "supported_sasl_mechanisms", "vendor_name"))
        return _observation(tool_id, "rootdse_observed" if present else "empty_rootdse_observed",
            "ldap_rootdse_observed" if present else "ldap_empty_rootdse_observed", normalized)
    if tool_id == SMB_TOOL_ID:
        return _observation(tool_id, "shares_observed", "smb_shares_observed", normalized)
    if normalized["status"] == "NXDOMAIN":
        return _observation(tool_id, "name_not_found", "dns_name_not_found", normalized)
    found = bool(normalized["answers"])
    return _observation(tool_id, "answer_observed" if found else "no_answer_observed",
        "dns_answer_observed" if found else "dns_no_answer_observed", normalized)


def parse_observation(value, result, *, execution_status):
    tool_id = value.get("tool_id") if type(value) is dict else None
    if type(tool_id) is not str or tool_id not in PARSER_VERSIONS:
        raise ValueError("invalid_network_tool_action")
    try:
        if set(value) not in (_ACTION_FIELDS, _ACTION_FIELDS | {"rationale"}):
            raise ValueError("invalid_action")
        parsed = parse_action({**value, "rationale": value.get("rationale", "")})
        if parsed.target != "127.0.0.1" or parsed.parameters.to_dict() != PARAMETERS[tool_id]:
            raise ValueError("invalid_action")
    except (ValueError, TypeError, KeyError, RecursionError):
        return _observation(tool_id, "inconclusive", "invalid_action")
    try:
        validate_tool_result(result, tool_id=tool_id, execution_status=execution_status)
    except (ValueError, TypeError, KeyError, RecursionError):
        return _observation(tool_id, "inconclusive", "invalid_result_metadata")
    if execution_status != "succeeded":
        return _observation(tool_id, "inconclusive", "execution_not_succeeded")
    if result["tool_observation"] is None:
        return _observation(tool_id, "inconclusive", "tool_output_not_interpretable")
    return classify_tool(tool_id, result["tool_observation"])
