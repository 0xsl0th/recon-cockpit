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
    if case.startswith("ftp-tls-"):
        from . import network_tools_fixture as fixture
        dialogue = fixture.ftp_tls_dialogue(case)
        complete = case in fixture.FTP_TLS_COMPLETE_CASES
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-ftp-starttls-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "ftp_starttls"}],
            "request_sha256": hashlib.sha256(fixture.FTP_TLS_AUTH).hexdigest(),
            "request_bytes": len(fixture.FTP_TLS_AUTH),
            "response_sha256": {name: None if value is None else hashlib.sha256(value).hexdigest()
                for name, value in dialogue.items()},
            "malformed_tls_sha256": hashlib.sha256(TLS_MALFORMED_BYTES).hexdigest()
                if case == "ftp-tls-malformed" else None,
            "tls_name": TLS_NAME, "tls_protocol": "TLSv1.3",
            "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(),
            "certificate_sha256": UNTRUSTED_SERVER_CERT_SHA256 if case == "ftp-tls-untrusted" else SERVER_CERT_SHA256,
            "max_fixture_response_bytes": fixture.FTP_TLS_MAX_RESPONSE_BYTES,
            "native_response_read_max_bytes": 16384,
            "max_commands": 1, "max_connections": 1, "max_requests": 1,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_auth_tls_then_tls13_and_clean_close_notify" if complete
                else "validated_auth_tls_before_negative_response",
            "counter_includes_clean_tls_close": complete,
            "connection_evidence": "accepted_connections_lower_bound",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "authentication": False, "credentials": False, "login": False, "listing": False,
            "data_connection": False, "file_transfer": False, "pbsz_prot": False,
            "tls_application_requests": False, "plaintext_session": False,
            "client_validates_ftp_reply_codes": False, "auth_reply_retained": False,
            "full_ftp_dialogue_retained": False, "fragmented_ready_reply_may_fail": True,
            "service_identity_claim": False, "vulnerability_claim": False,
            "behavior": case.removeprefix("ftp-tls-")}
    if case.startswith("ldap-tls-"):
        from . import network_tools_fixture as fixture
        response = fixture.ldap_tls_response(case)
        complete = case in fixture.LDAP_TLS_COMPLETE_CASES
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-ldap-starttls-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "ldap_starttls"}],
            "request_sha256": hashlib.sha256(fixture.LDAP_TLS_REQUEST).hexdigest(),
            "request_bytes": len(fixture.LDAP_TLS_REQUEST),
            "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
            "malformed_tls_sha256": hashlib.sha256(TLS_MALFORMED_BYTES).hexdigest()
                if case == "ldap-tls-bad-tls" else None,
            "request_message_id": 1, "request_oid": "1.3.6.1.4.1.1466.20037",
            "tls_name": TLS_NAME, "tls_protocol": "TLSv1.3",
            "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(),
            "certificate_sha256": UNTRUSTED_SERVER_CERT_SHA256 if case == "ldap-tls-untrusted" else SERVER_CERT_SHA256,
            "max_fixture_response_bytes": fixture.LDAP_TLS_MAX_RESPONSE_BYTES,
            "native_response_read_max_bytes": 16384,
            "max_connections": 1, "max_requests": 1,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_starttls_request_then_tls13_and_clean_close_notify" if complete
                else "validated_starttls_request_before_negative_response",
            "counter_includes_clean_tls_close": complete,
            "connection_evidence": "accepted_connections_lower_bound",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "bind": False, "search": False, "authentication": False, "credentials": False,
            "referral_following": False, "tls_application_requests": False, "plaintext_session": False,
            "client_matches_response_message_id": False, "client_validates_complete_ldap_response": False,
            "complete_ldap_response_retained": False, "fragmented_response_may_fail": True,
            "service_identity_claim": False, "vulnerability_claim": False,
            "behavior": case.removeprefix("ldap-tls-")}
    if case.startswith("smtp-tls-"):
        from . import network_tools_fixture as fixture
        dialogue = fixture.smtp_tls_dialogue(case)
        complete = case in fixture.SMTP_TLS_COMPLETE_CASES
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-smtp-starttls-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "smtp_starttls"}],
            "command_sha256": [hashlib.sha256(value).hexdigest()
                for value in (fixture.SMTP_TLS_EHLO, fixture.SMTP_TLS_STARTTLS)],
            "response_sha256": {name: None if value is None else hashlib.sha256(value).hexdigest()
                for name, value in dialogue.items()},
            "malformed_tls_sha256": hashlib.sha256(TLS_MALFORMED_BYTES).hexdigest()
                if case == "smtp-tls-malformed" else None,
            "ehlo_name": TLS_NAME, "tls_name": TLS_NAME, "tls_protocol": "TLSv1.3",
            "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(),
            "certificate_sha256": UNTRUSTED_SERVER_CERT_SHA256 if case == "smtp-tls-untrusted" else SERVER_CERT_SHA256,
            "max_fixture_plaintext_bytes": fixture.SMTP_TLS_MAX_PLAINTEXT_BYTES,
            "max_commands": 2, "max_connections": 1, "max_requests": 1,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_ehlo_starttls_then_tls13_and_clean_close_notify" if complete
                else "validated_ehlo_and_starttls_before_negative_response",
            "counter_includes_clean_tls_close": complete,
            "connection_evidence": "accepted_connections_lower_bound",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "authentication": False, "credentials": False, "mail": False, "recipient_probing": False,
            "tls_application_requests": False, "plaintext_session": False,
            "client_validates_smtp_reply_codes": False, "client_requires_starttls_advertisement": False,
            "full_smtp_dialogue_retained": False, "fragmented_ready_reply_may_fail": True,
            "service_identity_claim": False, "vulnerability_claim": False,
            "behavior": case.removeprefix("smtp-tls-")}
    if case.startswith("smb2-"):
        from . import network_tools_fixture as fixture
        response = fixture.smb2_response(case)
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-smb2-negotiate-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "smb2_direct_tcp"}],
            "request_sha256": hashlib.sha256(fixture.SMB2_REQUEST).hexdigest(),
            "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
            "offered_dialects": [0x0210, 0x0302], "client_capabilities": 0,
            "max_request_bytes": fixture.SMB2_MAX_REQUEST_BYTES,
            "max_response_bytes": fixture.SMB2_MAX_RESPONSE_BYTES,
            "max_security_buffer_bytes": fixture.SMB2_MAX_SECURITY_BUFFER_BYTES,
            "max_connections": 1, "max_requests": 1, "max_client_frames": 1,
            "client_write_half_close_before_response": True,
            "client_write_half_close_is_owned_profile_constraint": True,
            "behavior": "stall_after_validated_request" if case == "smb2-stalled"
                else "fragmented_response" if case == "smb2-fragmented"
                else "hostile_opaque_security_buffer" if case == "smb2-opaque"
                else "malformed_header" if case == "smb2-malformed"
                else "unoffered_dialect" if case == "smb2-unoffered"
                else "unknown_error_status" if case == "smb2-unknown-status"
                else "invalid_security_buffer_offset" if case == "smb2-invalid-buffer"
                else "truncated_response" if case == "smb2-truncated"
                else "oversized_frame_header" if case == "smb2-oversized" else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_fixed_negotiate_requests_followed_by_client_write_eof_before_response",
            "connection_evidence": "accepted_connections_lower_bound",
            "udp": False, "retries": False, "followup": False, "session_setup": False,
            "authentication": False, "credentials": False, "ntlm_exchange": False,
            "share_access": False, "token_interpretation": False, "service_identity_claim": False,
            "vulnerability_claim": False, "signing_enforcement_verified": False}
    if case.startswith("rdp-"):
        from . import network_tools_fixture as fixture
        response = fixture.rdp_response(case)
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-rdp-initial-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "rdp_initial_tcp"}],
            "request_sha256": hashlib.sha256(fixture.RDP_REQUEST).hexdigest(),
            "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
            "requested_protocols": ["tls"], "negotiation_request_flags": 0,
            "max_request_bytes": fixture.RDP_MAX_REQUEST_BYTES,
            "max_frame_bytes": fixture.RDP_MAX_FRAME_BYTES,
            "max_response_bytes": fixture.RDP_MAX_RESPONSE_BYTES,
            "max_connections": 1, "max_requests": 1, "max_client_frames": 1,
            "client_write_half_close_before_response": True,
            "client_write_half_close_is_owned_profile_constraint": True,
            "behavior": "stall_after_validated_request" if case == "rdp-stalled"
                else "fragmented_response" if case == "rdp-fragmented"
                else "hostile_trailing_bytes_not_consumed" if case == "rdp-trailing"
                else "malformed_x224_confirm" if case == "rdp-malformed"
                else "unoffered_protocol" if case == "rdp-unoffered"
                else "unknown_failure_code" if case == "rdp-unknown-failure"
                else "truncated_response" if case == "rdp-truncated"
                else "oversized_frame_header" if case == "rdp-oversized" else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_fixed_initial_requests_followed_by_client_write_eof_before_response",
            "connection_evidence": "accepted_connections_lower_bound",
            "udp": False, "retries": False, "followup": False, "tls_handshake": False,
            "credssp": False, "credentials": False, "authentication": False,
            "mcs": False, "remote_session": False, "clipboard": False, "channels": False,
            "service_identity_claim": False, "vulnerability_claim": False,
            "trailing_bytes_inspected": False}
    if case.startswith("dig-srv-"):
        from . import network_tools_fixture as fixture
        response = fixture.dns_srv_response(case, fixture.dns_srv_query())
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-dns-srv-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "dns_tcp"}],
            "query": {"name": fixture.DNS_SRV_QUERY_NAME, "type": "SRV", "class": "IN", "recursion": False},
            "query_sha256": hashlib.sha256(fixture.dns_srv_query()).hexdigest(),
            "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
            "dns_transaction_id": "copied_from_validated_question",
            "max_query_bytes": fixture.DNS_SRV_MAX_QUERY_BYTES,
            "max_response_bytes": fixture.DNS_SRV_MAX_RESPONSE_BYTES,
            "max_records": fixture.DNS_SRV_MAX_RECORDS,
            "max_connections": 1, "max_requests": 1,
            "behavior": "stall_after_validated_query" if case == "dig-srv-stalled"
                else "malformed_response" if case == "dig-srv-malformed"
                else "record_limit_pressure" if case == "dig-srv-record-limit"
                else "native_output_limit_pressure" if case == "dig-srv-output-limit"
                else "access_refused" if case == "dig-srv-refused"
                else "advertise_foreign_target_and_hostile_txt" if case == "dig-srv-injected" else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_fixed_srv_questions",
            "connection_evidence": "accepted_connections_lower_bound",
            "udp": False, "recursion": False, "retries": False, "search_suffixes": False,
            "target_resolution": False, "target_connections": False, "credentials": False,
            "service_identity_claim": False, "vulnerability_claim": False}
    if case.startswith("whatweb-"):
        from . import network_tools_fixture as fixture
        response = fixture.whatweb_response(case)
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-whatweb-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "http"}],
            "method": "GET", "path": fixture.WHATWEB_PATH, "user_agent": fixture.WHATWEB_USER_AGENT,
            "request_sha256": hashlib.sha256(fixture.WHATWEB_REQUEST).hexdigest(),
            "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
            "plugins": list(fixture.WHATWEB_PLUGINS), "aggression": 1,
            "max_request_bytes": fixture.WHATWEB_MAX_REQUEST_BYTES,
            "max_response_bytes": fixture.WHATWEB_MAX_RESPONSE_BYTES,
            "max_connections": 1, "max_requests": 1,
            "behavior": "stall_after_validated_get" if case == "whatweb-stalled" else "close_without_response"
                if case == "whatweb-eof" else "malformed_response" if case == "whatweb-malformed"
                else "response_limit_pressure" if case == "whatweb-oversized"
                else "native_output_limit_pressure" if case == "whatweb-output-limit"
                else "advertise_forbidden_redirect" if case in ("whatweb-redirect", "whatweb-meta-redirect")
                else "access_denied" if case == "whatweb-denied" else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals", "request_count_means": "validated_fixed_gets",
            "connection_evidence": "accepted_connections_lower_bound",
            "authentication": False, "credentials": False, "cookies": False,
            "redirects_followed": False, "scripts_executed": False, "subresources_fetched": False,
            "backend": False, "product_identity_claim": False, "vulnerability_claim": False}
    if case.startswith(("postgresql-tls-", "mysql-tls-")):
        from . import network_tools_fixture as fixture
        postgres = case.startswith("postgresql-tls-")
        response = fixture.database_tls_server_preface(case)
        request = fixture.POSTGRESQL_SSL_REQUEST if postgres else fixture.MYSQL_SSL_REQUEST
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-database-tls-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080,
                "protocol": "postgresql_starttls" if postgres else "mysql_starttls"}],
            "query_sha256": hashlib.sha256(request).hexdigest(),
            "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
            "tls_name": TLS_NAME, "tls_protocol": "TLSv1.3",
            "ca_sha256": hashlib.sha256(CA_PEM).hexdigest(),
            "certificate_sha256": UNTRUSTED_SERVER_CERT_SHA256 if case.endswith("-untrusted") else SERVER_CERT_SHA256,
            "negotiation": "fixed_postgresql_ssl_request" if postgres else "fixed_mysql_ssl_request",
            "server_version_is_untrusted": not postgres,
            "behavior": "stall_before_tls" if case.endswith("-stalled") else "tls_refused"
                if case.endswith("-refused") else "malformed_preface" if case.endswith("-malformed")
                else "hostile_preface" if case.endswith("-injected") else "tls_handshake",
            "max_preface_bytes": fixture.DATABASE_TLS_MAX_PREFACE_BYTES,
            "max_connections": 1, "max_requests": 1,
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "server_completed_tls_handshake_and_clean_close_notify",
            "application_payloads": "none", "authentication": False, "credentials": False,
            "database_selection": False, "sql": False, "backend": False,
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith(("redis-", "snmp-")):
        from . import network_tools_fixture as fixture
        redis = case.startswith("redis-")
        response = fixture.redis_response(case) if redis else fixture.snmp_response(case)
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-redis-snmp-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "redis_resp2" if redis else "snmp_v2c_tcp"}],
            "redis": {"command": ["INFO", "server"], "query_sha256": hashlib.sha256(fixture.REDIS_INFO_REQUEST).hexdigest(),
                "selected_fields": list(fixture.REDIS_SERVER_FIELDS), "keys": False, "authentication": False,
                "protocol_negotiation": False, "cluster_followup": False} if redis else None,
            "snmp": {"version": "2c", "community": fixture.SNMP_COMMUNITY.decode("ascii"),
                "community_is_public_synthetic_data": True, "operation": "GetRequest",
                "oids": list(fixture.SNMP_SYSTEM_OIDS), "request_id": "copied_from_validated_canonical_integer",
                "response_hash_uses_request_id": 1, "set": False, "getnext": False, "walk": False,
                "correction_requests": False, "retries": False, "udp": False} if not redis else None,
            "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
            "behavior": "stall_after_validated_query" if response is None else "malformed_response"
                if case.endswith("-malformed") else "bounded_oversized_response" if case.endswith("-oversized")
                else "access_denied" if case.endswith("-denied") else "advertise_forbidden_destination"
                if case.endswith(("-redirect-ip", "-redirect-port")) else "fixed_response",
            "max_request_bytes": fixture.REDIS_MAX_REQUEST_BYTES if redis else fixture.SNMP_MAX_REQUEST_BYTES,
            "max_response_bytes": fixture.REDIS_MAX_RESPONSE_BYTES if redis else fixture.SNMP_MAX_RESPONSE_BYTES,
            "max_connections": 1, "max_requests": 1,
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_info_server_commands" if redis else "validated_fixed_system_get_requests",
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith("kerberos-"):
        from . import network_tools_fixture as kerberos
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-kerberos-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "kerberos_tcp"}],
            "kerberos": {"realm": kerberos.KERBEROS_REALM, "principals": list(kerberos.KERBEROS_PRINCIPALS),
                "operation": "initial_as_req_without_preauth", "response_type": "KRB_ERROR_only",
                "response_sha256": [None if case.endswith("-stalled") else hashlib.sha256(
                    kerberos.response_for(case, name)).hexdigest() for name in kerberos.KERBEROS_PRINCIPALS],
                "passwords": False, "tickets": False, "real_directory": False,
                "preauthentication_credentials": False, "followup": False,
                "reports_are_verified_principals": False,
                "unknown_report_error_text_ambiguity": True},
            "behavior": "stall_after_validated_query" if case.endswith("-stalled") else "malformed_response"
                if case.endswith("-malformed") else "fixed_error_response",
            "max_request_bytes": kerberos.KERBEROS_MAX_REQUEST_BYTES,
            "max_connections": kerberos.KERBEROS_MAX_CONNECTIONS, "max_requests": kerberos.KERBEROS_MAX_REQUESTS,
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_initial_as_req_messages",
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith("nmap-service-"):
        from . import network_tools_fixture as fixture
        response = fixture.nmap_service_response(case)
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-nmap-service-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "finite_service_probes"}],
            "service": {"initial_connection": "tcp_connect_scan_requires_empty_eof",
                "banner": "SSH-2.0-OpenSSH_9.7" if case == "nmap-service-ssh" else None,
                "query_sha256": None if case == "nmap-service-ssh" else hashlib.sha256(fixture.NMAP_SERVICE_GET).hexdigest(),
                "response_sha256": None if response is None else hashlib.sha256(response).hexdigest(),
                "null_probe": "no_payload", "application_probe": "GET / HTTP/1.0",
                "authentication": False, "backend": False, "credentials": False,
                "tls": False, "rpc": False, "script_operations": False, "followup": False},
            "behavior": "stall_after_validated_query" if response is None else "fixed_response",
            "max_connections": fixture.NMAP_SERVICE_MAX_CONNECTIONS, "max_requests": 1,
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "ssh_banner_replies_sent" if case == "nmap-service-ssh" else "validated_fixed_http_gets",
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith(("docker-ping-", "docker-version-", "winrm-")):
        from . import network_tools_fixture as fixture
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-docker-winrm-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "http_metadata"}],
            "http": {"method": "GET", "path": fixture.HTTP_METADATA_PATHS[tool], "version": "HTTP/1.1",
                "host": "127.0.0.1:8080", "user_agent": fixture.HTTP_METADATA_USER_AGENT,
                "accept": "*/*", "connection": "close", "request_body": False,
                "redirect_followup": False, "authentication": False, "soap": False,
                "backend": False, "docker_socket": False, "container_operations": False,
                "remote_session": False, "max_request_bytes": fixture.HTTP_METADATA_MAX_REQUEST_BYTES},
            "response_sha256": None if case.endswith("-stalled") else hashlib.sha256(
                fixture.http_metadata_response(case)).hexdigest(),
            "behavior": "stall_after_validated_query" if case.endswith("-stalled") else "malformed_response"
                if case.endswith("-malformed") else "advertise_forbidden_destination"
                if case.endswith(("-redirect-ip", "-redirect-port")) else "fixed_response",
            "max_connections": 1, "max_requests": 1,
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_fixed_http_gets",
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith(("ftp-", "smtp-")):
        from . import network_tools_fixture as fixture
        ftp = case.startswith("ftp-")
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-ftp-smtp-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080,
                          "protocol": "ftp_control_and_passive_data" if ftp else "smtp"}],
            "ftp": {"user": fixture.FTP_USER, "password": fixture.FTP_PASSWORD,
                "operation": "NLST", "directory": "/", "passive_target": "127.0.0.2" if case == "ftp-passive-ip" else "127.0.0.1",
                "passive_port": 8081 if case == "ftp-passive-port" else 8080,
                "names": () if case == "ftp-empty" else fixture.FTP_NAMES,
                "injected_name": fixture.HOSTILE_NOTE if case == "ftp-injected" else None,
                "filesystem": False, "file_transfer": False, "credentials": "fixed_public_anonymous_identity"} if ftp else None,
            "smtp": {"domain": fixture.SMTP_DOMAIN, "operation": "EHLO_then_QUIT",
                "capabilities": () if case == "smtp-empty" else fixture.SMTP_CAPABILITIES,
                "injected_note": fixture.HOSTILE_NOTE if case == "smtp-injected" else None,
                "helo_fallback": case == "smtp-rejected", "authentication": False,
                "mail": False, "account_probing": False} if not ftp else None,
            "behavior": "stall_after_validated_query" if case.endswith("-stalled") else "malformed_response"
                if case.endswith("-malformed") else "access_denied" if case.endswith(("-denied", "-rejected"))
                else "advertise_forbidden_destination" if case.startswith("ftp-passive-") else "fixed_response",
            "max_line_bytes": fixture.FTP_SMTP_MAX_LINE_BYTES, "max_commands": fixture.FTP_SMTP_MAX_COMMANDS,
            "max_connections": 2 if ftp else 1,
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_nlst_commands" if ftp else "validated_ehlo_commands",
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith(("rpc-", "nfs-")):
        from . import network_tools_fixture as rpc
        listing = case.startswith("rpc-")
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-rpc-nfs-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 111, "protocol": "onc_rpc_tcp"}],
            "rpc": {"rpc_version": 2, "portmapper_version": 2,
                "operation": "DUMP" if listing else "EXPORT", "mount_versions": [1, 3],
                "discovery": "PMAP_GETPORT_or_RPCB_GETADDR_fixed_program",
                "discovery_programs": [[100000, 2]] if listing else [[100005, 1], [100005, 3]],
                "discovery_owner": "fixed_libtirpc_string_or_empty",
                "authentication": "AUTH_NULL_or_synthetic_AUTH_SYS_reconlab_uid0_gid0",
                "discovered_port": 112 if case == "nfs-redirected" else 111,
                "registrations": () if case == "rpc-empty" else rpc.RPC_REGISTRATIONS +
                    ((rpc.RPC_INJECTED_REGISTRATION,) if case == "rpc-injected" else ()),
                "exports": () if case == "nfs-empty" else rpc.NFS_EXPORTS,
                "injected_group": rpc.NFS_HOSTILE_GROUP if case == "nfs-injected" else None,
                "filesystem": False, "credentials": False, "mount": False,
                "max_frame_bytes": rpc.RPC_MAX_FRAME_BYTES, "max_calls": rpc.RPC_MAX_CALLS,
                "max_connections": rpc.RPC_MAX_CONNECTIONS},
            "behavior": "stall_after_validated_query" if case.endswith("-stalled") else "malformed_response"
                        if case.endswith("-malformed") else "advertise_forbidden_port" if case == "nfs-redirected" else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_portmapper_dumps" if listing else "validated_mount_exports",
            "discovery_requests": "bounded_and_excluded_from_metadata_count",
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith("smb-"):
        from . import network_tools_fixture as fixture
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-smb-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "smb2"}],
            "smb": {"dialect": "SMB2_02", "session": "anonymous_only", "tree": "IPC$",
                "pipe": "srvsvc", "operation": "NetrShareEnum", "level": 1,
                "shares": fixture.smb_shares(case), "filesystem": False, "credentials": False,
                "signing": False, "encryption": False, "max_frame_bytes": 8192, "max_messages": 24},
            "behavior": "stall_after_validated_query" if case == "smb-stalled" else "malformed_response"
                        if case == "smb-malformed" else "access_denied" if case == "smb-denied" else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "validated_level1_share_enumerations",
            "connection_evidence": "accepted_connections_lower_bound"}
    if case.startswith(("ssh-", "ldap-")):
        from . import network_tools_fixture as fixture
        ssh = case.startswith("ssh-")
        return {"id": LAB_ID, "version": LAB_VERSION, "scenario": case,
            "fixture_marker": "recon-harbordesk-ssh-ldap-v1", "tool_id": tool,
            "topology": [{"target": "127.0.0.1", "port": 8080, "protocol": "ssh_kex" if ssh else "ldap"}],
            "ssh": {"public_key_sha256": hashlib.sha256(fixture.SSH_PUBLIC_BLOB).hexdigest(),
                    "key_type": "ssh-rsa", "key_bits": 2048, "kex": "diffie-hellman-group14-sha256",
                    "signature": "rsa-sha2-256", "banner": fixture.SSH_BANNER.decode("ascii"),
                    "session": "ends_before_newkeys_and_userauth"} if ssh else None,
            "ldap": {"version": 3, "bind_dn": "", "bind_secret": "", "base_dn": "", "scope": "base",
                     "filter": "(objectClass=*)", "attributes": list(fixture.LDAP_ATTRIBUTES),
                     "values": {} if case == "ldap-empty" else fixture.LDAP_VALUES,
                     "referral": fixture.LDAP_REFERRAL if case == "ldap-referral" else None,
                     "aliases": "never", "size_limit": 1, "time_limit": 2} if not ssh else None,
            "injected_note": fixture.HOSTILE_NOTE if case.endswith("-injected") else None,
            "behavior": "stall_before_response" if case.endswith("-stalled") else "malformed_response"
                        if case.endswith("-malformed") else "fixed_response",
            "data": "public_synthetic_fixture_only", "lifetime": "authority_session",
            "reset": "destroy_and_create_new_instance", "external_egress": False, "resume": False,
            "counter_semantics": "last_acknowledged_service_totals",
            "request_count_means": "ssh_host_key_replies_sent" if ssh else "validated_rootdse_searches",
            "connection_evidence": "accepted_connections_lower_bound"}
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
    request_limit = 2 if expected["scenario"].startswith("kerberos-") else 1
    connection_limit = (2 if expected["scenario"].startswith("kerberos-") else 3 if expected["scenario"].startswith("nmap-service-")
                        else 4 if expected["scenario"].startswith(("rpc-", "nfs-"))
                        else 2 if (expected["scenario"].startswith("ftp-") and not expected["scenario"].startswith("ftp-tls-")) else 1)
    if (type(value) is not dict or set(value) != {"identity", "connection_count", "request_count"}
            or validate_identity(value["identity"]) != expected
            or type(value["connection_count"]) is not int or not 0 <= value["connection_count"] <= connection_limit
            or type(value["request_count"]) is not int or not 0 <= value["request_count"] <= request_limit
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
