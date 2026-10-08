"""Versioned, repository-reviewed tool descriptions, with no plugin loading.

Only the authority backend can execute a tool. A descriptor or compiled argv
does not grant permission, open a file, choose an executable, or launch a process.
The registry is explicit reviewed code; it never discovers entry points or
imports modules named by a proposal.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from .tool_parameters import (
    CurlHTTPSParameters, DigDNSParameters, FFufParameters, HTTPHeadersParameters, HTTPParameters, HTTPOptionsParameters,
    OpenSSLTLSParameters, SSHHostKeysParameters, SSHAlgorithmsParameters, LDAPRootDSEParameters, SMBShareListParameters,
    RPCInfoDumpParameters, ShowmountExportsParameters, CurlFTPListParameters, CurlSMTPCapabilitiesParameters,
    CurlDockerPingParameters, CurlDockerVersionParameters, CurlWinRMMetadataParameters, NmapServiceParameters,
    KerbruteUserenumParameters, RedisServerInfoParameters, SNMPSystemGetParameters, SNMPInterfaceNextParameters,
    PostgreSQLTLSParameters, MySQLTLSParameters, WhatWebParameters, DigSRVParameters, DigNSIDParameters, DigAXFRParameters, RDPInitialParameters, SMB2NegotiateParameters, SMTPStartTLSParameters, LDAPStartTLSParameters, FTPStartTLSParameters,
    NmapTCPParameters, TCPParameters, _fields, _reject,
)


ADAPTER_API_VERSION = "1"
NMAP_TOOL_ID = "nmap_tcp_connect_v1"
NMAP_EXECUTION_PROFILE = "owned-nmap-tcp-connect-v1"
NMAP_TARGET = "127.0.0.1"
NMAP_PORT = 8080
NMAP_TIMEOUT_SECONDS = 5
NMAP_MAX_OUTPUT_BYTES = 16_384
NMAP_SESSION_LIMITS = MappingProxyType({
    "max_steps": 3, "max_runtime_seconds": 60, "max_output_bytes": 18_432,
})
NMAP_EXECUTABLE = "/tool/nmap"
NMAP_DATA_DIRECTORY = "/tool/data"
LEGACY_PROPOSAL_PROFILE = "legacy-v1"
NMAP_PROPOSAL_PROFILE = "owned-nmap-http-v1"
HTTP_HEADERS_TOOL_ID = "http_headers_v1"
HTTP_HEADERS_EXECUTION_PROFILE = "owned-http-headers-v1"
HTTP_HEADERS_PATH = "/harbordesk/portal.html"
HTTP_HEADERS_PARAMETERS = MappingProxyType({
    "port": 8080, "method": "GET", "path": HTTP_HEADERS_PATH,
    "timeout_seconds": 1, "max_output_bytes": 2048,
})
CURL_TOOL_ID = "curl_https_get_v1"
HTTP_OPTIONS_TOOL_ID = "curl_http_options_v1"
HTTP_OPTIONS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
FFUF_TOOL_ID = "ffuf_content_discovery_v1"
CURL_PARAMETERS = MappingProxyType({
    "port": 8080, "method": "GET", "path": "/harbordesk/portal.html",
    "timeout_seconds": 3, "max_output_bytes": 8192,
})
FFUF_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 10, "max_output_bytes": 8192})
WEB_TOOLS_LIMITS = MappingProxyType({"max_steps": 1, "max_runtime_seconds": 60, "max_output_bytes": 8192})
DIG_TOOL_ID = "dig_dns_query_v1"
DIG_SRV_TOOL_ID = "dig_dns_srv_v1"
DIG_NSID_TOOL_ID = "dig_dns_nsid_v1"
DIG_AXFR_TOOL_ID = "dig_dns_axfr_v1"
RDP_TOOL_ID = "rdp_initial_negotiation_v1"
SMB2_TOOL_ID = "smb2_negotiate_metadata_v1"
OPENSSL_TOOL_ID = "openssl_tls_handshake_v1"
SSH_TOOL_ID = "ssh_host_keys_v1"
SSH_ALGORITHMS_TOOL_ID = "ssh_transport_algorithms_v1"
LDAP_TOOL_ID = "ldap_rootdse_v1"
SMB_TOOL_ID = "smb_share_list_v1"
RPCINFO_TOOL_ID = "rpcinfo_dump_v1"
SHOWMOUNT_TOOL_ID = "showmount_exports_v1"
FTP_TOOL_ID = "curl_ftp_list_v1"
SMTP_TOOL_ID = "curl_smtp_capabilities_v1"
DOCKER_PING_TOOL_ID = "curl_docker_ping_v1"
DOCKER_VERSION_TOOL_ID = "curl_docker_version_v1"
WINRM_TOOL_ID = "curl_winrm_metadata_v1"
NMAP_SERVICE_TOOL_ID = "nmap_service_identify_v1"
KERBRUTE_TOOL_ID = "kerbrute_userenum_v1"
REDIS_TOOL_ID = "redis_server_info_v1"
SNMP_TOOL_ID = "snmp_system_get_v1"
SNMP_NEXT_TOOL_ID = "snmp_interface_next_v1"
POSTGRESQL_TLS_TOOL_ID = "postgresql_tls_handshake_v1"
MYSQL_TLS_TOOL_ID = "mysql_tls_handshake_v1"
SMTP_TLS_TOOL_ID = "smtp_starttls_handshake_v1"
LDAP_TLS_TOOL_ID = "ldap_starttls_handshake_v1"
FTP_TLS_TOOL_ID = "ftp_starttls_handshake_v1"
WHATWEB_TOOL_ID = "whatweb_http_fingerprint_v1"
CONFIGURABLE_NMAP_TOOL_ID = "configurable_nmap_service_v1"
CONFIGURABLE_HEADERS_TOOL_ID = "configurable_http_headers_v1"
CONFIGURABLE_SSH_TOOL_ID = "configurable_ssh_host_keys_v1"
DIG_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
DIG_SRV_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
DIG_AXFR_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
DIG_NSID_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
RDP_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SMB2_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
OPENSSL_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SSH_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SSH_ALGORITHMS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
LDAP_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SMB_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
RPCINFO_PARAMETERS = MappingProxyType({"port": 111, "timeout_seconds": 5, "max_output_bytes": 8192})
SHOWMOUNT_PARAMETERS = MappingProxyType({"port": 111, "timeout_seconds": 5, "max_output_bytes": 8192})
FTP_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SMTP_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
DOCKER_PING_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
DOCKER_VERSION_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
WINRM_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
NMAP_SERVICE_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
KERBRUTE_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
REDIS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SNMP_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SNMP_NEXT_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
POSTGRESQL_TLS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
MYSQL_TLS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
SMTP_TLS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
LDAP_TLS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
FTP_TLS_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
WHATWEB_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
NETWORK_TOOLS_LIMITS = MappingProxyType({"max_steps": 1, "max_runtime_seconds": 60, "max_output_bytes": 8192})


@dataclass(frozen=True, slots=True)
class ToolAdapter:
    """One immutable bundled capability; all methods are data transformations."""

    tool_id: str
    parameter_type: type
    parameter_fields: tuple[str, ...]
    effect: str
    execution_profile: str
    result_contract: str
    parser_version: str
    execution_requirements: tuple[str, ...]
    adapter_api_version: str = ADAPTER_API_VERSION
    capability_version: str = "1"

    def parse_parameters(self, value):
        return self.parameter_type(**_fields(value, set(self.parameter_fields), "parameters"))

    def parameter_schema(self):
        # Keep property/required order identical to the original codec. The
        # schema describes syntax; operator policy and runtime remain stricter.
        properties = {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 30},
            "max_output_bytes": {"type": "integer", "minimum": 1, "maximum": 65536},
        }
        if self.tool_id in ("http_probe", HTTP_HEADERS_TOOL_ID, CURL_TOOL_ID, CONFIGURABLE_HEADERS_TOOL_ID):
            properties.update({
                "method": {"type": "string", "enum": ["GET", "HEAD"]},
                "path": {"type": "string", "minLength": 1, "maxLength": 256},
            })
        return {"type": "object", "properties": properties,
                "required": list(properties), "additionalProperties": False}

    def to_dict(self):
        return {
            "adapter_api_version": self.adapter_api_version,
            "tool_id": self.tool_id, "capability_version": self.capability_version,
            "parameters": self.parameter_schema(), "effect": self.effect,
            "execution_profile": self.execution_profile,
            "result_contract": self.result_contract, "parser_version": self.parser_version,
            "execution_requirements": list(self.execution_requirements),
            "approval": "operator_policy", "live_calls_enabled": False,
        }


ADAPTERS = MappingProxyType({
    "http_probe": ToolAdapter(
        "http_probe", HTTPParameters,
        ("port", "method", "path", "timeout_seconds", "max_output_bytes"),
        "read_owned_fixture_http", "owned-http-probe-v1",
        "decoded-http-probe-result-v1", "http-assessment-v1",
        ("private_namespaces", "scoped_network_filter", "no_process_execution"),
    ),
    "tcp_connect": ToolAdapter(
        "tcp_connect", TCPParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "connect_owned_fixture_tcp", "owned-tcp-connect-v1",
        "bounded-tcp-connect-result-v1", "tcp-connect-discovery-v1",
        ("private_namespaces", "scoped_network_filter", "no_process_execution"),
    ),
    NMAP_TOOL_ID: ToolAdapter(
        NMAP_TOOL_ID, NmapTCPParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "scan_owned_fixture_tcp", NMAP_EXECUTION_PROFILE,
        "bounded-nmap-xml-result-v1", "nmap-tcp-connect-xml-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_nmap_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "no_raw_sockets"),
    ),
    HTTP_HEADERS_TOOL_ID: ToolAdapter(
        HTTP_HEADERS_TOOL_ID, HTTPHeadersParameters,
        ("port", "method", "path", "timeout_seconds", "max_output_bytes"),
        "read_owned_fixture_http_response", HTTP_HEADERS_EXECUTION_PROFILE,
        "bounded-http-headers-result-v1", "http-headers-v1",
        ("private_namespaces", "scoped_network_filter", "no_process_execution",
         "no_redirect_following", "bounded_raw_response"),
    ),
    CURL_TOOL_ID: ToolAdapter(
        CURL_TOOL_ID, CurlHTTPSParameters,
        ("port", "method", "path", "timeout_seconds", "max_output_bytes"),
        "read_owned_fixture_https", "owned-curl-https-v1",
        "bounded-curl-wire-result-v1", "curl-https-http-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "verified_fixture_tls",
         "no_redirect_following", "bounded_raw_response"),
    ),
    HTTP_OPTIONS_TOOL_ID: ToolAdapter(
        HTTP_OPTIONS_TOOL_ID, HTTPOptionsParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_http_options", "owned-curl-http-options-v1",
        "bounded-curl-http-options-result-v1", "curl-http-options-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_options_request",
         "single_connection_and_request", "no_redirect_following", "no_authentication",
         "no_response_directed_followup", "bounded_raw_response",
         "untrusted_http_capability_metadata_only"),
    ),
    FFUF_TOOL_ID: ToolAdapter(
        FFUF_TOOL_ID, FFufParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "discover_owned_fixture_http_paths", "owned-ffuf-content-v1",
        "bounded-ffuf-json-result-v1", "ffuf-content-json-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "pinned_dictionary", "no_redirect_following"),
    ),
    DIG_TOOL_ID: ToolAdapter(
        DIG_TOOL_ID, DigDNSParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "query_owned_fixture_dns", "owned-dig-dns-v1",
        "bounded-dig-dns-result-v1", "dig-dns-text-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "fixed_dns_question", "tcp_only", "no_recursive_resolution"),
    ),
    DIG_AXFR_TOOL_ID: ToolAdapter(
        DIG_AXFR_TOOL_ID, DigAXFRParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_dns_zone_transfer", "owned-dig-dns-axfr-v1",
        "bounded-dig-dns-axfr-result-v1", "dig-dns-axfr-text-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "fixed_dns_axfr_question", "tcp_only", "no_recursive_resolution",
         "single_connection_and_question", "no_response_directed_followup",
         "untrusted_dns_zone_transfer_metadata_only"),
    ),
    DIG_NSID_TOOL_ID: ToolAdapter(
        DIG_NSID_TOOL_ID, DigNSIDParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_dns_nsid_metadata", "owned-dig-dns-nsid-v1",
        "bounded-dig-dns-nsid-result-v1", "dig-dns-nsid-text-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "fixed_dns_nsid_question", "tcp_only", "no_recursive_resolution",
         "single_connection_and_question", "no_response_directed_followup",
         "untrusted_dns_server_metadata_only"),
    ),
    DIG_SRV_TOOL_ID: ToolAdapter(
        DIG_SRV_TOOL_ID, DigSRVParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_dns_service_metadata", "owned-dig-dns-srv-v1",
        "bounded-dig-dns-srv-result-v1", "dig-dns-srv-text-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "fixed_dns_srv_question", "tcp_only", "no_recursive_resolution",
         "single_connection_and_question", "no_advertised_endpoint_followup",
         "untrusted_dns_service_metadata_only"),
    ),
    RDP_TOOL_ID: ToolAdapter(
        RDP_TOOL_ID, RDPInitialParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_rdp_initial_negotiation", "owned-rdp-initial-negotiation-v1",
        "bounded-rdp-initial-result-v1", "rdp-initial-negotiation-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "fixed_initial_protocol_offer", "single_connection_and_request", "tcp_only",
         "write_half_close_before_response", "no_authentication_or_security_handshake",
         "untrusted_negotiation_metadata_only"),
    ),
    SMB2_TOOL_ID: ToolAdapter(
        SMB2_TOOL_ID, SMB2NegotiateParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_smb2_negotiation_metadata", "owned-smb2-negotiate-v1",
        "bounded-smb2-negotiate-result-v1", "smb2-negotiate-metadata-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "fixed_smb2_negotiate_offer", "single_connection_and_request", "tcp_only",
         "write_half_close_before_response", "no_session_setup_or_authentication",
         "no_share_access", "untrusted_negotiation_metadata_only"),
    ),
    OPENSSL_TOOL_ID: ToolAdapter(
        OPENSSL_TOOL_ID, OpenSSLTLSParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_fixture_tls_handshake", "owned-openssl-tls-v1",
        "bounded-openssl-tls-result-v1", "openssl-tls-brief-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "verified_fixture_tls",
         "fixed_tls_name", "no_application_request"),
    ),
    POSTGRESQL_TLS_TOOL_ID: ToolAdapter(
        POSTGRESQL_TLS_TOOL_ID, PostgreSQLTLSParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_postgresql_tls_handshake", "owned-postgresql-tls-v1",
        "bounded-postgresql-tls-result-v1", "postgresql-tls-brief-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "verified_fixture_tls",
         "fixed_tls_name", "fixed_database_tls_preface", "no_database_login",
         "no_sql", "no_plaintext_downgrade", "no_application_request"),
    ),
    MYSQL_TLS_TOOL_ID: ToolAdapter(
        MYSQL_TLS_TOOL_ID, MySQLTLSParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_mysql_tls_handshake", "owned-mysql-tls-v1",
        "bounded-mysql-tls-result-v1", "mysql-tls-brief-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "verified_fixture_tls",
         "fixed_tls_name", "fixed_database_tls_preface", "no_database_login",
         "no_sql", "no_plaintext_downgrade", "no_application_request"),
    ),
    SMTP_TLS_TOOL_ID: ToolAdapter(
        SMTP_TLS_TOOL_ID, SMTPStartTLSParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_smtp_starttls_handshake", "owned-smtp-starttls-v1",
        "bounded-smtp-starttls-result-v1", "smtp-starttls-brief-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "verified_fixture_tls",
         "fixed_tls_name", "fixed_ehlo_and_starttls", "single_connection",
         "no_authentication_or_mail", "no_client_credentials", "no_plaintext_session",
         "no_tls_application_request", "owner_witnessed_clean_tls_close"),
    ),
    LDAP_TLS_TOOL_ID: ToolAdapter(
        LDAP_TLS_TOOL_ID, LDAPStartTLSParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_ldap_starttls_handshake", "owned-ldap-starttls-v1",
        "bounded-ldap-starttls-result-v1", "ldap-starttls-brief-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "verified_fixture_tls",
         "fixed_tls_name", "fixed_ldap_starttls_request", "single_connection",
         "no_bind_or_search", "no_client_credentials", "no_referral_following",
         "no_tls_application_request", "owner_witnessed_clean_tls_close"),
    ),
    FTP_TLS_TOOL_ID: ToolAdapter(
        FTP_TLS_TOOL_ID, FTPStartTLSParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_ftp_starttls_handshake", "owned-ftp-starttls-v1",
        "bounded-ftp-starttls-result-v1", "ftp-starttls-brief-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "verified_fixture_tls",
         "fixed_tls_name", "fixed_ftp_auth_tls_request", "single_connection",
         "no_login", "no_client_credentials", "no_data_connection", "no_file_transfer",
         "no_tls_application_request", "owner_witnessed_clean_tls_close"),
    ),
    WHATWEB_TOOL_ID: ToolAdapter(
        WHATWEB_TOOL_ID, WhatWebParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_http_application_hints", "owned-whatweb-http-v1",
        "bounded-whatweb-http-result-v1", "whatweb-json-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "fixed_http_get", "finite_passive_plugins", "single_connection_and_request",
         "bounded_response_input", "no_redirects", "no_retries", "no_authentication",
         "untrusted_application_hints_only"),
    ),
    SSH_TOOL_ID: ToolAdapter(
        SSH_TOOL_ID, SSHHostKeysParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_fixture_ssh_host_key", "owned-ssh-host-keys-v1",
        "bounded-ssh-host-key-result-v1", "ssh-keyscan-rsa-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_rsa_key_type",
         "no_authentication", "no_host_trust_claim"),
    ),
    SSH_ALGORITHMS_TOOL_ID: ToolAdapter(
        SSH_ALGORITHMS_TOOL_ID, SSHAlgorithmsParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_ssh_transport_algorithms", "owned-ssh-transport-algorithms-v1",
        "bounded-ssh-transport-algorithms-result-v1", "ssh-kexinit-wire-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes", "fixed_tcp_endpoint",
         "single_fixed_identification_and_kexinit", "fresh_cookie_only", "write_shutdown_before_response",
         "one_bounded_server_packet", "no_key_exchange_completion", "no_authentication",
         "no_host_trust_claim", "no_response_directed_followup", "untrusted_algorithm_advertisements"),
    ),
    LDAP_TOOL_ID: ToolAdapter(
        LDAP_TOOL_ID, LDAPRootDSEParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "read_owned_fixture_ldap_rootdse", "owned-ldap-rootdse-v1",
        "bounded-ldap-rootdse-result-v1", "ldap-rootdse-ldif-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "anonymous_rootdse_only",
         "fixed_attribute_list", "no_referral_following"),
    ),
    SMB_TOOL_ID: ToolAdapter(
        SMB_TOOL_ID, SMBShareListParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "list_owned_fixture_smb_shares", "owned-smb-share-list-v1",
        "bounded-smb-share-list-result-v1", "smb-share-list-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "anonymous_share_listing_only",
         "no_file_share_access", "no_followup_to_metadata"),
    ),
    RPCINFO_TOOL_ID: ToolAdapter(
        RPCINFO_TOOL_ID, RPCInfoDumpParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "list_owned_fixture_rpc_registrations", "owned-rpcinfo-dump-v1",
        "bounded-rpcinfo-dump-result-v1", "rpcinfo-dump-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "registration_metadata_only", "no_followup_to_metadata"),
    ),
    SHOWMOUNT_TOOL_ID: ToolAdapter(
        SHOWMOUNT_TOOL_ID, ShowmountExportsParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "list_owned_fixture_nfs_exports", "owned-showmount-exports-v1",
        "bounded-showmount-exports-result-v1", "showmount-exports-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "export_metadata_only", "no_mount_or_file_access"),
    ),
    FTP_TOOL_ID: ToolAdapter(
        FTP_TOOL_ID, CurlFTPListParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "list_owned_fixture_ftp_names", "owned-curl-ftp-list-v1",
        "bounded-curl-ftp-list-result-v1", "curl-ftp-list-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_control_and_data_endpoint",
         "anonymous_name_listing_only", "no_file_transfer", "no_followup_to_metadata"),
    ),
    SMTP_TOOL_ID: ToolAdapter(
        SMTP_TOOL_ID, CurlSMTPCapabilitiesParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_fixture_smtp_capabilities", "owned-curl-smtp-capabilities-v1",
        "bounded-curl-smtp-capabilities-result-v1", "curl-smtp-capabilities-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "capability_metadata_only", "no_authentication", "no_mail_submission"),
    ),
    DOCKER_PING_TOOL_ID: ToolAdapter(
        DOCKER_PING_TOOL_ID, CurlDockerPingParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_fixture_docker_ping", "owned-curl-docker-ping-v1",
        "bounded-curl-docker-ping-result-v1", "curl-docker-ping-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "fixed_metadata_get_only", "no_authentication", "no_redirect_following",
         "no_daemon_or_wsman_operations", "no_followup_to_metadata"),
    ),
    DOCKER_VERSION_TOOL_ID: ToolAdapter(
        DOCKER_VERSION_TOOL_ID, CurlDockerVersionParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "read_owned_fixture_docker_version", "owned-curl-docker-version-v1",
        "bounded-curl-docker-version-result-v1", "curl-docker-version-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "fixed_metadata_get_only", "no_authentication", "no_redirect_following",
         "no_daemon_or_wsman_operations", "no_followup_to_metadata"),
    ),
    REDIS_TOOL_ID: ToolAdapter(
        REDIS_TOOL_ID, RedisServerInfoParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_redis_server_metadata", "owned-redis-server-info-v1",
        "bounded-redis-server-info-result-v1", "redis-info-server-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "single_info_server", "no_authentication", "no_key_access",
         "no_cluster_redirects", "no_followup_to_metadata"),
    ),
    SNMP_TOOL_ID: ToolAdapter(
        SNMP_TOOL_ID, SNMPSystemGetParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_snmp_system_metadata", "owned-snmp-system-get-v1",
        "bounded-snmp-system-get-result-v1", "snmp-system-text-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "single_fixed_scalar_get", "public_synthetic_community", "no_walk_or_set",
         "no_mib_or_host_config", "no_udp", "no_followup_to_metadata"),
    ),
    SNMP_NEXT_TOOL_ID: ToolAdapter(
        SNMP_NEXT_TOOL_ID, SNMPInterfaceNextParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_snmp_interface_successor", "owned-snmp-interface-next-v1",
        "bounded-snmp-interface-next-result-v1", "snmp-interface-next-text-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "single_fixed_seed_getnext", "public_synthetic_community", "no_walk_or_set",
         "no_retries_or_oid_correction", "no_mib_or_host_config", "no_udp",
         "no_followup_to_returned_oid", "untrusted_interface_metadata_only"),
    ),
    KERBRUTE_TOOL_ID: ToolAdapter(
        KERBRUTE_TOOL_ID, KerbruteUserenumParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "enumerate_owned_synthetic_principal_reports", "owned-kerbrute-userenum-v1",
        "bounded-kerbrute-userenum-result-v1", "kerbrute-userenum-text-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes", "fixed_tcp_endpoint",
         "compiled_synthetic_principals", "no_passwords_or_spraying", "synthetic_error_only_kdc",
         "tool_report_only", "no_followup_to_metadata"),
    ),
    NMAP_SERVICE_TOOL_ID: ToolAdapter(
        NMAP_SERVICE_TOOL_ID, NmapServiceParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "identify_owned_fixture_service", "owned-nmap-service-identification-v1",
        "bounded-nmap-service-result-v1", "nmap-service-xml-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "finite_compiled_service_probes", "nse_scripts_disabled", "no_authentication",
         "no_followup_to_metadata"),
    ),
    WINRM_TOOL_ID: ToolAdapter(
        WINRM_TOOL_ID, CurlWinRMMetadataParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_owned_fixture_winrm_metadata", "owned-curl-winrm-metadata-v1",
        "bounded-curl-winrm-metadata-result-v1", "curl-winrm-metadata-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "no_child_processes", "fixed_tcp_endpoint",
         "fixed_metadata_get_only", "no_authentication", "no_redirect_following",
         "no_daemon_or_wsman_operations", "no_followup_to_metadata"),
    ),
    CONFIGURABLE_NMAP_TOOL_ID: ToolAdapter(
        CONFIGURABLE_NMAP_TOOL_ID, NmapServiceParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "identify_declared_owned_endpoint", "configurable-owned-endpoint-v1",
        "configurable-service-result-v1", "configurable-nmap-service-xml-v1",
        ("immutable_operator_scope", "private_endpoint_namespace", "scoped_network_filter",
         "pinned_tool_runtime", "finite_compiled_service_probes", "nse_scripts_disabled",
         "no_authentication", "no_external_connectivity"),
    ),
    CONFIGURABLE_HEADERS_TOOL_ID: ToolAdapter(
        CONFIGURABLE_HEADERS_TOOL_ID, HTTPHeadersParameters,
        ("port", "method", "path", "timeout_seconds", "max_output_bytes"),
        "observe_declared_owned_http_headers", "configurable-owned-endpoint-v1",
        "configurable-header-result-v1", "configurable-http-headers-v1",
        ("immutable_operator_scope", "private_endpoint_namespace", "scoped_network_filter",
         "no_redirect_following", "no_authentication", "no_external_connectivity"),
    ),
    CONFIGURABLE_SSH_TOOL_ID: ToolAdapter(
        CONFIGURABLE_SSH_TOOL_ID, SSHHostKeysParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "observe_declared_owned_ssh_host_key", "configurable-owned-endpoint-v1",
        "configurable-ssh-result-v1", "configurable-ssh-keyscan-v1",
        ("immutable_operator_scope", "private_endpoint_namespace", "scoped_network_filter",
         "pinned_tool_runtime", "no_authentication", "no_external_connectivity"),
    ),
})
SUPPORTED_TOOLS = tuple(ADAPTERS)
_PROPOSAL_PROFILES = MappingProxyType({
    LEGACY_PROPOSAL_PROFILE: ("http_probe", "tcp_connect"),
    NMAP_PROPOSAL_PROFILE: (NMAP_TOOL_ID, "http_probe"),
})


def get_adapter(tool_id: str, *, adapter_api_version=ADAPTER_API_VERSION) -> ToolAdapter:
    if type(adapter_api_version) is not str or adapter_api_version != ADAPTER_API_VERSION:
        _reject("unsupported_adapter_api")
    if type(tool_id) is not str or tool_id not in ADAPTERS:
        _reject("unsupported_tool")
    return ADAPTERS[tool_id]


def proposal_tools(profile=LEGACY_PROPOSAL_PROFILE):
    if type(profile) is not str or profile not in _PROPOSAL_PROFILES:
        _reject("unsupported_proposal_profile")
    return _PROPOSAL_PROFILES[profile]


def compile_nmap_argv(action):
    """Compile the sole supported executable profile, with no scope expansion.

    Revalidation prevents forged parameter instances from becoming executable
    arguments. The caller still must independently authorize and isolate it.
    """
    from .models import Action, parse_action

    if type(action) is not Action:
        _reject("invalid_action")
    action = parse_action(action.to_dict())
    if (action.tool_id != NMAP_TOOL_ID or action.target != NMAP_TARGET
            or action.parameters.to_dict() != {
                "port": NMAP_PORT, "timeout_seconds": NMAP_TIMEOUT_SECONDS,
                "max_output_bytes": NMAP_MAX_OUTPUT_BYTES,
            }):
        _reject("unsupported_nmap_execution_profile")
    return (
        NMAP_EXECUTABLE, "--unprivileged", "-sT", "-Pn", "-n", "-p", "8080",
        "--max-retries", "0", "--max-parallelism", "1", "--host-timeout", "3s",
        "--datadir", NMAP_DATA_DIRECTORY, "--no-stylesheet", "-oX", "-", NMAP_TARGET,
    )
