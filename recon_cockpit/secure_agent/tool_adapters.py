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
    CurlHTTPSParameters, FFufParameters, HTTPHeadersParameters, HTTPParameters,
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
FFUF_TOOL_ID = "ffuf_content_discovery_v1"
CURL_PARAMETERS = MappingProxyType({
    "port": 8080, "method": "GET", "path": "/harbordesk/portal.html",
    "timeout_seconds": 3, "max_output_bytes": 8192,
})
FFUF_PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 10, "max_output_bytes": 8192})
WEB_TOOLS_LIMITS = MappingProxyType({"max_steps": 1, "max_runtime_seconds": 60, "max_output_bytes": 8192})


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
        if self.tool_id in ("http_probe", HTTP_HEADERS_TOOL_ID, CURL_TOOL_ID):
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
    FFUF_TOOL_ID: ToolAdapter(
        FFUF_TOOL_ID, FFufParameters, ("port", "timeout_seconds", "max_output_bytes"),
        "discover_owned_fixture_http_paths", "owned-ffuf-content-v1",
        "bounded-ffuf-json-result-v1", "ffuf-content-json-v1",
        ("private_namespaces", "scoped_network_filter", "pinned_tool_runtime",
         "reviewed_exec_allowlist", "bounded_threads", "no_child_processes",
         "pinned_dictionary", "no_redirect_following"),
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
