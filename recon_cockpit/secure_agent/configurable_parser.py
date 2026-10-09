"""Closed endpoint-aware observations; raw tool bytes never become authority."""

import re

from .configurable_scope import endpoint, validate_scope
from . import http_headers_parser, network_tools_nmap_parser, network_tools_parser

NMAP = "configurable_nmap_service_v1"
HEADERS = "configurable_http_headers_v1"
SSH = "configurable_ssh_host_keys_v1"
VERSIONS = {NMAP: "configurable-nmap-service-xml-v1", HEADERS: "configurable-http-headers-v1",
            SSH: "configurable-ssh-keyscan-v1"}
MAX_OUTPUT_BYTES = 8192


def parser_version(tool_id):
    if type(tool_id) is not str or tool_id not in VERSIONS:
        raise ValueError("unsupported_configurable_parser")
    return VERSIONS[tool_id]


def _selected(tool_id, scope, endpoint_id):
    parser_version(tool_id)
    selected = endpoint(validate_scope(scope), endpoint_id)
    if ((tool_id == HEADERS and endpoint_id != "http")
            or (tool_id == SSH and endpoint_id != "ssh")):
        raise ValueError("configurable_parser_endpoint_mismatch")
    return selected


def validate_result(tool_id, value, scope, endpoint_id):
    selected = _selected(tool_id, scope, endpoint_id)
    version = parser_version(tool_id)
    if tool_id == NMAP:
        return network_tools_nmap_parser._validate_for_endpoint(
            value, selected["target"], selected["port"], version)
    if (type(value) is not dict or value.get("parser_version") != version
            or value.get("target") != selected["target"] or type(value.get("port")) is not int
            or value["port"] != selected["port"]):
        raise ValueError("invalid_configurable_observation")
    if tool_id == HEADERS:
        if set(value) != {"parser_version", "target", "port", "path", "headers"} or value["path"] != selected["path"]:
            raise ValueError("invalid_configurable_headers")
        return {**value, "headers": http_headers_parser.validate_result(value["headers"])}
    unscoped = {key: item for key, item in value.items() if key not in {"target", "port"}}
    unscoped["parser_version"] = network_tools_parser.parser_version(network_tools_parser.SSH_TOOL_ID)
    validated = network_tools_parser.validate_result(network_tools_parser.SSH_TOOL_ID, unscoped)
    return {**validated, "parser_version": version, "target": selected["target"], "port": selected["port"]}


def parse_tool_output(tool_id, raw, stderr, scope, endpoint_id, *, truncated=False):
    selected = _selected(tool_id, scope, endpoint_id)
    if (type(raw) is not bytes or type(stderr) is not bytes or not (raw or stderr)
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or type(truncated) is not bool or truncated):
        raise ValueError("invalid_configurable_output_size")
    version = parser_version(tool_id)
    if tool_id == NMAP:
        if stderr:
            raise ValueError("unexpected_configurable_nmap_diagnostics")
        return network_tools_nmap_parser._parse_for_endpoint(raw, selected["target"], selected["port"], version)
    if tool_id == HEADERS:
        if stderr:
            raise ValueError("unexpected_configurable_headers_diagnostics")
        return validate_result(tool_id, {"parser_version": version, "target": selected["target"],
            "port": selected["port"], "path": selected["path"],
            "headers": http_headers_parser.parse_http_headers(raw)}, scope, endpoint_id)
    banner = re.compile(r"# " + re.escape(selected["target"]) + ":" + str(selected["port"])
                        + r" SSH-2\.0-[\x20-\x7e]{1,200}")
    if stderr:
        diagnostic = network_tools_parser._lines(stderr)
        if len(diagnostic) != 1 or len(stderr.splitlines()) != 1 or banner.fullmatch(diagnostic[0]) is None:
            raise ValueError("unexpected_configurable_ssh_diagnostics")
    lines = network_tools_parser._lines(raw)
    if len(lines) != len(raw.splitlines()):
        raise ValueError("invalid_configurable_ssh_output")
    if len(lines) == 2 and banner.fullmatch(lines[0]) is not None:
        if stderr:
            raise ValueError("duplicate_configurable_ssh_banner")
        lines = lines[1:]
    if len(lines) != 1:
        raise ValueError("invalid_configurable_ssh_key_count")
    match = re.fullmatch(r"\[" + re.escape(selected["target"]) + r"\]:" + str(selected["port"])
                         + r" ssh-rsa ([A-Za-z0-9+/=]{1,1024})", lines[0])
    if match is None:
        raise ValueError("invalid_configurable_ssh_endpoint")
    encoded = match.group(1)
    return validate_result(tool_id, {"parser_version": version, "kind": "ssh_host_keys",
        "target": selected["target"], "port": selected["port"], "key_type": "ssh-rsa",
        "key_base64": encoded, **network_tools_parser._ssh_key_facts(encoded), "trust": "unverified"}, scope, endpoint_id)


def parse_output(tool_id, raw, stderr=b"", *, scope, endpoint_id, truncated=False):
    return parse_tool_output(tool_id, raw, stderr, scope, endpoint_id, truncated=truncated)
