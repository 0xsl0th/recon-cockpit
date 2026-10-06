"""Evidence-only bindings and independent replay for the composed owned profile."""

import hashlib
import re

from .nmap_contract import encode

RUNTIME_TOOLS = frozenset({'nmap_service_identify_v1', 'ffuf_content_discovery_v1'})


def validate_runtime_bindings(value, digest):
    """Bind both separately pinned executables before any workflow action runs."""
    if value is None and digest is None:
        return None  # Dry-run manifests make no runtime availability claim.
    if (type(value) is not dict or set(value) != RUNTIME_TOOLS
            or any(type(item) is not str or re.fullmatch(r'[0-9a-f]{64}', item) is None
                   for item in value.values())
            or type(digest) is not str or hashlib.sha256(encode(value)).hexdigest() != digest):
        raise ValueError('invalid_service_web_runtime_bindings')
    return dict(value)


def replay_result(record, result, manifest, *, deadline=None):
    """Reuse the accepted confined parsers; observations never come from labels."""
    bindings = validate_runtime_bindings(manifest.get('runtime_bindings'), manifest['runtime_sha256'])
    if bindings is None:
        raise ValueError('service_web_runtime_commitment_missing')
    tool_id, status = record['action']['tool_id'], record['execution_status']
    if tool_id == 'nmap_service_identify_v1':
        from .network_tools_contract import validate_tool_result
        from .network_tools_parser_runtime import parse_isolated_tool
        stdout, stderr = validate_tool_result(result, tool_id=tool_id,
            execution_status=status, runtime_sha256=bindings[tool_id])
        if status == 'succeeded':
            try:
                parsed = parse_isolated_tool(tool_id, stdout, stderr, deadline=deadline)
            except ValueError:
                parsed = None
            if encode(parsed) != encode(result['tool_observation']):
                raise ValueError('service_web_network_parsed_result_mismatch')
    elif tool_id == 'ffuf_content_discovery_v1':
        from .web_tools_contract import validate_tool_result
        from .web_tools_parser_runtime import parse_isolated_tool
        stdout, _ = validate_tool_result(result, tool_id=tool_id,
            execution_status=status, runtime_sha256=bindings[tool_id])
        if status == 'succeeded':
            try:
                parsed = parse_isolated_tool(tool_id, stdout, deadline=deadline)
            except ValueError:
                parsed = None
            if encode(parsed) != encode(result['tool_observation']):
                raise ValueError('service_web_ffuf_parsed_result_mismatch')
    elif tool_id == 'http_headers_v1':
        from .http_headers_contract import validate_http_result
        from .http_headers_parser_runtime import parse_isolated_headers
        raw = validate_http_result(result, execution_status=status)
        if status == 'succeeded' and not result['truncated']:
            try:
                parsed = parse_isolated_headers(raw, deadline=deadline)
            except ValueError:
                parsed = None
            if encode(parsed) != encode(result['http_headers']):
                raise ValueError('service_web_headers_parsed_result_mismatch')
    else:
        raise ValueError('unsupported_service_web_result_tool')
