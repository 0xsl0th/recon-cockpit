"""Closed T04 candidate contract for one owned twelve-path ffuf action."""

from types import MappingProxyType

if __package__:
    from .web_hierarchy_spec import (CASES as VARIANTS, PREFIXES, PATHS, WORDS, WORDLIST,
                                     MAX_OWNER_MESSAGE, MAX_CONNECTIONS)
else:
    # The isolated owner/parser has the same reviewed sibling source mounted.
    import importlib.util
    from pathlib import Path
    _definition = importlib.util.spec_from_file_location("production_hierarchy_native_spec",
        Path(__file__).with_name("web_hierarchy_spec.py"))
    _module = importlib.util.module_from_spec(_definition)
    _definition.loader.exec_module(_module)
    VARIANTS, PREFIXES, PATHS = _module.CASES, _module.PREFIXES, _module.PATHS
    WORDS, WORDLIST = _module.WORDS, _module.WORDLIST
    MAX_OWNER_MESSAGE, MAX_CONNECTIONS = _module.MAX_OWNER_MESSAGE, _module.MAX_CONNECTIONS

TOOL_ID = "ffuf_web_hierarchy_v1"
CASE_PARTS = MappingProxyType({f"web-hierarchy-{variant}": variant for variant in VARIANTS})
CASES = tuple(CASE_PARTS)
PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 10, "max_output_bytes": 8192})
LIMITS = MappingProxyType({"max_steps": 1, "max_runtime_seconds": 60, "max_output_bytes": 8192})
PARSER_VERSION = "ffuf-web-hierarchy-owner-json-v1"
MAX_OWNER_BYTES = MAX_OWNER_MESSAGE
OWNER_REPRESENTATION = "owned-web-hierarchy-owner-json-v1"
BOUNDARY_FIELDS = frozenset({"udp_sockets_blocked", "inherited_descriptors_closed"})


def case_parts(case):
    if type(case) is not str or case not in CASE_PARTS:
        raise ValueError("invalid_web_hierarchy_case")
    return CASE_PARTS[case]


def tool_for_case(case):
    case_parts(case)
    return TOOL_ID
