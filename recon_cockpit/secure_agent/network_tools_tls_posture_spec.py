"""Closed constants for four owned TLS version-posture candidate profiles."""

from types import MappingProxyType

TOOL_VERSIONS = MappingProxyType({
    "openssl_tls10_posture_v1": "tls1",
    "openssl_tls11_posture_v1": "tls1_1",
    "openssl_tls12_posture_v1": "tls1_2",
    "openssl_tls13_posture_v1": "tls1_3",
})
VERSION_TO_TOOL = MappingProxyType({version: tool for tool, version in TOOL_VERSIONS.items()})
CASE_PARTS = MappingProxyType({
    **{f"tls-posture-{version}-{variant}": (version, variant)
       for version in VERSION_TO_TOOL for variant in ("modern", "legacy", "reject")},
    "tls-posture-tls1_3-hrr": ("tls1_3", "hrr"),
})
CASES = tuple(CASE_PARTS)
PARAMETERS = MappingProxyType({"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192})
LIMITS = MappingProxyType({"max_steps": 1, "max_runtime_seconds": 30, "max_output_bytes": 8192})
PARSER_VERSION = "openssl-tls-posture-wire-v1"
MAX_OWNER_BYTES = 262144
OWNER_REPRESENTATION = "owned-tls-posture-owner-json-v1"
BOUNDARY_FIELDS = frozenset({"unix_socket_creation_blocked", "unix_socketpair_creation_blocked",
                            "udp_sockets_blocked", "inherited_descriptors_closed"})


def case_parts(case):
    if type(case) is not str or case not in CASE_PARTS:
        raise ValueError("invalid_tls_posture_case")
    return CASE_PARTS[case]


def tool_for_case(case):
    return VERSION_TO_TOOL[case_parts(case)[0]]
