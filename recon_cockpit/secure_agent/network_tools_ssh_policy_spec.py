"""Finite T03 authority and useful-case definitions; no dynamic policy input."""

from .network_tools_ssh_policy_parser import TOOL_ID, PARSER_VERSION, POLICY_ID, POLICY_SHA256
from .network_tools_fixture import SSH_POLICY_CASES as CASES

PARAMETERS = {"port": 8080, "timeout_seconds": 5, "max_output_bytes": 8192}
USEFUL_CASES = CASES[:8]
ORDINARY_CASES = CASES[:6]
ROBUSTNESS_CASES = CASES[6:8]
UNKNOWN_CASES = CASES[8:10]
SUCCESS_CASES = CASES[:10]  # A parsed unknown is not a completed policy task.
NEGATIVE_CASES = CASES[10:]


def response(case):
    from .network_tools_fixture import ssh_policy_response as read_response
    return read_response(case)


def useful_capture(case):
    if type(case) is not str or case not in SUCCESS_CASES:
        raise ValueError("invalid_ssh_policy_capture_case")
    raw = response(case)
    offset = raw.index(b"\r\n") + 2
    return raw[:offset + 4 + int.from_bytes(raw[offset:offset + 4], "big")]


def expected_status(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_ssh_policy_case")
    if case in ("ssh-policy-legacy", "ssh-policy-c2s-deviation", "ssh-policy-s2c-deviation"):
        return "deviation"
    return "conforming" if case in USEFUL_CASES else "inconclusive"
