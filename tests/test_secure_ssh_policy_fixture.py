"""Finite T03 fixtures preserve exact request validation before any response."""

import socket
import time

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as public
from recon_cockpit.secure_agent import network_tools_lab_contract as identity
from recon_cockpit.secure_agent import network_tools_ssh_policy_fixture as owner
from recon_cockpit.secure_agent import network_tools_ssh_policy_spec as spec
from recon_cockpit.secure_agent import network_tools_ssh_policy_parser as parser
from test_secure_ssh_algorithms_fixture import Connection


@pytest.mark.parametrize("case", spec.CASES)
def test_one_validated_request_and_actual_eof_precede_response(case, monkeypatch):
    connection, calls, sleeps = Connection(chunk_size=3), [], []
    monkeypatch.setattr(owner.time, "sleep", sleeps.append)
    def counted():
        assert connection.eof_observed and not connection.output and connection.input.tell() == 184
        calls.append(1)
    owner.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=counted)
    assert calls == [1]
    assert bytes(connection.output) == (spec.response(case) or b"")
    assert len(connection.output) <= 4355
    assert public.tool_for_case(case) == spec.TOOL_ID
    contract = identity.spec(case)
    assert contract["max_requests"] == contract["max_connections"] == 1
    assert contract["request_bytes"] == 184 and contract["policy_sha256"] == parser.POLICY_SHA256
    if case in spec.SUCCESS_CASES:
        result = parser.parse_output(spec.useful_capture(case))
        assert result["policy_status"] == spec.expected_status(case)
        assert (result["policy_status"] != "inconclusive") == (case in spec.USEFUL_CASES)
    else:
        with pytest.raises(ValueError):
            parser.parse_output(bytes(connection.output))


@pytest.mark.parametrize("case", ["ssh-policy-conforming", "ssh-policy-legacy"])
@pytest.mark.parametrize("extra", [b"\0", public.SSH_ALGORITHMS_REQUEST, b"KEXDH_INIT", b"ssh-userauth", b"session"])
def test_forbidden_followup_bytes_prevent_count_and_response(case, extra):
    connection, calls = Connection(public.SSH_ALGORITHMS_REQUEST + extra), []
    with pytest.raises(ValueError, match="followup_forbidden"):
        owner.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("error", [socket.timeout(), ConnectionResetError(), OSError("closed")])
def test_only_actual_write_eof_can_advance_the_request(error):
    connection, calls = Connection(at_eof=error), []
    with pytest.raises(OSError):
        owner.serve(connection, case="ssh-policy-conforming", deadline=time.monotonic() + 5,
            on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def test_guessed_method_packet_is_not_silently_included_in_the_policy_evidence():
    case = "ssh-policy-guessed"
    full, retained = spec.response(case), spec.useful_capture(case)
    assert full.startswith(retained) and len(full) > len(retained)
    assert parser.parse_output(retained)["first_kex_packet_follows"] is True
    with pytest.raises(ValueError):
        parser.parse_output(full)
