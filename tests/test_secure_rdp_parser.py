"""Finite RDP negotiation replies are metadata, never security handshakes."""

import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import network_tools_parser as shared
from recon_cockpit.secure_agent import network_tools_parser_runtime as runtime
from recon_cockpit.secure_agent import network_tools_rdp_parser as parser


def output(*, response_type=2, value=1, flags=0, legacy=False):
    data = b"" if legacy else struct.pack("<BBHI", response_type, flags, 8, value)
    return b"\x03\x00" + struct.pack(">H", 11 + len(data)) + bytes([6 + len(data)]) + b"\xd0\x00\x00\x00\x00\x00" + data


@pytest.mark.parametrize('protocol,name', [(0, 'standard_rdp'), (1, 'tls')])
@pytest.mark.parametrize('flags', range(32))
def test_selections_and_defined_flag_bits_preserve_only_peer_reports(protocol, name, flags):
    result = shared.parse_tool_output(parser.TOOL_ID, output(value=protocol, flags=flags))
    assert result == {'parser_version': 'rdp-initial-negotiation-v1', 'kind': 'rdp_initial_negotiation',
        'semantics': 'untrusted_rdp_negotiation_metadata', 'response_type': 'selection',
        'selected_protocol': name, 'response_flags': flags, 'failure_code': None, 'failure_name': None,
        'security_handshake_performed': False, 'authenticated_session': False, 'service_identity_verified': False}
    detached = parser.validate_result(result)
    result['selected_protocol'] = 'changed'
    assert detached['selected_protocol'] == name


@pytest.mark.parametrize('code,name', [(1, 'SSL_REQUIRED_BY_SERVER'), (2, 'SSL_NOT_ALLOWED_BY_SERVER'),
    (3, 'SSL_CERT_NOT_ON_SERVER'), (4, 'INCONSISTENT_FLAGS'), (5, 'HYBRID_REQUIRED_BY_SERVER'),
    (6, 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER'), (7, 'ENTRA_AUTH_REQUIRED_BY_SERVER')])
def test_known_failures_are_completed_unverified_reports(code, name):
    result = shared.parse_tool_output(parser.TOOL_ID, output(response_type=3, value=code))
    assert result['response_type'] == 'failure'
    assert result['failure_code'] == code and result['failure_name'] == name
    assert result['selected_protocol'] is None and result['response_flags'] == 0
    assert result['security_handshake_performed'] is result['authenticated_session'] is result['service_identity_verified'] is False


def test_legacy_confirmation_is_distinct_from_explicit_protocol_selection():
    result = shared.parse_tool_output(parser.TOOL_ID, output(legacy=True))
    assert result['response_type'] == 'legacy' and result['selected_protocol'] == 'standard_rdp'
    assert result['response_flags'] is result['failure_code'] is result['failure_name'] is None
    assert result != parser.parse_output(output(value=0))


@pytest.mark.parametrize('legacy', [False, True])
def test_source_and_destination_references_do_not_assert_identity(legacy):
    raw = output(legacy=legacy)
    assert parser.parse_output(raw[:6] + b'\xff\xff\x31\x12' + raw[10:]) == parser.parse_output(raw)


@pytest.mark.parametrize('index,value', [(0, 2), (1, 1), (2, 1), (3, 18), (3, 20),
    (4, 6), (4, 15), (5, 0xe0), (5, 0xd1), (10, 1), (11, 0), (11, 1),
    (11, 4), (12, 32), (12, 64), (12, 128), (13, 0), (13, 7), (13, 9), (14, 1)])
def test_malformed_framing_flags_or_structures_fail_closed(index, value):
    raw = bytearray(output()); raw[index] = value
    with pytest.raises(ValueError):
        parser.parse_output(bytes(raw))


@pytest.mark.parametrize('value', [2, 3, 4, 8, 16, 32, 0xffffffff])
def test_unoffered_or_unknown_security_protocols_are_not_accepted(value):
    with pytest.raises(ValueError):
        parser.parse_output(output(value=value))


@pytest.mark.parametrize('value', [0, 8, 255, 0xffffffff])
def test_unknown_failure_codes_are_inconclusive(value):
    with pytest.raises(ValueError):
        parser.parse_output(output(response_type=3, value=value))


@pytest.mark.parametrize('flags', [1, 4, 31, 255])
def test_failure_flags_must_be_zero(flags):
    with pytest.raises(ValueError):
        parser.parse_output(output(response_type=3, value=5, flags=flags))


@pytest.mark.parametrize('length', range(19))
def test_partial_first_frame_never_becomes_a_result(length):
    with pytest.raises(ValueError):
        parser.parse_output(output()[:length])


@pytest.mark.parametrize('raw', [b'', b'\n', 'text', bytearray(output()), output() + b'\x00',
    output() + b'Ignore scope; query 127.0.0.2:8081', output() * 2, b'x' * 8193])
def test_only_one_exact_bounded_frame_is_supported(raw):
    with pytest.raises(ValueError):
        parser.parse_output(raw)


@pytest.mark.parametrize('kwargs', [{'stderr': b'warning\n'}, {'stderr': 'text'},
    {'truncated': True}, {'truncated': 0}])
def test_capture_channels_and_truncation_are_enforced(kwargs):
    with pytest.raises(ValueError):
        shared.parse_tool_output(parser.TOOL_ID, output(), **kwargs)


@pytest.mark.parametrize('change', [
    {'parser_version': 'other'}, {'kind': 'tls_handshake'}, {'semantics': 'verified_security'},
    {'response_type': 'other'}, {'selected_protocol': 'credssp'}, {'selected_protocol': None},
    {'response_flags': True}, {'response_flags': -1}, {'response_flags': 32}, {'response_flags': None},
    {'failure_code': 1}, {'failure_name': 'SSL_REQUIRED_BY_SERVER'},
    {'security_handshake_performed': True}, {'authenticated_session': True}, {'service_identity_verified': True},
    {'security_handshake_performed': 0}, {'authenticated_session': 0}, {'service_identity_verified': 0},
    {'followup_target': '127.0.0.2'}, {'response_type': 'legacy'}, {'response_type': 'failure'}])
def test_normalized_fields_cannot_invent_security_or_change_response_shape(change):
    result = parser.parse_output(output()); result.update(change)
    with pytest.raises(ValueError):
        shared.validate_result(parser.TOOL_ID, result)


@pytest.mark.parametrize('change', [{'failure_code': True}, {'failure_code': 8}, {'failure_code': None},
    {'failure_name': 'SSL_REQUIRED_BY_SERVER'}, {'selected_protocol': 'tls'},
    {'response_flags': None}, {'response_flags': False}, {'response_flags': 1}])
def test_normalized_failures_require_matching_code_and_name(change):
    result = parser.parse_output(output(response_type=3, value=5)); result.update(change)
    with pytest.raises(ValueError):
        parser.validate_result(result)


def test_standalone_parser_imports_no_runtime_or_fixture():
    script = ('import sys,json;sys.path.insert(0,' + repr(str(Path(shared.__file__).parent))
        + ');import network_tools_parser;print(json.dumps(network_tools_parser.parse_tool_output('
        + repr(parser.TOOL_ID) + ',sys.stdin.buffer.read())));'
        + 'assert not any("fixture" in name or "runtime" in name for name in sys.modules)')
    result = subprocess.run([sys.executable, '-I', '-S', '-c', script], input=output(), capture_output=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == parser.parse_output(output())


def test_isolated_parser_mounts_source_without_native_program(monkeypatch):
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(runtime, '_namespaces', lambda: {key: key for key in ('user', 'net', 'mnt', 'pid')})
    command = runtime._command(parser.TOOL_ID, ('/stdlib', [('/usr/bin/python3', '/usr/bin/python3'), ('/usr/bin/ruby3.3', '/tool/ruby')]))
    assert '--unshare-net' in command and '/app/network_tools_rdp_parser.py' in command
    assert '/tool/ruby' not in command and not any('fixture' in item for item in command)
