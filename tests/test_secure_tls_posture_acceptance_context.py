"""A sampled refused TCP connection is evidence, never extra tool authority."""

import base64
import json
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from recon_cockpit.secure_agent.network_tools_tls_posture_receipt import encode_owner_receipt
from recon_cockpit.secure_agent.network_tools_tls_posture_spec import TOOL_VERSIONS
from test_network_tools_tls_posture_evidence import receipt


def extra_connection(version):
    tool, result = receipt(version)
    owner = json.loads(base64.b64decode(result["tls_posture_owner"]["raw_base64"]))
    case = f"tls-posture-{version}-" + owner["diagnostic"]["case"]
    expected = identity(case, str(uuid4()))
    owner["connection_count"] = 2
    owner["mediation"]["extra_frontend_connections_refused"] = 1
    result["tool_observation"] = None
    result["backend"] = contract.BACKEND
    result["owned_lab"] = {"identity": expected, "connection_count": 2, "request_count": 1}
    return tool, result, owner, expected


def validate(tool, result, owner, expected):
    result["tls_posture_owner"] = encode_owner_receipt(json.dumps(owner).encode())
    result["owned_lab"]["tls_posture_owner_sha256"] = result["tls_posture_owner"]["sha256"]
    return contract.validate_result_context(result, expected, tool_id=tool, execution_status="succeeded")


@pytest.mark.parametrize("version", TOOL_VERSIONS.values())
def test_one_queued_refusal_can_be_retained_without_a_useful_observation(version):
    tool, result, owner, expected = extra_connection(version)
    assert validate(tool, result, owner, expected)["connection_count"] == 2
    assert result["tool_observation"] is None
    # The same raw count can never accompany a useful observation.
    result["tool_observation"] = receipt(version)[1]["tool_observation"]
    with pytest.raises(ValueError, match="tls_posture_owner_progress_mismatch"):
        validate(tool, result, owner, expected)


@pytest.mark.parametrize("version", TOOL_VERSIONS.values())
@pytest.mark.parametrize("field", ("frontend_connections_admitted", "extra_frontend_connections_refused", "peer_streams_admitted"))
@pytest.mark.parametrize("bad", (None, False, True, 0, 2, "1"))
def test_two_connections_require_one_admitted_stream_and_explicit_refusal(version, field, bad):
    tool, result, owner, expected = extra_connection(version)
    owner["mediation"][field] = bad
    with pytest.raises(ValueError, match="tls_posture_extra_connection_not_refused"):
        validate(tool, result, owner, expected)


@pytest.mark.parametrize("version", TOOL_VERSIONS.values())
def test_third_observed_connection_cannot_fit_t02_evidence(version):
    tool, result, owner, expected = extra_connection(version)
    owner["connection_count"] = result["owned_lab"]["connection_count"] = 3
    with pytest.raises(ValueError):
        validate(tool, result, owner, expected)
