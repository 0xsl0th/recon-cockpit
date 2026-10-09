"""Policy assessment preserves unknowns and cannot infer sessions or exploitability."""

import copy
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_ssh_algorithms_parser as legacy
from recon_cockpit.secure_agent import network_tools_ssh_policy_parser as parser


def capture(case="ssh-algos-ok"):
    return fixture.ssh_algorithms_useful_capture(case)


def with_names(field, names):
    lists = list(fixture.SSH_ALGORITHMS_SERVER_NAME_LISTS)
    lists[legacy.ALGORITHM_FIELDS.index(field)] = ",".join(names).encode("ascii")
    return fixture.SSH_ALGORITHMS_SERVER_IDENTIFICATION + fixture._ssh_algorithms_packet(
        fixture._ssh_algorithms_kex_payload(lists))


def test_snapshot_is_explicit_complete_and_cannot_be_changed_through_a_decoded_copy():
    assert tuple(field for field, _, _ in parser.POLICY_RULES) == legacy.ALGORITHM_FIELDS
    for _, allowed, disallowed in parser.POLICY_RULES:
        assert allowed and disallowed and not set(allowed) & set(disallowed)
        assert len(set(allowed)) == len(allowed) and len(set(disallowed)) == len(disallowed)
    assert hashlib.sha256(parser.POLICY_BYTES).hexdigest() == parser.POLICY_SHA256
    assert parser.POLICY_SHA256 == "9261fe5fdd1c6908837cfd7b1997cbc186edcb11ef1f6cfafb92f11676c2275e"
    snapshot = json.loads(parser.POLICY_BYTES)
    snapshot["rules"]["kex_algorithms"]["allowed"].append("unknown@owned.test")
    result = parser.parse_output(with_names("kex_algorithms", ["unknown@owned.test"]))
    assert result["policy_status"] == "inconclusive"


@pytest.mark.parametrize("case", ["ok", "directional", "guessed", "fragmented", "injected"])
def test_existing_modern_lists_complete_and_preserve_observations(case):
    raw = capture("ssh-algos-" + case)
    observed = legacy.parse_output(raw)
    result = parser.parse_output(raw)
    assert result["policy_status"] == "conforming"
    assert result["algorithms"] == observed["algorithms"]
    assert result["first_kex_packet_follows"] is observed["first_kex_packet_follows"]
    assert result["policy_id"] == parser.POLICY_ID and result["policy_sha256"] == parser.POLICY_SHA256
    assert all(row == {"status": "conforming", "disallowed": [], "unknown": []}
        for row in result["rules"].values())
    assert result["key_exchange_completed"] is result["authenticated_session"] is result["service_identity_verified"] is False
    assert fixture.HOSTILE_NOTE not in json.dumps(result)
    assert parser.validate_result(result) == result


def test_legacy_advertisements_are_a_completed_policy_deviation():
    result = parser.parse_output(capture("ssh-algos-legacy"))
    assert result["policy_status"] == "deviation"
    assert sum(row["status"] == "deviation" for row in result["rules"].values()) == 6
    assert result["rules"]["kex_algorithms"]["disallowed"] == ["diffie-hellman-group14-sha1"]
    assert not any(row["unknown"] for row in result["rules"].values())
    assert "vulnerable" not in json.dumps(result) and "exploitability" not in result


@pytest.mark.parametrize("field,allowed,disallowed", parser.POLICY_RULES)
def test_each_direction_and_category_has_independent_pinned_judgments(field, allowed, disallowed):
    for name in disallowed:
        result = parser.parse_output(with_names(field, [name]))
        assert result["policy_status"] == "deviation"
        assert result["rules"][field] == {"status": "deviation", "disallowed": [name], "unknown": []}
        assert all(row["status"] == "conforming" for key, row in result["rules"].items() if key != field)
    for names in ([allowed[-1]], list(reversed(allowed))):
        result = parser.parse_output(with_names(field, names))
        assert result["policy_status"] == "conforming" and result["algorithms"][field] == names


@pytest.mark.parametrize("field,allowed,disallowed", parser.POLICY_RULES)
@pytest.mark.parametrize("unknown", ["unknown@owned.test", "X`|<>&", "CURVE25519-SHA256", "rsa-sha2-512"])
def test_unknowns_never_become_policy_passes_or_known_failures(field, allowed, disallowed, unknown):
    result = parser.parse_output(with_names(field, [allowed[0], unknown]))
    assert result["policy_status"] == "inconclusive"
    assert result["rules"][field] == {"status": "inconclusive", "disallowed": [], "unknown": [unknown]}
    assert result["algorithms"][field] == [allowed[0], unknown]
    assert parser.validate_result(result) == result


def test_unknown_and_known_deviation_retained_without_a_complete_policy_claim():
    result = parser.parse_output(with_names("kex_algorithms",
        ["diffie-hellman-group1-sha1", "unknown@owned.test"]))
    assert result["policy_status"] == "inconclusive"
    assert result["rules"]["kex_algorithms"] == {"status": "inconclusive",
        "disallowed": ["diffie-hellman-group1-sha1"], "unknown": ["unknown@owned.test"]}


@pytest.mark.parametrize("case", fixture.SSH_ALGORITHMS_CASES[6:])
def test_incomplete_or_malformed_capture_cannot_pass_a_policy(case):
    with pytest.raises(ValueError):
        parser.parse_output(fixture.ssh_algorithms_response(case) or b"")


@pytest.mark.parametrize("raw,stderr", [(b"", b""), (capture(), b"client failed\n"),
    (capture()[:-1], b""), (capture() + b"out-of-scope", b""),
    (fixture.ssh_algorithms_response("ssh-algos-guessed"), b"")])
def test_only_one_complete_supported_capture_can_be_assessed(raw, stderr):
    with pytest.raises(ValueError):
        parser.parse_output(raw, stderr)


def test_policy_summary_pressure_does_not_truncate_unknown_names_into_a_pass():
    # Valid wire data can fit the accepted collection summary but exceed the
    # smaller effective policy envelope after retaining per-rule unknowns.
    names = [chr(65 + index) * 40 for index in range(16)]
    raw = with_names("kex_algorithms", names)
    assert legacy.parse_output(raw)["algorithms"]["kex_algorithms"] == names
    with pytest.raises(ValueError, match="excess_ssh_policy_summary"):
        parser.parse_output(raw)


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(policy_id="caller-policy"),
    lambda r: r.update(policy_sha256="f" * 64),
    lambda r: r.update(parser_version=legacy.PARSER_VERSION),
    lambda r: r.update(kind="ssh_algorithm_metadata"),
    lambda r: r.update(semantics="verified_security"),
    lambda r: r.update(policy_status="conforming"),
    lambda r: r.update(authenticated_session=True),
    lambda r: r.update(key_exchange_completed=True),
    lambda r: r.update(service_identity_verified=True),
    lambda r: r.update(next_target="127.0.0.2"),
    lambda r: r["rules"]["kex_algorithms"].update(status="conforming", disallowed=[]),
    lambda r: r["rules"]["kex_algorithms"].update(unknown=["invented"]),
    lambda r: r["rules"].pop("mac_algorithms_server_to_client"),
    lambda r: r["rules"].update(exploitability="verified"),
])
def test_all_policy_bindings_and_rule_judgments_are_recomputed(mutate):
    result = parser.parse_output(capture("ssh-algos-legacy"))
    mutate(result)
    with pytest.raises(ValueError):
        parser.validate_result(result)


def test_results_and_inputs_are_detached_without_modifying_the_accepted_parser():
    observed = legacy.parse_output(capture())
    original = copy.deepcopy(observed)
    result = parser.assess_advertisements(observed)
    detached = parser.validate_result(result)
    result["algorithms"]["kex_algorithms"].clear()
    result["rules"]["kex_algorithms"]["unknown"].append("forged")
    assert observed == original == legacy.parse_output(capture())
    assert detached == parser.parse_output(capture())
