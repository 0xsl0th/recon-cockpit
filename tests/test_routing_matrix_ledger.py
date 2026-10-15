"""A v3 declared negative ends owner authority independently of the runner."""

from copy import deepcopy

import pytest

from recon_cockpit.secure_agent import routing_contract as contract, routing_ledger as ledger
from test_routing_ledger import Harness
from test_routing_matrix_contract import identity

NEGATIVES = tuple(profile for profile in contract.CASE_PROFILES
                  if profile != "baseline" and profile.rsplit("_", 1)[1].startswith("N"))


def matrix(profile, deployment="nginx-A"):
    h = Harness()
    h.selected = contract.selection(deployment=deployment, case_profile=profile)
    h.owner = identity(h.selected)
    h.ledger = ledger.Ledger(h.selected, h.owner, started_at=h.now, clock=lambda: h.now)
    h.action_digest = contract.digest(h.selected)
    return h


@pytest.mark.parametrize("deployment", ("nginx-A", "apache-B"))
@pytest.mark.parametrize("profile", NEGATIVES)
def test_declared_negative_settlement_preserves_prior_work_and_prevents_later_authority(deployment, profile):
    h = matrix(profile, deployment)
    negative, _ = profile.rsplit("_", 1)
    prior = "ssh_nmap" if negative.startswith("http_") else "http_headers"
    later = "ssh_keys" if negative != "ssh_keys" else "http_nmap"
    assert h.arm(prior)["status"] == "ok"
    assert h.connect()["status"] == "ok"
    if prior == "http_headers":
        assert h.request_unit()["status"] == "ok"
    assert h.bytes("response", 1)["status"] == "ok"
    assert h.finish_connection()["status"] == "ok"
    assert h.finish_action(1)["status"] == "ok"
    previous = h.verify()
    h.now += .25
    assert h.arm(negative)["status"] == "ok"
    assert h.connect()["status"] == "ok"
    assert h.finish_connection()["status"] == "ok"
    before = h.verify()
    assert not before["terminal"]
    assert h.finish_action()["status"] == "ok"
    stopped = h.verify()
    assert stopped["terminal"] and stopped["terminal_reason"] == "declared_negative_completed"
    assert stopped["active_action_sequence"] is stopped["active_connection"] is None
    assert stopped["counters"] == before["counters"]
    assert stopped["actions"][0] == previous["actions"][0]
    assert stopped["actions"][0]["output_bytes_retained"] == 1
    assert stopped["actions"][-1]["status"] == "finished"
    assert len(ledger.replay_responses(stopped)) == len(stopped["events"])
    with pytest.raises(ValueError, match="routing_ledger_terminal"):
        h.arm(later)
    assert h.ledger.snapshot() == stopped


@pytest.mark.parametrize("profile", ("baseline", "http_headers_O2", "http_headers_R1", "ssh_keys_R2"))
def test_ordinary_and_robustness_settlement_keeps_other_authorized_slots_available(profile):
    h = matrix(profile)
    first = "http_headers" if profile != "ssh_keys_R2" else "ssh_keys"
    second = "ssh_nmap"
    assert h.arm(first)["status"] == "ok"
    assert h.finish_action()["status"] == "ok"
    assert not h.verify()["terminal"]
    assert h.arm(second)["status"] == "ok"
    assert h.finish_action()["status"] == "ok"
    assert not h.verify()["terminal"]


@pytest.mark.parametrize("trigger,reason", (("budget", "action_response_bytes_limit"),
                                           ("deadline", "action_deadline"),
                                           ("output", "output_bytes_limit")))
def test_negative_cleanup_cannot_replace_an_earlier_terminal_refusal(trigger, reason):
    h = matrix("http_headers_N4")
    h.arm("http_headers")
    if trigger == "budget":
        h.connect(); h.request_unit()
        assert h.bytes("response", 2049)["reason"] == reason
        h.finish_connection()
    elif trigger == "deadline":
        h.now += 1
        assert h.ledger.check_deadline() is False
    else:
        assert h.finish_action(2049)["reason"] == reason
    before = h.verify()
    assert h.finish_action()["status"] == "ok"
    after = h.verify()
    assert after["terminal_reason"] == reason
    assert after["counters"] == before["counters"]
    assert after["actions"][-1]["status"] == "finished"


@pytest.mark.parametrize("field,value", (("terminal", False), ("terminal_reason", None),
    ("terminal_reason", "completed"), ("terminal_reason", "execution_failed")))
def test_saved_negative_settlement_cannot_erase_or_relabel_the_derived_stop(field, value):
    h = matrix("ssh_nmap_N1")
    h.arm("ssh_nmap"); h.finish_action()
    changed = deepcopy(h.verify())
    changed[field] = value
    with pytest.raises(ValueError, match="replay_changed"):
        ledger.validate_snapshot(changed, selected=h.selected, identity=h.owner)


def test_callers_cannot_invent_declared_negative_completion_with_a_stop_message():
    h = matrix("baseline")
    reply = h.call("STOP", reason="declared_negative_completed")
    assert reply["status"] == "denied" and reply["reason"] == "invalid_stop_reason"
    assert h.verify()["terminal_reason"] == "invalid_stop_reason"
