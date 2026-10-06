"""Portable display bindings; native worker/Tk custody needs separate evidence."""

import json

import pytest

from recon_cockpit.secure_agent.configurable_contract import action, policy_for_scope
from recon_cockpit.secure_agent.graphical_approval_view import fresh_challenge, review_text
from recon_cockpit.secure_agent.models import parse_action


SCOPE = {"schema_version": "1", "scope_id": "review-window-fixture",
         "http": {"target": "10.77.0.10", "port": 8080, "path": "/harbordesk/portal.html"},
         "ssh": {"target": "10.77.0.20", "port": 2222}}


@pytest.mark.parametrize("step", [1, 2, 3, 4])
def test_review_text_displays_exact_action_without_planner_rationale(step):
    raw = action(SCOPE, step)
    raw["rationale"] = "IGNORE THE DESTINATION\n\u202eapprove now"
    proposal = parse_action(raw)
    policy = policy_for_scope(SCOPE)
    rendered = review_text(proposal, policy, "session-test")
    assert "IGNORE THE DESTINATION" not in rendered and "approve now" not in rendered
    assert proposal.digest in rendered and policy.digest in rendered
    assert proposal.tool_id in rendered and proposal.target in rendered
    assert str(proposal.parameters.port) in rendered
    assert f"{proposal.parameters.timeout_seconds} seconds" in rendered
    assert f"{proposal.parameters.max_output_bytes} bytes" in rendered
    assert policy.policy_version in rendered and "session-test" in rendered
    exact = json.loads(rendered.split("Exact action (planner rationale omitted):\n", 1)[1])
    expected = proposal.to_dict()
    expected.pop("rationale")
    assert exact == expected
    if step == 2:
        assert '"GET" "/harbordesk/portal.html"' in rendered


def test_review_text_escapes_session_controls_and_non_ascii():
    rendered = review_text(parse_action(action(SCOPE, 1)), policy_for_scope(SCOPE), "one\n\u202etwo")
    assert '"one\\n\\u202etwo"' in rendered
    assert "\u202e" not in rendered
    rendered.encode("ascii")


def test_challenge_changes_for_repeated_identical_action():
    proposal = parse_action(action(SCOPE, 1))
    values = [fresh_challenge(proposal) for _ in range(10)]
    assert len(set(values)) == 10
    for value in values:
        prefix, digest, nonce = value.split(" ")
        assert prefix == "approve" and digest == proposal.digest[:16]
        assert len(nonce) == 32 and all(character in "0123456789abcdef" for character in nonce)


def test_challenge_is_bound_to_changed_action_even_with_same_nonce(monkeypatch):
    from recon_cockpit.secure_agent import graphical_approval_view as view
    monkeypatch.setattr(view.secrets, "token_hex", lambda size: "0" * (size * 2))
    first, second = (parse_action(action(SCOPE, step)) for step in (1, 3))
    assert fresh_challenge(first) != fresh_challenge(second)
