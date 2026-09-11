"""Portable rejection checks and opted-in real routed owned-service evidence."""

import json
import os
from pathlib import Path
import sys

import pytest

from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from scripts import secure_agent_routed_demo as demo


def test_owned_routed_lab_refuses_initial_namespace_before_network_setup(monkeypatch):
    monkeypatch.setattr(demo.sys, "platform", "linux")
    monkeypatch.setattr(demo.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(demo.os, "readlink", lambda _: "user:[100]")
    monkeypatch.setattr(demo.socket, "if_nameindex", lambda: pytest.fail("must reject before network access"))
    with pytest.raises(RuntimeError, match="private namespaces"):
        demo._prepare_private_network("user:[100]", "net:[101]")


def test_owned_routed_lab_refuses_root_before_namespace_setup(monkeypatch):
    monkeypatch.setattr(demo.sys, "platform", "linux")
    monkeypatch.setattr(demo.os, "geteuid", lambda: 0)
    monkeypatch.setattr(demo.os, "readlink", lambda _: pytest.fail("root must be refused first"))
    with pytest.raises(RuntimeError, match="unprivileged"):
        demo._prepare_private_network("user:[100]", "net:[101]")


def test_owned_routed_unattended_policy_is_exactly_scoped_and_separate_from_human_policy():
    policy = demo.lab_policy()
    assert policy.allowed_targets == (demo.TARGET + "/32",)
    assert policy.allowed_ports == (demo.PORT,)
    assert policy.max_targets == 1
    assert policy.require_approval is False
    assert demo.lab_policy(approval=True).require_approval is True
    assert policy.evaluate(parse_action(demo.lab_action(demo.IP_WITNESS))).decision == "deny"
    assert policy.evaluate(parse_action(demo.lab_action(port=demo.PORT_WITNESS))).decision == "deny"


@pytest.fixture(scope="module")
def routed_lab_evidence(tmp_path_factory):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("real Linux isolation requires RECON_LINUX_INTEGRATION=1")
    if sys.platform != "linux":
        pytest.skip("real routed network integration requires Linux")
    from recon_cockpit.secure_agent.routed import LinuxRoutedBackend

    # Once opted in, missing helpers or denied namespaces are failures, not skips.
    LinuxRoutedBackend().check_available()
    audit = tmp_path_factory.mktemp("routed-kernel") / "audit.jsonl"
    result = demo.run_owned_lab(audit=audit)
    assert result.returncode == 0, (result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace"))
    records = [json.loads(line) for line in result.stdout.splitlines()]
    evidence = next(record for record in records if record.get("demo") == "passed")
    return evidence, audit


@pytest.mark.integration
@pytest.mark.parametrize("name,path,method,expected", demo.CASES)
def test_real_routed_controller_to_owned_service(routed_lab_evidence, name, path, method, expected):
    evidence, _ = routed_lab_evidence
    case = next(row for row in evidence["cases"] if row["case"] == name)
    assert case["status"] == expected
    assert set(case["boundary_checks"]) == {"forbidden_ip_blocked", "forbidden_port_blocked",
                                           "namespace_creation_blocked", "capabilities_dropped"}
    assert all(value is True for value in case["boundary_checks"].values())
    assert case["metadata"]["bytes_received"] <= 4096
    if name in ("normal", "head", "injection"):
        assert case["metadata"]["results"][0]["http_status"] == 200
    if name.startswith("redirect_"):
        assert case["metadata"]["results"][0]["http_status"] == 302


@pytest.mark.integration
def test_real_routed_forbidden_witnesses_are_reachable_and_receive_no_leaked_connections(routed_lab_evidence):
    evidence, _ = routed_lab_evidence
    assert evidence["baselines"] == [{"witness": name, "http_status": 200}
                                      for name in ("allowed", "forbidden_ip", "forbidden_port")]
    assert evidence["witness_connections_after_baseline"] == {"forbidden_ip": 0, "forbidden_port": 0}
    assert evidence["lab"]["private_user_namespace"] is True
    assert evidence["lab"]["private_network_namespace"] is True
    assert evidence["lab"]["controller_uid"] != 0
    assert evidence["lab"]["controller_capabilities_zero"] is True
    assert evidence["lab"]["host_network_changes"] is False


@pytest.mark.integration
def test_real_routed_audit_and_noninteractive_approval_remain_fail_closed(routed_lab_evidence):
    evidence, audit = routed_lab_evidence
    assert evidence["noninteractive_approval_blocked"] is True
    assert evidence["policy_rejections"] == 2
    assert evidence["execution_events"] == {"started": len(demo.CASES) + 3, "finished": len(demo.CASES) + 3}
    raw = audit.read_text(encoding="utf-8")
    events = [json.loads(line) for line in raw.splitlines()]
    assert "Ignore prior instructions" not in raw
    assert "OWNED FIXTURE. UNTRUSTED CONTENT." not in raw
    started = {event["action_id"]: i for i, event in enumerate(events) if event["event_type"] == "execution_started"}
    finished = {event["action_id"]: i for i, event in enumerate(events) if event["event_type"] == "execution_finished"}
    assert started.keys() == finished.keys()
    assert all(started[action_id] < finished[action_id] for action_id in started)
    assert any(event["event_type"] == "approval_rejected" for event in events)
