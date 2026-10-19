"""Portable channel and custody checks; native confinement is a separate gate."""

from copy import deepcopy
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import name_tls_frontend_worker as frontend
from recon_cockpit.secure_agent import name_tls_transport as transport
from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent.name_tls_topology_spec import endpoints
from test_name_tls_authority import Harness, ROOT


class Channel:
    def settimeout(self, value):
        self.timeout = value

    def setblocking(self, value):
        self.blocking = value


def budget_channel(monkeypatch):
    h = Harness()
    h.dns()
    h.clock = .3
    h.arm("http")
    pending = []
    def send(channel, message):
        pending.append(deepcopy(message))
    def receive(channel, *, descriptor_required):
        assert descriptor_required is False
        return h.ledger.apply(pending.pop(0), role="http_frontend"), None
    monkeypatch.setattr(transport, "send_packet", send)
    monkeypatch.setattr(transport, "receive_packet", receive)
    monkeypatch.setattr(frontend.time, "monotonic", lambda: h.clock)
    budget = frontend.BudgetChannel(Channel(), "http_frontend", 60, h.identity["owner_identity_sha256"])
    budget.bind(2, contract.digest(h.action))
    assert budget.connection(1)
    budget.request("http")
    return h, budget


def test_partial_send_never_reuses_old_credit_as_fresh_authority(monkeypatch):
    h, budget = budget_channel(monkeypatch)
    active = {}
    budget.before_write(active, "request", 100)
    budget.after_write(active, "request", 1)
    budget.before_write(active, "request", 99)
    budget.after_write(active, "request", 99)
    reservations = [row["message"] for row in budget.reservations if row["message"]["operation"] == "RESERVE_BYTES"]
    assert [row["bytes"] for row in reservations] == [100, 99]
    assert h.ledger.snapshot()["actions"][1]["counters"]["request_bytes"] == 199
    assert budget.delivered == {"request": 100, "response": 0}
    budget.finish(request_bytes=100, response_bytes=0, transcript_sha256="f" * 64, reason="complete")
    assert h.ledger.snapshot()["actions"][1]["connection"]["delivered_request_bytes"] == 100


def test_expiry_between_short_send_and_retry_reaches_surviving_owner(monkeypatch):
    h, budget = budget_channel(monkeypatch)
    active = {}
    budget.before_write(active, "request", 100)
    budget.after_write(active, "request", 1)
    h.clock = 8.31
    with pytest.raises(frontend.BudgetRefused, match="action_deadline"):
        budget.before_write(active, "request", 99)
    assert budget.delivered["request"] == 1
    assert h.ledger.snapshot()["actions"][1]["counters"]["request_bytes"] == 100
    assert len(budget.reservations) == 4


def test_failed_send_keeps_whole_attempt_charge_and_next_attempt_can_hit_cap(monkeypatch):
    h, budget = budget_channel(monkeypatch)
    active = {}
    budget.before_write(active, "request", 200)
    # No successful after_write: this models EAGAIN without inventing delivery.
    with pytest.raises(frontend.BudgetRefused, match="action_request_bytes_limit"):
        budget.before_write(active, "request", 200)
    assert h.ledger.snapshot()["actions"][1]["counters"]["request_bytes"] == 200
    assert budget.delivered["request"] == 0
    budget.finish(request_bytes=0, response_bytes=0, transcript_sha256="f" * 64, reason="io_failure")
    assert h.ledger.snapshot()["counters"]["request_bytes"] == 240


def test_mismatched_delivered_totals_cannot_settle_owner_lease(monkeypatch):
    h, budget = budget_channel(monkeypatch)
    active = {}
    budget.before_write(active, "request", 20)
    budget.after_write(active, "request", 10)
    with pytest.raises(ValueError, match="delivery_changed"):
        budget.finish(request_bytes=20, response_bytes=0, transcript_sha256="f" * 64, reason="complete")
    assert h.ledger.snapshot()["active_connection"] is not None


def test_channel_failure_preserves_continuity_loss_and_cannot_start_another_action(monkeypatch):
    h, budget = budget_channel(monkeypatch)
    def fail(*args, **kwargs):
        raise OSError("lost private channel")
    monkeypatch.setattr(transport, "receive_packet", fail)
    with pytest.raises(OSError):
        budget.before_write({}, "request", 20)
    assert budget.failed and budget.continuity_lost
    with pytest.raises(ValueError, match="binding_changed"):
        budget.bind(3, "a" * 64)


def ready_value():
    h = Harness()
    ns = {name: name + ":[123]" for name in ("user", "net", "mnt", "pid")}
    value = {"ready": True, "role": "http_frontend", "namespaces": ns,
        "payload_identity": {"uid": 65534, "gid": 65534, "groups": [],
                             "uid_map": [[65534, 65534, 1]], "gid_map": [[65534, 65534, 1]]},
        "listener": list(endpoints()["http"]),
        "listener_identity": {"inode": 1, "netns_cookie": 2, "endpoint": list(endpoints()["http"])},
        "bounds": dict(frontend.BOUNDS), "checks": dict.fromkeys(frontend.CHECKS, True)}
    return h, ns, value


def test_readiness_receipt_is_exact_and_detached():
    h, ns, value = ready_value()
    actual = frontend.validate_ready(value, role="http_frontend", selected=h.selected, namespaces=ns)
    assert actual == value and actual is not value


@pytest.mark.parametrize("mutation", ["uid", "mapping", "groups", "port", "cookie", "role", "bounds", "check", "extra", "namespace"])
def test_changed_readiness_cannot_claim_frontend_confinement(mutation):
    h, ns, value = ready_value()
    if mutation == "uid":
        value["payload_identity"]["uid"] = 0
    elif mutation == "mapping":
        value["payload_identity"]["uid_map"][0][2] = 65535
    elif mutation == "groups":
        value["payload_identity"]["groups"] = [0]
    elif mutation == "port":
        value["listener"][1] += 1
    elif mutation == "cookie":
        value["listener_identity"]["netns_cookie"] = True
    elif mutation == "role":
        value["role"] = "tls_frontend"
    elif mutation == "bounds":
        value["bounds"]["processes"] = True
    elif mutation == "check":
        value["checks"]["exec_blocked"] = False
    elif mutation == "extra":
        value["unexpected"] = True
    else:
        value["namespaces"] = {**ns, "net": "net:[124]"}
    with pytest.raises(ValueError):
        frontend.validate_ready(value, role="http_frontend", selected=h.selected, namespaces=ns)


def test_frontend_source_closure_imports_without_any_server_key_module():
    script = """
import sys
sys.path.insert(0, sys.argv[1])
from recon_cockpit.secure_agent import name_tls_frontend_worker
assert not any('network_tools_fixture' in name or 'certificate_material' in name or name.endswith('name_tls_spec') for name in sys.modules)
assert not any(name.endswith(('name_tls_native_runtime','name_tls_daemon')) for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script, str(ROOT)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
