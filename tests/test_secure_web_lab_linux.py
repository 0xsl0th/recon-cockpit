"""Actual disconnected HarborDesk fixture reset and lifecycle evidence."""

import json
import os
from pathlib import Path
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.web_assessment_contract import action
from recon_cockpit.secure_agent.web_backend import AuthorizedWebLabBackend
from recon_cockpit.secure_agent.web_lab import WebLab
from recon_cockpit.secure_agent.web_lab_contract import (
    CASES, DIAGNOSTICS_PATH, INDEX_PATH, response, validate_closure,
)


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def require_real_linux():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual owned web lab isolation")
    assert sys.platform == "linux" and os.geteuid() != 0


def build(case):
    source = Path(__file__).resolve().parents[1] / "examples/secure-agent-nmap-policy.json"
    policy = parse_policy({**json.loads(source.read_text()), "require_approval": False})
    limits = SessionLimits()
    session = str(uuid4())
    lab = WebLab(case, session, limits)
    backend = AuthorizedWebLabBackend(policy, session, limits, lab, execute=True)
    return lab, backend, policy


def assert_closed(lab, owner, namespace_fds):
    assert owner.poll() is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(owner.pid, os.WNOHANG)
    for fd in namespace_fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    with pytest.raises(IsolationUnavailable):
        lab.start(ExecutionControl(time.monotonic() + 30))


@pytest.mark.parametrize("case", CASES)
def test_actual_fixture_repeats_bytes_with_new_identity_and_zero_counters(case):
    results = []
    for _ in range(2):
        lab, backend, policy = build(case)
        control = ExecutionControl(time.monotonic() + 30)
        observations = []
        try:
            lab.start(control)
            owner = lab._supervisor.processes["lab"]
            namespace_fds = lab._namespace_fds
            assert lab.snapshot(control) == {"connection_count": 0, "request_count": 0}
            assert all(lab._lab_namespaces[name] != os.readlink(f"/proc/self/ns/{name}")
                       for name in ("user", "net", "mnt", "pid"))
            for offset, path in enumerate((INDEX_PATH, DIAGNOSTICS_PATH), 1):
                result = backend.run(parse_action(action(case, offset + 1)), policy, control=control)
                assert result["status"] == "succeeded"
                assert result["boundary_checks"] == dict.fromkeys((
                    "forbidden_ip_blocked", "forbidden_port_blocked",
                    "namespace_creation_blocked", "capabilities_dropped"), True)
                row = result["results"][0]
                status, body, _ = response(case, path)
                assert (row["http_status"], row["body"].encode("ascii")) == (status, body)
                assert row["truncated"] is False and row["bytes_received"] <= 1024
                assert result["owned_lab"] == {"identity": lab.identity,
                    "connection_count": offset, "request_count": offset}
                observations.append((row["http_status"], row["body"], row["response_sha256"]))
            previous = result["owned_lab"]
        finally:
            receipt = lab.close()
        validate_closure(receipt, lab.identity, previous=previous)
        assert_closed(lab, owner, namespace_fds)
        results.append((lab.identity, observations))
    assert results[0][0]["instance_id"] != results[1][0]["instance_id"]
    assert results[0][0]["spec_sha256"] == results[1][0]["spec_sha256"]
    assert results[0][1] == results[1][1]


def test_cancelled_lab_reaps_owner_and_never_resets_into_same_authority():
    lab, _, _ = build("injected")
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic() + 30, cancelled)
    try:
        lab.start(control)
        owner = lab._supervisor.processes["lab"]
        namespace_fds = lab._namespace_fds
        assert lab.snapshot(control) == {"connection_count": 0, "request_count": 0}
        cancelled.set()
        with pytest.raises(ExecutionStopped, match="session_cancelled"):
            lab.snapshot(control)
    finally:
        receipt = lab.close()
    validate_closure(receipt, lab.identity)
    assert_closed(lab, owner, namespace_fds)
