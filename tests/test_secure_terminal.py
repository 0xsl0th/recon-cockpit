"""Scripted PTY unit mechanics only: no human evidence or fixture execution."""

import builtins
import errno
import io
import json
import os
import select
import threading
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.approvals import ApprovalStore
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.planner import proposal


@pytest.fixture
def approval_context():
    # The UI needs policy and grant state only; there is no execution backend.
    return SimpleNamespace(
        policy=parse_policy({
            "schema_version": "1", "policy_version": "scripted-pty-unit-v1",
            "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["http_probe"],
            "allowed_ports": [8080], "allowed_methods": ["GET", "HEAD"],
            "max_timeout_seconds": 3, "max_output_bytes": 4096, "max_targets": 1,
            "require_approval": True, "approval_ttl_seconds": 60,
        }),
        approvals=ApprovalStore(),
    )


@pytest.fixture
def interactive(monkeypatch):
    monkeypatch.setattr(cli, "sys", SimpleNamespace(
        stdin=SimpleNamespace(isatty=lambda: True),
        stdout=SimpleNamespace(isatty=lambda: True),
        stderr=io.StringIO(),
    ))


@pytest.fixture
def scripted_terminal(monkeypatch, interactive):
    pty = pytest.importorskip("pty")
    try:
        master, slave = pty.openpty()
    except OSError as exc:
        pytest.skip(f"PTY unavailable for portable terminal mechanics: {type(exc).__name__}")
    try:
        slave_name = os.ttyname(slave)

        def open_terminal(path, mode, **kwargs):
            assert path == "/dev/tty"
            # Use actual device opens, preserving the nonseekable stream that
            # made text mode r+ fail; StringIO would hide that regression.
            return builtins.open(slave_name, mode, **kwargs)

        monkeypatch.setattr(cli, "open", open_terminal, raising=False)
        yield master
    finally:
        os.close(slave)
        os.close(master)


def terminal_output(master):
    output = bytearray()
    deadline = time.monotonic() + 1
    while b"(blank denies): " not in output:
        ready, _, _ = select.select([master], [], [], max(0, deadline - time.monotonic()))
        assert ready, "the approval prompt was not flushed to the terminal"
        chunk = os.read(master, 4096)
        assert chunk, "the terminal closed before the approval prompt"
        output.extend(chunk)
        assert len(output) <= 4096
    return output.decode("utf-8")


def test_nonseekable_terminal_exact_scripted_challenge_issues_single_use_grant(
    approval_context, scripted_terminal,
):
    raw = json.dumps(proposal())
    action = parse_action(raw)
    challenge = "approve " + action.digest[:16]
    os.write(scripted_terminal, (challenge + "\n").encode("ascii"))

    reference = cli._human_approval(approval_context, raw)

    assert reference is not None
    assert f"Type '{challenge}' to approve once (blank denies): " in terminal_output(scripted_terminal)
    assert approval_context.approvals.consume(reference, action, approval_context.policy) is None
    assert (approval_context.approvals.consume(reference, action, approval_context.policy)
            == "approval_unknown_or_replayed")
    review = json.loads(cli.sys.stderr.getvalue())
    assert review["action_digest"] == action.digest
    assert review["policy_digest"] == approval_context.policy.digest
    assert "rationale" not in review["review_exact_action"]


@pytest.mark.parametrize("answer", ["", "deny", "approve 0000000000000000",
                                   "approve " + parse_action(proposal()).digest])
def test_nonseekable_terminal_blank_or_incorrect_scripted_answer_denies(
    approval_context, scripted_terminal, monkeypatch, answer,
):
    monkeypatch.setattr(approval_context.approvals, "issue",
                        lambda *_: pytest.fail("a denied answer must not issue a grant"))
    os.write(scripted_terminal, (answer + "\n").encode("ascii"))

    assert cli._human_approval(approval_context, json.dumps(proposal())) is None
    assert "to approve once (blank denies): " in terminal_output(scripted_terminal)
    assert ("Approval not granted: expected the displayed challenge with its 16-character digest prefix"
            in cli.sys.stderr.getvalue())


def test_missing_controlling_terminal_fails_closed(approval_context, interactive, monkeypatch):
    def missing_terminal(*_args, **_kwargs):
        raise OSError(errno.ENXIO, "No controlling terminal")

    monkeypatch.setattr(cli, "open", missing_terminal, raising=False)
    monkeypatch.setattr(approval_context.approvals, "issue",
                        lambda *_: pytest.fail("a missing terminal must not issue a grant"))
    assert cli._human_approval(approval_context, json.dumps(proposal())) is None


@pytest.mark.parametrize("stdin_tty,stdout_tty", [(False, True), (True, False), (False, False)])
def test_noninteractive_approval_does_not_open_terminal_or_parse_input(
    approval_context, monkeypatch, stdin_tty, stdout_tty,
):
    monkeypatch.setattr(cli, "sys", SimpleNamespace(
        stdin=SimpleNamespace(isatty=lambda: stdin_tty),
        stdout=SimpleNamespace(isatty=lambda: stdout_tty),
    ))
    monkeypatch.setattr(cli, "open", lambda *_args, **_kwargs: pytest.fail("must not open terminal"), raising=False)
    monkeypatch.setattr(cli, "parse_action", lambda *_: pytest.fail("must not parse noninteractive input"))
    assert cli._human_approval(approval_context, b"not proposal JSON") is None


def test_session_terminal_challenge_issues_a_single_use_grant(approval_context, scripted_terminal):
    action = parse_action(proposal())
    os.write(scripted_terminal, ("approve " + action.digest[:16] + "\n").encode("ascii"))
    reference = cli._human_approval(approval_context, json.dumps(proposal()),
                                    control=ExecutionControl(time.monotonic() + 5))
    assert reference is not None
    assert approval_context.approvals.consume(reference, action, approval_context.policy) is None
    assert approval_context.approvals.consume(reference, action, approval_context.policy) == "approval_unknown_or_replayed"


@pytest.mark.parametrize("cancel", [False, True])
def test_session_terminal_wait_stops_without_a_grant(approval_context, scripted_terminal, monkeypatch, cancel):
    stopped = threading.Event()
    control = ExecutionControl(time.monotonic() + (5 if cancel else 0.15), stopped)
    monkeypatch.setattr(approval_context.approvals, "issue",
                        lambda *_: pytest.fail("a stopped wait must not issue a grant"))
    timer = threading.Timer(0.15, stopped.set)
    if cancel:
        timer.start()
    try:
        with pytest.raises(ExecutionStopped) as error:
            cli._human_approval(approval_context, json.dumps(proposal()), control=control)
        assert error.value.reason == ("session_cancelled" if cancel else "session_timeout")
        assert "to approve once" in terminal_output(scripted_terminal)
    finally:
        if cancel:
            timer.join()


def test_session_terminal_rechecks_deadline_after_input(approval_context, scripted_terminal, monkeypatch):
    action = parse_action(proposal())
    os.write(scripted_terminal, ("approve " + action.digest[:16] + "\n").encode("ascii"))
    stopped = threading.Event()
    read = os.read

    def cancel_at_newline(*args):
        value = read(*args)
        if value == b"\n":
            stopped.set()
        return value

    monkeypatch.setattr(cli.os, "read", cancel_at_newline)
    monkeypatch.setattr(approval_context.approvals, "issue",
                        lambda *_: pytest.fail("cancellation at input completion must deny"))
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        cli._human_approval(approval_context, json.dumps(proposal()),
                            control=ExecutionControl(time.monotonic() + 5, stopped))
