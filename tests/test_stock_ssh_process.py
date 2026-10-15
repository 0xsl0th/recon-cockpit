"""Pre-syscall process graph and one-use budget enforcement."""

from copy import deepcopy
import base64

import pytest

from recon_cockpit.secure_agent import stock_ssh_process as process


def initial():
    ledger = process.ProcessLedger(2)
    ledger.request_exec(2, process.EXECUTABLES[0], process.ARGV[0], dict(process.ENVIRONMENT))
    ledger.exec_completed(2, process.EXECUTABLES[0])
    return ledger


def session():
    ledger = initial()
    ledger.request_fork(2, syscall="clone", flags=process.FORK_CLONE_FLAGS)
    ledger.fork_completed(2, 3)
    ledger.request_exec(2, process.EXECUTABLES[1], process.ARGV[1], dict(process.ENVIRONMENT))
    ledger.exec_completed(2, process.EXECUTABLES[1])
    return ledger


def test_exact_graph_keeps_writer_separate_and_reaps_every_identity():
    ledger = session()
    ledger.request_fork(2, syscall="fork")
    ledger.fork_completed(2, 4)
    ledger.request_exec(4, process.EXECUTABLES[2], process.ARGV[2], dict(process.ENVIRONMENT))
    ledger.exec_completed(4, process.EXECUTABLES[2])
    assert ledger.roles == {2: "session", 3: "writer", 4: "auth"}
    assert ledger.receipt()["all_server_processes_reaped"] is False
    for pid in (3, 4, 2):
        ledger.exit(pid, 0)
    receipt = ledger.receipt()
    assert receipt["all_server_processes_reaped"] is True
    assert (receipt["server_identities"], receipt["fork_attempts"], receipt["exec_attempts"]) == (3, 2, 3)
    receipt["events"][0]["operation"] = "tamper"
    assert ledger.receipt()["events"][0]["operation"] == "exec_reserved"


@pytest.mark.parametrize("pid", (None, False, True, 0, 1, -2, "2", 2.0))
def test_initial_pid_strict(pid):
    with pytest.raises(ValueError):
        process.ProcessLedger(pid)


@pytest.mark.parametrize("fault", ("path", "argv", "extra_arg", "environment", "extra_environment", "list_argv"))
def test_exec_arguments_fail_before_reserving(fault):
    ledger = process.ProcessLedger(2)
    path, argv, environment = process.EXECUTABLES[0], process.ARGV[0], dict(process.ENVIRONMENT)
    if fault == "path": path = "/usr/bin/python3"
    elif fault == "argv": argv = (argv[0], "-D")
    elif fault == "extra_arg": argv = (*argv, "-oPermitRootLogin=yes")
    elif fault == "environment": environment["LC_ALL"] = "C.UTF-8"
    elif fault == "extra_environment": environment["LD_PRELOAD"] = "/bad"
    else: argv = list(argv)
    with pytest.raises(ValueError):
        ledger.request_exec(2, path, argv, environment)
    assert ledger.execs == 0


@pytest.mark.parametrize("flags", (0, 17, process.FORK_CLONE_FLAGS | 0x100, process.FORK_CLONE_FLAGS | 0x10000,
                                   process.FORK_CLONE_FLAGS | 0x20000000, 2**64 - 1))
def test_shared_vm_threads_namespaces_and_unreviewed_forks_denied(flags):
    ledger = initial()
    with pytest.raises(ValueError):
        ledger.request_fork(2, syscall="clone", flags=flags)
    assert ledger.forks == 0


@pytest.mark.parametrize("syscall", ("vfork", "clone3", "execve", "", None))
def test_only_reviewed_fork_syscalls(syscall):
    with pytest.raises(ValueError):
        initial().request_fork(2, syscall=syscall)


def test_failed_exec_or_fork_never_restores_reserved_allowance():
    ledger = process.ProcessLedger(2)
    ledger.request_exec(2, process.EXECUTABLES[0], process.ARGV[0], dict(process.ENVIRONMENT))
    with pytest.raises(ValueError):
        ledger.request_exec(2, process.EXECUTABLES[0], process.ARGV[0], dict(process.ENVIRONMENT))
    ledger = initial()
    ledger.request_fork(2, syscall="fork")
    with pytest.raises(ValueError):
        ledger.request_fork(2, syscall="fork")


def test_state_writer_cannot_spawn_or_exec_and_parent_cannot_skip_writer():
    ledger = initial()
    with pytest.raises(ValueError):
        ledger.request_exec(2, process.EXECUTABLES[1], process.ARGV[1], dict(process.ENVIRONMENT))
    ledger = session()
    with pytest.raises(ValueError): ledger.request_fork(3, syscall="fork")
    with pytest.raises(ValueError):
        ledger.request_exec(3, process.EXECUTABLES[2], process.ARGV[2], dict(process.ENVIRONMENT))


@pytest.mark.parametrize("child", (1, 2, True, None, "3"))
def test_duplicate_or_invalid_fork_event_denied(child):
    ledger = initial()
    ledger.request_fork(2, syscall="fork")
    with pytest.raises(ValueError): ledger.fork_completed(2, child)


def test_unrequested_exec_or_fork_or_exit_event_denied():
    ledger = initial()
    with pytest.raises(ValueError): ledger.exec_completed(2, process.EXECUTABLES[1])
    with pytest.raises(ValueError): ledger.fork_completed(2, 3)
    with pytest.raises(ValueError): ledger.exit(3, 0)
    ledger.exit(2, 0)
    with pytest.raises(ValueError): ledger.exit(2, 0)


def complete_receipt():
    ledger = session()
    ledger.request_fork(2, syscall="clone", flags=process.FORK_CLONE_FLAGS)
    ledger.fork_completed(2, 4)
    ledger.request_exec(4, process.EXECUTABLES[2], process.ARGV[2], dict(process.ENVIRONMENT))
    ledger.exec_completed(4, process.EXECUTABLES[2])
    for pid in (3, 4, 2): ledger.exit(pid, 0)
    return {**ledger.receipt(), "stop_reason": "processes_exited", "descriptor": {
        "inode": 100, "netns_cookie": 200, "local": ["127.0.0.1", 19022], "peer": ["127.0.0.1", 32000]},
        "stderr_base64": "", "stderr_truncated": False, "elapsed_ms": 90.2}


def test_receipt_replays_graph_and_returns_detached_value():
    original = complete_receipt()
    checked = process.validate_receipt(original)
    assert checked == original and checked is not original
    checked["descriptor"]["local"][1] = 2222
    checked["events"][0]["image"] = "changed"
    assert process.validate_receipt(original) == original


@pytest.mark.parametrize("field,value", (("server_identities", 2), ("server_identities", True), ("fork_attempts", 0),
    ("exec_attempts", 4), ("all_server_processes_reaped", False), ("elapsed_ms", float("nan")),
    ("elapsed_ms", float("inf")), ("elapsed_ms", True), ("elapsed_ms", 6000.001), ("elapsed_ms", -1),
    ("profile", "other"), ("stop_reason", "assume_success"), ("stderr_truncated", 1),
    ("stderr_base64", "!"), ("stderr_base64", "Zg==\n"), ("stderr_base64", "Zh=="), ("events", [])))
def test_receipt_rejects_forged_counts_flags_stderr_and_limits(field, value):
    receipt = complete_receipt()
    receipt[field] = value
    with pytest.raises(ValueError): process.validate_receipt(receipt)


@pytest.mark.parametrize("fault", ("missing", "extra", "unknown_image", "extra_fork", "wrong_child_role",
    "shared_vm", "missing_exit", "bool_pid", "duplicate_exit", "wrong_order", "bool_exit", "unknown_event"))
def test_receipt_rejects_forged_or_incomplete_event_history(fault):
    receipt = complete_receipt()
    events = receipt["events"]
    if fault == "missing": del events[0]["image"]
    elif fault == "extra": events[0]["approved"] = True
    elif fault == "unknown_image": events[0]["image"] = "/usr/bin/python3"
    elif fault == "extra_fork": events.insert(4, {"operation": "fork_reserved", "pid": 2, "syscall": "fork", "flags": 0})
    elif fault == "wrong_child_role": events[3]["role"] = "auth"
    elif fault == "shared_vm": events[2]["flags"] |= 0x100
    elif fault == "missing_exit": events.pop()
    elif fault == "bool_pid": events[0]["pid"] = True
    elif fault == "duplicate_exit": events.append(dict(events[-1]))
    elif fault == "wrong_order": events[0], events[1] = events[1], events[0]
    elif fault == "bool_exit": events[-1]["status"] = True
    else: events[0]["operation"] = "approved"
    with pytest.raises(ValueError): process.validate_receipt(receipt)


@pytest.mark.parametrize("fault", ("missing", "extra", "bool_inode", "zero_cookie", "bad_address", "bad_port",
                                   "bool_port", "same_endpoint", "tuple"))
def test_receipt_rejects_forged_descriptor_identity(fault):
    receipt = complete_receipt()
    identity = receipt["descriptor"]
    if fault == "missing": del identity["inode"]
    elif fault == "extra": identity["fd"] = 9
    elif fault == "bool_inode": identity["inode"] = True
    elif fault == "zero_cookie": identity["netns_cookie"] = 0
    elif fault == "bad_address": identity["local"][0] = "10.77.0.20"
    elif fault == "bad_port": identity["local"][1] = 65536
    elif fault == "bool_port": identity["local"][1] = True
    elif fault == "same_endpoint": identity["local"] = identity["peer"]
    else: identity["local"] = tuple(identity["local"])
    with pytest.raises(ValueError): process.validate_receipt(receipt)


def test_receipt_allows_bounded_partial_stock_startup_but_never_claims_full_graph():
    ledger = initial()
    ledger.exit(2, 1)
    receipt = complete_receipt()
    receipt.update(ledger.receipt())
    assert process.validate_receipt(receipt)["exec_attempts"] == 1


def test_stderr_overflow_is_bounded_and_explicit():
    receipt = complete_receipt()
    receipt.update(stderr_base64=base64.b64encode(b"x"*65536).decode(), stderr_truncated=True,
                   stop_reason="stock_ssh_stderr_limit")
    process.validate_receipt(receipt)
    receipt["stop_reason"] = "processes_exited"
    with pytest.raises(ValueError): process.validate_receipt(receipt)


def test_session_exec_requires_successful_writer_creation_event():
    ledger = initial()
    ledger.request_fork(2, syscall="fork")
    with pytest.raises(ValueError):
        ledger.request_exec(2, process.EXECUTABLES[1], process.ARGV[1], dict(process.ENVIRONMENT))
