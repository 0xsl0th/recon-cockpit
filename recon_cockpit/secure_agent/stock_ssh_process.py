"""Finite, non-authorizing process ledger for the stock SSH owner.

Every request is reserved before the kernel syscall proceeds. Failed syscalls
consume their allowance too; no restart can restore this instance's budget.
"""

import base64
from copy import deepcopy
import math

from . import stock_ssh_spec as spec

PROFILE = "stock-ssh-process-custody-v1"
EXECUTABLES = tuple(row[2] for row in spec.SSHD_EXECUTABLES)
ARGV = (spec.SSHD_ARGV,
        (EXECUTABLES[1], *spec.SSHD_ARGV[1:], "-R"),
        (EXECUTABLES[2], *spec.SSHD_ARGV[1:], "-R"))
ENVIRONMENT = dict(spec.SSHD_ENVIRONMENT)
# Linux x86_64 glibc fork: SIGCHLD, CHILD_SETTID and CHILD_CLEARTID.
FORK_CLONE_FLAGS = 0x01200011
BOUNDS = {"max_server_identities": 3, "max_internal_fork_attempts": 2,
          "max_exec_attempts": 3, "max_threads_per_process": 1,
          "custodian_processes": 1, "address_space_bytes_per_process": 268435456,
          "file_descriptors_per_process": 64, "retained_bytes": 1048576}
STOP_REASONS = frozenset({"processes_exited", "stock_ssh_instance_timeout", "stock_ssh_instance_cancelled",
    "stock_ssh_exec_denied", "stock_ssh_fork_denied", "stock_ssh_unknown_process",
    "stock_ssh_unexpected_exec_event", "stock_ssh_unexpected_fork_event", "stock_ssh_stderr_limit",
    "stock_ssh_process_event_limit", "stock_ssh_invalid_wait_status", "stock_ssh_initial_stop_invalid",
    "stock_ssh_unknown_child_stop", "stock_ssh_unexpected_seccomp_event", "stock_ssh_unexpected_clone_event",
    "stock_ssh_exec_inode_changed", "stock_ssh_unexpected_trace_stop", "stock_ssh_unreviewed_syscall_abi",
    "stock_ssh_invalid_tracee_pointer", "stock_ssh_tracee_argument_limit", "stock_ssh_tracee_vector_limit",
    "stock_ssh_invalid_tracee_environment", "stock_ssh_custody_error"})


class ProcessLedger:
    def __init__(self, initial_pid):
        if type(initial_pid) is not int or initial_pid <= 1:
            raise ValueError("stock_ssh_invalid_initial_pid")
        self.roles = {initial_pid: "bootstrap"}
        self.initial_pid = initial_pid
        self.forks = 0
        self.execs = 0
        self.pending_forks = {}
        self.pending_execs = {}
        self.forked_roles = set()
        self.exited = set()
        self.events = []

    def _role(self, pid):
        if type(pid) is not int or pid not in self.roles or pid in self.exited:
            raise ValueError("stock_ssh_unknown_process")
        return self.roles[pid]

    def request_exec(self, pid, filename, argv, environment):
        role = self._role(pid)
        index = {"bootstrap": 0, "sshd": 1, "auth-bootstrap": 2}.get(role)
        if (index is None or pid in self.pending_execs or pid in self.pending_forks or self.execs >= 3
                or type(filename) is not str or filename != EXECUTABLES[index]
                or type(argv) is not tuple or argv != ARGV[index]
                or type(environment) is not dict or environment != ENVIRONMENT
                or (role == "sshd" and "sshd" not in self.forked_roles)):
            raise ValueError("stock_ssh_exec_denied")
        self.execs += 1
        self.pending_execs[pid] = index
        self.events.append({"operation": "exec_reserved", "pid": pid, "image": filename})

    def exec_completed(self, pid, filename):
        self._role(pid)
        index = self.pending_execs.pop(pid, None)
        if index is None or filename != EXECUTABLES[index]:
            raise ValueError("stock_ssh_unexpected_exec_event")
        self.roles[pid] = ("sshd", "session", "auth")[index]
        self.events.append({"operation": "exec_completed", "pid": pid, "image": filename})

    def request_fork(self, pid, *, syscall, flags=0):
        role = self._role(pid)
        if (role not in ("sshd", "session") or role in self.forked_roles
                or pid in self.pending_execs or pid in self.pending_forks
                or self.forks >= 2 or len(self.roles) >= 3
                or syscall not in ("fork", "clone")
                or (syscall == "clone" and flags != FORK_CLONE_FLAGS)
                or (syscall == "fork" and flags != 0)):
            raise ValueError("stock_ssh_fork_denied")
        self.forks += 1
        self.forked_roles.add(role)
        self.pending_forks[pid] = "writer" if role == "sshd" else "auth-bootstrap"
        self.events.append({"operation": "fork_reserved", "pid": pid, "syscall": syscall, "flags": flags})

    def fork_completed(self, pid, child):
        self._role(pid)
        role = self.pending_forks.pop(pid, None)
        if (role is None or type(child) is not int or child <= 1
                or child in self.roles or len(self.roles) >= 3):
            raise ValueError("stock_ssh_unexpected_fork_event")
        self.roles[child] = role
        self.events.append({"operation": "fork_completed", "pid": pid, "child": child, "role": role})

    def exit(self, pid, status):
        self._role(pid)
        self.exited.add(pid)
        self.events.append({"operation": "exit", "pid": pid, "status": status})

    def receipt(self):
        return {"profile": PROFILE, "server_identities": len(self.roles),
                "fork_attempts": self.forks, "exec_attempts": self.execs,
                "all_server_processes_reaped": set(self.roles) == self.exited,
                "events": [dict(event) for event in self.events]}


def validate_receipt(value):
    """Replay bounded saved custody events; never trust claimed counts or paths."""
    fields = {"profile", "server_identities", "fork_attempts", "exec_attempts", "all_server_processes_reaped",
              "events", "stop_reason", "descriptor", "stderr_base64", "stderr_truncated", "elapsed_ms"}
    if (type(value) is not dict or set(value) != fields or value["profile"] != PROFILE
            or value["all_server_processes_reaped"] is not True
            or type(value["stop_reason"]) is not str or value["stop_reason"] not in STOP_REASONS
            or type(value["stderr_truncated"]) is not bool
            or type(value["elapsed_ms"]) not in (int, float) or not math.isfinite(value["elapsed_ms"])
            or not 0 <= value["elapsed_ms"] <= 6000
            or type(value["events"]) is not list or not 1 <= len(value["events"]) <= 128):
        raise ValueError("invalid_stock_ssh_process_receipt")
    for name, maximum in (("server_identities", 3), ("fork_attempts", 2), ("exec_attempts", 3)):
        if type(value[name]) is not int or not (1 if name == "server_identities" else 0) <= value[name] <= maximum:
            raise ValueError("invalid_stock_ssh_process_count")
    identity = value["descriptor"]
    if (type(identity) is not dict or set(identity) != {"inode", "local", "peer", "netns_cookie"}
            or any(type(identity[key]) is not int or not 0 < identity[key] < 2**64 for key in ("inode", "netns_cookie"))):
        raise ValueError("invalid_stock_ssh_process_descriptor")
    for name in ("local", "peer"):
        endpoint = identity[name]
        if (type(endpoint) is not list or len(endpoint) != 2 or endpoint[0] != "127.0.0.1"
                or type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535):
            raise ValueError("invalid_stock_ssh_process_endpoint")
    if identity["local"] == identity["peer"]:
        raise ValueError("invalid_stock_ssh_process_endpoint")
    if type(value["stderr_base64"]) is not str or len(value["stderr_base64"]) > 87384:
        raise ValueError("invalid_stock_ssh_process_stderr")
    try:
        raw = base64.b64decode(value["stderr_base64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("invalid_stock_ssh_process_stderr") from None
    if (len(raw) > 65536 or base64.b64encode(raw).decode("ascii") != value["stderr_base64"]
            or value["stderr_truncated"] and (len(raw) != 65536 or value["stop_reason"] != "stock_ssh_stderr_limit")):
        raise ValueError("invalid_stock_ssh_process_stderr")
    first = value["events"][0]
    if type(first) is not dict or type(first.get("pid")) is not int or not 1 < first["pid"] < 2**31:
        raise ValueError("invalid_stock_ssh_process_event")
    ledger = ProcessLedger(first["pid"])
    try:
        for event in value["events"]:
            if (type(event) is not dict or type(event.get("pid")) is not int or not 1 < event["pid"] < 2**31
                    or type(event.get("operation")) is not str):
                raise ValueError("invalid_stock_ssh_process_event")
            operation, pid = event["operation"], event["pid"]
            shape = {"operation", "pid"} | {
                "exec_reserved": {"image"}, "exec_completed": {"image"},
                "fork_reserved": {"syscall", "flags"}, "fork_completed": {"child", "role"}, "exit": {"status"}
            }.get(operation, {"unknown"})
            if set(event) != shape:
                raise ValueError("invalid_stock_ssh_process_event")
            if operation == "exec_reserved":
                index = EXECUTABLES.index(event["image"])
                ledger.request_exec(pid, event["image"], ARGV[index], dict(ENVIRONMENT))
            elif operation == "exec_completed":
                ledger.exec_completed(pid, event["image"])
            elif operation == "fork_reserved":
                if type(event["flags"]) is not int or type(event["syscall"]) is not str:
                    raise ValueError("invalid_stock_ssh_process_event")
                ledger.request_fork(pid, syscall=event["syscall"], flags=event["flags"])
            elif operation == "fork_completed":
                if type(event["child"]) is not int or not 1 < event["child"] < 2**31:
                    raise ValueError("invalid_stock_ssh_process_event")
                ledger.fork_completed(pid, event["child"])
                if ledger.roles[event["child"]] != event["role"]:
                    raise ValueError("invalid_stock_ssh_process_event")
            elif operation == "exit":
                if type(event["status"]) is not int or not -64 <= event["status"] <= 255:
                    raise ValueError("invalid_stock_ssh_process_event")
                ledger.exit(pid, event["status"])
        rebuilt = ledger.receipt()
    except (ValueError, TypeError, KeyError):
        raise ValueError("invalid_stock_ssh_process_event") from None
    if any(value[key] != item for key, item in rebuilt.items()):
        raise ValueError("invalid_stock_ssh_process_replay")
    return deepcopy(value)
