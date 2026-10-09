"""Networkless TLS corroboration; execution authority remains a separate check."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _runtime_files, _trusted_program
from .planner_worker import BOUNDARY_NAMES, NAMESPACE_NAMES
from .network_tools_tls_posture_parser import MAX_INPUT_BYTES, MAX_RESULT_BYTES, validate_result, encode_input
from .network_tools_tls_posture_spec import PARSER_VERSION


MAX_REPLY_BYTES = MAX_RESULT_BYTES + 1024
MAX_PARSE_SECONDS = 2
MAX_TOTAL_SECONDS = 10
PARSER_MODULES = (
    "planner_worker", "network_tools_tls_posture_parser_worker", "network_tools_tls_posture_parser",
    "network_tools_tls_posture_spec", "tls_posture_observation_contract",
    "tls_posture_diagnostic_trace", "tls_posture_mediated_trace", "tls_posture_mediator", "tls_posture_hello",
)
_LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_tls_observation_reply_key")
        result[key] = value
    return result


def _command(bootstrap):
    stdlib, files = bootstrap
    if (type(stdlib) is not str or re.fullmatch(r"/usr/lib/python3\.\d+", stdlib) is None
            or type(files) is not list or not files):
        raise IsolationUnavailable("TLS observation parser runtime invalid")
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv", "--setenv", "LC_ALL", "C",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    destinations = set()
    for row in files:
        if type(row) not in {tuple, list} or len(row) != 2:
            raise IsolationUnavailable("TLS observation parser runtime invalid")
        source, destination = row
        if (type(source) is not str or type(destination) is not str
                or any(part in path for path in (source, destination) for part in ("..", "//"))
                or destination in destinations):
            raise IsolationUnavailable("TLS observation parser runtime invalid")
        python = destination == "/usr/bin/python3" and re.fullmatch(r"/usr/bin/python3(?:\.\d+)?", source)
        if not python and not (_LIBRARY.fullmatch(source) and _LIBRARY.fullmatch(destination)):
            raise IsolationUnavailable("TLS observation parser runtime invalid")
        destinations.add(destination)
        argv += ["--ro-bind", source, destination]
    if "/usr/bin/python3" not in destinations:
        raise IsolationUnavailable("TLS observation parser runtime invalid")
    directory = Path(__file__).parent
    # The ordinary package initializer imports application models. Use the
    # inert secure-agent initializer at both levels of this minimal package.
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    for name in PARSER_MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    host = _namespaces()
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/network_tools_tls_posture_parser_worker.py",
             *(host[name] for name in NAMESPACE_NAMES)]
    return argv


def _parse_isolated(tool_id, raw, control, bootstrap):
    control.check()
    code, stdout, stderr, reason = _capture_bounded(
        _command(bootstrap), raw, min(MAX_PARSE_SECONDS, control.remaining()), MAX_REPLY_BYTES, control=control)
    control.check()
    if (type(code) is not int or code != 0 or reason is not None or type(stdout) is not bytes
            or type(stderr) is not bytes or stderr or not 0 < len(stdout) <= MAX_REPLY_BYTES):
        raise IsolationUnavailable("TLS observation parser isolation unavailable")
    try:
        value = json.loads(stdout, object_pairs_hook=_unique_object)
        if (type(value) is not dict or set(value) != {"contract_version", "boundary_checks", "status", "result"}
                or type(value["contract_version"]) is not str or value["contract_version"] != PARSER_VERSION
                or type(value["boundary_checks"]) is not dict or set(value["boundary_checks"]) != BOUNDARY_NAMES
                or any(item is not True for item in value["boundary_checks"].values())
                or type(value["status"]) is not str or value["status"] not in {"parsed", "invalid"}):
            raise ValueError("invalid_tls_observation_parser_reply")
        if value["status"] == "parsed":
            if type(value["result"]) is not dict or set(value["result"]) != {"input_sha256", "observation"}:
                raise ValueError("invalid_tls_posture_parser_result")
            encoded = json.dumps(value["result"], sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
            if len(encoded) > MAX_RESULT_BYTES:
                raise ValueError("invalid_tls_observation_result_size")
            result = validate_result(tool_id, value["result"]["observation"])
            if value["result"]["input_sha256"] != hashlib.sha256(raw).hexdigest():
                raise ValueError("tls_observation_input_commitment_mismatch")
            return result
        if value["result"] is not None:
            raise ValueError("invalid_tls_observation_parser_reply")
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise IsolationUnavailable("TLS observation parser reply invalid") from None
    raise ValueError("invalid_tls_observation_input")


def parse_isolated_tls_posture(tool_id, stdout, stderr, *, owner_raw, exit_code,
                               stop_reason, truncated, control=None, deadline=None, closure=None):
    """Corroborate bounded actual streams and owner bytes in a networkless worker."""
    raw = encode_input(tool_id, stdout, stderr, owner_raw=owner_raw, exit_code=exit_code,
                       stop_reason=stop_reason, truncated=truncated)
    if control is not None and type(control) is not ExecutionControl:
        raise ValueError("invalid_tls_posture_parser_control")
    if sys.platform != "linux" or (closure is None and os.geteuid() == 0):
        raise IsolationUnavailable("TLS posture parsing requires unprivileged Linux isolation")
    clock = time.monotonic if control is None else control.clock
    limits = [clock() + MAX_TOTAL_SECONDS]
    if control is not None:
        control.check()
        limits.append(control.deadline)
    if deadline is not None:
        ExecutionControl(deadline, clock=clock).check()
        limits.append(deadline)
    bounded = ExecutionControl(min(limits), None if control is None else control.cancelled, clock)
    bounded.check()
    if closure is None:
        bootstrap = _runtime_files("/usr/bin/python3", None, control=bounded)
    else:
        if (type(closure) is not dict or set(closure) != {"stdlib", "files"}
                or type(closure["files"]) is not list or not closure["files"]
                or any(type(path) is not str for path in closure["files"])):
            raise IsolationUnavailable("TLS posture parser runtime closure invalid")
        bootstrap = closure["stdlib"], [(path, path) for path in closure["files"]]
    result = _parse_isolated(tool_id, raw, bounded, bootstrap)
    if (result["owner_sha256"] != hashlib.sha256(owner_raw).hexdigest()
            or result["stdout_sha256"] != hashlib.sha256(stdout).hexdigest()
            or result["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()):
        raise IsolationUnavailable("TLS posture parser commitment mismatch")
    expected_exit = 0 if result["outcome"] == "handshake_completed" else 1
    if exit_code != expected_exit or stop_reason is not None or truncated:
        raise IsolationUnavailable("TLS posture parser execution mismatch")
    return result
