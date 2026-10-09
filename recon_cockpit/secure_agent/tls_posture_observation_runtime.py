"""Networkless corroboration of retained owned TLS diagnostic receipts.

This parser has no target, execution permit, registered profile or configurable
runtime closure. Its normalized output remains non-authoritative diagnostic
data, even when every parser isolation witness succeeds.
"""

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
from .tls_posture_observation_contract import CONTRACT_VERSION, MAX_INPUT_BYTES, MAX_RESULT_BYTES, validate_observation


MAX_REPLY_BYTES = MAX_RESULT_BYTES + 1024
MAX_PARSE_SECONDS = 2
MAX_TOTAL_SECONDS = 10
PARSER_MODULES = (
    "planner_worker", "tls_posture_observation_worker", "tls_posture_observation_contract",
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
             "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/tls_posture_observation_worker.py",
             *(host[name] for name in NAMESPACE_NAMES)]
    return argv


def _parse_isolated(raw, control, bootstrap):
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
                or type(value["contract_version"]) is not str or value["contract_version"] != CONTRACT_VERSION
                or type(value["boundary_checks"]) is not dict or set(value["boundary_checks"]) != BOUNDARY_NAMES
                or any(item is not True for item in value["boundary_checks"].values())
                or type(value["status"]) is not str or value["status"] not in {"parsed", "invalid"}):
            raise ValueError("invalid_tls_observation_parser_reply")
        if value["status"] == "parsed":
            encoded = json.dumps(value["result"], sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
            if len(encoded) > MAX_RESULT_BYTES:
                raise ValueError("invalid_tls_observation_result_size")
            result = validate_observation(value["result"])
            if result["input_sha256"] != hashlib.sha256(raw).hexdigest():
                raise ValueError("tls_observation_input_commitment_mismatch")
            return result
        if value["result"] is not None:
            raise ValueError("invalid_tls_observation_parser_reply")
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise IsolationUnavailable("TLS observation parser reply invalid") from None
    raise ValueError("invalid_tls_observation_input")


def parse_isolated_observation(raw: bytes, *, deadline=None, control=None) -> dict:
    """Parse one bounded retained diagnostic; never execute the selected tool."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
        raise ValueError("invalid_tls_observation_input_size")
    if control is not None and type(control) is not ExecutionControl:
        raise ValueError("invalid_tls_observation_parser_control")
    if sys.platform != "linux" or os.geteuid() == 0:
        raise IsolationUnavailable("TLS observation parsing requires unprivileged Linux isolation")
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
    bootstrap = _runtime_files("/usr/bin/python3", None, control=bounded)
    return _parse_isolated(raw, bounded, bootstrap)
