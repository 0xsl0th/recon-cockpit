"""Networkless bounded parsing of retained curl/ffuf output for capture/replay."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _namespaces, _runtime_files, _trusted_program
from .planner_worker import BOUNDARY_NAMES
from .web_tools_parser import MAX_OUTPUT_BYTES, parser_version, validate_result, _unique_object


def _command(tool_id, bootstrap):
    parser_version(tool_id)
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv", "--setenv", "LC_ALL", "C",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if Path(destination).name not in {"nft", "bwrap", "nsenter", "curl", "ffuf"}:
            argv += ["--ro-bind", source, destination]
    for name in ("web_tools_parser", "web_tools_parser_worker", "http_headers_parser", "planner_worker"):
        argv += ["--ro-bind", str(Path(__file__).with_name(name + ".py")), "/app/" + name + ".py"]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/web_tools_parser_worker.py", tool_id, *_namespaces().values()]
    return argv


def _parse_isolated(tool_id, raw, control, bootstrap):
    version = parser_version(tool_id)
    control.check()
    code, stdout, _, reason = _capture_bounded(
        _command(tool_id, bootstrap), raw, min(2, control.remaining()), 4096, control=control)
    if code != 0 or reason is not None:
        raise IsolationUnavailable("Web tool parser isolation unavailable")
    try:
        value = json.loads(stdout, object_pairs_hook=_unique_object)
        if (type(value) is not dict or set(value) != {"profile", "tool_id", "boundary_checks", "status", "result"}
                or value["profile"] != version or value["tool_id"] != tool_id
                or type(value["boundary_checks"]) is not dict or set(value["boundary_checks"]) != BOUNDARY_NAMES
                or any(item is not True for item in value["boundary_checks"].values())
                or type(value["status"]) is not str or value["status"] not in {"parsed", "invalid"}):
            raise ValueError("invalid_web_tool_parser_reply")
        if value["status"] == "parsed":
            return validate_result(tool_id, value["result"])
        if value["result"] is not None:
            raise ValueError("invalid_web_tool_parser_reply")
    except (ValueError, TypeError, RecursionError):
        raise IsolationUnavailable("Web tool parser reply invalid") from None
    raise ValueError("invalid_web_tool_output")


def parse_isolated_tool_output(tool_id, raw: bytes, *, truncated=False, deadline=None, control=None, closure=None):
    parser_version(tool_id)
    if (type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT_BYTES
            or type(truncated) is not bool or truncated):
        raise ValueError("invalid_web_tool_output_size")
    if sys.platform != "linux" or (closure is None and os.geteuid() == 0):
        raise IsolationUnavailable("Web tool parsing requires unprivileged Linux isolation")
    if control is not None and type(control) is not ExecutionControl:
        raise ValueError("invalid_web_tool_parser_control")
    clock = time.monotonic if control is None else control.clock
    limits = [clock() + 10]
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
        if (type(closure) is not dict or type(closure.get("stdlib")) is not str
                or not closure["stdlib"].startswith("/") or type(closure.get("files")) is not list
                or not closure["files"] or any(type(path) is not str or not path.startswith("/")
                                               for path in closure["files"])):
            raise IsolationUnavailable("Web tool parser runtime closure invalid")
        bootstrap = closure["stdlib"], [(path, path) for path in closure["files"]]
    return _parse_isolated(tool_id, raw, bounded, bootstrap)


parse_isolated_tool = parse_isolated_tool_output
