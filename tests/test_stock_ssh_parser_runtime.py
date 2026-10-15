"""Independent parser replies require complete isolation and endpoint binding."""

import base64
from copy import deepcopy
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import stock_ssh_parser as parser
from recon_cockpit.secure_agent import stock_ssh_parser_runtime as isolated
from recon_cockpit.secure_agent import stock_ssh_parser_worker as worker
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.planner_worker import BOUNDARY_NAMES
from test_stock_ssh_parser import xml, key

CLOSURE = {"stdlib": "/stdlib", "files": ["/usr/bin/python3", "/lib/libc.so.6"]}


def receipt(configuration="A", tool=parser.NMAP):
    return {"profile": parser.parser_version(tool), "tool_id": tool, "configuration": configuration,
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), "status": "parsed",
        "result": parser.parse_output(tool, xml(configuration) if tool == parser.NMAP else key(configuration),
                                      configuration=configuration)}


def capture(monkeypatch, value=None, code=0, error=b"", reason=None):
    monkeypatch.setattr(isolated.sys, "platform", "linux")
    monkeypatch.setattr(isolated, "_command", lambda *args: ["confined"])
    value = receipt() if value is None else value
    monkeypatch.setattr(isolated, "_capture_bounded", lambda *a, **k: (
        code, json.dumps(value).encode(), error, reason))


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("tool", (parser.NMAP, parser.SSH))
def test_success_requires_exact_tool_configuration_and_independent_reply(monkeypatch, configuration, tool):
    value = receipt(configuration, tool)
    capture(monkeypatch, value)
    raw = xml(configuration) if tool == parser.NMAP else key(configuration)
    result = isolated.parse_isolated_tool_output(tool, raw, configuration=configuration, closure=CLOSURE)
    assert result == value["result"]


@pytest.mark.parametrize("change", (
    lambda value: value.update(profile="wrong"), lambda value: value.update(tool_id=parser.SSH),
    lambda value: value.update(configuration="B"), lambda value: value.update(extra=True),
    lambda value: value["boundary_checks"].update(socket_creation_blocked=False),
    lambda value: value["boundary_checks"].update(process_creation_blocked=1),
    lambda value: value["boundary_checks"].pop("no_new_privs"),
    lambda value: value["result"].update(target="10.77.0.99"),
    lambda value: value["result"].update(port=12222),
    lambda value: value.update(status="invalid"), lambda value: value.update(status="failed"),
))
def test_missing_boundary_or_mismatched_reply_has_no_host_fallback(monkeypatch, change):
    value = receipt()
    change(value)
    capture(monkeypatch, value)
    with pytest.raises(IsolationUnavailable):
        isolated.parse_isolated_tool_output(parser.NMAP, xml(), configuration="A", closure=CLOSURE)


@pytest.mark.parametrize("code,error,reason", ((78, b"", None), (0, b"unexpected", None),
    (0, b"", "timeout"), (0, b"", "output_limit")))
def test_child_refusal_timeout_or_diagnostics_fail_closed(monkeypatch, code, error, reason):
    capture(monkeypatch, code=code, error=error, reason=reason)
    with pytest.raises(IsolationUnavailable):
        isolated.parse_isolated_tool_output(parser.NMAP, xml(), configuration="A", closure=CLOSURE)


def test_invalid_tool_bytes_are_distinct_from_an_invalid_isolation_reply(monkeypatch):
    value = receipt()
    value.update(status="invalid", result=None)
    capture(monkeypatch, value)
    with pytest.raises(ValueError, match="invalid_stock_ssh_tool_output"):
        isolated.parse_isolated_tool_output(parser.NMAP, b"malformed", configuration="A", closure=CLOSURE)


def test_parser_uses_bounded_original_bytes_and_earliest_deadline(monkeypatch):
    monkeypatch.setattr(isolated.sys, "platform", "linux")
    monkeypatch.setattr(isolated, "_command", lambda *args: ["confined"])
    seen = []
    def run(argv, payload, timeout, limit, *, control):
        seen.append((argv, json.loads(payload), timeout, limit, control))
        return 0, json.dumps(receipt()).encode(), b"", None
    monkeypatch.setattr(isolated, "_capture_bounded", run)
    guard = ExecutionControl(110, clock=lambda: 100)
    isolated.parse_isolated_tool_output(parser.NMAP, xml(), configuration="A", deadline=101,
                                        control=guard, closure=CLOSURE)
    argv, payload, timeout, limit, control = seen[0]
    assert argv == ["confined"] and timeout == 1 and limit == 4096
    assert payload == {"configuration": "A", "raw": base64.b64encode(xml()).decode(), "stderr": ""}
    assert control.deadline == 101 and control.clock is guard.clock


@pytest.mark.parametrize("fault", ("configuration", "tool", "size", "truncated", "deadline"))
def test_validation_precedes_runtime_access(monkeypatch, fault):
    monkeypatch.setattr(isolated.sys, "platform", "linux")
    monkeypatch.setattr(isolated, "_runtime_files", lambda *a, **k: pytest.fail("runtime accessed"))
    args = dict(configuration="A", closure=CLOSURE)
    raw, tool = xml(), parser.NMAP
    if fault == "configuration": args["configuration"] = "C"
    elif fault == "tool": tool = "other"
    elif fault == "size": raw = b"x" * 8193
    elif fault == "truncated": args["truncated"] = True
    else: args["deadline"] = 0
    with pytest.raises((ValueError, ExecutionStopped)):
        isolated.parse_isolated_tool_output(tool, raw, **args)


@pytest.mark.parametrize("closure", ({}, {"stdlib": "relative", "files": ["/lib/x"]},
    {"stdlib": "/stdlib", "files": []}, {"stdlib": "/stdlib", "files": ["relative"]}))
def test_invalid_closure_never_launches_parser(monkeypatch, closure):
    monkeypatch.setattr(isolated.sys, "platform", "linux")
    monkeypatch.setattr(isolated, "_command", lambda *a: pytest.fail("parser launched"))
    with pytest.raises(IsolationUnavailable):
        isolated.parse_isolated_tool_output(parser.NMAP, xml(), configuration="A", closure=closure)


def test_parser_mounts_only_its_modules_and_cannot_inherit_native_tools(monkeypatch):
    monkeypatch.setattr(isolated, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(isolated, "_namespaces", lambda: dict.fromkeys(("user", "net", "mnt", "pid"), "private"))
    paths = ["/usr/bin/python3", "/lib/libc.so.6", "/usr/bin/nmap", "/usr/bin/ssh-keyscan", "/usr/bin/curl"]
    argv = isolated._command(parser.NMAP, ("/stdlib", [(path, path) for path in paths]))
    for path in paths[-3:]: assert path not in argv
    assert all(option in argv for option in ("--unshare-net", "--unshare-pid", "--cap-drop", "--clearenv", "--new-session"))
    assert "/app/recon_cockpit/secure_agent/stock_ssh_parser_worker.py" in argv
    assert not any("stock_ssh_spec.py" in value or "fixture.py" in value for value in argv)


def worker_call(monkeypatch, value=None, payload=None, *, bootstrap_fails=False):
    value = {"configuration": "A", "raw": base64.b64encode(xml()).decode(), "stderr": ""} if value is None else value
    payload = json.dumps(value).encode() if payload is None else payload
    output, error = io.BytesIO(), io.StringIO()
    monkeypatch.setattr(worker.sys, "argv", ["worker", parser.NMAP, "user:[1]", "net:[2]", "mnt:[3]", "pid:[4]"])
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    monkeypatch.setattr(worker.sys, "stdout", SimpleNamespace(buffer=output))
    monkeypatch.setattr(worker.sys, "stderr", error)
    def bootstrap(host):
        assert set(host) == {"user", "net", "mnt", "pid"}
        if bootstrap_fails: raise RuntimeError("denied")
        return dict.fromkeys(BOUNDARY_NAMES, True)
    monkeypatch.setattr(worker.planner_worker, "_bootstrap", bootstrap)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda *args: None)
    code = worker.main()
    return code, output.getvalue(), error.getvalue()


def test_worker_runs_bootstrap_before_consuming_untrusted_payload(monkeypatch):
    code, raw, error = worker_call(monkeypatch)
    assert code == 0 and not error
    assert json.loads(raw) == receipt()
    code, raw, error = worker_call(monkeypatch, bootstrap_fails=True)
    assert code == 78 and not raw and error == "stock_ssh_parser_refused\n"


@pytest.mark.parametrize("payload", (b"{}", b"[]", b"x" * 16385,
    b'{"configuration":"A","configuration":"B","raw":"eA==","stderr":""}',
    b'{"configuration":"A","raw":"eA===","stderr":""}',
    b'{"configuration":"A","raw":123,"stderr":""}'))
def test_worker_rejects_ambiguous_oversized_or_noncanonical_transport(monkeypatch, payload):
    code, raw, error = worker_call(monkeypatch, payload=payload)
    assert code == 78 and not raw and error == "stock_ssh_parser_refused\n"
