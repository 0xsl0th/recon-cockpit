"""Portable adapter checks and opted-in real offline codec sandbox evidence."""

import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import broker_ipc, openai_isolation, openai_protocol
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_isolation import LinuxOpenAIPlanner
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig
from recon_cockpit.secure_agent.planner_isolation import BOUNDARY_NAMES


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def observation():
    return encode({"step": 1, "untrusted_observation": None})


def config():
    return OpenAIConfig("offline-fixture-model", 512)


def proposal():
    return {"schema_version": "1", "action": None, "done": True}


def response(plan=None):
    return encode({
        "object": "response", "status": "completed", "error": None, "incomplete_details": None,
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": json.dumps(proposal() if plan is None else plan)}]}],
    })


def envelope(**changes):
    return {"schema_version": "1", "proposal": proposal(),
            "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True), **changes}


def control(seconds=30, cancelled=None):
    return ExecutionControl(time.monotonic() + seconds, cancelled)


@pytest.fixture
def transport(monkeypatch):
    planner = LinuxOpenAIPlanner()
    state = {"reply": encode(envelope()), "calls": []}
    monkeypatch.setattr(planner, "check_available", lambda: None)
    monkeypatch.setattr(planner, "_command", lambda *_: ["fixed-openai-sandbox"])
    monkeypatch.setattr(openai_isolation, "_runtime_files", lambda *_a, **_k: ("stdlib", []))

    def supervise(argv, init, exchange, *, control):
        state["calls"].append((argv, init, exchange, control))
        return state["reply"]

    monkeypatch.setattr(broker_ipc, "supervise", supervise)
    return planner, state


def test_adapter_sends_only_bounded_data_configuration_and_copies_evidence(transport):
    planner, state = transport
    callback = lambda *_a, **_k: response()
    bounded = control()
    assert json.loads(planner.plan(config(), observation(), callback, control=bounded)) == proposal()
    argv, raw, exchange, passed_control = state["calls"][0]
    assert argv == ["fixed-openai-sandbox"] and exchange is callback and passed_control is bounded
    assert len(raw) <= broker_ipc.MAX_INIT_BYTES
    assert json.loads(raw) == {
        "schema_version": "1", "config": {"model": "offline-fixture-model", "max_output_tokens": 512},
        "observation": {"step": 1, "untrusted_observation": None},
    }
    checks = planner.boundary_checks
    checks["root_read_only"] = False
    assert planner.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"\xff", b"x" * 32769, encode(envelope(schema_version="2")),
    encode(envelope(proposal=None)), encode(envelope(proposal=[])), encode(envelope(extra=True)),
    encode(envelope(boundary_checks={})),
    encode(envelope(boundary_checks={**dict.fromkeys(BOUNDARY_NAMES, True), "root_read_only": 1})),
    encode(envelope(boundary_checks={**dict.fromkeys(BOUNDARY_NAMES, True), "root_read_only": False})),
    encode(envelope(boundary_checks={**dict.fromkeys(BOUNDARY_NAMES, True), "extra": True})),
    encode(envelope(proposal={"text": "x" * 16384})),
])
def test_invalid_result_clears_old_evidence_and_never_echoes_details(transport, raw):
    planner, state = transport
    planner.plan(config(), observation(), lambda *_a, **_k: response(), control=control())
    state["reply"] = raw
    with pytest.raises(IsolationUnavailable, match="^Isolated OpenAI parser failed; no fallback is permitted$"):
        planner.plan(config(), observation(), lambda *_a, **_k: response(), control=control())
    assert planner.boundary_checks is None


@pytest.mark.parametrize("raw", [None, "{}", bytearray(b"{}"), b"\xff", b" " * 8193, b"{}"])
def test_invalid_observation_never_launches(transport, raw):
    planner, state = transport
    with pytest.raises(ValueError):
        planner.plan(config(), raw, lambda *_a, **_k: response(), control=control())
    assert state["calls"] == [] and planner.boundary_checks is None


@pytest.mark.parametrize("failure", [AuditUnavailable("PRIVATE-AUDIT"), ExecutionStopped("session_cancelled"),
                                     ExecutionStopped("session_timeout")])
def test_control_and_audit_failures_preserve_identity(transport, monkeypatch, failure):
    planner, _state = transport

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(broker_ipc, "supervise", fail)
    with pytest.raises(type(failure)) as error:
        planner.plan(config(), observation(), lambda *_a, **_k: response(), control=control())
    assert error.value is failure
    assert planner.boundary_checks is None


def test_missing_isolation_never_falls_back_or_calls_broker(transport, monkeypatch):
    planner, state = transport

    def unavailable():
        raise IsolationUnavailable("no namespace setup")

    monkeypatch.setattr(planner, "check_available", unavailable)
    with pytest.raises(IsolationUnavailable):
        planner.plan(config(), observation(), lambda *_a, **_k: pytest.fail("no broker call"), control=control())
    assert state["calls"] == []


def test_command_mounts_only_fixed_codec_modules_and_safe_package_initializers(monkeypatch):
    monkeypatch.setattr(openai_isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(openai_isolation, "_namespaces", lambda: {name: f"{name}:[100]" for name in ("user", "net", "mnt", "pid")})
    argv = LinuxOpenAIPlanner()._command("/usr/lib/python3.14", [("/lib/native.so", "/lib/native.so")])
    mounts = [(argv[i + 1], argv[i + 2]) for i, word in enumerate(argv) if word == "--ro-bind"]
    app = {destination: source for source, destination in mounts if destination.startswith("/app/")}
    assert set(app) == {
        "/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py",
        "/app/recon_cockpit/secure_agent/models.py", "/app/recon_cockpit/secure_agent/session_protocol.py",
        "/app/recon_cockpit/secure_agent/openai_protocol.py", "/app/recon_cockpit/secure_agent/broker_ipc.py",
        "/app/planner_worker.py", "/app/openai_worker.py",
    }
    assert app["/app/recon_cockpit/__init__.py"] == app["/app/recon_cockpit/secure_agent/__init__.py"]
    assert app["/app/recon_cockpit/__init__.py"].endswith("secure_agent/__init__.py")
    assert "--cap-add" not in argv and "--share-net" not in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[-8:-4] == ["/usr/bin/python3", "-I", "-S", "/app/openai_worker.py"]
    assert not any("controller.py" in word or "session.py" in word or "slirp" in word for word in argv)


@pytest.fixture
def real_planner():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1" or sys.platform != "linux":
        pytest.skip("real codec sandbox requires explicit Linux opt-in")
    planner = LinuxOpenAIPlanner()
    planner.check_available()
    return planner


@pytest.mark.integration
def test_real_sandbox_builds_request_and_decodes_only_data_without_live_calls(real_planner):
    requests = []

    def exchange(request, *, control):
        requests.append(request)
        assert request == openai_protocol.build_request(config(), observation())
        control.check()
        return response()

    assert json.loads(real_planner.plan(config(), observation(), exchange, control=control())) == proposal()
    assert len(requests) == 1
    assert real_planner.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)


@pytest.mark.integration
@pytest.mark.parametrize("raw", [b"invalid PRIVATE-RESPONSE", response({"schema_version": "1", "action": None, "done": False})])
def test_real_parser_rejects_malformed_api_response_inside_sandbox(real_planner, raw):
    with pytest.raises(IsolationUnavailable, match="no fallback"):
        real_planner.plan(config(), observation(), lambda *_a, **_k: raw, control=control())
    assert real_planner.boundary_checks is None


def mount_test_codec(planner, monkeypatch, tmp_path, suffix):
    # Substitution is trusted test instrumentation after the real bootstrap;
    # production callers have no module/path selection option.
    path = tmp_path / "trusted-test-codec.py"
    path.write_text(Path(openai_protocol.__file__).read_text() + "\n" + suffix)
    original = planner._command

    def command(stdlib, files):
        argv = original(stdlib, files)
        matches = [i for i, word in enumerate(argv) if word == "--ro-bind"
                   and argv[i + 2] == "/app/recon_cockpit/secure_agent/openai_protocol.py"]
        assert len(matches) == 1
        argv[matches[0] + 1] = str(path)
        return argv

    monkeypatch.setattr(planner, "_command", command)


@pytest.mark.integration
def test_real_response_parser_cannot_read_host_canaries_or_create_sockets(real_planner, monkeypatch, tmp_path):
    sentinel = tmp_path / "private-host-canary"
    sentinel.write_text("PRIVATE-HOST-CANARY")
    monkeypatch.setenv("OPENAI_API_KEY", "PRIVATE-HOST-CANARY")
    source = os.open(sentinel, os.O_RDONLY)
    inherited = fcntl.fcntl(source, fcntl.F_DUPFD, 128)
    os.set_inheritable(inherited, True)
    suffix = f'''
import errno,importlib.util,os,socket
original_decode = decode_response
def decode_response(raw):
    result = json.loads(original_decode(raw))
    checks = {{"credentials_absent": "OPENAI_API_KEY" not in os.environ}}
    checks["controller_absent"] = importlib.util.find_spec("recon_cockpit.secure_agent.controller") is None
    checks["session_absent"] = importlib.util.find_spec("recon_cockpit.secure_agent.session") is None
    try:
        fd = os.open({str(sentinel)!r}, os.O_RDONLY)
    except OSError as error:
        checks["host_file_absent"] = error.errno == errno.ENOENT
    else:
        os.close(fd); checks["host_file_absent"] = False
    try:
        os.fstat({inherited})
    except OSError as error:
        checks["inherited_fd_absent"] = error.errno == errno.EBADF
    else:
        checks["inherited_fd_absent"] = False
    for name,family in (("inet_denied",socket.AF_INET),("inet6_denied",socket.AF_INET6),("unix_denied",socket.AF_UNIX)):
        try:
            connection=socket.socket(family,socket.SOCK_STREAM)
        except OSError as error:
            checks[name]=error.errno==errno.EPERM
        else:
            connection.close(); checks[name]=False
    result["witnesses"] = checks
    return _encode(result)
'''
    mount_test_codec(real_planner, monkeypatch, tmp_path, suffix)
    try:
        result = json.loads(real_planner.plan(config(), observation(), lambda *_a, **_k: response(), control=control()))
    finally:
        os.close(inherited)
        os.close(source)
    assert result["witnesses"] == dict.fromkeys({
        "credentials_absent", "controller_absent", "session_absent", "host_file_absent",
        "inherited_fd_absent", "inet_denied", "inet6_denied", "unix_denied",
    }, True)
    assert "PRIVATE-HOST-CANARY" not in json.dumps(result)
    assert sentinel.read_text() == "PRIVATE-HOST-CANARY"


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["cancelled", "deadline", "output"])
def test_real_hostile_codec_is_bounded_and_worker_reaped(real_planner, monkeypatch, tmp_path, mode):
    suffix = ("import os,time\ndef build_request(*args):\n    os.write(1,b'X'*65536)\n    time.sleep(30)\n"
              if mode == "output" else "import time\ndef build_request(*args):\n    time.sleep(30)\n")
    mount_test_codec(real_planner, monkeypatch, tmp_path, suffix)
    processes = []
    timers = []
    cancelled = threading.Event()
    original = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            processes.append(child)
            if mode == "cancelled":
                timer = threading.Timer(0.3, cancelled.set)
                timers.append(timer)
                timer.start()
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    try:
        expected = IsolationUnavailable if mode == "output" else ExecutionStopped
        with pytest.raises(expected):
            real_planner.plan(config(), observation(), lambda *_a, **_k: pytest.fail("hostile request must not reach broker"),
                              control=control(2 if mode == "deadline" else 10, cancelled))
        assert len(processes) == 1 and processes[0].returncode == -signal.SIGKILL
        assert real_planner.boundary_checks is None
    finally:
        for timer in timers:
            timer.cancel()
            timer.join(timeout=1)
        for child in processes:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)
