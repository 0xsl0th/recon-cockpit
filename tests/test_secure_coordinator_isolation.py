"""Portable launcher validation and opt-in Linux coordinator boundary evidence."""

import fcntl
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import (coordinator_ipc as ipc, coordinator_isolation as isolation,
                                       coordinator_worker as worker, session_planner)
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES, LinuxCoordinator, LinuxOfflineCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def control(seconds=10, cancelled=None):
    return ExecutionControl(time.monotonic() + seconds, cancelled)


def init(version="1"):
    return encode({"schema_version": version, "session_id": str(uuid4())})


def reply(request, *, stop=True, observation=None):
    return encode({"schema_version": "1", "session_id": request["session_id"],
                   "sequence": request["sequence"], "stop": stop, "observation": observation})


def offline_reply(request, *, stop=False, plan=None):
    return encode({"schema_version": "2", "session_id": request["session_id"],
                   "sequence": request["sequence"], "stop": stop, "plan": plan})


@pytest.fixture
def launcher(monkeypatch):
    coordinator = LinuxCoordinator()
    monkeypatch.setattr(coordinator, "check_available", lambda: None)
    monkeypatch.setattr(isolation, "_runtime_files", lambda *_a, **_k: ("/stdlib", []))
    monkeypatch.setattr(coordinator, "_command", lambda *_a: ["fixed-coordinator"])
    return coordinator


def test_adapter_exposes_verified_boundary_before_authority_callback(launcher, monkeypatch):
    initial = init()
    session_id = json.loads(initial)["session_id"]
    expected = encode({"schema_version": "1", "session_id": session_id, "status": "closed"})

    def supervise(argv, raw, exchange, *, control, max_requests):
        assert argv == ["fixed-coordinator"] and raw == initial
        assert max_requests == ipc.MAX_REQUESTS
        assert exchange(b"request", control=control) == b"response"
        return expected

    def exchange(raw, *, control):
        assert raw == b"request"
        assert launcher.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
        checks = launcher.boundary_checks
        checks.clear()
        assert launcher.boundary_checks
        return b"response"

    monkeypatch.setattr(ipc, "supervise", supervise)
    assert launcher.run(initial, exchange, control=control()) == expected


@pytest.mark.parametrize("result", [b"bad", b"[]", b"{}", encode({"schema_version": "1", "session_id": str(uuid4()), "status": "closed"})])
def test_adapter_rejects_invalid_or_cross_session_final_result(launcher, monkeypatch, result):
    def supervise(_argv, _raw, exchange, *, control, max_requests):
        exchange(b"request", control=control)
        return result

    monkeypatch.setattr(ipc, "supervise", supervise)
    with pytest.raises(IsolationUnavailable, match="no fallback"):
        launcher.run(init(), lambda *_a, **_k: b"response", control=control())
    assert launcher.boundary_checks is None


@pytest.mark.parametrize("raw", [b"x" * 513, b"{}", b"[]", b'{"schema_version":"1","session_id":"invalid"}',
                                 b'{"schema_version":"1","session_id":1}', "not bytes"])
def test_invalid_init_cannot_launch(launcher, monkeypatch, raw):
    monkeypatch.setattr(ipc, "supervise", lambda *_a, **_k: pytest.fail("must not launch"))
    with pytest.raises((ValueError, ipc.IPCError)):
        launcher.run(raw, lambda *_a, **_k: b"", control=control())


@pytest.mark.parametrize("scenario", [None, [], 1, "arbitrary-script", "../controller"])
def test_only_fixed_scenarios_are_selectable(scenario):
    with pytest.raises(ValueError):
        LinuxCoordinator(scenario)


@pytest.mark.parametrize("failure", [AuditUnavailable("private audit"), ExecutionStopped("session_cancelled")])
def test_callback_audit_and_control_errors_preserve_identity(launcher, monkeypatch, failure):
    def supervise(_argv, _raw, exchange, *, control, max_requests):
        return exchange(b"request", control=control)

    def exchange(*_a, **_k):
        raise failure

    monkeypatch.setattr(ipc, "supervise", supervise)
    with pytest.raises(type(failure)) as error:
        launcher.run(init(), exchange, control=control())
    assert error.value is failure
    assert launcher.boundary_checks is None


def test_missing_isolation_never_reaches_authority(launcher, monkeypatch):
    def unavailable():
        raise IsolationUnavailable("unavailable")

    monkeypatch.setattr(launcher, "check_available", unavailable)
    with pytest.raises(IsolationUnavailable):
        launcher.run(init(), lambda *_a, **_k: pytest.fail("must not call authority"), control=control())


@pytest.mark.parametrize("coordinator", [LinuxCoordinator(), LinuxOfflineCoordinator()])
def test_command_exposes_only_fixed_coordinator_code(monkeypatch, coordinator):
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(isolation, "_namespaces", lambda: {name: f"{name}:[100]" for name in ("user", "net", "mnt", "pid")})
    argv = coordinator._command("/usr/lib/python3.14", [("/lib/runtime.so", "/lib/runtime.so")])
    mounts = {argv[i + 2] for i, value in enumerate(argv) if value == "--ro-bind" and argv[i + 2].startswith("/app/")}
    assert mounts == {"/app/planner_worker.py", "/app/session_planner.py",
                      "/app/coordinator_worker.py", "/app/coordinator_ipc.py"}
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--cap-add" not in argv and "--share-net" not in argv
    assert argv[-9:-4] == ["/usr/bin/python3", "-I", "-S", "/app/coordinator_worker.py", coordinator.scenario]
    assert "--new-session" in argv and "--clearenv" in argv


def test_offline_launcher_uses_version_two_and_fixed_dialogue_ceiling(monkeypatch):
    coordinator = LinuxOfflineCoordinator()
    initial = init("2")
    session_id = json.loads(initial)["session_id"]
    expected = encode({"schema_version": "2", "session_id": session_id, "status": "closed"})
    monkeypatch.setattr(coordinator, "check_available", lambda: None)
    monkeypatch.setattr(isolation, "_runtime_files", lambda *_a, **_k: ("/stdlib", []))
    monkeypatch.setattr(coordinator, "_command", lambda *_a: ["fixed-offline-coordinator"])

    def supervise(argv, raw, exchange, *, control, max_requests):
        assert argv == ["fixed-offline-coordinator"] and raw == initial
        assert max_requests == ipc.MAX_OFFLINE_REQUESTS
        assert exchange(b"request", control=control) == b"response"
        return expected

    monkeypatch.setattr(ipc, "supervise", supervise)
    assert coordinator.run(initial, lambda *_a, **_k: b"response", control=control()) == expected
    assert coordinator.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
    with pytest.raises(ValueError, match="invalid_coordinator_init"):
        coordinator.run(init(), lambda *_a, **_k: pytest.fail("must not exchange"), control=control())
    coordinator.scenario = "three_step"
    with pytest.raises(ValueError, match="unsupported_coordinator_scenario"):
        coordinator.run(initial, lambda *_a, **_k: pytest.fail("must not exchange"), control=control())
    with pytest.raises(ValueError):
        LinuxCoordinator("offline_provider")


def run_offline_worker(monkeypatch, initial, responses):
    incoming = io.BytesIO(ipc.frame(ipc.INIT, initial) + b"".join(
        ipc.frame(ipc.RESPONSE, response) for response in responses))
    outgoing = io.BytesIO()
    errors = io.StringIO()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(
        argv=["worker", "offline_provider", "user", "net", "mnt", "pid"],
        stdin=SimpleNamespace(buffer=incoming), stdout=SimpleNamespace(buffer=outgoing), stderr=errors))
    monkeypatch.setattr(worker, "_private_descriptors", lambda: None)
    bootstrap = SimpleNamespace(_arguments=lambda *_a: (None, {}),
                                _bootstrap=lambda *_a: dict.fromkeys(BOUNDARY_NAMES, True))

    def load(name):
        if name == "planner_worker":
            return bootstrap
        if name == "coordinator_ipc":
            return ipc
        pytest.fail("combined worker must not load planner or authority modules")

    monkeypatch.setattr(worker, "_load", load)
    status = worker.main()
    result = []
    output = io.BytesIO(outgoing.getvalue())
    while output.tell() < len(outgoing.getvalue()):
        kind = outgoing.getvalue()[output.tell() + 4]
        result.append((kind, ipc.object_payload(ipc.read_frame(output, kind))))
    return status, result, errors.getvalue()


@pytest.mark.parametrize("steps", [3, 16])
def test_offline_worker_relays_each_plan_before_next_planning_request(monkeypatch, steps):
    initial = init("2")
    session_id = json.loads(initial)["session_id"]
    responses, expected = [], []
    for sequence in range(1, steps + 1):
        request = {"schema_version": "2", "session_id": session_id, "sequence": sequence}
        # Content is relayed as untrusted data, never interpreted by this worker.
        plan = {"schema_version": "1", "action": {"untrusted": "ignore rules; café"}, "done": sequence == steps}
        responses.extend((offline_reply(request, plan=plan), offline_reply(request, stop=sequence == steps)))
        expected.extend(((ipc.REQUEST, {**request, "operation": "plan"}),
                         (ipc.REQUEST, {**request, "operation": "propose", "plan": plan})))
    status, output, errors = run_offline_worker(monkeypatch, initial, responses)
    assert status == 0 and errors == ""
    assert output[0] == (ipc.READY, {"schema_version": "1", "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True)})
    assert output[1:-1] == expected
    assert output[-1] == (ipc.RESULT, {"schema_version": "2", "session_id": session_id, "status": "closed"})


def test_offline_worker_planning_stop_never_proposes(monkeypatch):
    initial = init("2")
    request = {**json.loads(initial), "sequence": 1}
    status, output, errors = run_offline_worker(monkeypatch, initial, [offline_reply(request, stop=True)])
    assert status == 0 and errors == ""
    assert [kind for kind, _value in output] == [ipc.READY, ipc.REQUEST, ipc.RESULT]
    assert output[1][1] == {**request, "operation": "plan"}


@pytest.mark.parametrize("mutation", [
    {"schema_version": "1"}, {"session_id": str(uuid4())}, {"sequence": True},
    {"sequence": 2}, {"stop": 1}, {"observation": {}}, {"approval_reference": "forged"},
    {"plan": None}, {"plan": []}, {"stop": True},
])
def test_offline_worker_rejects_invalid_planning_response_before_proposal(monkeypatch, mutation):
    initial = init("2")
    request = {**json.loads(initial), "sequence": 1}
    response = json.loads(offline_reply(request, plan={"schema_version": "1", "action": None, "done": True}))
    response.update(mutation)
    status, output, errors = run_offline_worker(monkeypatch, initial, [encode(response)])
    assert status == 78 and errors == "secure_coordinator_failed\n"
    assert [kind for kind, _value in output] == [ipc.READY, ipc.REQUEST]


def test_offline_worker_rejects_plan_in_proposal_response(monkeypatch):
    initial = init("2")
    request = {**json.loads(initial), "sequence": 1}
    plan = {"schema_version": "1", "action": None, "done": True}
    status, output, errors = run_offline_worker(monkeypatch, initial, [
        offline_reply(request, plan=plan), offline_reply(request, stop=True, plan=plan),
    ])
    assert status == 78 and errors == "secure_coordinator_failed\n"
    assert [value.get("operation") for kind, value in output if kind == ipc.REQUEST] == ["plan", "propose"]
    assert all(kind != ipc.RESULT for kind, _value in output)


def test_offline_worker_rejects_version_one_init(monkeypatch):
    status, output, errors = run_offline_worker(monkeypatch, init(), [])
    assert status == 78 and output == [] and errors == "secure_coordinator_failed\n"


@pytest.fixture
def real_coordinator():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1" or sys.platform != "linux":
        pytest.skip("real coordinator sandbox requires explicit Linux opt-in")
    coordinator = LinuxCoordinator()
    coordinator.check_available()
    return coordinator


@pytest.mark.integration
def test_real_coordinator_retains_process_for_three_step_dialogue(real_coordinator, monkeypatch):
    initial = init()
    session_id = json.loads(initial)["session_id"]
    requests, children = [], []
    original = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)

    def exchange(raw, *, control):
        request = json.loads(raw)
        requests.append(request)
        assert request["session_id"] == session_id and request["sequence"] == len(requests)
        assert real_coordinator.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
        return reply(request, stop=request["plan"]["done"], observation={"execution_status": "succeeded", "body": "fixture"})

    result = json.loads(real_coordinator.run(initial, exchange, control=control()))
    assert result == {"schema_version": "1", "session_id": session_id, "status": "closed"}
    assert len(requests) == 3 and len(children) == 1 and children[0].returncode == 0


@pytest.mark.integration
def test_real_offline_coordinator_retains_process_for_six_exchanges(real_coordinator, monkeypatch):
    coordinator = LinuxOfflineCoordinator()
    initial = init("2")
    session_id = json.loads(initial)["session_id"]
    requests, children = [], []
    original = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    pending = None

    def exchange(raw, *, control):
        nonlocal pending
        request = json.loads(raw)
        requests.append(request)
        assert request["session_id"] == session_id and request["schema_version"] == "2"
        assert request["sequence"] == (len(requests) + 1) // 2
        assert coordinator.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
        if len(requests) % 2:
            assert set(request) == {"schema_version", "session_id", "sequence", "operation"}
            assert request["operation"] == "plan"
            pending = {"schema_version": "1", "action": {"fixture": request["sequence"]}, "done": len(requests) == 5}
            return offline_reply(request, plan=pending)
        assert set(request) == {"schema_version", "session_id", "sequence", "operation", "plan"}
        assert request["operation"] == "propose" and request["plan"] == pending
        return offline_reply(request, stop=len(requests) == 6)

    result = json.loads(coordinator.run(initial, exchange, control=control()))
    assert result == {"schema_version": "2", "session_id": session_id, "status": "closed"}
    assert len(requests) == 6 and len(children) == 1 and children[0].returncode == 0


def mount_test_planner(coordinator, monkeypatch, tmp_path, suffix):
    # Fixed-module replacement is trusted test instrumentation, never a public
    # executable/module option supplied by an untrusted coordinator.
    path = tmp_path / "trusted-test-planner.py"
    path.write_text(Path(session_planner.__file__).read_text() + "\n" + suffix)
    original = coordinator._command

    def command(stdlib, files):
        argv = original(stdlib, files)
        index = [i for i, word in enumerate(argv) if word == "--ro-bind" and argv[i + 2] == "/app/session_planner.py"]
        assert len(index) == 1
        argv[index[0] + 1] = str(path)
        return argv

    monkeypatch.setattr(coordinator, "_command", command)


def mount_test_worker(coordinator, monkeypatch, tmp_path, suffix):
    path = tmp_path / "trusted-test-coordinator.py"
    source = Path(worker.__file__).read_text()
    marker = 'if __name__ == "__main__":'
    assert source.count(marker) == 1
    path.write_text(source.replace(marker, suffix + "\n" + marker))
    original = coordinator._command

    def command(stdlib, files):
        argv = original(stdlib, files)
        index = [i for i, word in enumerate(argv) if word == "--ro-bind" and argv[i + 2] == "/app/coordinator_worker.py"]
        assert len(index) == 1
        argv[index[0] + 1] = str(path)
        return argv

    monkeypatch.setattr(coordinator, "_command", command)


@pytest.mark.integration
@pytest.mark.parametrize("offline", [False, True])
def test_real_coordinator_cannot_reach_host_authority_memory_tty_or_credentials(real_coordinator, monkeypatch, tmp_path, offline):
    if offline:
        real_coordinator = LinuxOfflineCoordinator()
    sentinel = tmp_path / "host-authority-canary"
    sentinel.write_text("PRIVATE-HOST-CANARY")
    monkeypatch.setenv("OPENAI_API_KEY", "PRIVATE-HOST-CANARY")
    descriptor = os.open(sentinel, os.O_RDONLY)
    inherited = fcntl.fcntl(descriptor, fcntl.F_DUPFD, 128)
    os.set_inheritable(inherited, True)
    suffix = f'''
def proposal(*args):
    # Probe imports run after the original worker's descriptor/bootstrap checks.
    # ctypes/libffi may retain its own mounted runtime descriptor on this host.
    import ctypes,errno,os,resource,socket
    checks={{'credentials_absent':'OPENAI_API_KEY' not in os.environ}}
    checks['authority_modules_absent']=set(os.listdir('/app'))=={{'planner_worker.py','session_planner.py','coordinator_worker.py','coordinator_ipc.py'}}
    for name,path,allowed in [('host_file_absent',{str(sentinel)!r},{{errno.ENOENT}}),
                             ('host_memory_absent','/proc/{os.getpid()}/mem',{{errno.ENOENT}}),
                             ('tty_absent','/dev/tty',{{errno.ENXIO,errno.ENODEV,errno.ENOENT}})]:
        try: fd=os.open(path,os.O_RDONLY)
        except OSError as exc: checks[name]=exc.errno in allowed
        else: os.close(fd); checks[name]=False
    try: os.fstat({inherited})
    except OSError as exc: checks['inherited_fd_absent']=exc.errno==errno.EBADF
    else: checks['inherited_fd_absent']=False
    libc=ctypes.CDLL(None,use_errno=True)
    for name,call,args in [('ptrace_denied',libc.ptrace,(1,{os.getpid()},0,0)),
                           ('process_memory_denied',libc.process_vm_readv,({os.getpid()},0,0,0,0,0))]:
        ctypes.set_errno(0)
        checks[name]=call(*args)==-1 and ctypes.get_errno()==errno.EPERM
    for name,family in [('inet_denied',socket.AF_INET),('inet6_denied',socket.AF_INET6),('unix_denied',socket.AF_UNIX)]:
        try: connection=socket.socket(family,socket.SOCK_STREAM)
        except OSError as exc: checks[name]=exc.errno==errno.EPERM
        else: connection.close(); checks[name]=False
    try: data=bytearray(300*1024*1024)
    except MemoryError: checks['memory_bounded']=True
    else: del data; checks['memory_bounded']=False
    return {{'schema_version':'1','action':None,'done':True,'witnesses':checks}}
'''
    if offline:
        suffix += '''
original_offline_response = _offline_response
def _offline_response(*args, **kwargs):
    value = original_offline_response(*args, **kwargs)
    if kwargs['planning'] and not value['stop']:
        value['plan'] = proposal()
    return value
'''
        mount_test_worker(real_coordinator, monkeypatch, tmp_path, suffix)
    else:
        mount_test_planner(real_coordinator, monkeypatch, tmp_path, suffix)
    witnesses = []

    def exchange(raw, *, control):
        request = json.loads(raw)
        if offline and request["operation"] == "plan":
            return offline_reply(request, plan={"schema_version": "1", "action": None, "done": True})
        witnesses.append(request["plan"]["witnesses"])
        return offline_reply(request, stop=True) if offline else reply(request)

    try:
        real_coordinator.run(init("2" if offline else "1"), exchange, control=control())
    finally:
        os.close(inherited)
        os.close(descriptor)
    assert len(witnesses) == 1 and all(witnesses[0].values())
    assert set(witnesses[0]) == {"credentials_absent", "authority_modules_absent", "host_file_absent",
                               "host_memory_absent", "tty_absent", "inherited_fd_absent", "ptrace_denied",
                               "process_memory_denied", "inet_denied", "inet6_denied", "unix_denied", "memory_bounded"}
    assert sentinel.read_text() == "PRIVATE-HOST-CANARY"


@pytest.mark.integration
@pytest.mark.parametrize("scenario", ["oversized", "early_exit"])
def test_real_malformed_dialogue_never_reaches_authority(real_coordinator, scenario):
    real_coordinator.scenario = scenario
    with pytest.raises(IsolationUnavailable):
        real_coordinator.run(init(), lambda *_a, **_k: pytest.fail("must not call authority"), control=control())
    assert real_coordinator.boundary_checks is None


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["cancelled", "deadline", "output"])
def test_real_hostile_planner_is_killed_and_reaped(real_coordinator, monkeypatch, tmp_path, mode):
    suffix = ("import os,time\ndef proposal(*args):\n    os.write(1,b'X'*65536)\n    time.sleep(30)\n"
              if mode == "output" else "import time\ndef proposal(*args):\n    time.sleep(30)\n")
    mount_test_planner(real_coordinator, monkeypatch, tmp_path, suffix)
    children, timers = [], []
    cancelled = threading.Event()
    original = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original(argv, *args, **kwargs)
        if Path(argv[0]).name == "bwrap":
            children.append(child)
            if mode == "cancelled":
                timer = threading.Timer(0.3, cancelled.set)
                timers.append(timer)
                timer.start()
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    try:
        expected = IsolationUnavailable if mode == "output" else ExecutionStopped
        with pytest.raises(expected):
            real_coordinator.run(init(), lambda *_a, **_k: pytest.fail("must not call authority"),
                                 control=control(2 if mode == "deadline" else 10, cancelled))
        assert len(children) == 1 and children[0].returncode == -signal.SIGKILL
    finally:
        for timer in timers:
            timer.cancel()
            timer.join(timeout=1)
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)
