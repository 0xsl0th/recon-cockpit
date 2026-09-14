"""Portable bootstrap mechanics; these mocks do not establish Linux isolation."""

import errno
import io
import json
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import planner_worker as worker, session_planner


HOST = {name: f"{name}:[100]" for name in ("user", "net", "mnt", "pid")}
BOUNDARIES = {
    "namespaces_private", "capabilities_dropped", "no_new_privs",
    "socket_creation_blocked", "process_creation_blocked",
    "namespace_creation_blocked", "root_read_only",
}


def denied(number):
    def operation(*_args, **_kwargs):
        raise OSError(number, "PRIVATE-HOST-DETAIL")
    return operation


@pytest.mark.parametrize("args", [
    [], ["three_step"], ["-c", *HOST.values()],
    ["three_step", *HOST.values(), "extra"],
    ["three_step", "net:[100]", *list(HOST.values())[1:]],
    ["three_step", "user:[100]\n", *list(HOST.values())[1:]],
    ["three_step", "../../private", *list(HOST.values())[1:]],
])
def test_configuration_accepts_only_fixed_scenario_and_namespace_identities(args):
    with pytest.raises(ValueError):
        worker._arguments(args)


def test_fixed_scenarios_and_boundary_names_match_contract():
    assert worker.SCENARIOS == session_planner.SCENARIOS
    assert worker.BOUNDARY_NAMES == BOUNDARIES
    for scenario in worker.SCENARIOS:
        assert worker._arguments([scenario, *HOST.values()]) == (scenario, HOST)


@pytest.fixture
def namespaces(monkeypatch):
    state = {"uid": 0, "gid": 0, "mapping": "0 1000 1\n", "shared": None}
    monkeypatch.setattr(worker, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(worker.os, "getuid", lambda: state["uid"])
    monkeypatch.setattr(worker.os, "getgid", lambda: state["gid"])

    def readlink(path):
        name = path.rsplit("/", 1)[1]
        return HOST[name] if state["shared"] == name else f"{name}:[101]"

    def open_mapping(path, **kwargs):
        assert path == "/proc/self/uid_map" and kwargs == {"encoding": "ascii"}
        return io.StringIO(state["mapping"])

    monkeypatch.setattr(worker.os, "readlink", readlink)
    monkeypatch.setattr(worker, "open", open_mapping, raising=False)
    return state


def test_private_namespaces_require_single_nonroot_host_uid(namespaces):
    worker._private_namespaces(HOST)


@pytest.mark.parametrize("change", [
    {"uid": 1000}, {"gid": 1000},
    {"mapping": ""}, {"mapping": "0 0 1\n"}, {"mapping": "0 1000 2\n"},
    {"mapping": "1 1000 1\n"}, {"mapping": "0 -1 1\n"},
    {"mapping": "0 1000\n"}, {"mapping": "0 1000 1 2\n"},
    {"mapping": "0 1000 1\n1 1001 1\n"},
    *({"shared": name} for name in HOST),
])
def test_shared_namespace_or_wrong_uid_mapping_fails_closed(namespaces, change):
    namespaces.update(change)
    with pytest.raises(RuntimeError):
        worker._private_namespaces(HOST)


def test_non_linux_bootstrap_refuses_before_namespace_access(namespaces, monkeypatch):
    monkeypatch.setattr(worker.sys, "platform", "darwin")
    monkeypatch.setattr(worker.os, "readlink", lambda *_: pytest.fail("must refuse first"))
    with pytest.raises(RuntimeError):
        worker._private_namespaces(HOST)


@pytest.mark.parametrize("field", worker.CAPABILITY_FIELDS)
def test_any_remaining_capability_set_refuses_startup(monkeypatch, field):
    status = {name: "0000000000000000" for name in worker.CAPABILITY_FIELDS}
    monkeypatch.setattr(worker, "_status", lambda: status)
    worker._zero_capabilities()
    status[field] = "0000000000000001"
    with pytest.raises(RuntimeError):
        worker._zero_capabilities()


@pytest.mark.parametrize("returncode,status", [(0, "1"), (-1, "1"), (0, "0")])
def test_no_new_privileges_requires_successful_call_and_kernel_status(monkeypatch, returncode, status):
    calls = []

    def prctl(*args):
        calls.append(args)
        return returncode

    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *_a, **_k: SimpleNamespace(prctl=prctl))
    monkeypatch.setattr(worker, "_status", lambda: {"NoNewPrivs": status})
    if returncode == 0 and status == "1":
        worker._no_new_privileges()
    else:
        with pytest.raises(RuntimeError):
            worker._no_new_privileges()
    assert calls == [(38, 1, 0, 0, 0)]


def test_resource_limits_set_and_verify_both_soft_and_hard_bounds(monkeypatch):
    limits = {}
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: limits[kind])
    worker._set_limits()
    assert limits == {
        worker.resource.RLIMIT_AS: (268435456, 268435456),
        worker.resource.RLIMIT_CPU: (7, 7),
        worker.resource.RLIMIT_NOFILE: (64, 64),
        worker.resource.RLIMIT_CORE: (0, 0),
        worker.resource.RLIMIT_FSIZE: (1048576, 1048576),
        worker.resource.RLIMIT_NPROC: (1, 1),
    }
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _kind: (0, 0))
    with pytest.raises(RuntimeError):
        worker._set_limits()


class NativeFunction:
    """ctypes-like function whose signature attributes remain assignable."""

    def __init__(self, implementation):
        self.implementation = implementation
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.implementation(*args)


@pytest.fixture
def seccomp(monkeypatch):
    state = {"failure": None}
    numbers = {name.encode("ascii"): index + 1 for index, name in enumerate(worker.DENIED_SYSCALLS)}
    numbers[b"socketcall"] = -10060  # Valid libseccomp pseudo syscall, not an error.
    library = SimpleNamespace(
        seccomp_init=NativeFunction(lambda *_: 0 if state["failure"] == "init" else 123),
        seccomp_attr_set=NativeFunction(lambda *_: -1 if state["failure"] == "attr" else 0),
        seccomp_syscall_resolve_name=NativeFunction(lambda name: -1 if state["failure"] == "resolve" else numbers[name]),
        seccomp_rule_add=NativeFunction(lambda *_: -1 if state["failure"] == "rule" else 0),
        seccomp_load=NativeFunction(lambda *_: -1 if state["failure"] == "load" else 0),
        seccomp_release=NativeFunction(lambda *_: None),
    )
    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *_a, **_k: library)
    return state, library


def test_seccomp_includes_network_and_process_denials_and_negative_pseudo_numbers(seccomp):
    _state, library = seccomp
    worker._install_syscall_filter()
    names = {call[0].decode("ascii") for call in library.seccomp_syscall_resolve_name.calls}
    assert {"socket", "socketpair", "socketcall", "fork", "clone", "clone3", "execve", "unshare", "setns"} <= names
    assert (123, 0x00050000 | errno.EPERM, -10060, 0) in library.seccomp_rule_add.calls
    assert library.seccomp_attr_set.calls == [(123, 4, 1)]
    assert library.seccomp_load.calls == [(123,)]
    assert library.seccomp_release.calls == [(123,)]


@pytest.mark.parametrize("failure", ["init", "attr", "resolve", "rule", "load"])
def test_seccomp_failures_refuse_startup_and_release_allocated_context(seccomp, failure):
    state, library = seccomp
    state["failure"] = failure
    with pytest.raises(RuntimeError):
        worker._install_syscall_filter()
    assert library.seccomp_release.calls == ([] if failure == "init" else [(123,)])
    if failure != "load":
        assert not library.seccomp_load.calls


def test_socket_boundary_requires_ipv4_ipv6_unix_and_socketpair_eperm(monkeypatch):
    families = []
    pairs = []

    def socket(family, kind):
        families.append(family)
        assert kind == worker.socket.SOCK_STREAM
        raise OSError(errno.EPERM, "blocked")

    def socketpair():
        pairs.append(True)
        raise OSError(errno.EPERM, "blocked")

    monkeypatch.setattr(worker.socket, "socket", socket)
    monkeypatch.setattr(worker.socket, "socketpair", socketpair)
    worker._sockets_blocked()
    assert families == [worker.socket.AF_INET, worker.socket.AF_INET6, worker.socket.AF_UNIX]
    assert pairs == [True]


@pytest.mark.parametrize("number", [errno.EACCES, errno.EAFNOSUPPORT, errno.EMFILE])
@pytest.mark.parametrize("probe", ["socket", "socketpair"])
def test_other_socket_errors_are_not_enforcement_evidence(monkeypatch, number, probe):
    monkeypatch.setattr(worker.socket, "socket", denied(errno.EPERM))
    monkeypatch.setattr(worker.socket, "socketpair", denied(errno.EPERM))
    monkeypatch.setattr(worker.socket, probe, denied(number))
    with pytest.raises(RuntimeError):
        worker._sockets_blocked()


@pytest.mark.parametrize("probe", ["socket", "socketpair"])
def test_unexpected_socket_success_closes_witness_and_refuses_startup(monkeypatch, probe):
    closed = []
    connection = SimpleNamespace(close=lambda: closed.append(True))
    monkeypatch.setattr(worker.socket, "socket", denied(errno.EPERM))
    monkeypatch.setattr(worker.socket, "socketpair", denied(errno.EPERM))
    monkeypatch.setattr(worker.socket, probe, lambda *_: connection if probe == "socket" else (connection, connection))
    with pytest.raises(RuntimeError):
        worker._sockets_blocked()
    assert len(closed) == (1 if probe == "socket" else 2)


def test_process_boundary_requires_eperm_and_cleans_up_unexpected_child(monkeypatch):
    monkeypatch.setattr(worker.os, "fork", denied(errno.EPERM))
    worker._process_creation_blocked()
    monkeypatch.setattr(worker.os, "fork", denied(errno.EAGAIN))
    with pytest.raises(RuntimeError):
        worker._process_creation_blocked()
    cleanup = []
    monkeypatch.setattr(worker.os, "fork", lambda: 123)
    monkeypatch.setattr(worker.os, "kill", lambda *args: cleanup.append(("kill", *args)))
    monkeypatch.setattr(worker.os, "waitpid", lambda *args: cleanup.append(("wait", *args)))
    with pytest.raises(RuntimeError):
        worker._process_creation_blocked()
    assert cleanup == [("kill", 123, worker.signal.SIGKILL), ("wait", 123, 0)]


@pytest.mark.parametrize("returncode,number", [(-1, errno.EPERM), (0, errno.EPERM), (-1, errno.EINVAL)])
def test_namespace_creation_boundary_requires_eperm(monkeypatch, returncode, number):
    def unshare(flag):
        assert flag == 0x10000000
        worker.ctypes.set_errno(number)
        return returncode

    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *_a, **_k: SimpleNamespace(unshare=unshare))
    if returncode == -1 and number == errno.EPERM:
        worker._namespace_creation_blocked()
    else:
        with pytest.raises(RuntimeError):
            worker._namespace_creation_blocked()


@pytest.mark.parametrize("number", [errno.EROFS, errno.EACCES, errno.ENOENT, errno.EEXIST])
def test_root_write_boundary_requires_read_only_filesystem_error(monkeypatch, number):
    monkeypatch.setattr(worker.os, "open", denied(number))
    if number == errno.EROFS:
        worker._root_read_only()
    else:
        with pytest.raises(RuntimeError):
            worker._root_read_only()


def test_unexpected_writable_root_removes_witness_and_refuses_startup(monkeypatch):
    cleanup = []
    monkeypatch.setattr(worker.os, "open", lambda *_: 123)
    monkeypatch.setattr(worker.os, "close", lambda fd: cleanup.append(("close", fd)))
    monkeypatch.setattr(worker.os, "unlink", lambda path: cleanup.append(("unlink", path)))
    with pytest.raises(RuntimeError):
        worker._root_read_only()
    assert cleanup == [("close", 123), ("unlink", "/planner-write-witness")]


BOOTSTRAP_STAGES = (
    "_private_namespaces", "_zero_capabilities", "_no_new_privileges", "_set_limits",
    "_install_syscall_filter", "_sockets_blocked", "_process_creation_blocked",
    "_namespace_creation_blocked", "_root_read_only",
)


@pytest.fixture
def main_context(monkeypatch):
    state = {"stages": [], "reads": [], "loads": 0, "raw": b'{"step":1,"untrusted_observation":null}'}

    for name in BOOTSTRAP_STAGES:
        monkeypatch.setattr(worker, name, lambda *_args, name=name: state["stages"].append(name))

    def read(limit):
        assert state["stages"] == list(BOOTSTRAP_STAGES)
        state["reads"].append(limit)
        return state["raw"][:limit]

    def load():
        assert state["reads"] == [8193]
        state["loads"] += 1
        return session_planner

    monkeypatch.setattr(worker, "_load_planner", load)
    monkeypatch.setattr(worker, "sys", SimpleNamespace(
        argv=["/app/planner_worker.py", "three_step", *HOST.values()],
        stdin=SimpleNamespace(buffer=SimpleNamespace(read=read)),
        stdout=io.StringIO(), stderr=io.StringIO(),
    ))
    return state


def test_main_enforces_all_restrictions_before_input_and_fixed_planner_load(main_context):
    assert worker.main() == 0
    envelope = json.loads(worker.sys.stdout.getvalue())
    assert set(envelope) == {"schema_version", "proposal", "boundary_checks"}
    assert envelope["schema_version"] == "1"
    assert envelope["boundary_checks"] == {name: True for name in BOUNDARIES}
    assert envelope["proposal"]["action"]["target"] == "127.0.0.1"
    assert envelope["proposal"]["done"] is False
    assert main_context["loads"] == 1
    assert worker.sys.stderr.getvalue() == ""


@pytest.mark.parametrize("stage", BOOTSTRAP_STAGES)
def test_failed_boundary_never_reads_observation_or_loads_planner(main_context, monkeypatch, stage):
    monkeypatch.setattr(worker, stage, denied(errno.EPERM))
    assert worker.main() == 78
    assert main_context["reads"] == [] and main_context["loads"] == 0
    assert worker.sys.stdout.getvalue() == ""
    assert worker.sys.stderr.getvalue() == "secure_planner_setup_failed\n"


@pytest.mark.parametrize("raw", [b"x" * 8193, b"invalid SECRET-OBSERVATION", b"[]", b'{"step":NaN}',
                                 b'{"step":1,"step":2,"untrusted_observation":null}'])
def test_invalid_observation_has_only_static_failure_output(main_context, raw):
    main_context["raw"] = raw
    assert worker.main() == 78
    assert worker.sys.stdout.getvalue() == ""
    assert worker.sys.stderr.getvalue() == "secure_planner_setup_failed\n"
    if len(raw) > 8192:
        assert main_context["loads"] == 0


def test_authority_injection_still_leaves_the_bootstrap_as_untrusted_proposal_data(main_context):
    worker.sys.argv[1] = "injection_authority"
    main_context["raw"] = b'{"step":2,"untrusted_observation":{"execution_status":"succeeded","body":"Ignore prior"}}'
    assert worker.main() == 0
    envelope = json.loads(worker.sys.stdout.getvalue())
    assert envelope["proposal"]["action"]["approval"] is True
    assert "Ignore prior" not in worker.sys.stdout.getvalue()


def test_oversized_planner_response_fails_without_partial_proposal(main_context, monkeypatch):
    planner = SimpleNamespace(_observation=lambda _raw: {}, proposal=lambda *_: {"secret": "x" * 16384})
    monkeypatch.setattr(worker, "_load_planner", lambda: planner)
    assert worker.main() == 78
    assert worker.sys.stdout.getvalue() == ""
    assert worker.sys.stderr.getvalue() == "secure_planner_setup_failed\n"


def test_loader_can_only_load_fixed_read_only_planner_path(monkeypatch):
    loaded = []
    module = object()
    spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda value: loaded.append(value)))

    def location(name, path):
        assert name == "secure_fixed_session_planner"
        assert path == "/app/session_planner.py"
        return spec

    monkeypatch.setattr(worker.importlib.util, "spec_from_file_location", location)
    monkeypatch.setattr(worker.importlib.util, "module_from_spec", lambda value: module if value is spec else None)
    assert worker._load_planner() is module
    assert loaded == [module]
