"""Portable checks for the networkless observation boundary, not TLS execution."""

import hashlib
import io
import json
from pathlib import Path
import stat
import threading
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent import tls_posture_observation_contract as contract
from recon_cockpit.secure_agent import tls_posture_observation_runtime as runtime
from recon_cockpit.secure_agent import tls_posture_observation_worker as worker
from recon_cockpit.secure_agent import planner_worker


RAW = b'{"deliberately":"opaque in the parent"}'


def reply(status="parsed"):
    return {"contract_version": contract.CONTRACT_VERSION,
            "boundary_checks": dict.fromkeys(runtime.BOUNDARY_NAMES, True), "status": status,
            "result": {"input_sha256": hashlib.sha256(RAW).hexdigest()} if status == "parsed" else None}


def control():
    return ExecutionControl(110, clock=lambda: 100)


@pytest.fixture
def captured(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "_command", lambda bootstrap: ["fixed-parser"])
    monkeypatch.setattr(runtime, "validate_observation", lambda value: dict(value))
    def install(value=None, *, code=0, reason=None, raw=None, stderr=b""):
        def capture(argv, data, timeout, limit, *, control):
            calls.append((argv, data, timeout, limit, control))
            return code, raw if raw is not None else json.dumps(value).encode(), stderr, reason
        monkeypatch.setattr(runtime, "_capture_bounded", capture)
    return install, calls


def test_only_witnessed_reply_committed_to_exact_input_returns_result(captured):
    install, calls = captured
    install(reply())
    assert runtime._parse_isolated(RAW, control(), None) == reply()["result"]
    assert calls[0][:4] == (["fixed-parser"], RAW, 2, 5120)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(contract_version="old"),
    lambda value: value.update(contract_version=1),
    lambda value: value.update(extra="instructions"),
    lambda value: value.pop("result"),
    lambda value: value.update(boundary_checks={}),
    lambda value: value["boundary_checks"].update(socket_creation_blocked=False),
    lambda value: value["boundary_checks"].update(socket_creation_blocked=1),
    lambda value: value["boundary_checks"].update(extra=True),
    lambda value: value.update(status="unknown"),
    lambda value: value.update(status=True),
    lambda value: value.update(status="invalid"),
    lambda value: value.update(result=None),
    lambda value: value["result"].update(input_sha256="0" * 64),
    lambda value: value["result"].pop("input_sha256"),
])
def test_unwitnessed_mismatched_or_malformed_envelope_never_releases_data(captured, mutation):
    install, _ = captured
    value = reply()
    mutation(value)
    install(value)
    with pytest.raises(IsolationUnavailable):
        runtime._parse_isolated(RAW, control(), None)


@pytest.mark.parametrize("raw", [b"not-json", b'{"status":"parsed","status":"invalid"}', b"[]",
    b"{" * 1000, b"\xff", b"{} {}", b"x" * 5121])
def test_json_response_and_transport_sizes_are_strict(captured, raw):
    install, _ = captured
    install(raw=raw)
    with pytest.raises(IsolationUnavailable):
        runtime._parse_isolated(RAW, control(), None)


@pytest.mark.parametrize("code,reason,stderr", [(78, None, b""), (True, None, b""),
    (0, "timeout", b""), (0, "output_limit", b""), (0, None, b"unexpected stderr")])
def test_failed_or_noisy_worker_never_counts_as_malformed_input(captured, code, reason, stderr):
    install, _ = captured
    install(reply(), code=code, reason=reason, stderr=stderr)
    with pytest.raises(IsolationUnavailable):
        runtime._parse_isolated(RAW, control(), None)


def test_invalid_observation_requires_successful_boundary_proof(captured):
    install, _ = captured
    install(reply("invalid"))
    with pytest.raises(ValueError, match="invalid_tls_observation_input"):
        runtime._parse_isolated(RAW, control(), None)


def test_parent_revalidates_normalized_result(captured, monkeypatch):
    install, _ = captured
    install(reply())
    def reject(value):
        raise ValueError("unsafe normalized result")
    monkeypatch.setattr(runtime, "validate_observation", reject)
    with pytest.raises(IsolationUnavailable, match="reply invalid"):
        runtime._parse_isolated(RAW, control(), None)


def test_result_cap_applies_inside_larger_transport_envelope(captured):
    install, _ = captured
    value = reply()
    value["result"]["large"] = "x" * contract.MAX_RESULT_BYTES
    install(value)
    with pytest.raises(IsolationUnavailable):
        runtime._parse_isolated(RAW, control(), None)


@pytest.fixture
def entry(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(runtime.time, "monotonic", lambda: 100)
    def discover(python, nft, *, control):
        calls.append(("discover", python, nft, control))
        return ("stdlib", "files")
    def parse(raw, control, bootstrap):
        calls.append(("parse", raw, control, bootstrap))
        return {"parsed": True}
    monkeypatch.setattr(runtime, "_runtime_files", discover)
    monkeypatch.setattr(runtime, "_parse_isolated", parse)
    return calls


def test_entry_keeps_raw_bytes_unparsed_until_worker_and_uses_fixed_discovery(entry):
    assert runtime.parse_isolated_observation(b"not even JSON") == {"parsed": True}
    assert entry[0][:3] == ("discover", "/usr/bin/python3", None)
    assert entry[1][1] == b"not even JSON"
    assert entry[0][3].deadline == entry[1][2].deadline == 110


@pytest.mark.parametrize("raw", [b"", "text", bytearray(b"x"), None, b"x" * (contract.MAX_INPUT_BYTES + 1)])
def test_invalid_input_starts_no_runtime_probe(entry, raw):
    with pytest.raises(ValueError, match="input_size"):
        runtime.parse_isolated_observation(raw)
    assert entry == []


def test_exact_input_cap_reaches_isolated_parser(entry):
    raw = b"x" * contract.MAX_INPUT_BYTES
    runtime.parse_isolated_observation(raw)
    assert entry[1][1] is raw


@pytest.mark.parametrize("platform,uid", [("darwin", 1000), ("linux", 0)])
def test_unavailable_platform_refuses_before_discovery(entry, monkeypatch, platform, uid):
    monkeypatch.setattr(runtime.sys, "platform", platform)
    monkeypatch.setattr(runtime.os, "geteuid", lambda: uid)
    with pytest.raises(IsolationUnavailable):
        runtime.parse_isolated_observation(RAW)
    assert entry == []


@pytest.mark.parametrize("deadline", [True, float("inf"), float("nan"), "deadline"])
def test_invalid_deadline_starts_no_probe(entry, deadline):
    with pytest.raises(ValueError):
        runtime.parse_isolated_observation(RAW, deadline=deadline)
    assert entry == []


def test_no_arbitrary_closure_argument_is_available(entry):
    with pytest.raises(TypeError):
        runtime.parse_isolated_observation(RAW, closure={"files": ["/tmp/executable"]})
    assert entry == []


@pytest.mark.parametrize("invalid", [True, {}, SimpleNamespace(deadline=110)])
def test_control_requires_exact_trusted_type(entry, invalid):
    with pytest.raises(ValueError, match="parser_control"):
        runtime.parse_isolated_observation(RAW, control=invalid)
    assert entry == []


@pytest.mark.parametrize("cancel", [False, True])
def test_expired_or_cancelled_parse_starts_nothing(entry, cancel):
    event = threading.Event()
    if cancel:
        event.set()
    request_control = ExecutionControl(110 if cancel else 99, event, lambda: 100)
    with pytest.raises(ExecutionStopped):
        runtime.parse_isolated_observation(RAW, control=request_control)
    assert entry == []


def test_shorter_deadline_and_cancellation_survive_composition(entry):
    event = threading.Event()
    request_control = ExecutionControl(109, event, lambda: 100)
    runtime.parse_isolated_observation(RAW, control=request_control, deadline=104)
    assert entry[1][2].deadline == 104 and entry[1][2].cancelled is event


@pytest.mark.parametrize("point", ["before", "during"])
def test_cancellation_cannot_release_a_finished_worker_reply(captured, monkeypatch, point):
    install, calls = captured
    install(reply())
    event = threading.Event()
    request_control = ExecutionControl(110, event, lambda: 100)
    if point == "before":
        event.set()
    else:
        previous = runtime._capture_bounded
        def capture(*args, **kwargs):
            value = previous(*args, **kwargs)
            event.set()
            return value
        monkeypatch.setattr(runtime, "_capture_bounded", capture)
    with pytest.raises(ExecutionStopped, match="cancelled"):
        runtime._parse_isolated(RAW, request_control, None)
    assert bool(calls) is (point == "during")


def bootstrap():
    return ("/usr/lib/python3.13", [("/usr/bin/python3.13", "/usr/bin/python3"),
        ("/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6")])


def test_mounts_are_exact_pure_package_and_distribution_runtime(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runtime, "_namespaces", lambda: dict.fromkeys(runtime.NAMESPACE_NAMES, "host"))
    argv = runtime._command(bootstrap())
    assert all(option in argv for option in ("--unshare-net", "--unshare-user", "--unshare-pid", "--clearenv", "--cap-drop"))
    mounts = [(argv[index + 1], argv[index + 2]) for index, arg in enumerate(argv) if arg == "--ro-bind"]
    app = [destination for _, destination in mounts if destination.startswith("/app/")]
    assert set(app) == {"/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py",
        *("/app/recon_cockpit/secure_agent/" + name + ".py" for name in runtime.PARSER_MODULES)}
    assert all(Path(source).name == "__init__.py" and "secure_agent" in source
               for source, destination in mounts if destination.endswith("__init__.py"))
    assert not any(word in destination for _, destination in mounts
                   for word in ("owner", "fixture", "material", "openssl", "nft", "bwrap", "nsenter", "models.py"))
    assert argv[-4:] == ["host"] * 4
    assert argv[-5] == "/app/recon_cockpit/secure_agent/tls_posture_observation_worker.py"


@pytest.mark.parametrize("row", [("/usr/bin/openssl", "/tool/openssl"), ("/tmp/fake", "/usr/bin/python3"),
    ("/home/secret", "/lib/secret.so"), ("/usr/lib/../secret.so", "/lib/secret.so"),
    ("/usr/lib/secret.so", "/lib/../secret.so"), ("/usr/lib/secret.so", "/tool/data/key.pem"),
    ("/usr/bin/python3.13", "/usr/bin/python3")])
def test_unreviewed_or_duplicate_mount_refuses(monkeypatch, row):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    stdlib, files = bootstrap()
    with pytest.raises(IsolationUnavailable):
        runtime._command((stdlib, files + [row]))


@pytest.mark.parametrize("value", [("/usr", []), ("/usr/lib/python3.13", []),
    ("/usr/lib/python3.13", [("/lib/libc.so.6", "/lib/libc.so.6")])])
def test_runtime_requires_narrow_stdlib_and_interpreter(monkeypatch, value):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    with pytest.raises(IsolationUnavailable):
        runtime._command(value)


@pytest.fixture
def worker_setup(monkeypatch):
    events, limits = [], {}
    source, output, errors = io.BytesIO(RAW), io.BytesIO(), io.StringIO()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(argv=["worker", "u", "n", "m", "p"],
        stdin=SimpleNamespace(buffer=source), stdout=SimpleNamespace(buffer=output), stderr=errors))
    monkeypatch.setattr(worker, "_private_descriptors", lambda: events.append("private_fds"))
    monkeypatch.setattr(worker, "_close_bootstrap_descriptors", lambda: events.append("close_bootstrap_fds"))
    monkeypatch.setattr(worker.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFIFO))
    monkeypatch.setattr(planner_worker, "_bootstrap", lambda host:
        events.append(("bootstrap", host)) or dict.fromkeys(runtime.BOUNDARY_NAMES, True))
    def setlimit(kind, value):
        limits[kind] = value
        events.append(("limit", kind, value))
    monkeypatch.setattr(worker.resource, "setrlimit", setlimit)
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: limits[kind])
    monkeypatch.setattr(contract, "parse_observation", lambda raw: events.append(("parse", raw)) or reply()["result"])
    monkeypatch.setattr(contract, "validate_observation", lambda value: events.append("validate") or dict(value))
    return events, source, output, errors


def test_worker_limits_and_bootstrap_precede_untrusted_parse(worker_setup):
    events, _, output, errors = worker_setup
    assert worker.main() == 0 and errors.getvalue() == ""
    assert events[0] == "private_fds"
    assert events[1] == ("bootstrap", dict(zip(runtime.NAMESPACE_NAMES, ("u", "n", "m", "p"))))
    assert [event[0] for event in events[2:4]] == ["limit", "limit"]
    assert events[4:6] == ["close_bootstrap_fds", "private_fds"]
    assert events[6][0] == "parse"
    assert events[-1] == "validate"
    assert json.loads(output.getvalue()) == reply()


def test_worker_parser_rejection_is_witnessed_invalid_result(worker_setup, monkeypatch):
    _, _, output, errors = worker_setup
    def fail(raw):
        raise ValueError("private untrusted fragment")
    monkeypatch.setattr(contract, "parse_observation", fail)
    assert worker.main() == 0 and errors.getvalue() == ""
    assert json.loads(output.getvalue()) == reply("invalid")


@pytest.mark.parametrize("raw", [b"", b"x" * (contract.MAX_INPUT_BYTES + 1)])
def test_worker_input_bound_fails_without_partial_parse(worker_setup, raw):
    events, source, output, errors = worker_setup
    source.truncate(0)
    source.write(raw)
    source.seek(0)
    assert worker.main() == 78 and output.getvalue() == b""
    assert not any(isinstance(event, tuple) and event[0] == "parse" for event in events)
    assert errors.getvalue() == "tls_posture_observation_parser_refused\n"


def test_worker_resource_failure_precedes_parse(worker_setup, monkeypatch):
    events, _, output, errors = worker_setup
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (0, 0))
    assert worker.main() == 78 and output.getvalue() == b""
    assert not any(isinstance(event, tuple) and event[0] == "parse" for event in events)
    assert errors.getvalue() == "tls_posture_observation_parser_refused\n"


def test_worker_result_pressure_is_not_cropped_or_emitted(worker_setup, monkeypatch):
    _, _, output, errors = worker_setup
    monkeypatch.setattr(contract, "parse_observation", lambda raw: {"large": "x" * contract.MAX_RESULT_BYTES})
    assert worker.main() == 78 and output.getvalue() == b""
    assert errors.getvalue() == "tls_posture_observation_parser_refused\n"


@pytest.mark.parametrize("failure", [RuntimeError("private path"), MemoryError("private bytes")])
def test_worker_unexpected_failure_releases_only_static_diagnostic(worker_setup, monkeypatch, failure):
    _, _, output, errors = worker_setup
    def fail(raw):
        raise failure
    monkeypatch.setattr(contract, "parse_observation", fail)
    assert worker.main() == 78 and output.getvalue() == b""
    assert errors.getvalue() == "tls_posture_observation_parser_refused\n"


@pytest.mark.parametrize("pipe,args", [(False, 5), (True, 4), (True, 6)])
def test_worker_requires_private_pipe_and_exact_argv(worker_setup, monkeypatch, pipe, args):
    events, _, output, _ = worker_setup
    monkeypatch.setattr(worker.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFIFO if pipe else stat.S_IFREG))
    worker.sys.argv = ["worker"] * args
    assert worker.main() == 78 and events == [] and output.getvalue() == b""


@pytest.mark.parametrize("live", [False, True])
def test_descriptor_check_refuses_inherited_fds_not_closed_listing_handle(monkeypatch, live):
    monkeypatch.setattr(worker.os, "listdir", lambda path: ["0", "1", "2", "3"])
    def inspect(fd):
        if live:
            return SimpleNamespace()
        raise OSError(9, "closed listing descriptor")
    monkeypatch.setattr(worker.os, "fstat", inspect)
    if live:
        with pytest.raises(ValueError, match="inherited_tls_observation_descriptor"):
            worker._private_descriptors()
    else:
        worker._private_descriptors()


def test_bootstrap_descriptor_cleanup_keeps_only_stdio(monkeypatch):
    closed = []
    monkeypatch.setattr(worker.os, "listdir", lambda path: ["0", "1", "2", "3", "4"])
    def close(fd):
        closed.append(fd)
        if fd == 4:
            raise OSError(9, "closed listing descriptor")
    monkeypatch.setattr(worker.os, "close", close)
    worker._close_bootstrap_descriptors()
    assert closed == [3, 4]


def test_bootstrap_descriptor_cleanup_error_cannot_reach_input(worker_setup, monkeypatch):
    events, _, output, errors = worker_setup
    def refuse():
        raise OSError(1, "private descriptor context")
    monkeypatch.setattr(worker, "_close_bootstrap_descriptors", refuse)
    assert worker.main() == 78 and output.getvalue() == b""
    assert not any(isinstance(event, tuple) and event[0] == "parse" for event in events)
    assert errors.getvalue() == "tls_posture_observation_parser_refused\n"


def test_worker_defers_ctypes_bootstrap_import_until_after_entry_descriptor_check():
    source = Path(worker.__file__).read_text()
    prefix = source[:source.index("def main():")]
    assert "from recon_cockpit.secure_agent import planner_worker" not in prefix
