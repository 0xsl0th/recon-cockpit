"""Portable checks for the new owner-mediated diagnostic, never acceptance."""

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import stat
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import tls_posture_diagnostic as original
from recon_cockpit.secure_agent import tls_posture_diagnostic_worker as fixed
from recon_cockpit.secure_agent import tls_posture_mediated as mediated
from recon_cockpit.secure_agent import tls_posture_mediated_worker as client


def manifest():
    return {"version": "1", "profile": fixed.PROFILE, "executable": "/tool/openssl",
        "interpreter": "/lib64/ld-linux-x86-64.so.2", "files": [
            {"source": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
             "destination": "/lib64/ld-linux-x86-64.so.2", "size": 10, "sha256": "a" * 64},
            {"source": "compiled:fixture-ca", "destination": "/tool/data/fixture-ca.pem",
             "size": fixed.CA_SIZE, "sha256": fixed.CA_SHA256},
            {"source": "/usr/bin/openssl", "destination": "/tool/openssl", "size": 10, "sha256": "b" * 64}]}


def namespaces(number):
    return {name: name + f":[{number}]" for name in ("user", "net", "mnt", "pid")}


def receipt():
    return {"sequence": 1, "connection_count": 1, "request_count": 1,
            "diagnostic": {}, "mediation": {}}


def test_owned_mediation_mounts_are_additional_owner_only_modules(monkeypatch):
    monkeypatch.setattr(original.DiagnosticLab, "_owner_command", lambda *args:
        ["bwrap", "--remount-ro", "/", "/app/tls_posture_diagnostic_fixture.py"])
    lab = mediated.MediatedLab("modern", "tls1_3")
    argv = lab._owner_command("unused", [], 11)
    assert argv[-1] == "/app/tls_posture_mediated_owner.py"
    assert argv.count("--ro-bind") == 2
    assert "/app/tls_posture_mediator.py" in argv
    assert lab.identity["diagnostic_only"] is True and lab.identity["mediated"] is True
    assert lab.limits.max_runtime_seconds == original.SESSION_SECONDS


def test_client_has_no_owner_modules_or_peer_descriptors(monkeypatch):
    monkeypatch.setattr(original, "_trusted_program", lambda name: "/usr/bin/" + name)
    lab = SimpleNamespace(_bootstrap=("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"),
        ("/usr/sbin/nft", "/usr/sbin/nft")]), _namespace_fds=(10, 11), _private_peer_fd=999)
    argv = mediated.client_command(lab, manifest(), [20, 21, 22], "a" * 64)
    assert argv[-2] == "/app/recon_cockpit/secure_agent/tls_posture_mediated_worker.py"
    assert argv[-1] == "a" * 64
    assert "/app/recon_cockpit/secure_agent/tls_posture_diagnostic_worker.py" in argv
    assert "20,21,22" in argv and "999" not in argv
    assert argv.count("--ro-bind-data") == 3
    assert "--net=/proc/self/fd/11" in argv and "--unshare-net" not in argv
    assert not any(word in arg for arg in argv for word in
        ("mediated_owner", "tls_posture_mediator.py", "material", "fixture.py", "owned_lab_worker"))
    assert "/usr/sbin/nft" not in argv and "CAP_NET_ADMIN" not in argv
    permissions = fixed.permissions(manifest())
    assert not any("/app" in path or "python" in path for path in permissions)


def mock_snapshot(monkeypatch, value):
    lab = mediated.MediatedLab("modern", "tls1_3")
    pipe = io.BytesIO()
    lab._supervisor = SimpleNamespace(processes={"lab": SimpleNamespace(stdin=pipe)})
    monkeypatch.setattr(lab, "_check", lambda _: None)
    monkeypatch.setattr(lab, "_verify_pins", lambda: None)
    monkeypatch.setattr(lab, "_read_message", lambda: value)
    return lab, pipe


def test_snapshot_is_single_use_and_does_not_add_authority(monkeypatch):
    lab, pipe = mock_snapshot(monkeypatch, receipt())
    value = lab.snapshot(None)
    assert set(value) == {"connection_count", "request_count", "diagnostic", "mediation"}
    assert lab._counts == {"connection_count": 1, "request_count": 1}
    assert json.loads(pipe.getvalue()) == {"sequence": 1, "minimum_connections": 0, "minimum_requests": 0}
    with pytest.raises(mediated.IsolationUnavailable, match="single-use"):
        lab.snapshot(None)


@pytest.mark.parametrize("key,replacement", [
    ("sequence", True), ("sequence", 2), ("connection_count", True), ("connection_count", 3),
    ("request_count", -1), ("request_count", 3), ("diagnostic", []), ("mediation", None),
])
def test_snapshot_rejects_malformed_envelope_before_reporting_counts(monkeypatch, key, replacement):
    value = receipt()
    value[key] = replacement
    lab, _ = mock_snapshot(monkeypatch, value)
    with pytest.raises(mediated.IsolationUnavailable, match="receipt invalid"):
        lab.snapshot(None)
    assert lab._counts == {"connection_count": 0, "request_count": 0}


@pytest.mark.parametrize("mutation", ["extra", "missing", "not_dict"])
def test_snapshot_requires_exact_envelope(monkeypatch, mutation):
    value = receipt()
    if mutation == "extra": value["approved"] = True
    elif mutation == "missing": del value["mediation"]
    else: value = []
    lab, _ = mock_snapshot(monkeypatch, value)
    with pytest.raises(mediated.IsolationUnavailable):
        lab.snapshot(None)


def fake_trial_runtime(monkeypatch, capture, *, failure_at=None):
    events, value = [], manifest()
    class Lab:
        _namespace_fds = (10, 11)
        _private_peer_fd = 999
        _lab_namespaces = namespaces(2)
        def __init__(self, *_): pass
        def start(self, *_):
            events.append("start")
            if failure_at == "start": raise RuntimeError("start failure")
        def snapshot(self, *_):
            if failure_at == "snapshot": raise RuntimeError("snapshot failure")
            return {key: item for key, item in receipt().items() if key != "sequence"}
        def close(self): events.append("close"); return {"status": "closed"}
    monkeypatch.setattr(mediated, "MediatedLab", Lab)
    monkeypatch.setattr(mediated, "inspect_runtime", lambda _: value)
    monkeypatch.setattr(mediated, "sealed_snapshots", lambda *args: [20, 21, 22])
    monkeypatch.setattr(mediated, "_namespaces", lambda: namespaces(1))
    monkeypatch.setattr(mediated, "client_command", lambda *args: ["unexecuted"])
    monkeypatch.setattr(mediated, "_capture_bounded", capture)
    monkeypatch.setattr(mediated, "os", SimpleNamespace(close=lambda fd: events.append(fd)))
    return events


@pytest.mark.parametrize("code,reason,ready", [(0, None, True), (1, None, True), (-9, "timeout", True),
    (-9, "output_limit", True), (78, None, False)])
def test_trial_preserves_raw_execution_and_only_passes_namespace_and_runtime_fds(monkeypatch, code, reason, ready):
    def capture(argv, raw, timeout, limit, *, control, pass_fds):
        assert pass_fds == (10, 11, 20, 21, 22) and 999 not in pass_fds
        assert 0 < timeout <= 5
        prefix = client.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b"\n"
        assert limit == 8192 + len(prefix)
        request = json.loads(raw)
        assert set(request) == {"version", "deadline", "host_namespaces", "lab_namespaces", "manifest"}
        return code, b"client bytes", (prefix if ready else b"") + b"client diagnostics", reason
    events = fake_trial_runtime(monkeypatch, capture)
    result = mediated.run_trial("hrr", "tls1_3")
    assert events == ["start", 20, 21, 22, "close"]
    assert result["diagnostic_only"] is True and result["mediated"] is True
    assert result["confinement"]["unix_socket_and_socketpair_denied"] is ready
    assert result["execution"]["exit_code"] == code and result["execution"]["stop_reason"] == reason
    assert result["cleanup"] == {"closed": True}
    assert result["actual_provider_calls"] == result["actual_cost_microusd"] == 0
    assert base64.b64decode(result["execution"]["raw_stderr_base64"]) == b"client diagnostics"
    assert "assessment_outcome" not in result and "authority" not in result


@pytest.mark.parametrize("point", ["start", "capture", "snapshot"])
def test_failed_trial_still_closes_runtime_descriptors_and_owner(monkeypatch, point):
    def capture(*args, **kwargs):
        if point == "capture": raise KeyboardInterrupt
        return 78, b"", b"", None
    events = fake_trial_runtime(monkeypatch, capture, failure_at=point)
    with pytest.raises(KeyboardInterrupt if point == "capture" else RuntimeError):
        mediated.run_trial("modern", "tls1_2")
    assert events == ["start", 20, 21, 22, "close"]


@pytest.mark.parametrize("case,version", [("external", "tls1_3"), ("hrr", "tls1_2"),
    ("modern", "-tls1_3 -connect outside:443")])
def test_invalid_selection_cannot_even_inspect_runtime(monkeypatch, case, version):
    monkeypatch.setattr(mediated, "inspect_runtime", lambda _: pytest.fail("unexpected inspection"))
    with pytest.raises(ValueError):
        mediated.run_trial(case, version)


def test_private_peer_witnesses_require_actual_permission_denial(monkeypatch):
    events = []
    def denied(*args): events.append(args); raise PermissionError
    monkeypatch.setattr(client.socket, "socket", denied)
    monkeypatch.setattr(client.socket, "socketpair", denied)
    client.unix_socket_witnesses()
    assert events == [(socket.AF_UNIX, socket.SOCK_STREAM), ()]


@pytest.mark.parametrize("allowed", ["socket", "socketpair"])
def test_any_successful_private_socket_witness_closes_and_refuses(monkeypatch, allowed):
    closed = []
    def denied(*args): raise PermissionError
    def descriptor(number): return SimpleNamespace(close=lambda: closed.append(number))
    monkeypatch.setattr(client.socket, "socket", lambda *args: descriptor(1) if allowed == "socket" else denied())
    monkeypatch.setattr(client.socket, "socketpair", lambda: (descriptor(2), descriptor(3)))
    with pytest.raises(ValueError, match="allowed"):
        client.unix_socket_witnesses()
    assert closed == ([1] if allowed == "socket" else [2, 3])


def test_unexpected_witness_errors_do_not_count_as_denial(monkeypatch):
    def failed(*args): raise OSError("socket subsystem unavailable")
    monkeypatch.setattr(client.socket, "socket", failed)
    with pytest.raises(OSError):
        client.unix_socket_witnesses()


@pytest.mark.parametrize("witness_denied", [True, False])
def test_worker_emits_ready_only_after_seccomp_witnesses_and_descriptor_closure(monkeypatch, witness_denied):
    from recon_cockpit.secure_agent import tool_worker_common as common, worker
    events = []
    request = {"version": "tls1_3", "deadline": 100, "manifest": manifest()}
    stdin = SimpleNamespace(buffer=io.BytesIO(b"private request"), close=lambda: events.append("stdin_close"))
    stderr = io.StringIO()
    monkeypatch.setattr(client, "sys", SimpleNamespace(argv=["worker", "a" * 64], stdin=stdin, stderr=stderr, path=[]))
    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: 1))
    monkeypatch.setattr(fixed, "validate_request", lambda *args: request)
    monkeypatch.setattr(fixed, "private_descriptors", lambda: events.append("no_inherited_fds"))
    monkeypatch.setattr(fixed, "close_private_descriptors", lambda: events.append("close_private_fds"))
    monkeypatch.setattr(fixed, "_namespaces", lambda *args: events.append("namespaces"))
    monkeypatch.setattr(fixed, "verify_files", lambda *args: events.append("runtime_pins"))
    monkeypatch.setattr(fixed, "limits", lambda: events.append("limits"))
    monkeypatch.setattr(worker, "drop_privileges", lambda: events.append("drop_privileges"))
    monkeypatch.setattr(common, "syscall_filter", lambda **kwargs: events.append("seccomp"))
    monkeypatch.setattr(common, "_witnesses", lambda: events.append("network_witnesses"))
    monkeypatch.setattr(common, "apply_landlock", lambda permissions: events.append("landlock"))

    def witness():
        events.append("unix_witnesses")
        if not witness_denied: raise ValueError("mediated_socketpair_allowed")
    def denied(*args): raise PermissionError
    class Executed(BaseException): pass
    def execute(path, argv, environment):
        assert path == "/tool/openssl" and argv == fixed.FIXED_ARGV["tls1_3"]
        assert environment == dict(fixed.ENVIRONMENT)
        events.append("exec")
        raise Executed
    def write(fd, raw):
        assert fd == 2 and raw == client.READY_PREFIX + b"a" * 64 + b"\n"
        events.append("ready")
    monkeypatch.setattr(client, "unix_socket_witnesses", witness)
    monkeypatch.setattr(client, "socket", SimpleNamespace(socket=denied,
        AF_INET=socket.AF_INET, SOCK_DGRAM=socket.SOCK_DGRAM, IPPROTO_UDP=socket.IPPROTO_UDP))
    monkeypatch.setattr(client, "os", SimpleNamespace(fstat=lambda _: SimpleNamespace(st_mode=stat.S_IFIFO),
        close=lambda fd: events.append("close_stdin"), open=lambda *args: 0,
        dup2=lambda *args, **kwargs: None, set_inheritable=lambda *args: None,
        O_RDONLY=0, O_CLOEXEC=1, write=write, execve=execute))
    if witness_denied:
        with pytest.raises(Executed): client.main()
        assert events == ["no_inherited_fds", "namespaces", "runtime_pins", "limits", "drop_privileges",
            "seccomp", "network_witnesses", "unix_witnesses", "stdin_close", "close_private_fds",
            "no_inherited_fds", "close_stdin", "landlock", "ready", "exec"]
    else:
        assert client.main() == 78
        assert "ready" not in events and "exec" not in events
        assert stderr.getvalue() == "tls_posture_mediated_worker_refused\n"


def test_new_instrument_is_not_in_accepted_catalog():
    from recon_cockpit.secure_agent import tool_adapters, network_tools_runtime
    assert not any(tool.startswith("tls_posture_") for tool in tool_adapters.ADAPTERS)
    assert not any("posture" in tool for tool in network_tools_runtime.EXECUTABLES)


def test_old_worker_ready_cannot_confirm_new_private_peer_witnesses(monkeypatch):
    def capture(argv, raw, *args, **kwargs):
        old_prefix = fixed.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b"\n"
        return 0, b"", old_prefix, None
    fake_trial_runtime(monkeypatch, capture)
    result = mediated.run_trial("modern", "tls1_3")
    assert result["confinement"]["worker_ready"] is False
    assert result["confinement"]["unix_socket_and_socketpair_denied"] is False
    assert base64.b64decode(result["execution"]["raw_stderr_base64"]).startswith(fixed.READY_PREFIX)


def cli_module():
    path = Path(__file__).resolve().parents[1] / "scripts/tls_posture_mediated.py"
    spec = importlib.util.spec_from_file_location("tls_mediated_test_script", path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def cli_args(output):
    return ["--case", "modern", "--version", "tls1_3", "--output", str(output), "--execute-owned-diagnostic"]


def test_cli_keeps_private_failure_receipt_without_exception_text(tmp_path, monkeypatch, capsys):
    module = cli_module()
    def fail(*args): raise RuntimeError("private diagnostic context")
    monkeypatch.setattr(module, "run_trial", fail)
    output = tmp_path / "failure.json"
    assert module.main(cli_args(output)) == 2
    raw = output.read_text()
    assert json.loads(raw)["failure_type"] == "RuntimeError"
    assert json.loads(raw)["mediated"] is True
    assert output.stat().st_mode & 0o777 == 0o600
    assert "private diagnostic context" not in raw + capsys.readouterr().out
    with pytest.raises(FileExistsError): module.main(cli_args(output))


def test_cli_cannot_follow_symlink_or_overwrite_a_receipt(tmp_path, monkeypatch):
    module = cli_module()
    monkeypatch.setattr(module, "run_trial", lambda *args: pytest.fail("execution before reservation"))
    target = tmp_path / "old.json"
    target.write_text("old receipt")
    link = tmp_path / "symlink.json"
    link.symlink_to(target)
    with pytest.raises(FileExistsError): module.main(cli_args(link))
    assert target.read_text() == "old receipt"


def test_cli_requires_explicit_execution_flag_before_reserving_file(tmp_path, monkeypatch):
    module = cli_module()
    monkeypatch.setattr(module, "run_trial", lambda *args: pytest.fail("unexpected execution"))
    output = tmp_path / "absent.json"
    with pytest.raises(SystemExit): module.main(cli_args(output)[:-1])
    assert not output.exists()
