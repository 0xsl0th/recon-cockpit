"""Portable boundary checks for the unregistered ffuf feasibility instrument."""

import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
from types import SimpleNamespace
import time

import pytest

from recon_cockpit.secure_agent import web_hierarchy_diagnostic_runtime as runtime
from recon_cockpit.secure_agent import web_hierarchy_diagnostic_worker as worker
from recon_cockpit.secure_agent import web_tools_runtime as accepted
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.web_hierarchy_spec import PATHS, WORDLIST


def manifest():
    return {"version": "1", "profile": worker.PROFILE, "executable": "/tool/ffuf",
        "interpreter": "/lib64/ld-linux-x86-64.so.2", "files": [
            {"source": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
             "destination": "/lib64/ld-linux-x86-64.so.2", "size": 10, "sha256": "a" * 64},
            {"source": worker.COMPILED_SOURCE, "destination": worker.COMPILED_DESTINATION,
             "size": len(WORDLIST), "sha256": hashlib.sha256(WORDLIST).hexdigest()},
            {"source": "/usr/bin/ffuf", "destination": "/tool/ffuf", "size": 10, "sha256": "b" * 64}]}


def request():
    return {"deadline": 20, "manifest": manifest(),
        "host_namespaces": {name: name + ":[1]" for name in ("user", "net", "mnt", "pid")},
        "lab_namespaces": {name: name + ":[2]" for name in ("user", "net", "mnt", "pid")}}


def validate(value):
    raw = worker.encode(value)
    return worker.validate_request(raw, hashlib.sha256(raw).hexdigest(), now=10)


def test_manifest_and_compiled_corpus_are_distinct_from_the_accepted_profile():
    assert worker.validate_manifest(manifest()) == manifest()
    assert len(PATHS) == 12 and len(set(PATHS)) == 12
    assert len(WORDLIST.splitlines()) == 12
    assert worker.PROFILE != accepted.PROFILE
    old_args = accepted.FIXED_ARGV[accepted.FFUF]
    expected = tuple(worker.COMPILED_DESTINATION if part == "/tool/data/paths.txt" else part for part in old_args)
    assert worker.FIXED_ARGV == expected
    assert dict(worker.ENVIRONMENT) == accepted.execution_environment(accepted.FFUF)
    assert worker.FIXED_ARGV.count("-t") == 1
    assert worker.FIXED_ARGV[worker.FIXED_ARGV.index("-t") + 1] == "1"
    assert not {"-ac", "-recursion", "-r", "-request", "-config", "-replay-proxy", "-x"} & set(worker.FIXED_ARGV)
    with pytest.raises(TypeError):
        worker.ENVIRONMENT["HTTP_PROXY"] = "http://127.0.0.2:8080"


@pytest.mark.parametrize("field", ["target", "port", "case", "paths", "wordlist", "argv", "environment",
    "request", "timeout", "credentials", "policy", "approval", "audit"])
def test_recommitting_extra_request_fields_cannot_expand_the_diagnostic(field):
    value = request()
    value[field] = "injected"
    with pytest.raises(ValueError, match="invalid_web_hierarchy_request"):
        validate(value)


@pytest.mark.parametrize("deadline", [10, 20.01, float("inf"), float("nan"), True, -1, "20", None])
def test_deadline_is_finite_positive_and_at_most_ten_seconds(deadline):
    value = request()
    value["deadline"] = deadline
    with pytest.raises(ValueError):
        validate(value)


def test_commitment_duplicate_fields_and_private_namespaces_are_required():
    value = request()
    assert validate(value) == value
    raw = worker.encode(value)
    with pytest.raises(ValueError, match="commitment"):
        worker.validate_request(raw, "0" * 64, now=10)
    raw = b'{"deadline":20,' + raw[1:]
    with pytest.raises(ValueError, match="duplicate"):
        worker.validate_request(raw, hashlib.sha256(raw).hexdigest(), now=10)
    for field in value["host_namespaces"]:
        changed = deepcopy(value)
        changed["lab_namespaces"][field] = changed["host_namespaces"][field]
        with pytest.raises(ValueError, match="not_private"):
            validate(changed)


@pytest.mark.parametrize("fault", ["bad_wordlist", "host_wordlist", "additional_file", "untrusted_binary",
    "duplicate", "traversal", "large_file", "bool_size", "wrong_profile", "untrusted_loader", "missing_loader",
    "unknown_field", "unknown_entry_field", "bad_digest", "unsorted", "nul_path"])
def test_manifest_rejects_runtime_or_data_expansion(fault):
    value = manifest()
    compiled = value["files"][1]
    if fault == "bad_wordlist": compiled["sha256"] = "c" * 64
    elif fault == "host_wordlist": compiled["source"] = "/tmp/paths.txt"
    elif fault == "additional_file":
        value["files"].append({"source": "/etc/ffuf/ffufrc", "destination": "/etc/ffuf/ffufrc",
                               "sha256": "d" * 64, "size": 10})
    elif fault == "untrusted_binary": value["files"][2]["source"] = "/tmp/ffuf"
    elif fault == "duplicate": value["files"].append(deepcopy(compiled))
    elif fault == "traversal": value["files"][0]["source"] = "/usr/lib/../secret.so"
    elif fault == "large_file": value["files"][0]["size"] = worker.MAX_FILE_BYTES + 1
    elif fault == "bool_size": value["files"][0]["size"] = True
    elif fault == "wrong_profile": value["profile"] = accepted.PROFILE
    elif fault == "untrusted_loader": value["interpreter"] = "/usr/bin/python3"
    elif fault == "missing_loader": value["interpreter"] = "/lib64/ld-linux-missing.so.2"
    elif fault == "unknown_field": value["args"] = []
    elif fault == "unknown_entry_field": compiled["content"] = "hello"
    elif fault == "bad_digest": compiled["sha256"] = "a" * 63
    elif fault == "unsorted": value["files"].reverse()
    else: value["files"][0]["destination"] += "\0"
    with pytest.raises(ValueError):
        worker.validate_manifest(value)


def test_request_size_bound_is_enforced_before_json_parsing():
    raw = b" " * (worker.MAX_REQUEST_BYTES + 1)
    with pytest.raises(ValueError, match="commitment"):
        worker.validate_request(raw, hashlib.sha256(raw).hexdigest(), now=10)


def test_inspection_reuses_accepted_elf_bytes_without_mutating_accepted_manifest(monkeypatch):
    new = manifest()
    source, destination, raw = accepted._compiled(accepted.FFUF)
    original = {"version": "1", "profile": accepted.PROFILE, "tool_id": accepted.FFUF,
        "executable": "/tool/ffuf", "interpreter": new["interpreter"],
        "files": [dict(new["files"][0]), {"source": source, "destination": destination,
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, dict(new["files"][2])]}
    before = deepcopy(original)
    selected = []
    monkeypatch.setattr(accepted, "inspect_tool_runtime", lambda tool, control: selected.append(tool) or original)
    assert runtime.inspect_runtime(object()) == new
    assert original == before and selected == [accepted.FFUF]


def test_limits_keep_accepted_go_ceiling_and_never_raise_inherited_caps(monkeypatch):
    values = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda key, value: values.update({key: value}))
    worker.limits()
    assert values == {resource.RLIMIT_AS: (2048 * 1024 * 1024,) * 2, resource.RLIMIT_CPU: (5, 5),
        resource.RLIMIT_NOFILE: (64, 64), resource.RLIMIT_NPROC: (16, 16),
        resource.RLIMIT_CORE: (0, 0), resource.RLIMIT_FSIZE: (0, 0)}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (2, 2))
    worker.limits()
    assert set(values.values()) == {(0, 0), (2, 2)}


def test_client_mounts_only_compiled_corpus_and_no_owner_or_host_configuration(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    lab = SimpleNamespace(_bootstrap=("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"),
        ("/usr/sbin/nft", "/usr/sbin/nft")]), _namespace_fds=(10, 11))
    argv = runtime.client_command(lab, manifest(), [20, 21, 22], "a" * 64)
    assert argv.count("--ro-bind-data") == 3 and "--unshare-net" not in argv
    assert "CAP_NET_ADMIN" not in argv and "--net=/proc/self/fd/11" in argv
    assert "/usr/sbin/nft" not in argv and "20,21,22" in argv
    assert "--clearenv" in argv and worker.SCRAPER_DIRECTORY in argv
    assert not any("fixture" in arg or "owner" in arg or "diagnostic.py" in arg for arg in argv)
    permissions = worker.permissions(manifest())
    assert permissions[worker.COMPILED_DESTINATION] == 4
    assert permissions[worker.SCRAPER_DIRECTORY] == 8
    assert "/usr/bin/python3" not in permissions
    assert not any(path.startswith(("/home", "/etc", "/root")) for path in permissions)


def _fake_capture_setup(monkeypatch):
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    lab = SimpleNamespace(_check=lambda _: None, _verify_pins=lambda: None,
        _lab_namespaces=request()["lab_namespaces"], _namespace_fds=(500, 501))
    fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    monkeypatch.setattr(runtime, "inspect_runtime", lambda _: manifest())
    monkeypatch.setattr(runtime, "sealed_snapshots", lambda *_: [fd])
    monkeypatch.setattr(runtime, "_namespaces", lambda: request()["host_namespaces"])
    monkeypatch.setattr(runtime, "client_command", lambda *_: ["test-never-executed"])
    return lab, ExecutionControl(time.monotonic() + 60), fd


@pytest.mark.parametrize("ready,pressure,stop", [(True, False, None), (False, False, None),
    (True, True, None), (True, False, "timeout")])
def test_capture_binds_readiness_caps_output_and_closes_sealed_descriptors(monkeypatch, ready, pressure, stop):
    lab, control, fd = _fake_capture_setup(monkeypatch)
    def capture(argv, raw, timeout, maximum, *, control, pass_fds):
        value = json.loads(raw)
        assert 0 < timeout <= 10 and value["deadline"] <= control.deadline
        assert pass_fds == (500, 501, fd)
        prefix = worker.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n"
        assert maximum == 8192 + len(prefix)
        return 0, b"x" * (8200 if pressure else 3), (prefix if ready else b"refused\n"), stop
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    result = runtime.capture_client(lab, control)
    assert set(result) == {"runtime_manifest", "runtime_sha256", "argv", "execution", "confinement"}
    assert set(result["confinement"].values()) == {ready}
    execution = result["execution"]
    assert execution["truncated"] is pressure
    assert execution["stop_reason"] == ("output_limit" if pressure else stop)
    assert len(base64.b64decode(execution["raw_stdout_base64"])) + len(base64.b64decode(execution["raw_stderr_base64"])) <= 8192
    with pytest.raises(OSError):
        os.fstat(fd)


def test_capture_propagates_cancellation_and_closes_sealed_descriptors(monkeypatch):
    lab, control, fd = _fake_capture_setup(monkeypatch)
    def stopped(*args, **kwargs):
        raise ExecutionStopped("session_cancelled")
    monkeypatch.setattr(runtime, "_capture_bounded", stopped)
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        runtime.capture_client(lab, control)
    with pytest.raises(OSError):
        os.fstat(fd)


def test_custom_clock_cannot_launch_native_diagnostic(monkeypatch):
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    with pytest.raises(IsolationUnavailable, match="fixed Linux control"):
        runtime.capture_client(None, ExecutionControl(20, clock=lambda: 10))


def _script():
    path = Path(__file__).resolve().parents[1] / "scripts" / "web_hierarchy_native.py"
    definition = importlib.util.spec_from_file_location("web_hierarchy_native_script_test", path)
    module = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(module)
    return module


@pytest.mark.parametrize("failure", [False, True])
def test_script_reserves_private_evidence_before_launch_and_sanitizes_failure(tmp_path, monkeypatch, capsys, failure):
    script = _script()
    destination = tmp_path / "new.json"
    def trial(case):
        assert case == "nested" and destination.exists()
        assert destination.stat().st_mode & 0o777 == 0o600
        if failure:
            raise ValueError("private environment text must never be emitted")
        return {"diagnostic_only": True, "execution": {"exit_code": 0, "stop_reason": None,
                "elapsed_ms": 123, "truncated": False}, "confinement": {"worker_ready": True},
                "cleanup": {"closed": True}}
    monkeypatch.setattr(script, "run_trial", trial)
    result = script.main(["--case", "nested", "--output", str(destination), "--execute-owned-diagnostic"])
    report = json.loads(destination.read_text())
    output = capsys.readouterr().out
    assert result == (2 if failure else 0)
    assert json.loads(output)["diagnostic_only"] is True
    assert "private environment" not in destination.read_text() + output
    if failure:
        assert report["failure_type"] == "ValueError"
        assert report["actual_provider_calls"] == report["actual_cost_microusd"] == 0


@pytest.mark.parametrize("symlink", [False, True])
def test_script_cannot_overwrite_existing_receipts_or_follow_symlinks(tmp_path, monkeypatch, symlink):
    script = _script()
    original = tmp_path / "original.json"
    original.write_bytes(b"existing private evidence")
    output = tmp_path / "link.json" if symlink else original
    if symlink:
        output.symlink_to(original)
    monkeypatch.setattr(script, "run_trial", lambda *_: pytest.fail("trial executed"))
    with pytest.raises(FileExistsError):
        script.main(["--case", "nested", "--output", str(output), "--execute-owned-diagnostic"])
    assert original.read_bytes() == b"existing private evidence"


def test_script_requires_explicit_diagnostic_flag_before_creating_file(tmp_path, monkeypatch):
    script = _script()
    output = tmp_path / "missing.json"
    monkeypatch.setattr(script, "run_trial", lambda *_: pytest.fail("trial executed"))
    with pytest.raises(SystemExit) as exc:
        script.main(["--case", "nested", "--output", str(output)])
    assert exc.value.code == 2 and not output.exists()
