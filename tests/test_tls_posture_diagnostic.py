"""Portable checks for the unregistered, owned-only TLS feasibility instrument."""

import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import tls_posture_diagnostic as diagnostic
from recon_cockpit.secure_agent import tls_posture_diagnostic_worker as worker
from recon_cockpit.secure_agent.network_tools_fixture import TLS_CERTIFICATE_CA_PEM


def manifest():
    return {"version": "1", "profile": worker.PROFILE, "executable": "/tool/openssl",
        "interpreter": "/lib64/ld-linux-x86-64.so.2", "files": [
            {"source": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
             "destination": "/lib64/ld-linux-x86-64.so.2", "size": 10, "sha256": "a" * 64},
            {"source": "compiled:fixture-ca", "destination": "/tool/data/fixture-ca.pem",
             "size": worker.CA_SIZE, "sha256": worker.CA_SHA256},
            {"source": "/usr/bin/openssl", "destination": "/tool/openssl", "size": 10, "sha256": "b" * 64}]}


def launch():
    return {"version": "tls1_3", "deadline": 15, "manifest": manifest(),
        "host_namespaces": {name: name + ":[1]" for name in ("user", "net", "mnt", "pid")},
        "lab_namespaces": {name: name + ":[2]" for name in ("user", "net", "mnt", "pid")}}


def validate(value):
    raw = worker.encode(value)
    return worker.validate_request(raw, hashlib.sha256(raw).hexdigest(), now=10)


@pytest.mark.parametrize("case,version", [(case, version) for case in ("modern", "legacy", "reject")
                                         for version in worker.VERSIONS] + [("hrr", "tls1_3")])
def test_only_finite_owned_trial_selections(case, version):
    diagnostic.validate_selection(case, version)


@pytest.mark.parametrize("case,version", [("external", "tls1_3"), ("127.0.0.1", "tls1_3"),
    ("hrr", "tls1_2"), ("modern", "TLS1.3"), ("modern", "-tls1_3 -connect evil:443"), (True, "tls1_3")])
def test_unknown_targets_modes_versions_are_rejected_before_execution(case, version):
    with pytest.raises(ValueError):
        diagnostic.validate_selection(case, version)


def test_client_ca_pin_is_public_and_matches_selected_owner_material():
    assert len(TLS_CERTIFICATE_CA_PEM) == worker.CA_SIZE
    assert hashlib.sha256(TLS_CERTIFICATE_CA_PEM).hexdigest() == worker.CA_SHA256
    assert b"PRIVATE KEY" not in TLS_CERTIFICATE_CA_PEM
    assert worker.validate_manifest(manifest()) == manifest()


def test_fixed_argv_and_environment_cannot_be_extended():
    for version, argv in worker.FIXED_ARGV.items():
        assert type(argv) is tuple
        assert argv[:2] == ("/tool/openssl", "s_client")
        assert argv[argv.index("-connect") + 1] == "127.0.0.1:8080"
        assert argv[argv.index("-auth_level") + 1] == "2"
        assert argv.count("-" + version) == 1
        assert "-verify_return_error" in argv and "-no_ign_eof" in argv and "-nocommands" in argv
        assert not {"-cert", "-key", "-keylogfile", "-reconnect", "-proxy", "-starttls", "-sess_out"} & set(argv)
    assert dict(worker.ENVIRONMENT) == {"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1"}
    with pytest.raises(TypeError):
        worker.FIXED_ARGV["tls1_3"] = ("/bin/sh",)
    with pytest.raises(TypeError):
        worker.ENVIRONMENT["SSLKEYLOGFILE"] = "/tmp/keylog"


@pytest.mark.parametrize("field", ["target", "port", "argv", "command", "environment", "ca_file", "client_key", "timeout"])
def test_even_recommitted_requests_cannot_add_options(field):
    value = launch()
    value[field] = "injected"
    with pytest.raises(ValueError, match="invalid_diagnostic_request"):
        validate(value)


@pytest.mark.parametrize("deadline", [10, 15.01, float("inf"), True, -1])
def test_client_deadline_cannot_expire_or_exceed_five_seconds(deadline):
    value = launch()
    value["deadline"] = deadline
    with pytest.raises(ValueError):
        validate(value)


def test_request_commitment_and_private_namespace_identities_are_mandatory():
    value = launch()
    assert validate(value) == value
    raw = worker.encode(value)
    with pytest.raises(ValueError, match="commitment"):
        worker.validate_request(raw, "0" * 64, now=10)
    value["lab_namespaces"]["net"] = value["host_namespaces"]["net"]
    with pytest.raises(ValueError, match="not_private"):
        validate(value)


@pytest.mark.parametrize("fault", ["wrong_ca", "host_ca", "private_key", "untrusted_binary", "duplicate",
                                    "traversal", "large_file", "bool_size", "wrong_profile", "untrusted_loader"])
def test_manifest_refuses_new_trust_inputs_and_runtime_expansion(fault):
    value = manifest()
    ca = value["files"][1]
    if fault == "wrong_ca": ca["sha256"] = "c" * 64
    elif fault == "host_ca": ca["source"] = "/etc/ssl/cert.pem"
    elif fault == "private_key": ca["destination"] = "/tool/data/client.key"
    elif fault == "untrusted_binary": value["files"][2]["source"] = "/tmp/openssl"
    elif fault == "duplicate": value["files"].append(deepcopy(ca))
    elif fault == "traversal": value["files"][0]["source"] = "/usr/lib/../secret.so"
    elif fault == "large_file": value["files"][0]["size"] = worker.MAX_FILE_BYTES + 1
    elif fault == "bool_size": value["files"][0]["size"] = True
    elif fault == "wrong_profile": value["profile"] = "network-tools-runtime-v1"
    else: value["interpreter"] = "/usr/bin/python3"
    with pytest.raises(ValueError):
        worker.validate_manifest(value)


def test_client_limits_are_ordinary_and_do_not_raise_inherited_caps(monkeypatch):
    values = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda key, value: values.update({key: value}))
    worker.limits()
    assert values == {resource.RLIMIT_AS: (256 * 1024 * 1024,) * 2,
        resource.RLIMIT_CPU: (5, 5), resource.RLIMIT_NOFILE: (64, 64),
        resource.RLIMIT_NPROC: (1, 1), resource.RLIMIT_CORE: (0, 0), resource.RLIMIT_FSIZE: (0, 0)}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (2, 2))
    worker.limits()
    assert set(values.values()) == {(0, 0), (1, 1), (2, 2)}


def test_client_mounts_never_receive_owner_material_or_management_descriptors(monkeypatch):
    monkeypatch.setattr(diagnostic, "_trusted_program", lambda name: "/usr/bin/" + name)
    lab = SimpleNamespace(_bootstrap=("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"),
        ("/usr/sbin/nft", "/usr/sbin/nft")]), _namespace_fds=(10, 11))
    argv = diagnostic.client_command(lab, manifest(), [20, 21, 22], "a" * 64)
    assert argv.count("--ro-bind-data") == 3 and "--unshare-net" not in argv
    assert "CAP_NET_ADMIN" not in argv and "--net=/proc/self/fd/11" in argv
    assert not any("material" in arg or "fixture.py" in arg or "owned_lab_worker" in arg for arg in argv)
    assert "/usr/sbin/nft" not in argv and "20,21,22" in argv
    permissions = worker.permissions(manifest())
    assert permissions["/tool/data/fixture-ca.pem"] == 4
    assert not any(path.startswith(("/home", "/etc", "/root")) for path in permissions)
    assert "/usr/bin/python3" not in permissions


@pytest.mark.parametrize("code,reason,ready", [(0, None, True), (1, None, True), (-9, "timeout", True),
    (-9, "output_limit", True), (78, None, False)])
def test_raw_failure_receipts_keep_process_status_and_always_close_lab(monkeypatch, code, reason, ready):
    value = manifest()
    seen = []

    class Lab:
        _namespace_fds = ()
        _lab_namespaces = {name: name + ":[2]" for name in ("user", "net", "mnt", "pid")}
        def __init__(self, *_): pass
        def start(self, *_): seen.append("start")
        def snapshot(self, *_): return {"connection_count": 1, "request_count": 1, "diagnostic": {}}
        def close(self): seen.append("close"); return {"status": "closed"}

    def capture(argv, raw, *args, **kwargs):
        prefix = worker.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b"\n" if ready else b""
        return code, b"raw client", prefix + b"received alert", reason

    monkeypatch.setattr(diagnostic, "DiagnosticLab", Lab)
    monkeypatch.setattr(diagnostic, "inspect_runtime", lambda control: value)
    monkeypatch.setattr(diagnostic, "sealed_snapshots", lambda *args: [])
    monkeypatch.setattr(diagnostic, "_namespaces", lambda: launch()["host_namespaces"])
    monkeypatch.setattr(diagnostic, "client_command", lambda *args: ["unexecuted"])
    monkeypatch.setattr(diagnostic, "_capture_bounded", capture)
    result = diagnostic.run_trial("modern", "tls1_3")
    assert seen == ["start", "close"] and result["cleanup"]["closed"] is True
    assert result["execution"]["exit_code"] == code and result["execution"]["stop_reason"] == reason
    assert result["execution"]["truncated"] is (reason == "output_limit")
    assert result["confinement"]["worker_ready"] is ready
    assert base64.b64decode(result["execution"]["raw_stderr_base64"]) == b"received alert"
    assert result["diagnostic_only"] is True and result["actual_provider_calls"] == 0
    assert "assessment_outcome" not in result and "authority" not in result


def test_instrument_is_not_registered_as_an_accepted_tool():
    from recon_cockpit.secure_agent import tool_adapters, network_tools_runtime
    assert not any(tool.startswith("tls_posture_") for tool in tool_adapters.ADAPTERS)
    assert not any("posture" in tool for tool in network_tools_runtime.EXECUTABLES)


def test_bootstrap_descriptors_are_closed_before_tool_exec(monkeypatch):
    closed = []
    monkeypatch.setattr(worker.os, "listdir", lambda path: ["0", "1", "2", "3", "4"])
    monkeypatch.setattr(worker.os, "close", closed.append)
    worker.close_private_descriptors()
    assert closed == [3, 4]


def test_script_retains_private_failure_receipt_without_exception_text(tmp_path, monkeypatch, capsys):
    filename = Path(__file__).resolve().parents[1] / "scripts/tls_posture_native.py"
    spec = importlib.util.spec_from_file_location("tls_native_test_script", filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def failed(*args):
        raise RuntimeError("private context that must not be printed")

    monkeypatch.setattr(module, "run_trial", failed)
    output = tmp_path / "failure.json"
    args = ["--case", "modern", "--version", "tls1_3", "--output", str(output), "--execute-owned-diagnostic"]
    assert module.main(args) == 2
    raw = output.read_text()
    assert json.loads(raw)["failure_type"] == "RuntimeError"
    assert output.stat().st_mode & 0o777 == 0o600
    assert "private context" not in raw + capsys.readouterr().out
    with pytest.raises(FileExistsError):
        module.main(args)
