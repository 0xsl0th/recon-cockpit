"""Portable negative authority, closure and thread-filter checks."""

from copy import deepcopy
import hashlib
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol
from recon_cockpit.secure_agent import web_tools_runtime as runtime
from recon_cockpit.secure_agent.executor_worker import digest, encode
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.web_tools_contract import LIMITS, action
from recon_cockpit.secure_agent.web_tools_execution import consume_launch
from recon_cockpit.secure_agent.web_tools_lab_contract import identity
from recon_cockpit.secure_agent.web_tools_worker import clone_denials
from recon_cockpit.secure_agent.web_tools_worker import _landlock_permissions


def manifest(tool_id=runtime.CURL):
    source, destination, raw = runtime._compiled(tool_id)
    entries = [(runtime.EXECUTABLES[tool_id], runtime.FIXED_ARGV[tool_id][0], b"data"),
               ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", b"data"),
               (source, destination, raw)]
    return {"version": "1", "profile": runtime.PROFILE, "tool_id": tool_id,
            "executable": runtime.FIXED_ARGV[tool_id][0], "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "files": [{"source": src, "destination": dst, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for src, dst, data in sorted(entries, key=lambda row: row[1])]}


def policy():
    return parse_policy({"schema_version": "1", "policy_version": "test-web-tool-v1",
        "allowed_targets": ["127.0.0.1"], "allowed_tools": [runtime.CURL, runtime.FFUF],
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 10,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": True, "approval_ttl_seconds": 60})


def configuration(case="curl-ok"):
    return {"version": "1", "service_id": str(uuid4()), "session_id": str(uuid4()),
        "policy": policy().to_dict(), "limits": dict(LIMITS), "execute": True,
        "profile": "owned_web_tools_lab", "case": case}


def envelope(case="curl-ok"):
    selected = parse_action(action(case))
    host = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    return {"mode": "owned_web_tools_lab", "identity": identity(case, str(uuid4())),
        "namespaces": {name: name + ":[200]" for name in host}, "runtime": manifest(selected.tool_id),
        "launch": {"schema_version": "1", "mode": "web_tools_owned", "execute": True,
            "session_id": str(uuid4()), "nonce": "a" * 64, "sequence": 1,
            "action": selected.to_dict(), "action_digest": selected.digest,
            "policy": policy().to_dict(), "policy_digest": policy().digest,
            "limits": dict(LIMITS), "limits_digest": digest(LIMITS), "deadline": 130,
            "output_reserved_before": 0, "output_reserved_after": 8192, "host_namespaces": host}}


def verify(value):
    raw = encode(value)
    return consume_launch(raw, "a" * 64, hashlib.sha256(raw).hexdigest(), now=100)


def recommit(value):
    for field in ("action", "policy", "limits"):
        value["launch"][field + "_digest"] = digest(value["launch"][field])


@pytest.mark.parametrize("case", ["curl-ok", "curl-untrusted", "ffuf-normal", "ffuf-wildcard"])
def test_independent_launch_validator_accepts_only_the_selected_fixed_tool(case):
    value = envelope(case)
    request, deadline, namespaces, runtime_digest = verify(value)
    assert request["tool_id"] == action(case)["tool_id"] and deadline == 130
    assert namespaces == value["namespaces"] and runtime_digest == runtime.manifest_digest(value["runtime"])
    assert admission.profile_allows(parse_action(action(case)), configuration(case))


@pytest.mark.parametrize("case", ["curl-ok", "ffuf-normal"])
@pytest.mark.parametrize("fault", ["mode", "inner_mode", "identity", "manifest", "namespace", "deadline",
    "sequence", "reservation", "policy", "action", "limit"])
def test_fresh_commitments_do_not_bypass_fixed_authority(case, fault):
    value = envelope(case)
    launch = value["launch"]
    if fault == "mode": value["mode"] = "owned_http_headers_lab"
    elif fault == "inner_mode": launch["mode"] = "http_headers_owned"
    elif fault == "identity": value["identity"]["spec_sha256"] = "b" * 64
    elif fault == "manifest": value["runtime"] = manifest(runtime.FFUF if case.startswith("curl") else runtime.CURL)
    elif fault == "namespace": value["namespaces"] = dict(launch["host_namespaces"])
    elif fault == "deadline": launch["deadline"] = 161
    elif fault == "sequence": launch["sequence"] = 2
    elif fault == "reservation": launch["output_reserved_before"] = 1
    elif fault == "policy": launch["policy"]["allowed_tools"] = []
    elif fault == "action":
        launch["action"]["target"] = "127.0.0.2"
        launch["policy"]["allowed_targets"] = ["127.0.0.0/8"]
    else: launch["limits"]["max_steps"] = 2
    recommit(value)
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("profile,case", [("fixture", None), ("discovery_fixture", None), ("owned_lab", "a"),
    ("owned_nmap_lab", "a"), ("owned_web_lab", "vulnerable"), ("owned_http_headers_lab", "vulnerable")])
def test_existing_profiles_never_admit_either_new_tool(profile, case):
    for selected in ("curl-ok", "ffuf-normal"):
        assert not admission.profile_allows(parse_action(action(selected)), {"profile": profile, "case": case})


def test_case_binding_and_single_reservation_are_independently_checked():
    assert not admission.profile_allows(parse_action(action("ffuf-normal")), configuration("curl-ok"))
    config = configuration()
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    def message(sequence):
        return {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
            "sequence": sequence, "operation": "admit", "action": action("curl-ok"), "policy_digest": digest(config["policy"])}
    assert state.handle(message(1))["reason"] is None
    assert state.handle(message(2))["reason"] == "admission_step_limit"
    for field in LIMITS:
        changed = deepcopy(config)
        changed["limits"][field] += 1
        with pytest.raises(ValueError): admission.configuration(changed)


@pytest.mark.parametrize("tool_id", [runtime.CURL, runtime.FFUF])
def test_manifest_pins_compiled_data_and_rejects_unreviewed_paths(tool_id):
    original = manifest(tool_id)
    assert runtime.validate_manifest(original, tool_id=tool_id) == original
    assert all(not src.startswith("compiled:") for src, _ in runtime.runtime_source_mounts(original))
    for field, value in (("source", "/tmp/evil"), ("sha256", "b" * 64), ("size", True)):
        changed = deepcopy(original)
        row = next(item for item in changed["files"] if item["source"].startswith("compiled:"))
        row[field] = value
        with pytest.raises(ValueError): runtime.validate_manifest(changed)
    changed = deepcopy(original)
    changed["interpreter"] = "/usr/bin/python3"
    with pytest.raises(ValueError): runtime.validate_manifest(changed)
    changed = deepcopy(original)
    changed["files"] += [deepcopy(changed["files"][0])]
    with pytest.raises(ValueError): runtime.validate_manifest(changed)


def test_thread_clone_rules_admit_go_and_pthread_flags_but_no_process_or_namespaces():
    def denied(flags):
        return any(flags & mask == value for mask, value in clone_denials())
    for flags in (0x50F00, 0x3D0F00, 0x13D0F00):
        assert not denied(flags)
        for bit in (0x100, 0x800, 0x10000):
            assert denied(flags & ~bit)
        for bit in (0x80, 0x2000, 0x4000, 0x8000, 0x20000, 0x2000000, 0x4000000,
                    0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 1 << 32):
            assert denied(flags | bit)
    for flags in (0, 17, 0x100 | 17, 0x50F00 | 17):
        assert denied(flags)


def test_fixed_command_has_only_owned_namespace_fds_and_selected_data(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        manifest(runtime.FFUF), [20, 21, 22], "a" * 64, "b" * 64)
    assert argv[:5] == ["/usr/bin/nsenter", "--user=/proc/self/fd/10", "--net=/proc/self/fd/11",
                        "--preserve-credentials", "--"]
    assert "CAP_NET_ADMIN" not in argv and "--unshare-net" not in argv
    assert argv.count("--ro-bind-data") == 3 and "20,21,22" in argv
    assert not any("web_tools_tls_fixture" in item for item in argv)
    assert runtime.FIXED_ARGV[runtime.CURL][1] == "--disable"
    for forbidden in ("-r", "-ac", "-recursion", "-input-cmd", "-x", "-replay-proxy"):
        assert forbidden not in runtime.FIXED_ARGV[runtime.FFUF]


def test_launcher_profile_cannot_mount_the_other_tool_manifest():
    config = {**configuration(), "owned_lab": identity("curl-ok", str(uuid4()))}
    closure = {"stdlib": "/usr/lib/python3.13", "files": ["/usr/bin/python3", "/usr/sbin/nft", "/usr/bin/bwrap", "/usr/bin/nsenter"],
               "web_tools_runtime": manifest(runtime.FFUF)}
    with pytest.raises(ValueError, match="runtime_changed"):
        launcher_protocol.initial({"configuration": config, "runtime": closure, "deadline": 130}, 100)


def test_expired_session_never_inspects_or_starts_a_tool(monkeypatch):
    monkeypatch.setattr(runtime, "inspect_tool_runtime", lambda *_: pytest.fail("expired runtime inspected"))
    with pytest.raises(ExecutionStopped):
        runtime.run_web_tool_owned(lab=None, launch={}, control=ExecutionControl(time.monotonic() - 1))


def test_manifest_size_ceiling_keeps_maximum_capture_receipt_bounded():
    from recon_cockpit.secure_agent.web_tools_contract import BOUNDARY_FIELDS
    import base64
    value = manifest()
    # The maximum retained bytes are shared between stdout and stderr, so the
    # complete manifest plus base64 capture must still fit the action JSON cap.
    receipt = {"status": "output_limit", "results": [], "tool_observation": None,
        "boundary_checks": dict.fromkeys(BOUNDARY_FIELDS, True), "bytes_received": 8192, "truncated": True,
        "raw_output_base64": base64.b64encode(b"x" * 8192).decode("ascii"), "raw_stderr_base64": "",
        "provenance": {"runtime_manifest": value, "runtime_sha256": runtime.manifest_digest(value)}}
    assert len(encode(receipt)) - len(encode(value)) + runtime.MAX_MANIFEST_BYTES < 30000
    value["files"] *= 17
    with pytest.raises(ValueError): runtime.validate_manifest(value)


@pytest.mark.parametrize("tool_id", [runtime.CURL, runtime.FFUF])
def test_ffuf_config_is_an_empty_sandbox_directory_with_no_config_file_access(monkeypatch, tool_id):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    selected = manifest(tool_id)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        selected, [20, 21, 22], "a" * 64, "b" * 64)
    environment = runtime.execution_environment(tool_id)
    permissions = _landlock_permissions(selected)
    config_paths = [path for path in permissions if path.startswith("/tool/config")]
    if tool_id == runtime.FFUF:
        leaf = runtime.FFUF_SCRAPER_DIRECTORY
        index = argv.index(leaf)
        assert argv[index - 3:index + 1] == ["--perms", "0555", "--dir", leaf]
        assert index < argv.index("--remount-ro")
        assert environment["XDG_CONFIG_HOME"] == "/tool/config"
        assert config_paths == [leaf] and permissions[leaf] == 8
    else:
        assert runtime.FFUF_SCRAPER_DIRECTORY not in argv and not config_paths
        assert "XDG_CONFIG_HOME" not in environment
    assert not {"HOME", "http_proxy", "https_proxy", "CURL_HOME", "LD_PRELOAD"} & set(environment)
    assert not any("config" in item["source"] for item in selected["files"])
