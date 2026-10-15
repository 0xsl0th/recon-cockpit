"""Exact stock SSH clients retain authority binding, closed mounts and READY/GO."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import stock_ssh_client_runtime as runtime, stock_ssh_client_worker as worker
from recon_cockpit.secure_agent import stock_ssh_contract as contract, stock_ssh_spec as spec
from recon_cockpit.secure_agent import stock_ssh_runtime as daemon, stock_ssh_nmap_runtime as nmap
from recon_cockpit.secure_agent import network_tools_runtime as native
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.stock_ssh_execution import consume_launch
from test_secure_network_tools_runtime import manifest as native_manifest

NONCE = "a" * 64
SESSION = str(UUID(int=921))
HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}


def daemon_manifest(configuration="A", case="O1"):
    rows = [(source, destination, b"native") for destination, source in daemon._native_files().items()]
    rows += [(daemon.LIBRARY_ROOT + "ld-linux-x86-64.so.2" if path == daemon.INTERPRETER else path,
              path, b"native") for path in sorted(daemon.DEPENDENCIES)]
    rows += list(spec.compiled_files(configuration, case))
    return {"schema_version": "1", "profile": daemon.PROFILE, "configuration": configuration, "case": case,
        "selection_sha256": spec.selection_digest(configuration, case), "executable": daemon.DESTINATION,
        "interpreter": daemon.INTERPRETER, "executables": daemon._native_files(),
        "elf_dependencies": daemon._elf_dependencies(),
        "dependency_kind": "fixed_daemon_helpers_and_elf_linked_dependencies_only",
        "runtime_closure_verified": False, "daemon_execution_performed": False,
        "files": [{"source": source, "destination": destination, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                  for source, destination, raw in sorted(rows, key=lambda row: row[1])]}


def manifests(configuration="A", case="O1"):
    client = (nmap.from_native_manifest(native_manifest(native.NMAP_SERVICE)) if spec.action_kind(case) == "nmap"
              else native_manifest(native.SSH))
    return {"daemon": daemon_manifest(configuration, case), "client": client}


def envelope(configuration="A", case="O1"):
    selected = contract.selection(configuration, case)
    bundle = manifests(configuration, case)
    action = parse_action(contract.action(selected))
    policy, limits = contract.policy_for_selection(selected), contract.limits(selected)
    return {"mode": contract.PROFILE, "selection": selected,
        "identity": {"version": "1", "profile": contract.PROFILE, "instance_id": str(UUID(int=922)),
            "session_id": SESSION, **selected, **contract.runtime_digests(bundle, selected)},
        "runtime": bundle, "namespaces": {name: name + ":[200]" for name in HOST},
        "launch": {"schema_version": "1", "mode": contract.PROFILE, "execute": True, "session_id": SESSION,
            "nonce": NONCE, "sequence": 1, "action": action.to_dict(), "action_digest": action.digest,
            "policy": policy.to_dict(), "policy_digest": policy.digest, "limits": limits,
            "limits_digest": hashlib.sha256(spec.encode(limits)).hexdigest(), "deadline": 150,
            "output_reserved_before": 0, "output_reserved_after": limits["max_output_bytes"], "host_namespaces": HOST}}


def request(configuration="A", case="O1"):
    value = envelope(configuration, case)
    raw = spec.encode(value)
    return consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)[0]


@pytest.mark.parametrize("configuration,case", spec.TRIALS)
def test_exact_action_can_only_compile_its_finite_native_argv(configuration, case):
    value = request(configuration, case)
    argv = worker.argv_for(value)
    assert argv == spec.client_argv(configuration, case)
    assert argv[-1] == spec._scope(configuration)["ssh"]["target"]
    assert argv[argv.index("-p") + 1] == str(spec._scope(configuration)["ssh"]["port"])
    if spec.action_kind(case) == "nmap":
        assert argv[argv.index("--version-intensity") + 1] == "0"
        assert "--script" not in argv and "--version-all" not in argv and "-n" in argv
    else:
        assert argv == ("/tool/ssh-keyscan", "-4", "-T", "2", "-p", argv[5], "-t", "rsa", argv[-1])


@pytest.mark.parametrize("change", (
    lambda value: value.update(target="10.77.0.99"), lambda value: value["parameters"].update(port=22),
    lambda value: value["parameters"].update(timeout_seconds=6), lambda value: value.update(tool_id="ssh"),
    lambda value: value.update(endpoint_id="http"), lambda value: value.update(case="O2"),
    lambda value: value.update(configuration="B"), lambda value: value["scope"]["ssh"].update(port=22),
    lambda value: value["selection"].update(selection_sha256="b" * 64),
))
def test_changed_request_cannot_change_command_or_scope(change):
    value = request()
    change(value)
    with pytest.raises(ValueError): worker.argv_for(value)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", ("O1", "O2"))
def test_closed_client_module_set_imports_and_checks_envelope_without_repository(tmp_path, configuration, case):
    package = tmp_path / "recon_cockpit" / "secure_agent"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    source = Path(runtime.__file__).parent
    for module in runtime.MODULES:
        shutil.copyfile(source / (module + ".py"), package / (module + ".py"))
    raw = spec.encode(envelope(configuration, case))
    code = """import hashlib,sys
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent import stock_ssh_client_worker as worker
from recon_cockpit.secure_agent.stock_ssh_execution import consume_launch
raw=sys.argv[2].encode('ascii')
request,deadline,namespaces,digest=consume_launch(raw,sys.argv[3],hashlib.sha256(raw).hexdigest(),now=100)
assert request['endpoint_id']=='ssh' and deadline==150 and digest
assert worker.argv_for(request)[-1]==request['target']
assert worker.__file__.startswith(sys.argv[1])
print('closed-ssh-client-ok')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path), raw.decode(), NONCE],
                            capture_output=True, timeout=10, env={"LC_ALL": "C"})
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout == b"closed-ssh-client-ok\n"


@pytest.mark.parametrize("case", spec.CASES)
def test_go_uses_selected_deadline_without_extending_session(case):
    raw = spec.encode({"nonce": NONCE, "deadline": 105})
    assert worker.validate_go(raw, NONCE, 160, case, now=100) == 105
    for session, now in ((160, 105), (104.99, 100), (160, 99.99)):
        with pytest.raises(ValueError): worker.validate_go(raw, NONCE, session, case, now=now)


@pytest.mark.parametrize("change", (
    lambda value: value.update(nonce="b" * 64), lambda value: value.update(deadline=True),
    lambda value: value.update(deadline=100), lambda value: value.update(deadline=105.001),
    lambda value: value.update(deadline="105"), lambda value: value.update(extra=True),
    lambda value: value.pop("nonce"),
))
def test_changed_go_cannot_arm_new_or_longer_action(change):
    value = {"nonce": NONCE, "deadline": 105}
    change(value)
    with pytest.raises(ValueError): worker.validate_go(spec.encode(value), NONCE, 160, "O1", now=100)


@pytest.mark.parametrize("raw", (b"x" * 257, b'{"nonce":"x","deadline":NaN}',
    b'{"nonce":"x","deadline":101,"deadline":100}', b"[]", "not bytes"))
def test_invalid_go_framing_and_ambiguous_json_refused(raw):
    with pytest.raises((ValueError, TypeError)): worker.validate_go(raw, NONCE, 160, "O1", now=100)


@pytest.mark.parametrize("case", ("O1", "O2"))
def test_client_mounts_only_selected_snapshots_and_has_no_daemon_or_private_fd(monkeypatch, case):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    selected = contract.selection("A", case)
    client = manifests("A", case)["client"]
    entries = runtime.client_runtime_module(selected).runtime_files(client)
    descriptors = list(range(40, 40 + len(entries)))
    forbidden = {"nmap", "ssh-keyscan", "nsenter", "nft", "ip", "nginx", "apache2", "bwrap", "sshd", "sshd-session", "sshd-auth"}
    paths = ["/usr/bin/" + name for name in forbidden] + ["/usr/bin/python3", "/lib/libc.so"]
    lab = SimpleNamespace(selection=selected, _namespace_fds=(30, 31))
    argv = runtime._command(lab, ("/stdlib", [(p, p) for p in paths]), client, descriptors, NONCE, "b" * 64)
    assert argv[:4] == ["/usr/bin/nsenter", "--user=/proc/self/fd/30", "--net=/proc/self/fd/31", "--preserve-credentials"]
    clear = argv.index(runtime._CLOSE_EXCEPT)
    assert argv[clear + 1] == ",".join(map(str, descriptors))
    mounts = [argv[i+1:i+3] for i, value in enumerate(argv) if value == "--ro-bind"]
    assert all(Path(src).name not in forbidden for src, _ in mounts)
    assert all(dst not in {"/peer", "/scratch", "/stock-peer", "/stock-ssh-peer", spec.HOST_KEY_PATH} for _, dst in mounts)
    assert "--bind" not in argv and "--bind-fd" not in argv and "--tmpfs" not in argv
    assert [argv[i+1:i+3] for i, value in enumerate(argv) if value == "--ro-bind-data"] == [
        [str(fd), row["destination"]] for fd, row in zip(descriptors, entries, strict=True)]
    assert argv[-6:] == ["/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/stock_ssh_client_worker.py", NONCE, "b" * 64]
    with pytest.raises(ValueError):
        runtime._command(lab, ("/stdlib", []), client, descriptors + [999], NONCE, "b" * 64)


def test_native_runtime_kind_and_recognition_profile_cannot_be_swapped():
    selected = contract.selection("A", "O1")
    ssh = contract.selection("A", "O2")
    nmap_manifest, key_manifest = manifests()["client"], manifests(case="O2")["client"]
    assert runtime.validate_client_runtime(nmap_manifest, selected) == nmap_manifest
    assert runtime.validate_client_runtime(key_manifest, ssh) == key_manifest
    for value, selection in ((key_manifest, selected), (nmap_manifest, ssh),
        (native_manifest(native.NMAP_SERVICE), selected), (None, selected), (None, ssh)):
        with pytest.raises(ValueError): runtime.validate_client_runtime(value, selection)


@pytest.mark.parametrize("case", ("O1", "O2"))
def test_preflight_uses_only_selected_fixed_native_runtime(monkeypatch, case):
    selected = contract.selection("A", case)
    expected = manifests(case=case)["client"]
    calls = []
    monkeypatch.setattr(native, "inspect_tool_runtime", lambda tool, control: calls.append((tool, control)) or expected)
    monkeypatch.setattr(nmap, "inspect_runtime", lambda control: calls.append((native.NMAP_SERVICE, control)) or expected)
    control = object()
    assert runtime.inspect_client_runtime(selected, control) == expected
    assert calls == [(runtime.underlying_tool(selected), control)]


def test_private_descriptor_check_refuses_live_extra_fds_but_not_closed_entries(monkeypatch):
    monkeypatch.setattr(worker.os, "listdir", lambda path: ["0", "1", "2", "9"])
    monkeypatch.setattr(worker.os, "fstat", lambda fd: object())
    with pytest.raises(ValueError, match="inherited_descriptor"): worker.private_descriptors()
    def closed(_): raise OSError("closed")
    monkeypatch.setattr(worker.os, "fstat", closed)
    worker.private_descriptors()


@pytest.mark.parametrize("code,now,reason,expected", ((-signal.SIGALRM, 105, None, "timeout"),
    (128 + signal.SIGALRM, 105, None, "timeout"), (-signal.SIGALRM, 104.99, None, None),
    (1, 105, None, None), (0, 105, None, None), (-signal.SIGALRM, 105, "output_limit", "output_limit")))
def test_native_timeout_label_requires_deadline_and_timer_evidence(code, now, reason, expected):
    assert runtime._native_stop_reason(code, reason, 105, now=now) == expected
