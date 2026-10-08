"""Portable negative authority, closure and thread-filter checks."""

from copy import deepcopy
import hashlib
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent.executor_worker import digest, encode
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_contract import CASES, LIMITS, action
from recon_cockpit.secure_agent.network_tools_execution import consume_launch
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from recon_cockpit.secure_agent.network_tools_worker import clone_denials
from recon_cockpit.secure_agent.network_tools_worker import _landlock_permissions


def manifest(tool_id=runtime.DIG):
    if tool_id == runtime.NUCLEI:
        from recon_cockpit.secure_agent.network_tools_nuclei_runtime import manifest as nuclei_manifest
        return nuclei_manifest()
    if tool_id == runtime.SSH_ALGORITHMS:
        from test_secure_ssh_algorithms_runtime import manifest as algorithms_manifest
        return algorithms_manifest()
    if tool_id == runtime.SMB2:
        from test_secure_smb2_runtime import manifest as smb2_manifest
        return smb2_manifest()
    if tool_id == runtime.RDP:
        from test_secure_rdp_runtime import manifest as rdp_manifest
        return rdp_manifest()
    if tool_id == runtime.WHATWEB:
        from test_secure_whatweb_runtime import manifest as whatweb_manifest
        return whatweb_manifest()
    entries = [(runtime.EXECUTABLES[tool_id], runtime.FIXED_ARGV[tool_id][0], b"data"),
               ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", b"data")]
    entries.extend(runtime.compiled_files(tool_id))
    return runtime.compact_manifest({"version": "1", "profile": runtime.PROFILE, "tool_id": tool_id,
            "executable": runtime.FIXED_ARGV[tool_id][0], "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "files": [{"source": src, "destination": dst, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for src, dst, data in sorted(entries, key=lambda row: row[1])]})


def policy():
    return parse_policy({"schema_version": "1", "policy_version": "test-network-tool-v1",
        "allowed_targets": ["127.0.0.1"], "allowed_tools": [runtime.NUCLEI, runtime.TLS_CERTIFICATE, runtime.SSH_ALGORITHMS, runtime.SNMP_NEXT, runtime.HTTP_OPTIONS, runtime.DIG, runtime.DIG_AXFR, runtime.DIG_NSID, runtime.DIG_SRV, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.SMB, runtime.RPCINFO, runtime.SHOWMOUNT, runtime.FTP, runtime.SMTP, runtime.DOCKER_PING, runtime.DOCKER_VERSION, runtime.WINRM, runtime.NMAP_SERVICE, runtime.KERBRUTE, runtime.REDIS, runtime.SNMP, runtime.POSTGRESQL_TLS, runtime.MYSQL_TLS, runtime.WHATWEB, runtime.RDP, runtime.SMB2, runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS],
        "allowed_ports": [8080, 111], "allowed_methods": ["GET", "OPTIONS"], "max_timeout_seconds": 10,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": True, "approval_ttl_seconds": 60})


def configuration(case="dig-ok"):
    return {"version": "1", "service_id": str(uuid4()), "session_id": str(uuid4()),
        "policy": policy().to_dict(), "limits": dict(LIMITS), "execute": True,
        "profile": "owned_network_tools_lab", "case": case}


def envelope(case="dig-ok"):
    selected = parse_action(action(case))
    host = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    return {"mode": "owned_network_tools_lab", "identity": identity(case, str(uuid4())),
        "namespaces": {name: name + ":[200]" for name in host}, "runtime": manifest(selected.tool_id),
        "launch": {"schema_version": "1", "mode": "network_tools_owned", "execute": True,
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


@pytest.mark.parametrize("case", CASES)
def test_independent_launch_validator_accepts_only_the_selected_fixed_tool(case):
    value = envelope(case)
    request, deadline, namespaces, runtime_digest = verify(value)
    assert request["tool_id"] == action(case)["tool_id"] and deadline == 130
    assert namespaces == value["namespaces"] and runtime_digest == runtime.manifest_digest(value["runtime"])
    assert admission.profile_allows(parse_action(action(case)), configuration(case))


@pytest.mark.parametrize("case", ["dig-ok", "openssl-ok", "ssh-ok", "ldap-ok", "smb-ok", "rpc-ok", "nfs-ok", "ftp-ok", "smtp-ok", "docker-ping-ok", "docker-version-ok", "winrm-ok", "nmap-service-http", "kerberos-ok"])
@pytest.mark.parametrize("fault", ["mode", "inner_mode", "identity", "manifest", "namespace", "deadline",
    "sequence", "reservation", "policy", "action", "limit"])
def test_fresh_commitments_do_not_bypass_fixed_authority(case, fault):
    value = envelope(case)
    launch = value["launch"]
    if fault == "mode": value["mode"] = "owned_http_headers_lab"
    elif fault == "inner_mode": launch["mode"] = "http_headers_owned"
    elif fault == "identity": value["identity"]["spec_sha256"] = "b" * 64
    elif fault == "manifest": value["runtime"] = manifest(runtime.OPENSSL if case.startswith("dig") else runtime.DIG)
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
    ("owned_nmap_lab", "a"), ("owned_web_lab", "vulnerable"), ("owned_http_headers_lab", "vulnerable"), ("owned_web_tools_lab", "curl-ok")])
def test_existing_profiles_never_admit_network_tools(profile, case):
    for selected in ("dig-ok", "openssl-ok", "ssh-ok", "ldap-ok", "smb-ok", "rpc-ok", "nfs-ok", "ftp-ok", "smtp-ok", "docker-ping-ok", "docker-version-ok", "winrm-ok", "nmap-service-http", "kerberos-ok"):
        assert not admission.profile_allows(parse_action(action(selected)), {"profile": profile, "case": case})


def test_case_binding_and_single_reservation_are_independently_checked():
    assert not admission.profile_allows(parse_action(action("openssl-ok")), configuration("dig-ok"))
    config = configuration()
    state = admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    def message(sequence):
        return {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
            "sequence": sequence, "operation": "admit", "action": action("dig-ok"), "policy_digest": digest(config["policy"])}
    assert state.handle(message(1))["reason"] is None
    assert state.handle(message(2))["reason"] == "admission_step_limit"
    for field in LIMITS:
        changed = deepcopy(config)
        changed["limits"][field] += 1
        with pytest.raises(ValueError): admission.configuration(changed)


@pytest.mark.parametrize("tool_id", [runtime.DIG, runtime.DIG_AXFR, runtime.DIG_NSID, runtime.DIG_SRV, runtime.OPENSSL, runtime.RPCINFO, runtime.SHOWMOUNT])
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
        manifest(runtime.OPENSSL), [20, 21, 22], "a" * 64, "b" * 64)
    assert argv[:5] == ["/usr/bin/nsenter", "--user=/proc/self/fd/10", "--net=/proc/self/fd/11",
                        "--preserve-credentials", "--"]
    assert "CAP_NET_ADMIN" not in argv and "--unshare-net" not in argv
    assert argv.count("--ro-bind-data") == 3 and "20,21,22" in argv
    assert not any("web_tools_tls_fixture" in item for item in argv)
    assert runtime.FIXED_ARGV[runtime.DIG][1:3] == ("-r", "-4")
    for required in ("+tcp", "+norecurse", "+tries=1", "+time=2", "+nosearch", "+noedns", "+noadflag", "+nocdflag"):
        assert required in runtime.FIXED_ARGV[runtime.DIG]
    for forbidden in ("-f", "+trace", "AXFR", "+search", "-x"):
        assert forbidden not in runtime.FIXED_ARGV[runtime.DIG]
    for required in ("-verify_return_error", "-verify_hostname", "-CAfile", "-no-CApath", "-no-CAstore", "-tls1_3"):
        assert required in runtime.FIXED_ARGV[runtime.OPENSSL]
    for forbidden in ("-reconnect", "-starttls", "-cert", "-key", "-proxy", "-sess_out", "-keylogfile", "-provider", "-engine"):
        assert forbidden not in runtime.FIXED_ARGV[runtime.OPENSSL]


def test_launcher_profile_cannot_mount_the_other_tool_manifest():
    config = {**configuration(), "owned_lab": identity("dig-ok", str(uuid4()))}
    closure = {"stdlib": "/usr/lib/python3.13", "files": ["/usr/bin/python3", "/usr/sbin/nft", "/usr/bin/bwrap", "/usr/bin/nsenter"],
               "network_tools_runtime": manifest(runtime.OPENSSL)}
    with pytest.raises(ValueError, match="runtime_changed"):
        launcher_protocol.initial({"configuration": config, "runtime": closure, "deadline": 130}, 100)


def test_expired_session_never_inspects_or_starts_a_tool(monkeypatch):
    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(runtime, "inspect_tool_runtime", lambda *_: pytest.fail("expired runtime inspected"))
    with pytest.raises(ExecutionStopped):
        runtime.run_network_tool_owned(lab=None, launch={}, control=ExecutionControl(time.monotonic() - 1))


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_unsupported_platform_never_inspects_or_starts_a_tool(monkeypatch, platform):
    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(runtime, "inspect_tool_runtime", lambda *_: pytest.fail("unsupported runtime inspected"))
    with pytest.raises(IsolationUnavailable, match="require Linux authority control"):
        runtime.run_network_tool_owned(lab=None, launch={}, control=ExecutionControl(time.monotonic() + 60))


def test_manifest_size_ceiling_keeps_maximum_capture_receipt_bounded():
    from recon_cockpit.secure_agent.network_tools_contract import BOUNDARY_FIELDS
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


@pytest.mark.parametrize("tool_id", [runtime.DIG, runtime.DIG_AXFR, runtime.DIG_NSID, runtime.DIG_SRV, runtime.OPENSSL, runtime.SSH, runtime.LDAP, runtime.SMB, runtime.RPCINFO, runtime.SHOWMOUNT, runtime.FTP, runtime.SMTP, runtime.DOCKER_PING, runtime.DOCKER_VERSION, runtime.WINRM, runtime.NMAP_SERVICE, runtime.KERBRUTE])
def test_tools_get_only_fixed_data_and_no_host_configuration(tool_id):
    selected = manifest(tool_id)
    environment = runtime.execution_environment(tool_id)
    permissions = _landlock_permissions(selected)
    assert not {"HOME", "http_proxy", "https_proxy", "LOCALDOMAIN", "RES_OPTIONS", "LD_PRELOAD", "OPENSSL_MODULES"} & set(environment)
    assert environment["OPENSSL_CONF"] == "/dev/null"
    if tool_id in (runtime.DIG, runtime.DIG_AXFR, runtime.DIG_NSID, runtime.DIG_SRV):
        assert runtime._compiled(tool_id) == ("compiled:resolver", "/etc/resolv.conf",
            b"# fixed TCP nameserver supplied by reviewed argv\n")
        assert permissions["/etc/resolv.conf"] == 4
        assert environment["UV_THREADPOOL_SIZE"] == "1"
    elif tool_id == runtime.OPENSSL:
        assert permissions["/tool/data/fixture-ca.pem"] == 4
        assert "/etc/resolv.conf" not in permissions
    elif tool_id in (runtime.RPCINFO, runtime.SHOWMOUNT):
        assert runtime._compiled(tool_id) == ("compiled:rpc-netconfig", "/etc/netconfig",
            b"tcp tpi_cots_ord v inet tcp - -\n")
        assert permissions["/etc/netconfig"] == 4
        assert permissions["/etc/services"] == 4
        assert not {"/etc/rpc", "/etc/protocols", "/etc/resolv.conf"} & set(permissions)
    elif tool_id == runtime.KERBRUTE:
        assert permissions["/tool/data/principals.txt"] == 4
        assert environment["GOMAXPROCS"] == "1" and environment["GOMEMLIMIT"] == "64MiB"
        assert not any(path.startswith("/etc/") for path in permissions)
    elif tool_id == runtime.NMAP_SERVICE:
        assert {"/tool/data/nmap-services", "/tool/data/nmap-protocols",
                "/tool/data/nmap-service-probes", "/tool/data/nse_main.lua"} <= set(permissions)
        assert not any(path.startswith("/etc/") for path in permissions)
    elif tool_id == runtime.SMB:
        assert permissions["/tool/data/smb.conf"] == 4
        assert "/etc/resolv.conf" not in permissions
        assert "/tool/data" not in permissions
    else:
        assert runtime._compiled(tool_id) is None
        assert not any(path.startswith(("/etc/", "/tool/data", "/tool/config")) for path in permissions)
        assert (environment.get("LDAPNOINIT") == "1") == (tool_id == runtime.LDAP)
    assert "/usr/bin/python3" not in permissions
    assert not any("_fixture" in path or ".digrc" in path or "ssl/certs" in path for path in permissions)


@pytest.mark.parametrize("tool_id,threads", [(runtime.DIG, True), (runtime.DIG_SRV, True), (runtime.DIG_NSID, True), (runtime.DIG_AXFR, True), (runtime.OPENSSL, False),
                                            (runtime.SSH, False), (runtime.LDAP, False), (runtime.SMB, False),
                                            (runtime.RPCINFO, False), (runtime.SHOWMOUNT, False),
                                            (runtime.FTP, False), (runtime.SMTP, False),
                                            (runtime.DOCKER_PING, False), (runtime.DOCKER_VERSION, False), (runtime.WINRM, False), (runtime.NMAP_SERVICE, False)])
def test_only_dig_selects_the_bounded_thread_filter(monkeypatch, tool_id, threads):
    from recon_cockpit.secure_agent import network_tools_worker as worker
    selected = []
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kw: selected.append(kw))
    worker.syscall_filter(tool_id)
    assert selected == [{"allow_threads": threads}]
    with pytest.raises(ValueError):
        worker.syscall_filter("ffuf_content_discovery_v1")


@pytest.mark.parametrize("case", ["dig-ok", "openssl-ok", "ssh-ok", "ldap-ok", "smb-ok", "rpc-ok", "nfs-ok", "ftp-ok", "smtp-ok", "docker-ping-ok", "docker-version-ok", "winrm-ok", "nmap-service-http", "kerberos-ok"])
def test_runtime_retains_and_binds_both_output_channels(monkeypatch, case):
    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform="linux"))
    launch = envelope(case)
    selected = launch.pop("runtime")
    monkeypatch.setattr(runtime, "_snapshot", lambda *_: [])
    monkeypatch.setattr(runtime, "_command", lambda *_: ["fixed-worker"])
    stdout, stderr = b"dns or application output", b"TLS diagnostics"
    def captured(argv, raw, *args, **kwargs):
        prefix = runtime.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b"\n"
        return 0, stdout, prefix + stderr, None
    monkeypatch.setattr(runtime, "_capture_bounded", captured)
    lab = SimpleNamespace(_namespace_fds=(10, 11), _check=lambda *_: None, _verify_pins=lambda: None)
    result = runtime.run_network_tool_owned(lab=lab, launch=launch,
        control=ExecutionControl(time.monotonic() + 20), manifest=selected,
        closure={"stdlib": "/usr/lib/python3.13", "files": [], "network_tools_runtime": selected})
    assert result["bytes_received"] == len(stdout) + len(stderr)
    assert result["provenance"]["output_sha256"] == hashlib.sha256(stdout).hexdigest()
    assert result["provenance"]["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()
    assert result["provenance"]["runtime_sha256"] == runtime.manifest_digest(selected)


def test_admission_case_map_matches_the_closed_owned_contract():
    assert set(admission.NETWORK_TOOL_CASES) == set(CASES)
    for case in CASES:
        assert admission.NETWORK_TOOL_CASES[case] == action(case)["tool_id"]
        assert admission.configuration(configuration(case))["case"] == case
    for case in ("ssh-other", "ldap-other", "openssl-other", "dig-other", "ftp-other", "smtp-other", "docker-ping-other", "docker-version-other", "winrm-other", "nmap-service-other", "", None, []):
        config = configuration()
        config["case"] = case
        with pytest.raises(ValueError):
            admission.configuration(config)
        assert not admission.profile_allows(parse_action(action("openssl-ok")), config)


@pytest.mark.parametrize("case", ["dig-ok", "openssl-ok", "ssh-ok", "ldap-ok", "smb-ok", "rpc-ok", "nfs-ok", "ftp-ok", "smtp-ok", "docker-ping-ok", "docker-version-ok", "winrm-ok", "nmap-service-http", "kerberos-ok"])
@pytest.mark.parametrize("other_case", ["dig-ok", "openssl-ok", "ssh-ok", "ldap-ok", "smb-ok", "rpc-ok", "nfs-ok", "ftp-ok", "smtp-ok", "docker-ping-ok", "docker-version-ok", "winrm-ok", "nmap-service-http", "kerberos-ok"])
def test_all_network_tools_bind_case_action_and_manifest_independently(case, other_case):
    if case == other_case:
        return
    assert not admission.profile_allows(parse_action(action(other_case)), configuration(case))
    value = envelope(case)
    value["runtime"] = manifest(action(other_case)["tool_id"])
    with pytest.raises(ValueError):
        verify(value)
    value = envelope(case)
    value["launch"]["action"] = action(other_case)
    value["runtime"] = manifest(action(other_case)["tool_id"])
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)
    config = {**configuration(case), "owned_lab": identity(case, str(uuid4()))}
    closure = {"stdlib": "/usr/lib/python3.13", "files": ["/usr/bin/python3", "/usr/sbin/nft", "/usr/bin/bwrap", "/usr/bin/nsenter"],
               "network_tools_runtime": manifest(action(other_case)["tool_id"])}
    with pytest.raises(ValueError, match="runtime_changed"):
        launcher_protocol.initial({"configuration": config, "runtime": closure, "deadline": 130}, 100)


@pytest.mark.parametrize("tool_id", [runtime.SSH, runtime.LDAP])
def test_ssh_ldap_manifests_require_only_the_selected_elf_and_libraries(tool_id):
    value = manifest(tool_id)
    assert runtime.validate_manifest(value, tool_id=tool_id) == value
    assert runtime._compiled(tool_id) is None
    assert len(runtime.runtime_source_mounts(value)) == 2
    for destination in ("/etc/ldap/ldap.conf", "/etc/ssh/ssh_config", "/etc/ssh/moduli",
                        "/tool/data/fixture-ca.pem", "/tool/config/ldap.conf"):
        changed = deepcopy(value)
        changed["files"].append({"source": destination, "destination": destination,
            "size": 4, "sha256": hashlib.sha256(b"data").hexdigest()})
        changed["files"].sort(key=lambda row: row["destination"])
        with pytest.raises(ValueError):
            runtime.validate_manifest(changed)
    for index in range(len(value["files"])):
        changed = deepcopy(value)
        changed["files"].pop(index)
        with pytest.raises(ValueError):
            runtime.validate_manifest(changed)
    changed = deepcopy(value)
    executable = next(row for row in changed["files"] if row["destination"] == changed["executable"])
    executable["source"] = runtime.EXECUTABLES[runtime.LDAP if tool_id == runtime.SSH else runtime.SSH]
    with pytest.raises(ValueError):
        runtime.validate_manifest(changed)


def test_ssh_ldap_fixed_commands_disable_config_authentication_and_referrals():
    ssh = runtime.FIXED_ARGV[runtime.SSH]
    assert ssh == ("/tool/ssh-keyscan", "-4", "-T", "2", "-p", "8080", "-t", "rsa", "127.0.0.1")
    ldap = runtime.FIXED_ARGV[runtime.LDAP]
    assert ldap[:5] == ("/tool/ldapsearch", "-x", "-LLL", "-P", "3")
    for flag, value in (("-H", "ldap://127.0.0.1:8080"), ("-s", "base"), ("-b", ""),
                        ("-a", "never"), ("-l", "2"), ("-z", "1")):
        assert ldap[ldap.index(flag) + 1] == value
    assert tuple(ldap[index + 1] for index, arg in enumerate(ldap) if arg == "-o") == ("nettimeout=2", "ldif_wrap=no")
    assert ldap[-5:] == ("(objectClass=*)", "namingContexts", "supportedLDAPVersion", "supportedSASLMechanisms", "vendorName")
    assert not {"-C", "-D", "-w", "-W", "-y", "-Y", "-X", "-U", "-Z", "-ZZ", "-f", "-t"} & set(ldap)
    assert runtime.execution_environment(runtime.LDAP)["LDAPNOINIT"] == "1"


@pytest.mark.parametrize("tool_id", [runtime.SSH, runtime.LDAP])
def test_new_tool_command_never_mounts_owner_private_fixture_material(monkeypatch, tool_id):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        manifest(tool_id), [20, 21], "a" * 64, "b" * 64)
    assert argv.count("--ro-bind-data") == 2
    assert not any("network_tools_ssh_fixture" in item or "web_tools_tls_fixture" in item for item in argv)
    assert not any("/etc/ssh" in item or "/etc/ldap" in item or "fixture-ca.pem" in item for item in argv)


@pytest.mark.parametrize("tool_id", [runtime.RPCINFO, runtime.SHOWMOUNT])
def test_rpc_metadata_has_only_fixed_tcp_transport_and_synthetic_hostname(monkeypatch, tool_id):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    selected = manifest(tool_id)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        selected, [20, 21, 22, 23], "a" * 64, "b" * 64)
    assert argv[argv.index("--hostname") + 1] == "reconlab"
    assert "--unshare-uts" in argv and "CAP_NET_ADMIN" not in argv
    assert argv.count("--ro-bind-data") == 4
    assert not any("network_tools_rpc_fixture" in arg for arg in argv)
    assert runtime.FIXED_ARGV[tool_id] == (("/tool/rpcinfo", "-p", "127.0.0.1")
        if tool_id == runtime.RPCINFO else ("/tool/showmount", "-e", "127.0.0.1"))
    assert set(runtime.execution_environment(tool_id)) == {"LC_ALL", "OPENSSL_CONF", "MALLOC_ARENA_MAX"}
    assert {row["destination"] for row in selected["files"] if row["source"].startswith("compiled:")} == {"/etc/netconfig", "/etc/services"}
    for path in ("/etc/protocols", "/etc/rpc", "/etc/hosts", "/etc/krb5.conf", "/tmp/ccache"):
        changed = deepcopy(selected)
        changed["files"].append({"source": path, "destination": path, "size": 4,
            "sha256": hashlib.sha256(b"data").hexdigest()})
        changed["files"].sort(key=lambda row: row["destination"])
        with pytest.raises(ValueError):
            runtime.validate_manifest(changed)


@pytest.mark.parametrize("case", ["rpc-ok", "nfs-ok"])
@pytest.mark.parametrize("port", [80, 110, 112, 8080, 65534])
def test_rpc_admission_never_accepts_a_discovered_or_substituted_port(case, port):
    proposal = action(case)
    proposal["parameters"]["port"] = port
    # Strict tool parameter parsing may reject before admission; if parseable,
    # a broad policy still cannot authorize another execution endpoint.
    try:
        selected = parse_action(proposal)
    except ValueError:
        return
    assert not admission.profile_allows(selected, configuration(case))


@pytest.mark.parametrize("port", [True, None, 0, 80, 112, 8081, "111"])
def test_common_witness_does_not_accept_arbitrary_ports(monkeypatch, port):
    from recon_cockpit.secure_agent import tool_worker_common as common
    monkeypatch.setattr(common.worker, "verify_network_boundary", lambda *_: pytest.fail("invalid witness invoked"))
    with pytest.raises(ValueError, match="unsupported_tool_boundary_port"):
        common._witnesses(port=port)


@pytest.mark.parametrize("explicit,expected", [(None, 8080), (8080, 8080), (111, 111)])
def test_common_witness_preserves_default_and_uses_only_explicit_fixed_rpc_port(monkeypatch, explicit, expected):
    from recon_cockpit.secure_agent import tool_worker_common as common
    class WitnessObserved(Exception):
        pass
    def witness(port):
        assert port == expected
        raise WitnessObserved
    monkeypatch.setattr(common.worker, "verify_network_boundary", witness)
    with pytest.raises(WitnessObserved):
        common._witnesses(**({} if explicit is None else {"port": explicit}))


@pytest.mark.parametrize("tool_id", [runtime.RPCINFO, runtime.SHOWMOUNT])
def test_rpc_lookup_databases_are_both_required_and_pinned(tool_id):
    assert runtime.compiled_files(tool_id) == (
        ("compiled:rpc-netconfig", "/etc/netconfig", b"tcp tpi_cots_ord v inet tcp - -\n"),
        ("compiled:rpc-services", "/etc/services", b"sunrpc 111/tcp rpcbind portmapper\n"))
    original = manifest(tool_id)
    for source, destination, _ in runtime.compiled_files(tool_id):
        for field, changed_value in (("source", "/etc/services"), ("sha256", "b" * 64), ("size", 1)):
            changed = deepcopy(original)
            row = next(row for row in changed["files"] if row["destination"] == destination)
            row[field] = changed_value
            with pytest.raises(ValueError):
                runtime.validate_manifest(changed)
        changed = deepcopy(original)
        changed["files"] = [row for row in changed["files"] if row["source"] != source]
        with pytest.raises(ValueError):
            runtime.validate_manifest(changed)


@pytest.mark.parametrize("additional", [(("compiled:resolver", b"extra"),),
    (("/etc/services", b"extra"),), (("compiled:rpc-services", "text"),),
    (("compiled:rpc-services", b""),)])
def test_additional_compiled_staging_rejects_replacement_or_host_file_authority(additional):
    from recon_cockpit.secure_agent import tool_runtime_common as common
    with pytest.raises(IsolationUnavailable, match="Invalid additional compiled"):
        common.sealed_snapshots({"files": []}, "compiled:resolver", b"first",
            object(), additional_compiled=additional)


@pytest.mark.parametrize("tool_id", [runtime.FTP, runtime.SMTP, runtime.DOCKER_PING, runtime.DOCKER_VERSION, runtime.WINRM])
def test_curl_metadata_manifest_has_no_configuration_and_cannot_import_credentials(monkeypatch, tool_id):
    value = manifest(tool_id)
    assert runtime.validate_manifest(value, tool_id=tool_id) == value
    assert runtime.compiled_files(tool_id) == ()
    assert runtime.EXECUTABLES[tool_id] == "/usr/bin/curl"
    assert value["executable"] == "/tool/curl"
    for path in ("/etc/curlrc", "/root/.curlrc", "/root/.netrc", "/etc/resolv.conf",
                 "/etc/hosts", "/etc/ssl/certs", "/tool/config/curlrc", "compiled:curl-config",
                 "/var/run/docker.sock", "/root/.docker/config.json", "/tmp/krb5cc_1000"):
        changed = deepcopy(value)
        changed["files"].append({"source": path, "destination": path,
            "size": 4, "sha256": hashlib.sha256(b"data").hexdigest()})
        changed["files"].sort(key=lambda row: row["destination"])
        with pytest.raises(ValueError):
            runtime.validate_manifest(changed)
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        value, [20, 21], "a" * 64, "b" * 64)
    assert argv.count("--ro-bind-data") == 2
    assert "CAP_NET_BIND_SERVICE" not in argv and "CAP_NET_ADMIN" not in argv
    for owner_module in ("network_tools_ftp_smtp_fixture", "network_tools_http_metadata_fixture"):
        assert owner_module not in runtime.MODULES
        assert not any(owner_module in arg for arg in argv)
    assert set(runtime.execution_environment(tool_id)) == {"LC_ALL", "OPENSSL_CONF", "MALLOC_ARENA_MAX"}


@pytest.mark.parametrize("tool_id,protocol", [(runtime.FTP, "ftp"), (runtime.SMTP, "smtp")])
def test_curl_metadata_commands_disable_config_proxy_retry_redirect_and_transfer(tool_id, protocol):
    argv = runtime.FIXED_ARGV[tool_id]
    assert argv[:2] == ("/tool/curl", "--disable")
    assert {"--silent", "--show-error", "--ipv4", "--globoff"} <= set(argv)
    for flag, value in (("--proto", "=" + protocol), ("--proto-redir", "=" + protocol),
                        ("--noproxy", "*"), ("--proxy", ""), ("--connect-timeout", "1"),
                        ("--max-time", "3"), ("--max-filesize", "8192"), ("--retry", "0")):
        assert argv.count(flag) == 1 and argv[argv.index(flag) + 1] == value
    assert not {"--location", "--config", "--netrc", "--netrc-optional", "--netrc-file", "--upload-file",
                "--data", "--form", "--mail-from", "--mail-rcpt", "--quote", "--prequote",
                "--postquote", "--ftp-port", "--ftp-create-dirs", "--remote-name", "--remote-header-name",
                "--ssl", "--ssl-reqd", "--oauth2-bearer", "--login-options"} & set(argv)
    if tool_id == runtime.FTP:
        assert argv[-1] == "ftp://127.0.0.1:8080/"
        assert {"--ftp-pasv", "--disable-epsv", "--no-ftp-skip-pasv-ip", "--list-only"} <= set(argv)
        assert argv[argv.index("--ftp-method") + 1] == "nocwd"
        assert argv[argv.index("--user") + 1] == "anonymous:anonymous@"
        assert argv[argv.index("--dump-header") + 1] == "%"
    else:
        assert argv[-1] == "smtp://127.0.0.1:8080/reconlab"
        assert argv[argv.index("--request") + 1] == "QUIT"
        assert argv[argv.index("--dump-header") + 1] == "-"
        assert argv[argv.index("--output") + 1] == "/dev/null"
        assert "--user" not in argv


@pytest.mark.parametrize("case", ["ftp-ok", "smtp-ok"])
@pytest.mark.parametrize("target,port", [("127.0.0.1", 21), ("127.0.0.1", 25),
    ("127.0.0.1", 111), ("127.0.0.1", 8081), ("127.0.0.2", 8080)])
def test_ftp_smtp_admission_does_not_accept_advertised_endpoints(case, target, port):
    proposal = action(case)
    proposal["target"], proposal["parameters"]["port"] = target, port
    try:
        selected = parse_action(proposal)
    except ValueError:
        return
    assert not admission.profile_allows(selected, configuration(case))


@pytest.mark.parametrize("tool_id,path", [(runtime.DOCKER_PING, "/_ping"),
    (runtime.DOCKER_VERSION, "/version"), (runtime.WINRM, "/wsman")])
def test_http_metadata_commands_are_fixed_unauthenticated_gets_without_redirects(tool_id, path):
    argv = runtime.FIXED_ARGV[tool_id]
    assert argv[:2] == ("/tool/curl", "--disable")
    assert {"--silent", "--show-error", "--ipv4", "--globoff", "--http1.1", "--include"} <= set(argv)
    for flag, value in (("--proto", "=http"), ("--proto-redir", "=http"),
                        ("--noproxy", "*"), ("--proxy", ""), ("--connect-timeout", "1"),
                        ("--max-time", "3"), ("--max-filesize", "8192"), ("--retry", "0"),
                        ("--max-redirs", "0"), ("--request", "GET"), ("--header", "Connection: close"),
                        ("--user-agent", "recon-cockpit-b6/1")):
        assert argv.count(flag) == 1 and argv[argv.index(flag) + 1] == value
    assert argv[-1] == "http://127.0.0.1:8080" + path
    assert not {"--location", "--location-trusted", "--fail", "--fail-with-body", "--config",
                "--netrc", "--netrc-optional", "--netrc-file", "--user", "--proxy-user",
                "--negotiate", "--ntlm", "--anyauth", "--oauth2-bearer", "--delegation",
                "--unix-socket", "--abstract-unix-socket", "--upload-file", "--data",
                "--data-binary", "--form", "--cookie", "--cookie-jar", "--cert", "--key",
                "--resolve", "--connect-to", "--output", "--remote-name", "--remote-header-name"} & set(argv)


@pytest.mark.parametrize("case", ["docker-ping-ok", "docker-version-ok", "winrm-ok"])
@pytest.mark.parametrize("target,port", [("127.0.0.1", 2375), ("127.0.0.1", 2376),
    ("127.0.0.1", 5985), ("127.0.0.1", 5986), ("127.0.0.1", 8081), ("127.0.0.2", 8080)])
def test_http_metadata_admission_does_not_accept_default_or_advertised_endpoints(case, target, port):
    proposal = action(case)
    proposal["target"], proposal["parameters"]["port"] = target, port
    selected = parse_action(proposal)
    assert not admission.profile_allows(selected, configuration(case))


@pytest.mark.parametrize("case", ["docker-ping-ok", "docker-version-ok", "winrm-ok"])
@pytest.mark.parametrize("field,value", [("path", "/containers/json"), ("url", "http://127.0.0.2:8080/"),
    ("method", "POST"), ("headers", {"Authorization": "Basic eA=="}), ("body", "CreateShell"),
    ("socket", "/var/run/docker.sock"), ("credentials", "operator")])
def test_http_metadata_parameters_cannot_select_paths_mutations_or_credentials(case, field, value):
    proposal = action(case)
    proposal["parameters"][field] = value
    with pytest.raises(ValueError):
        parse_action(proposal)


def test_http_metadata_fixture_stays_out_of_native_and_parser_closures(monkeypatch):
    from recon_cockpit.secure_agent import launcher_isolation, network_tools_parser_runtime as parser
    assert "network_tools_http_metadata_fixture" in launcher_isolation.NETWORK_TOOLS_MODULES
    assert "network_tools_http_metadata_fixture" not in runtime.MODULES
    monkeypatch.setattr(parser, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(parser, "_namespaces", lambda: dict.fromkeys(("user", "net", "mnt", "pid"), "ns:[1]"))
    for tool_id in (runtime.DOCKER_PING, runtime.DOCKER_VERSION, runtime.WINRM):
        argv = parser._command(tool_id, ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"),
                                                                ("/usr/bin/curl", "/usr/bin/curl")]))
        assert "/usr/bin/curl" not in argv
        assert not any("network_tools_http_metadata_fixture" in arg for arg in argv)
