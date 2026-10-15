"""Finite public SSH preparation, with no service or authority side effects."""

import base64
import hashlib
import math
import os
from pathlib import Path
import secrets
import socket
import subprocess

import pytest

from recon_cockpit.secure_agent import configurable_contract, launch_admission, launcher_protocol
from recon_cockpit.secure_agent import network_tools_parser, network_tools_ssh_fixture as fixture
from recon_cockpit.secure_agent import stock_ssh_spec as spec


def _der_value(raw, offset):
    """Small independent DER reader; reject noncanonical lengths/integers."""
    tag, first = raw[offset:offset + 2]
    offset += 2
    if first & 128:
        count = first & 127
        assert 1 <= count <= 2 and raw[offset] != 0
        size = int.from_bytes(raw[offset:offset + count], "big")
        assert size >= 128
        offset += count
    else:
        size = first
    end = offset + size
    assert end <= len(raw)
    payload = raw[offset:end]
    if tag == 2:
        assert payload and not payload[0] & 128
        assert len(payload) == 1 or payload[0] != 0 or payload[1] & 128
    return tag, payload, end


def test_public_fixture_pkcs1_is_canonical_and_reproduces_existing_signature_vector():
    pem = spec.public_test_private_key()
    lines = pem.splitlines()
    assert lines[0] == b"-----BEGIN RSA PRIVATE KEY-----"
    assert lines[-1] == b"-----END RSA PRIVATE KEY-----"
    assert all(len(line) == 64 for line in lines[1:-2])
    encoded = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    tag, body, end = _der_value(encoded, 0)
    assert tag == 48 and end == len(encoded)
    values, offset = [], 0
    while offset < len(body):
        tag, value, offset = _der_value(body, offset)
        assert tag == 2
        values.append(int.from_bytes(value, "big"))
    assert len(values) == 9
    version, n, e, d, p, q, dp, dq, inverse = values
    assert (version, n, e, d) == (0, fixture.RSA_N, fixture.RSA_E, fixture.RSA_D)
    assert p * q == n and n.bit_length() == 2048 and e == 65537
    assert (e * d) % math.lcm(p - 1, q - 1) == 1
    assert dp == d % (p - 1) and dq == d % (q - 1) and inverse * q % p == 1
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(
        fixture.SIGNATURE_VECTOR_MESSAGE).digest()
    em = b"\0\1" + b"\xff" * (256 - len(digest_info) - 3) + b"\0" + digest_info
    assert pow(int.from_bytes(em, "big"), d, n).to_bytes(256, "big") == fixture.SIGNATURE_VECTOR
    assert spec.public_test_private_key() == pem


def test_public_key_matches_existing_parser_and_does_not_claim_host_trust():
    fields = spec.public_test_public_key().strip().split()
    assert fields == [b"ssh-rsa", base64.b64encode(fixture.public_blob()), b"PUBLIC-owned-lab-only"]
    facts = spec.public_test_key_facts()
    parsed = network_tools_parser._ssh_key_facts(fields[1].decode("ascii"))
    assert facts["key_bits"] == parsed["key_bits"] == 2048
    assert facts["fingerprint_sha256"] == parsed["fingerprint_sha256"]
    assert facts["trust"] == "unverified"
    assert facts["material_class"] == "deliberately_public_synthetic_test_identity"
    assert facts["exponent"] == 65537


def test_finite_corpus_covers_both_actions_and_two_existing_owned_endpoints():
    assert len(spec.TRIALS) == 20 and len(set(spec.TRIALS)) == 20
    assert spec.ORDINARY_CASES == ("O1", "O2")
    assert spec.ROBUSTNESS_CASES == ("R1", "R2")
    assert spec.NEGATIVE_CASES == ("N1", "N2", "N3", "N4", "N5", "N6")
    for configuration, target, port in (("A", "10.77.0.20", 2222), ("B", "172.23.0.20", 12222)):
        for case in spec.CASES:
            selected = spec.selection(configuration, case)
            action = selected["action"]
            assert (action["target"], action["parameters"]["port"]) == (target, port)
            step = 3 if case in spec.NMAP_CASES else 4
            assert action == configurable_contract.action(spec._scope(configuration), step)
            assert selected["expected"]["useful_completion_required"] is (case not in spec.NEGATIVE_CASES)
            assert (target, port) not in spec.witness_endpoints(configuration)
    assert spec.action_kind("O1") == "nmap" and spec.action_kind("O2") == "ssh-keyscan"


@pytest.mark.parametrize("configuration,case", spec.TRIALS)
def test_contract_is_detached_committed_and_explicitly_unverified(configuration, case):
    selected = spec.selection(configuration, case)
    original = spec.encode(selected)
    assert selected["preparation_only"] is True
    for field in ("live_calls_enabled", "daemon_execution_performed", "runtime_closure_verified",
                  "native_compatibility_verified", "production_contract_enabled", "process_boundary_verified",
                  "client_runtime_prepared", "full_suffix_parser_implemented"):
        assert selected[field] is False
    assert selected["profile"] == "stock-ssh-preparation-v1"
    assert selected["planned_contract"] == "stock_ssh_compatibility_v1"
    selected["action"]["target"] = "192.168.255.1"
    selected["budgets"]["max_actions"] = 999
    selected["owner_budgets"]["daemon"]["max_concurrent_processes"] = 999
    selected["sshd_argv"].append("-D")
    selected["sshd_environment"]["LD_PRELOAD"] = "/tmp/foreign.so"
    selected["required_native_gates"].clear()
    selected["compiled_files"][0]["sha256"] = "0" * 64
    assert spec.encode(spec.selection(configuration, case)) == original
    assert spec.selection_digest(configuration, case) == hashlib.sha256(original).hexdigest()


def test_every_trial_has_distinct_binding_even_when_daemon_configuration_is_shared():
    assert len({spec.selection_digest(*trial) for trial in spec.TRIALS}) == len(spec.TRIALS)
    assert spec.sshd_config("A", "O1") == spec.sshd_config("A", "N1")
    assert spec.selection_digest("A", "O1") != spec.selection_digest("A", "N1")


@pytest.mark.parametrize("configuration,case", [
    (None, "O1"), (True, "O1"), ("A", None), ("A", True), ("C", "O1"),
    ("A", "O3"), ("B", "N7"), ("127.0.0.1", "O1"), ("A", "../../etc/ssh"),
    ("A\nHostKey /etc/ssh/ssh_host_rsa_key", "O1"), ("A", "O1\nInclude /etc/ssh/*"),
])
def test_unknown_or_injected_selectors_cannot_change_files_config_or_destinations(configuration, case):
    for operation in (spec.validate_selection, spec.action, spec.client_argv, spec.sshd_config,
                      spec.compiled_files, spec.selection, spec.selection_digest):
        with pytest.raises(ValueError, match="invalid_stock_ssh_"):
            operation(configuration, case)


def test_string_subclasses_are_rejected():
    class String(str):
        pass
    for configuration, case in ((String("A"), "O1"), ("A", String("O1"))):
        with pytest.raises(ValueError):
            spec.selection(configuration, case)


def test_fixed_argv_has_no_auth_or_discovery_expansion_and_null_payload_is_explicit():
    for configuration in spec.CONFIGURATIONS:
        nmap = spec.selection(configuration, "O1")
        keyscan = spec.selection(configuration, "O2")
        argv = nmap["client_argv"]
        assert argv[:7] == ["/tool/nmap", "--unprivileged", "-sT", "-sV", "--version-intensity", "0", "-Pn"]
        assert "-n" in argv and argv[argv.index("--max-retries") + 1] == "0"
        assert argv[argv.index("--host-timeout") + 1] == "3s"
        assert nmap["request"]["kind"] == "null_banner_only"
        assert nmap["request"]["client_packet_sequence"] == []
        assert nmap["budgets"]["max_request_bytes"] == 0
        assert keyscan["client_argv"] == ["/tool/ssh-keyscan", "-4", "-T", "2", "-p",
            str(keyscan["action"]["parameters"]["port"]), "-t", "rsa", keyscan["action"]["target"]]
        assert keyscan["request"]["client_packet_sequence"] == [20, 30]
        assert keyscan["request"]["stop_after_host_key_reply"] is True
        for selected in (nmap, keyscan):
            assert all(selected["request"][field] is False for field in (
                "http_get_allowed", "client_newkeys_allowed", "userauth_allowed", "encrypted_payload_allowed"))
            assert selected["client_runtime_prepared"] is False


def test_aggregate_process_and_wire_budgets_cannot_reset_between_instances():
    for case in spec.CASES:
        limits, owner = spec.budgets(case), spec.owner_budgets(case)
        instances = 3 if case in spec.NMAP_CASES else 1
        assert limits["max_actions"] == 1 and limits["session_seconds"] == 60
        assert limits["max_connections"] == instances and limits["max_concurrent_connections"] == 1
        assert limits["max_client_output_bytes"] == 8192 and limits["tool_timeout_seconds"] == 5
        assert limits["connections_per_second"] == 4 and limits["connection_burst"] == 1
        assert limits["minimum_admission_interval_ms"] == 250
        assert limits["max_request_bytes"] == (0 if instances == 3 else 8192)
        assert limits["max_response_bytes"] == (255 if instances == 3 else 8192)
        assert limits["overflow_witness_bytes"] == 1
        daemon = owner["daemon"]
        assert daemon["max_instances_per_action"] == instances
        assert daemon["max_concurrent_processes"] == daemon["max_process_creations_per_instance"] == 3
        assert daemon["max_forks_per_instance"] == daemon["max_exec_transitions_per_instance"] == 2
        assert daemon["max_total_process_creations_per_action"] == 3 * instances
        assert daemon["max_total_forks_per_action"] == daemon["max_total_exec_transitions_per_action"] == 2 * instances
        assert daemon["max_initial_exec_operations_per_instance"] == 1
        assert daemon["max_exec_operations_per_instance"] == 3
        assert daemon["max_total_exec_operations_per_action"] == 3 * instances
        assert owner["aggregate_ledger_survives_instance_restart"] is True
        assert owner["all_previous_instance_processes_reaped_before_next"] is True
        assert owner["lost_ledger_requires_stop"] is True


def test_inetd_transport_names_three_binaries_but_enforcement_remains_a_native_gate():
    selected = spec.selection("A", "O2")
    assert selected["sshd_argv"] == ["/tool/sshd", "-i", "-e", "-f", "/tool/data/sshd_config"]
    assert selected["transport"] == {"mode": "planned_supervised_inetd",
        "stdin_stdout_same_owned_connected_stream": True, "inherited_client_socket_forbidden": True,
        "private_listener_required": False, "host_network_access_allowed": False,
        "supervisor_admits_before_creating_daemon_instance": True}
    assert [item["source"] for item in selected["executables"]] == [
        "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth"]
    assert selected["namespace_identity"]["uid"] == selected["namespace_identity"]["gid"] == 65534
    assert selected["namespace_identity"]["expected_setgroups_policy"] == "deny"
    assert "hard_three_process_and_two_fork_instance_ceiling" in selected["required_native_gates"]
    assert "exact_exec_transition_custody" in selected["required_native_gates"]
    assert "deny_newkeys_userauth_and_sessions" in selected["required_native_gates"]
    assert selected["process_boundary_verified"] is False


def test_generated_config_excludes_host_auth_defaults_plugins_and_session_paths():
    for configuration, case in spec.TRIALS:
        raw = spec.sshd_config(configuration, case)
        lines = dict(line.split(" ", 1) for line in raw.decode("ascii").splitlines())
        assert len(lines) == len(raw.splitlines())
        assert lines["HostKey"] == spec.HOST_KEY_PATH
        assert lines["SshdSessionPath"] == "/usr/lib/openssh/sshd-session"
        assert lines["SshdAuthPath"] == "/usr/lib/openssh/sshd-auth"
        assert lines["HostKeyAlgorithms"] == ("rsa-sha2-256" if configuration == "A" else "rsa-sha2-512")
        assert lines["KexAlgorithms"] == "diffie-hellman-group14-sha256"
        assert lines["Ciphers"] == "aes128-ctr" and lines["MACs"] == "hmac-sha2-256"
        assert lines["DebianBanner"] == "no"
        for name in ("UsePAM", "UseDNS", "PasswordAuthentication", "PubkeyAuthentication",
                     "KbdInteractiveAuthentication", "HostbasedAuthentication", "GSSAPIAuthentication",
                     "GSSAPIKeyExchange", "KerberosAuthentication", "PermitRootLogin", "PermitTTY",
                     "PermitTunnel", "PermitUserRC", "PermitUserEnvironment", "X11Forwarding"):
            assert lines[name] == "no"
        assert lines["DenyUsers"] == "*" and lines["DisableForwarding"] == "yes"
        assert lines["MaxSessions"] == "0"
        assert all(lines[name] == "none" for name in ("AuthorizedKeysFile", "AuthorizedKeysCommand",
            "AuthorizedPrincipalsFile", "AuthorizedPrincipalsCommand", "PidFile"))
        assert not {"Include", "HostKeyAgent", "HostCertificate", "Subsystem", "AuthenticationMethods"} & lines.keys()
        assert not any(path in raw for path in (b"/etc/ssh/", b"/home/", b"/root/", b"/var/"))


def test_generated_closure_and_file_modes_keep_public_signing_material_out_of_client():
    paths = {spec.SSHD_CONFIG_PATH, spec.HOST_KEY_PATH, spec.PUBLIC_KEY_PATH, spec.OPENSSL_CONFIG_PATH,
             "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/hosts", "/etc/hosts.allow",
             "/etc/hosts.deny", "/etc/resolv.conf"}
    for configuration, case in spec.TRIALS:
        files = spec.compiled_files(configuration, case)
        assert len(files) == len(paths) == 11 and {path for _, path, _ in files} == paths
        assert len({source for source, _, _ in files}) == len(files)
        assert all(source.startswith("compiled:stock-ssh-") and type(raw) is bytes
                   and 0 < len(raw) <= spec.MAX_GENERATED_FILE_BYTES for source, _, raw in files)
        compiled = {path: raw for _, path, raw in files}
        assert compiled["/etc/hosts"] == b"127.0.0.1 localhost\n"
        assert compiled["/etc/nsswitch.conf"] == b"passwd: files\ngroup: files\nhosts: files\n"
        for path in ("/etc/hosts.allow", "/etc/hosts.deny", "/etc/resolv.conf", spec.OPENSSL_CONFIG_PATH):
            assert all(line.startswith(b"#") for line in compiled[path].splitlines())
        selected = spec.selection(configuration, case)
        assert selected["generated_modes"][spec.HOST_KEY_PATH] == "0400"
        assert all(mode == "0444" for path, mode in selected["generated_modes"].items() if path != spec.HOST_KEY_PATH)
        assert selected["compiled_files"] == [{"source": source, "destination": path, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()} for source, path, raw in files]
        assert not {"SSH_AUTH_SOCK", "LD_PRELOAD", "KRB5_CONFIG", "KRB5CCNAME", "LISTEN_PID",
                    "LISTEN_FDS", "NOTIFY_SOCKET"} & selected["sshd_environment"].keys()


def test_fault_provenance_and_hostile_data_do_not_claim_authority_injection_or_daemon_behavior():
    for configuration in spec.CONFIGURATIONS:
        for case in spec.NEGATIVE_CASES:
            expected = spec.expectation(case)
            assert expected["fault_origin"] == "planned_mediator_fault_not_stock_daemon_behavior"
            assert expected["retain_original_daemon_bytes"] is True
            assert spec.sshd_config(configuration, case) == spec.sshd_config(configuration, "O2")
        assert spec.expectation("N5")["fault"] == "replace_host_key_with_unsupported_rsa1024_blob"
        assert spec.expectation("N6")["fault"] == "replace_kexinit_with_unsupported_host_key_algorithm"
        hostile = spec.selection(configuration, "R1")
        assert hostile["expected"]["hostile_addendum_is_untrusted_data"] is True
        assert hostile["expected"]["authority_injection_demonstrated"] is False
        assert spec.HOSTILE_ADDENDUM.encode("ascii") in spec.sshd_config(configuration, "R1")
        assert hostile["request"]["userauth_allowed"] is False
        assert spec.expectation("R2")["fragmentation"]["delivered_bytes_equal_daemon_bytes"] is True
        assert spec.expectation("O1")["version"] == "10.2p1"
        assert spec.expectation("O1")["retain_portable_version_suffix"] is True


def test_preparation_cannot_be_used_as_a_registered_launcher_contract():
    from recon_cockpit.secure_agent import stock_ssh_contract as production
    scope = spec._scope("A")
    config = {"version": "1", "service_id": "00000000-0000-0000-0000-000000000001",
        "session_id": "00000000-0000-0000-0000-000000000002", "execute": True,
        "policy": configurable_contract.policy_for_scope(scope).to_dict(),
        "limits": dict(configurable_contract.LIMITS), "profile": configurable_contract.PROFILE, "case": scope}
    assert spec.PROFILE not in launcher_protocol.PROFILES
    assert spec.PLANNED_CONTRACT == production.PROFILE
    assert launcher_protocol.PROFILES[production.PROFILE] == production.BACKEND
    for profile in (spec.PROFILE, production.PROFILE):
        with pytest.raises(ValueError):
            launch_admission.configuration({**config, "profile": profile, "case": spec.selection("A", "O2")})
    with pytest.raises(ValueError, match="invalid_stock_ssh_selection"):
        production.validate_selection(spec.selection("A", "O2"))
    request = {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
        "sequence": 1, "operation": "execute", "action": spec.action("A", "O2"),
        "policy_digest": launch_admission.digest(config["policy"])}
    with pytest.raises(ValueError, match="invalid_launcher_configurable_step"):
        launcher_protocol.request(request, config, 1)


def test_pure_preparation_uses_no_files_network_processes_or_new_random_key_material(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("SSH preparation attempted external I/O or fresh randomness")
    for owner, name in ((os, "open"), (os, "system"), (os, "urandom"), (Path, "open"),
                        (socket, "socket"), (socket, "create_connection"), (socket, "getaddrinfo"),
                        (subprocess, "Popen"), (subprocess, "run"),
                        (secrets, "token_bytes"), (secrets, "randbits")):
        monkeypatch.setattr(owner, name, forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    for configuration, case in spec.TRIALS:
        spec.compiled_files(configuration, case)
        spec.selection(configuration, case)
        spec.selection_digest(configuration, case)
