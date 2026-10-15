"""Closed name-binding proposals commit their inputs without doing native work."""

from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess

import pytest

from recon_cockpit.secure_agent import name_tls_spec as spec
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_tls_certificate_material as material


def files(configuration="A", case="O1"):
    return {destination: raw for _, destination, raw in spec.compiled_files(configuration, case)}


def test_exact_23_case_46_selection_inventory_and_driver_partition():
    assert spec.CONFIGURATIONS == ("A", "B")
    assert spec.CASES == ("O1", "O2", "O3", "O4", "O5", "R1", "R2",
                          "N1", "N2", "N3", "N4", "N5", "N6", "N7", "N8",
                          "N9", "N10", "N11", "N12", "N13", "N14", "N15", "N16")
    assert len(spec.TRIALS) == len(set(spec.TRIALS)) == 46
    expected_drivers = {**dict.fromkeys(("O1", "O2", "O3", "O4", "O5", "R1", "N2", "N3", "N5", "N11", "N12", "N13", "N16"), "stock_daemon_configuration"),
                        **dict.fromkeys(("R2", "N6", "N7", "N8"), "bounded_wire_transform"),
                        **dict.fromkeys(("N1", "N4", "N9", "N10", "N14", "N15"), "authority_owner_probe")}
    assert {case: spec.driver("A", case)["kind"] for case in spec.CASES} == expected_drivers
    categories = [spec.expectation(configuration, case)["category"] for configuration, case in spec.TRIALS]
    assert (categories.count("ordinary"), categories.count("robustness"), categories.count("negative")) == (10, 4, 32)


class Text(str):
    pass


@pytest.mark.parametrize("configuration,case", [
    (None, "O1"), (True, "O1"), ({}, "O1"), (1, "O1"), (Text("A"), "O1"),
    ("a", "O1"), ("10.77.0.10", "O1"), ("/etc/dnsmasq.conf", "O1"),
    ("A", None), ("A", Text("O1")), ("A", True), ("A", "O6"), ("A", "N17"),
    ("A", "N4\ninclude /etc/private"), ("A", ["O1"]), ("A", "harbordesk.test"),
])
def test_selectors_reject_other_values_types_and_config_injection(configuration, case):
    for operation in (spec.selection, spec.selection_digest, spec.compiled_files,
                      spec.operations, spec.expectation, spec.driver, spec.dns_argv,
                      spec.tls_argv, spec.request_bytes, spec.dnsmasq_config, spec.nginx_config):
        with pytest.raises(ValueError):
            operation(configuration, case)


@pytest.mark.parametrize("configuration,case", spec.TRIALS)
def test_detached_json_and_complete_file_and_operation_commitments(configuration, case):
    original = spec.selection(configuration, case)
    assert json.loads(spec.encode(original)) == original
    assert spec.selection_digest(configuration, case) == hashlib.sha256(spec.encode(original)).hexdigest()
    assert original["native_execution"] == original["runtime_closure"] == "unverified"
    assert original["preparation_only"] is True
    for flag in ("live_calls_enabled", "native_execution_performed", "runtime_closure_verified", "configuration_validation_performed"):
        assert original[flag] is False
    assert "action" not in original and "grant" not in original and "tool_id" not in original
    actual_files = spec.compiled_files(configuration, case)
    assert len(actual_files) == len({path for _, path, _ in actual_files}) == len({source for source, _, _ in actual_files}) == 10
    for row, (source, destination, raw) in zip(original["compiled_files"], actual_files, strict=True):
        assert type(raw) is bytes and 0 < len(raw) <= 8192
        assert (row["source"], row["destination"], row["size"], row["sha256"]) == (
            source, destination, len(raw), hashlib.sha256(raw).hexdigest())
    changed = deepcopy(original)
    changed["endpoints"]["allowed_service_addresses"].append("127.0.0.1")
    changed["operations"][0]["environment"]["LD_PRELOAD"] = "private.so"
    changed["compiled_files"][0]["sha256"] = "0" * 64
    changed["driver"]["kind"] = "caller_selected_driver"
    assert spec.selection(configuration, case) == original
    assert hashlib.sha256(spec.encode(changed)).hexdigest() != spec.selection_digest(configuration, case)


def test_equal_daemon_bytes_still_bind_different_probe_and_transform_expectations():
    assert len({spec.selection_digest(configuration, case) for configuration, case in spec.TRIALS}) == 46
    baseline = files()
    for case in ("O2", "O3", "O4", "R2", "N1", "N4", "N6", "N7", "N8", "N9", "N10", "N15"):
        assert files(case=case) == baseline
        assert spec.selection_digest("A", case) != spec.selection_digest("A", "O1")
    # Mutating expectations, independently of generated-file hashes, changes the commitment.
    selected = spec.selection("A", "N15")
    selected["driver"]["probe"]["attempts"].pop()
    assert hashlib.sha256(spec.encode(selected)).hexdigest() != spec.selection_digest("A", "N15")


@pytest.mark.parametrize("configuration,resolver,dns_port,service,http_port,path,tls_port,excluded", [
    ("A", "10.77.0.53", 5353, "10.77.0.10", 8080, "/harbordesk/portal.html", 8443, "10.77.0.99"),
    ("B", "172.23.0.53", 15353, "172.23.0.10", 18080, "/portal/index.html", 18443, "172.23.0.99"),
])
def test_exact_numeric_endpoints_dns_tcp_question_named_http_and_verified_tls_inputs(
        configuration, resolver, dns_port, service, http_port, path, tls_port, excluded):
    selected = spec.selection(configuration, "O4")
    assert selected["endpoints"] == {"resolver": {"target": resolver, "port": dns_port, "transport": "tcp"},
        "http": {"target": service, "port": http_port, "path": path}, "tls": {"target": service, "port": tls_port},
        "excluded_address": excluded, "allowed_service_addresses": [service]}
    dns, http, tls = selected["operations"]
    assert dns["argv"] == ["/tool/dig", "-r", "-4", "@" + resolver, "-p", str(dns_port), "harbordesk.test.", "IN", "A",
        "+tcp", "+norecurse", "+noedns", "+nocookie", "+nosearch", "+noadflag", "+nocdflag", "+tries=1", "+retry=0", "+time=2",
        "+noall", "+question", "+answer", "+authority", "+additional", "+comments", "+stats"]
    assert dns["question"] == {"name": "harbordesk.test.", "class": "IN", "type": "A"}
    assert dns["udp_fallback"] is dns["search"] is dns["recursion"] is False
    expected_http = f"GET {path} HTTP/1.1\r\nHost: harbordesk.test:{http_port}\r\nConnection: close\r\n\r\n".encode("ascii")
    assert spec.request_bytes(configuration, "O4") == expected_http
    assert http["request"] == {"ascii": expected_http.decode("ascii"), "bytes": len(expected_http), "sha256": hashlib.sha256(expected_http).hexdigest()}
    assert http["follow_redirects"] is False
    assert tls["argv"] == ["/tool/openssl", "s_client", "-4", "-connect", f"{service}:{tls_port}", "-servername", "harbordesk.test",
        "-verify_hostname", "harbordesk.test", "-verify_return_error", "-CAfile", spec.CA_PATH, "-no-CApath", "-no-CAstore",
        "-no_ticket", "-no_renegotiation", "-nocommands", "-groups", "P-256", "-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-brief"]
    assert tls["stdin"]["bytes"] == tls["application_input_bytes"] == 0
    assert tls["reconnect"] is tls["session_resumption"] is tls["certificate_directed_fetch"] is False
    for operation in selected["operations"]:
        assert operation["proposal_only"] is operation["separate_explicit_authorization_required"] is True
        assert operation["automatic_execution"] is False
        assert operation["environment"] == {"LC_ALL": "C", "MALLOC_ARENA_MAX": "1", "OPENSSL_CONF": spec.OPENSSL_CONFIG_PATH, "TZ": "UTC0"}


@pytest.mark.parametrize("configuration", spec.CONFIGURATIONS)
def test_resolver_closed_records_no_host_lookup_cache_upstream_or_extra_services(configuration):
    target = spec.endpoints(configuration)
    for case in spec.CASES:
        raw = spec.dnsmasq_config(configuration, case)
        lines = raw.decode("ascii").splitlines()
        assert {"no-resolv", "no-hosts", "no-poll", "cache-size=0", "no-negcache", "bind-interfaces", "local=/test/"} <= set(lines)
        assert [line for line in lines if line.startswith("listen-address=")] == ["listen-address=" + target["resolver"]["target"]]
        assert [line for line in lines if line.startswith("port=")] == ["port=" + str(target["resolver"]["port"])]
        assert not any(line.startswith(prefix) for line in lines for prefix in (
            "server=", "rev-server=", "resolv-file=", "addn-hosts=", "conf-file=", "conf-dir=", "conf-script=", "servers-file=",
            "dhcp-", "enable-tftp", "enable-dbus", "dnssec", "nftset=", "ipset=", "expand-hosts", "domain="))
    baseline = spec.dnsmasq_config(configuration, "O1")
    assert f"host-record=harbordesk.test,{target['http']['target']},60\n".encode() in baseline
    excluded = spec.dnsmasq_config(configuration, "N2")
    assert f"host-record=harbordesk.test,{target['excluded_address']},60\n".encode() in excluded
    assert target["http"]["target"].encode() not in excluded
    ambiguous = spec.dnsmasq_config(configuration, "N3")
    records = [line for line in ambiguous.splitlines() if line.startswith(b"host-record=")]
    assert set(records) == {f"host-record=harbordesk.test,{address},60".encode() for address in (target["http"]["target"], target["excluded_address"])}
    cname = spec.dnsmasq_config(configuration, "N5")
    assert b"cname=harbordesk.test,alias.harbordesk.test,60\n" in cname
    assert b"host-record=harbordesk.test," not in cname
    ttl_one = spec.dnsmasq_config(configuration, "N14")
    assert ttl_one == baseline.replace(b"local-ttl=60\n", b"local-ttl=1\n").replace(b",60\n", b",1\n")
    changed = {path for path in files(configuration) if files(configuration)[path] != files(configuration, "N14")[path]}
    assert changed == {spec.DNSMASQ_CONFIG_PATH}
    assert spec.driver(configuration, "N14")["stock_daemon_bytes"] == "baseline_except_dns_ttl_1"


@pytest.mark.parametrize("configuration,case", spec.TRIALS)
def test_nginx_exact_raw_host_default_sni_and_protocol_context_are_explicit(configuration, case):
    raw = spec.nginx_config(configuration, case)
    target = spec.endpoints(configuration)
    assert f'if ($http_host != "harbordesk.test:{target["http"]["port"]}") {{ return 421; }}'.encode() in raw
    assert b"$host" not in raw
    assert b"ssl_reject_handshake on;" in raw
    assert b"ssl_ecdh_curve prime256v1;" in raw
    assert b"ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;" in raw
    assert b"ssl_session_tickets off;" in raw and b"ssl_session_cache off;" in raw and b"ssl_early_data off;" in raw
    assert raw.index(b"ssl_protocols ") < raw.index(b"  server {")
    assert raw.count(b"ssl_protocols ") == 1
    assert (b"ssl_protocols TLSv1.2;" if case == "N16" else b"ssl_protocols TLSv1.3;") in raw
    assert (b"TLSv1.3" if case == "N16" else b"TLSv1.2") not in raw
    assert not any(word in raw for word in (b"include ", b"load_module ", b"resolver ", b"proxy_pass ", b"root ", b"alias "))
    assert b"access_log off;" in raw and b"return 444;" in raw
    if case == "O5":
        assert spec.expectation(configuration, case)["location_metadata"].encode() in raw
    if case == "R1":
        assert spec.HOSTILE_BODY.encode() in raw


def test_c15_public_material_is_exact_and_private_key_is_owner_only():
    assert fixture.TLS_CERTIFICATE_CA_PEM != fixture.CA_PEM
    variants = {"O1": "tls-cert-ok", "N11": "tls-cert-wrong-name", "N12": "tls-cert-untrusted", "N13": "tls-cert-expired"}
    for case, original in variants.items():
        generated = files(case=case)
        assert generated[spec.CA_PATH] == fixture.TLS_CERTIFICATE_CA_PEM
        assert generated[spec.SERVER_KEY_PATH] == material.SERVER_KEY_PEM
        cert = generated[spec.SERVER_CERTIFICATE_PATH]
        assert cert == material.certificate_for_case(original)
        assert hashlib.sha256(cert).hexdigest() == fixture.TLS_CERTIFICATE_CERT_SHA256[original]
        der = ssl.PEM_cert_to_DER_cert(cert.decode("ascii"))
        assert hashlib.sha256(der).hexdigest() == fixture.TLS_CERTIFICATE_DER_SHA256[original]
        # ASN.1 OID 1.2.840.10045.3.1.7: the existing public prime256v1 key.
        assert bytes.fromhex("06082a8648ce3d030107") in der
        selected = spec.selection("A", case)
        key_row = next(row for row in selected["compiled_files"] if row["destination"] == spec.SERVER_KEY_PATH)
        assert key_row["scope"] == "owner_only"
        assert material.SERVER_KEY_PEM.decode("ascii") not in spec.encode(selected).decode("ascii")
        assert generated["/etc/resolv.conf"].strip() == generated[spec.OPENSSL_CONFIG_PATH].strip() == b""


@pytest.mark.parametrize("configuration", spec.CONFIGURATIONS)
def test_recorder_transform_templates_have_exact_framing_question_and_closed_rdata(configuration):
    target = spec.endpoints(configuration)
    for case, counts in (("N6", (1, 0, 1, 1)), ("N7", (1, 1, 0, 0)), ("N8", (1, 1, 0, 0))):
        transform = spec.driver(configuration, case)["transformation"]
        frame = bytes.fromhex(transform["frame_template_hex"])
        declared = struct.unpack_from("!H", frame)[0]
        assert len(frame) == transform["frame_bytes"]
        assert hashlib.sha256(frame).hexdigest() == transform["frame_template_sha256"]
        assert frame[2:4] == b"\0\0" and transform["copy_request_transaction_id_to_frame_offsets"] == [2, 3]
        assert struct.unpack_from("!HHHH", frame, 6) == counts
        assert frame[14:35] == b"\x0aharbordesk\x04test\0\0\x01\0\x01"
        assert declared == len(frame) - 2 + int(case == "N8")
        assert transform["close_after_frame"] is True and transform["frames"] == 1
        assert transform["udp_fallback"] is False and transform["additional_queries"] == 0
        if case == "N6":
            assert frame.endswith(ipaddress.IPv4Address(target["excluded_address"]).packed)
            assert b"\x02ns\x0aharbordesk\x04test\0" in frame
        elif case == "N7":
            assert struct.unpack_from("!H", frame, 37)[0] == 28
            assert frame.endswith(ipaddress.IPv6Address("2001:db8::99").packed)
    segmented = spec.driver(configuration, "R2")["transformation"]
    assert segmented["split_offsets"] == [1, 2, 13] and segmented["writes"] == 4
    assert segmented["delivered_bytes_equal_daemon_bytes"] is True


def test_authority_probes_pin_changed_answer_expiry_and_both_replay_classes():
    changed = spec.selection("A", "N1")
    probe = changed["driver"]["probe"]
    assert probe["first_observation"] == {"answers": ["10.77.0.10"], "ttl": 60}
    assert probe["second_observation"] == {"answers": ["10.77.0.99"], "ttl": 60}
    assert probe["old_binding_invalidated"] is probe["fresh_review_and_authority_required"] is True
    assert probe["max_dns_queries"] == changed["expected"]["max_dns_queries"] == 2
    assert [row["operation"] for row in changed["operations"]] == ["dns", "dns", "http"]
    changed["operations"][0]["environment"]["LC_ALL"] = "wrong"
    assert changed["operations"][1]["environment"]["LC_ALL"] == "C"
    undeclared = spec.selection("A", "N4")
    assert undeclared["driver"]["probe"]["proposed_question"] == "other.harbordesk.test. IN A"
    assert undeclared["expected"]["max_dns_queries"] == 0
    host = spec.driver("A", "N9")["probe"]
    assert "Host: other.harbordesk.test:8080\r\n" in host["proposed_request"]["ascii"]
    assert host["delivered_http_requests"] == 0
    sni = spec.driver("A", "N10")["probe"]["proposed_argv"]
    assert sni[sni.index("-servername") + 1] == "other.harbordesk.test"
    assert sni[sni.index("-verify_hostname") + 1] == "harbordesk.test"
    expiry = spec.driver("B", "N14")["probe"]
    assert expiry["clock"] == "owner_monotonic" and expiry["observed_ttl_seconds"] == 1
    assert expiry["synthetic_clock_advance_allowed"] is expiry["refresh_observation_allowed"] is False
    replay = spec.driver("B", "N15")["probe"]
    assert replay["attempts"] == [{"kind": "finished_owner_binding_and_grant", "configuration": "B"},
        {"kind": "cross_configuration_grant", "grant_configuration": "A", "requested_configuration": "B"}]
    assert replay["destination_change_allowed"] is False


def test_no_negative_case_or_refusal_can_claim_useful_tls_or_extra_delivery():
    for case in spec.CASES:
        expected = spec.expectation("A", case)
        assert expected["automatic_followups"] == expected["advertised_destinations_contacted"] == expected["ipv6_transports"] == expected["udp_queries"] == 0
        assert expected["refusal_is_useful_execution"] is False
        if case in spec.NEGATIVE_CASES:
            assert expected["useful_tls_claim_allowed"] is False
            assert expected["max_http_requests_delivered"] == 0
            assert expected["max_tls_handshakes_started"] == int(case in ("N11", "N12", "N13", "N16"))
    assert [op["operation"] for op in spec.operations("A", "O1")] == ["dns"]
    assert [op["operation"] for op in spec.operations("A", "O4")] == ["dns", "http", "tls"]
    policy = spec.selection("A", "O4")["binding_policy"]
    assert policy["expires_at"] == "min(owner_deadline, observation_monotonic + min(observed_ttl, 60))"
    assert policy["observation_creates_authority"] is policy["caller_or_wall_clock_refresh_allowed"] is False


def test_preparation_has_no_external_io_execution_or_authority_side_effects(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("pure name/TLS preparation attempted external I/O or authority")
    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    from recon_cockpit.secure_agent.models import Action
    monkeypatch.setattr(Action, "__init__", forbidden)
    for configuration, case in spec.TRIALS:
        spec.selection(configuration, case)
        spec.selection_digest(configuration, case)
        spec.compiled_files(configuration, case)


def test_preparation_profile_is_absent_from_accepted_catalog():
    from recon_cockpit.secure_agent import tool_catalog
    catalog = tool_catalog.list_tools()
    assert catalog["accepted_capability_count"] == 52 and catalog["candidate_capability_count"] == 0
    assert spec.PROFILE not in json.dumps(catalog)


def test_canonical_encoding_rejects_non_json_and_nonfinite_inputs():
    assert spec.encode({"z": 1, "a": [True, None]}) == b'{"a":[true,null],"z":1}'
    with pytest.raises(ValueError):
        spec.encode({"not_finite": float("nan")})
    with pytest.raises(TypeError):
        spec.encode({"raw_bytes": b"not json"})
