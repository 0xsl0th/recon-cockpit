"""Apache preparation retains the corpus and cannot grant execution authority."""

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from recon_cockpit.secure_agent import configurable_contract, configurable_workflow
from recon_cockpit.secure_agent import launch_admission, launcher_protocol, tool_catalog
from recon_cockpit.secure_agent import stock_apache_spec as apache, stock_http_spec as http


def test_same_corpus_retains_exact_actions_requests_useful_work_and_hard_limits():
    assert apache.TRIALS == http.TRIALS and len(apache.TRIALS) == 26
    categories = []
    for configuration, case in apache.TRIALS:
        selected = apache.selection(configuration, case)
        categories.append(selected["expected"]["category"])
        assert selected["action"] == http.action(configuration, case)
        assert apache.request_bytes(configuration, case) == http.request_bytes(configuration, case)
        assert selected["budgets"] == http.budgets(case)
        assert selected["owner_budgets"] == http.owner_budgets()
        assert selected["expected"] == http.expectation(case)
        assert selected["request"] == http.selection(configuration, case)["request"]
        assert selected["denied_destinations"] == http.selection(configuration, case)["denied_destinations"]
    assert tuple(categories.count(category) for category in ("ordinary", "robustness", "negative")) == (12, 4, 10)


def test_selectors_cannot_supply_directives_endpoints_paths_or_unreviewed_cases():
    class String(str):
        pass
    invalid = [(None, "O1"), (True, "O1"), (String("A"), "O1"), ("A", String("O1")),
               ("127.0.0.1:8080", "O1"), ("A\nInclude /etc/apache2/apache2.conf", "O1"),
               ("B", "O7"), ("B", "N6"), ("A", "../../etc/passwd"), ("A", None)]
    for configuration, case in invalid:
        for operation in (apache.validate_selection, apache.action, apache.request_bytes,
                          apache.apache_config, apache.compiled_files, apache.selection, apache.selection_digest):
            with pytest.raises(ValueError):
                operation(configuration, case)


def test_selection_is_detached_distinct_and_explicitly_unverified():
    selected = apache.selection("A", "O1")
    pristine = apache.encode(selected)
    assert selected["profile"] != http.PROFILE
    assert selected["planned_contract"] == "stock_http_compatibility_v1"
    assert all(selected[field] is False for field in (
        "live_calls_enabled", "daemon_execution_performed", "runtime_closure_verified",
        "native_compatibility_verified", "production_contract_enabled"))
    selected["action"]["target"] = "10.77.0.99"
    selected["apache_argv"].append("-DUNREVIEWED")
    selected["apache_environment"]["LD_PRELOAD"] = "/tmp/unsafe.so"
    selected["modules"][0]["source"] = "/tmp/unsafe.so"
    selected["budgets"]["max_requests"] = 100
    selected["owner_budgets"]["daemon"]["max_processes"] = 100
    assert apache.encode(apache.selection("A", "O1")) == pristine
    assert apache.selection_digest("A", "O1") == hashlib.sha256(pristine).hexdigest()
    assert apache.action("A", "O1") == apache.action("A", "R1")
    assert len({apache.selection_digest(*pair) for pair in apache.TRIALS}) == 26
    assert all(apache.selection_digest(*pair) != http.selection_digest(*pair) for pair in apache.TRIALS)


def test_private_listener_and_nonzero_identity_are_proposed_without_enlarging_client_scope():
    for configuration in apache.CONFIGURATIONS:
        selected = apache.selection(configuration, "O1")
        assert selected["namespace_identity"] == {"uid": 65534, "gid": 65534}
        assert selected["private_daemon_endpoint"] == {"transport": "tcp", "target": "127.0.0.1", "port": 19080}
        assert selected["action"]["target"] != "127.0.0.1"
        assert selected["action"]["parameters"]["port"] != 19080
        config = apache.apache_config(configuration, "O1")
        assert config.count(b"Listen ") == 1
        assert b"Listen 127.0.0.1:19080 http\n" in config
        assert b"User reconlab\nGroup reconlab\n" in config
        assert b"ServerLimit 1\nMaxRequestWorkers 1\n" in config
        assert selected["apache_argv"] == ["/tool/apache2", "-X", "-d", "/scratch", "-f", "/tool/data/apache2.conf"]
        assert selected["apache_environment"] == {"LC_ALL": "C", "MALLOC_ARENA_MAX": "1", "TZ": "UTC0"}
    public = {path: raw for _, path, raw in apache.compiled_files("A", "O1")}
    assert public["/etc/passwd"] == b"reconlab:x:65534:65534:Owned lab:/nonexistent:/nonexistent\n"
    assert public["/etc/group"] == b"reconlab:x:65534:\n"
    assert public["/etc/nsswitch.conf"] == b"passwd: files\ngroup: files\n"


def test_generated_configuration_loads_only_closed_modules_and_public_files():
    expected_modules = ("mpm_prefork", "authz_core", "headers", "alias")
    assert apache.APACHE_MODULES == tuple((name + "_module", "/usr/lib/apache2/modules/mod_" + name + ".so",
        "/tool/modules/mod_" + name + ".so") for name in expected_modules)
    paths = {"/tool/data/apache2.conf", "/tool/public/root.html", "/tool/public/selected.html",
             "/etc/passwd", "/etc/group", "/etc/nsswitch.conf"}
    for configuration, case in apache.TRIALS:
        compiled = apache.compiled_files(configuration, case)
        assert len(compiled) == len(paths) and {path for _, path, _ in compiled} == paths
        assert all(source.startswith("compiled:stock-apache-") and type(raw) is bytes
                   and 0 < len(raw) <= 8192 for source, _, raw in compiled)
        config = apache.apache_config(configuration, case)
        assert config.count(b"LoadModule ") == 4
        assert b"AllowOverride None\n" in config and b"Options None\n" in config
        assert b"ForceType text/html\n" in config and b"AddDefaultCharset UTF-8\n" in config
        assert not any(value in config for value in (
            b"Include ", b"IncludeOptional ", b"/etc/apache2", b"/var/", b"ProxyPass", b"ScriptAlias",
            b"CustomLog", b"TransferLog", b"mod_ssl", b"mod_mime", b"mod_dir", b"mod_cgi"))
        listed = apache.selection(configuration, case)["compiled_files"]
        assert listed == [{"source": source, "destination": path, "size": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest()} for source, path, raw in compiled]


@pytest.mark.parametrize("configuration", apache.CONFIGURATIONS)
def test_faults_preserve_real_original_response_and_hostile_content_stays_in_public_file(configuration):
    ordinary = apache.apache_config(configuration, "O1")
    assert ordinary == apache.apache_config(configuration, "R2")
    assert all(apache.apache_config(configuration, case) == ordinary for case in apache.NEGATIVE_CASES)
    assert b"Header always set Content-Security-Policy" in ordinary
    assert b"Header always set X-Frame-Options \"DENY\"" in ordinary
    assert b"Header always set X-Content-Type-Options \"nosniff\"" in ordinary
    assert b"Header always set" not in apache.apache_config(configuration, "O2")
    hostile = {path: raw for _, path, raw in apache.compiled_files(configuration, "R1")}
    assert hostile[apache.SELECTED_FILE] == http.HOSTILE_BODY
    assert http.HOSTILE_BODY not in hostile[apache.APACHE_CONFIG_PATH]
    assert hostile[apache.ROOT_FILE] == http.ORDINARY_BODY
    for case in apache.NEGATIVE_CASES:
        assert apache.expectation(case)["retain_original_daemon_response"] is True
        assert apache.expectation(case)["validated_requests_delivered_to_daemon"] == 1


@pytest.mark.parametrize("configuration", apache.CONFIGURATIONS)
def test_error_and_redirect_cases_use_local_public_error_content_and_unfollowed_other_target(configuration):
    files = {path: raw for _, path, raw in apache.compiled_files(configuration, "O3")}
    config = files[apache.APACHE_CONFIG_PATH]
    target = apache.action(configuration, "O3")["parameters"]["path"]
    assert apache.PUBLIC_ROOT + target not in files
    assert b'ErrorDocument 404 "/__owned_error.html"\n' in config
    assert b'AliasMatch "^/__owned_error\\.html$" "/tool/public/selected.html"\n' in config
    assert files[apache.SELECTED_FILE] == http.ORDINARY_BODY
    assert apache.expectation("O3")["headers"]["status_code"] == 404
    other = apache.action("B" if configuration == "A" else "A", "O1")
    redirect = apache.apache_config(configuration, "O4")
    destination = f'"http://{other["target"]}:{other["parameters"]["port"]}/"\n'.encode("ascii")
    assert b"RedirectMatch 302 " in redirect and destination in redirect
    assert apache.expectation("O4")["redirect_followup_allowed"] is False
    assert apache.response_body("O4") is None


def test_advertising_changes_only_the_server_token_setting():
    for configuration in apache.CONFIGURATIONS:
        assert apache.apache_config(configuration, "O6") == apache.apache_config(configuration, "O5").replace(
            b"ServerTokens Full\n", b"ServerTokens Prod\n")
        assert apache.expectation("O5")["version_advertising"] is True
        assert apache.expectation("O6")["version_advertising"] is False
        assert apache.expectation("O6")["invented_version_allowed"] is False


def test_preparation_cannot_be_admitted_as_a_launcher_mode_or_skip_workflow_predecessor():
    scope = http._scope("A")
    config = {"version": "1", "service_id": "00000000-0000-0000-0000-000000000001",
        "session_id": "00000000-0000-0000-0000-000000000002", "execute": True,
        "policy": configurable_contract.policy_for_scope(scope).to_dict(),
        "limits": dict(configurable_contract.LIMITS), "profile": configurable_contract.PROFILE, "case": scope}
    assert apache.PROFILE not in launcher_protocol.PROFILES
    assert apache.PLANNED_CONTRACT in launcher_protocol.PROFILES
    # Registering the separate production contract cannot turn preparation
    # metadata or the configurable workflow policy into launch authority.
    for profile in (apache.PROFILE, apache.PLANNED_CONTRACT):
        with pytest.raises(ValueError):
            launch_admission.configuration({**config, "profile": profile, "case": apache.selection("A", "O1")})
    request = {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
        "sequence": 1, "operation": "execute", "action": apache.action("A", "O1"),
        "policy_digest": launch_admission.digest(config["policy"])}
    with pytest.raises(ValueError, match="invalid_launcher_configurable_step"):
        launcher_protocol.request(request, config, 1)


def test_preparation_never_opens_files_networks_or_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Apache preparation attempted external I/O")
    for owner, name in ((os, "open"), (os, "system"), (Path, "open"),
                        (socket, "socket"), (socket, "create_connection"), (socket, "getaddrinfo"),
                        (subprocess, "Popen"), (subprocess, "run")):
        monkeypatch.setattr(owner, name, forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    for configuration, case in apache.TRIALS:
        apache.compiled_files(configuration, case)
        apache.selection(configuration, case)
        apache.selection_digest(configuration, case)


def test_accepted_catalog_and_configurable_cards_remain_byte_identical():
    # Pinned accepted catalog/configurable projection from main before S3.2.
    scopes = [json.loads((Path("examples") / name).read_bytes()) for name in (
        "secure-agent-configurable-scope.json", "secure-agent-configurable-scope-alternate.json")]
    catalog = tool_catalog.list_tools()
    assert tuple(catalog[key] for key in ('capability_count', 'accepted_capability_count',
        'candidate_capability_count', 'external_program_count')) == (55, 52, 3, 17)
    assert {row['tool_id'] for row in catalog['tools'] if row.get('acceptance_status') == 'candidate'} == {
        'owned_name_dns_v1', 'owned_name_http_v1', 'owned_name_tls_v1'}
    catalog['tools'] = [row for row in catalog['tools'] if row['tool_id'] not in (
        'owned_name_dns_v1', 'owned_name_http_v1', 'owned_name_tls_v1')]
    catalog.update(capability_count=52, accepted_capability_count=52,
                   candidate_capability_count=0, external_program_count=17)
    assert len(catalog['tools']) == 52
    projected = {"catalog": catalog,
        "descriptions": {row["tool_id"]: tool_catalog.describe_tool(row["tool_id"]) for row in catalog["tools"]},
        "configurable": [{"descriptor": configurable_contract.capability_descriptor(scope),
                          "card": configurable_workflow.card_identity(scope)} for scope in scopes]}
    assert catalog["accepted_capability_count"] == 52 and catalog["candidate_capability_count"] == 0
    assert hashlib.sha256(apache.encode(projected)).hexdigest() == "51c20322f4b2ac0c9ebd8027c682775501a2564c4039aa7349f46cc6f7b1ea3a"
