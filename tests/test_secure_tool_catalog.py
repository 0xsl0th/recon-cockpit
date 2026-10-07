"""The operator catalog describes accepted contracts without granting authority."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import tool_catalog as catalog
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.tool_adapters import ADAPTERS


# Capability names and program families are the accepted coverage inventory,
# independently of how the catalog happens to assemble its rows.
PROGRAMS = {
    "tcp_connect": None, "http_probe": None, "http_headers_v1": None,
    "nmap_tcp_connect_v1": "nmap", "nmap_service_identify_v1": "nmap",
    "curl_https_get_v1": "curl", "curl_ftp_list_v1": "curl",
    "curl_smtp_capabilities_v1": "curl", "curl_docker_ping_v1": "curl",
    "curl_docker_version_v1": "curl", "curl_winrm_metadata_v1": "curl",
    "ffuf_content_discovery_v1": "ffuf", "dig_dns_query_v1": "dig",
    "openssl_tls_handshake_v1": "openssl", "ssh_host_keys_v1": "ssh-keyscan",
    "ldap_rootdse_v1": "ldapsearch", "smb_share_list_v1": "smbclient",
    "rpcinfo_dump_v1": "rpcinfo", "showmount_exports_v1": "showmount",
    "kerbrute_userenum_v1": "kerbrute",
    "redis_server_info_v1": "redis-cli", "snmp_system_get_v1": "snmpget",
    "configurable_nmap_service_v1": "nmap", "configurable_http_headers_v1": None,
    "configurable_ssh_host_keys_v1": "ssh-keyscan",
}
NORMAL_NETWORK_CASES = {
    "dig_dns_query_v1": ("dig-ok", "network-tools"),
    "openssl_tls_handshake_v1": ("openssl-ok", "network-tools"),
    "ssh_host_keys_v1": ("ssh-ok", "ssh-ldap"),
    "ldap_rootdse_v1": ("ldap-ok", "ssh-ldap"),
    "smb_share_list_v1": ("smb-ok", "smb"),
    "rpcinfo_dump_v1": ("rpc-ok", "rpc-nfs"),
    "showmount_exports_v1": ("nfs-ok", "rpc-nfs"),
    "curl_ftp_list_v1": ("ftp-ok", "ftp-smtp"),
    "curl_smtp_capabilities_v1": ("smtp-ok", "ftp-smtp"),
    "curl_docker_ping_v1": ("docker-ping-ok", "docker-winrm"),
    "curl_docker_version_v1": ("docker-version-ok", "docker-winrm"),
    "curl_winrm_metadata_v1": ("winrm-ok", "docker-winrm"),
    "nmap_service_identify_v1": ("nmap-service-http", "nmap-service"),
    "kerbrute_userenum_v1": ("kerberos-ok", "kerberos"),
    "redis_server_info_v1": ("redis-ok", "redis-snmp"),
    "snmp_system_get_v1": ("snmp-ok", "redis-snmp"),
}
GATES = {"--owned-lab", "--isolated-audit", "--isolated-approvals",
         "--isolated-launch-admission", "--isolated-launcher",
         "--require-launch-audit", "--require-launch-approval"}
ROOT = Path(__file__).resolve().parents[1]


def accepted_recipe(tool):
    """Use the existing action constructors as an oracle, not catalog helpers."""
    if tool.startswith("configurable_"):
        from recon_cockpit.secure_agent import configurable_contract as contract
        scope_file = "examples/secure-agent-configurable-scope.json"
        scope = json.loads((ROOT / scope_file).read_text())
        return ("--configurable-assessment", scope_file, "configurable", contract.WORKFLOW,
                [contract.action(scope, step) for step in range(1, 5)], contract.LIMITS)
    if tool in NORMAL_NETWORK_CASES:
        from recon_cockpit.secure_agent import network_tools_contract as contract
        case, policy = NORMAL_NETWORK_CASES[tool]
        return ("--network-tool-assessment", case, policy, contract.WORKFLOW,
                [contract.action(case)], contract.LIMITS)
    if tool in {"curl_https_get_v1", "ffuf_content_discovery_v1"}:
        from recon_cockpit.secure_agent import web_tools_contract as contract
        case = "curl-ok" if tool == "curl_https_get_v1" else "ffuf-normal"
        return ("--web-tool-assessment", case, "web-tools", contract.WORKFLOW,
                [contract.action(case)], contract.LIMITS)
    if tool == "nmap_tcp_connect_v1":
        from recon_cockpit.secure_agent import nmap_contract as contract
        return ("--nmap-assessment", "a", "nmap", contract.WORKFLOW,
                [contract.action("a", step) for step in (1, 2, 3)], contract.LIMITS)
    if tool == "http_headers_v1":
        from recon_cockpit.secure_agent import http_headers_contract as contract
        return ("--http-headers-assessment", "vulnerable", "http-headers", contract.WORKFLOW,
                [contract.action("vulnerable", step) for step in (1, 2)], contract.LIMITS)
    from recon_cockpit.secure_agent.discovery_contract import discovery_action
    from recon_cockpit.secure_agent.evaluation_contract import FIXED_LIMITS
    from recon_cockpit.secure_agent.owned_lab_contract import capability_descriptor
    assert tool in {"tcp_connect", "http_probe"}
    return ("--workflow-assessment", "a", "discovery", capability_descriptor()["workflow_id"],
            [discovery_action("a", step) for step in (1, 2, 3)], FIXED_LIMITS)


def public_action(value, step):
    return {"step": step, **{key: value[key] for key in ("tool_id", "target", "parameters")}}


def test_inventory_contains_each_accepted_capability_once_without_counting_curl_modes_as_programs():
    result = catalog.list_tools()
    assert result["schema_version"] == "1" and result["catalog_id"] == "bundled-secure-tools-v1"
    assert result["read_only"] is True and result["live_calls_enabled"] is False
    assert result["runtime_availability"] == "not_checked"
    ids = [row["tool_id"] for row in result["tools"]]
    assert ids == sorted(PROGRAMS) == sorted(ADAPTERS)
    assert result["capability_count"] == len(ids) == 25
    families = {row["external_program"] for row in result["tools"] if row["external_program"] is not None}
    assert families == set(PROGRAMS.values()) - {None}
    assert result["external_program_count"] == len(families) == 13
    for row in result["tools"]:
        tool = row["tool_id"]
        adapter = ADAPTERS[tool]
        assert row["external_program"] == PROGRAMS[tool]
        assert row["implementation"] == ("native" if PROGRAMS[tool] is None else "external_program")
        assert (row["effect"], row["execution_profile"], row["parser_version"]) == (
            adapter.effect, adapter.execution_profile, adapter.parser_version)


@pytest.mark.parametrize("tool", sorted(PROGRAMS))
def test_owned_actions_parameters_and_session_budgets_match_the_existing_contract(tool):
    result = catalog.describe_tool(tool)
    selector, case, policy_name, workflow, actions, limits = accepted_recipe(tool)
    assert result["read_only"] is True and result["live_calls_enabled"] is False
    assert result["adapter"] == ADAPTERS[tool].to_dict()
    assert result["external_program"] == PROGRAMS[tool]
    selected = [value["parameters"] for value in actions if value["tool_id"] == tool]
    assert result["fixed_parameters"] == selected
    selected_action = next(value for value in actions if value["tool_id"] == tool)
    assert result["owned_scope"] == {"target": selected_action["target"], "port": selected[0]["port"], "owned_lab_only": True}
    run = result["run"]
    assert (run["selector"], run["case"], run["workflow_id"]) == (selector, case, workflow)
    assert run["actions"] == [public_action(value, step) for step, value in enumerate(actions, 1)]
    assert run["session_limits"] == limits
    assert len(actions) <= limits["max_steps"]
    assert sum(value["parameters"]["max_output_bytes"] for value in actions) <= limits["max_output_bytes"]
    assert run["policy"] == f"examples/secure-agent-{policy_name}-policy.json"
    policy = parse_policy(json.loads((ROOT/run["policy"]).read_text()))
    for value in actions:
        assert policy.evaluate(parse_action(value)).decision == "approval_required"
    assert (ROOT/run["runbook"]).is_file()


@pytest.mark.parametrize("tool,sequence", [
    ("tcp_connect", ["tcp_connect", "http_probe", "http_probe"]),
    ("http_probe", ["tcp_connect", "http_probe", "http_probe"]),
    ("nmap_tcp_connect_v1", ["nmap_tcp_connect_v1", "http_probe", "http_probe"]),
    ("http_headers_v1", ["nmap_tcp_connect_v1", "http_headers_v1"]),
])
def test_existing_multi_action_recipes_disclose_every_tool_and_distinguish_action_from_session_limits(tool, sequence):
    value = catalog.describe_tool(tool)
    run = value["run"]
    assert [action["tool_id"] for action in run["actions"]] == sequence
    assert run["action_count"] == len(sequence)
    assert set(run["tool_ids"]) == set(sequence)
    assert run["session_limits"]["max_output_bytes"] > max(p["max_output_bytes"] for p in value["fixed_parameters"])
    assert run["session_limits"]["max_runtime_seconds"] > max(p["timeout_seconds"] for p in value["fixed_parameters"])


@pytest.mark.parametrize("tool", sorted(PROGRAMS))
def test_recipe_is_explicitly_dry_run_uses_all_gates_and_inert_fresh_paths(tool):
    run = catalog.describe_tool(tool)["run"]
    argv = run["dry_run_argv"]
    assert argv[:3] == ["python", "-m", "recon_cockpit.secure_agent"]
    assert all(type(value) is str for value in argv)
    assert argv[argv.index(run["selector"])+1] == run["case"]
    assert argv[argv.index("--policy")+1] == run["policy"]
    assert "--dry-run" in argv and "--execute" not in argv
    assert GATES <= set(argv)
    assert not any(flag in argv for flag in ("--routed", "--fixture", "--proposal", "--openai-model"))
    audit = argv[argv.index("--audit")+1]
    evidence = argv[argv.index("--assessment-dir")+1]
    assert "<NEW-" in audit and "<NEW-" in evidence and audit != evidence
    assert all(argv.count(flag) == 1 for flag in GATES | {"--dry-run", "--policy", "--audit", "--assessment-dir"})


def test_syntax_schema_does_not_pretend_to_authorize_broader_ports_names_or_http_methods():
    kerberos = catalog.describe_tool("kerbrute_userenum_v1")
    assert kerberos["adapter"]["parameters"]["properties"]["port"]["maximum"] == 65535
    assert kerberos["fixed_parameters"] == [{"port":8080,"timeout_seconds":5,"max_output_bytes":8192}]
    http = catalog.describe_tool("http_probe")
    assert http["adapter"]["parameters"]["properties"]["method"]["enum"] == ["GET", "HEAD"]
    assert {value["method"] for value in http["fixed_parameters"]} == {"GET"}
    assert {value["path"] for value in http["fixed_parameters"]} == {
        "/assessment/a/index.json", "/assessment/a/diagnostics.json"}


def test_kerberos_description_retains_upstream_spoof_ambiguity_and_unauthenticated_report_semantics():
    value = catalog.describe_tool("kerbrute_userenum_v1")
    limits = " ".join(value["limitations"]).lower()
    assert "tool report" in limits or "tool_report_only" in limits
    assert "existence" in limits and "absence" in limits
    assert "spoof" in limits or "error text" in limits or "error-text" in limits
    assert "password" in limits and "ticket" in limits
    assert "no_followup_to_metadata" in value["adapter"]["execution_requirements"]


@pytest.mark.parametrize("tool,terms", [
    ("smb_share_list_v1", ("empty", "denied", "inconclusive")),
    ("nmap_service_identify_v1", ("unidentified", "not no service")),
    ("ssh_host_keys_v1", ("fingerprint", "identity", "trust")),
    ("ffuf_content_discovery_v1", ("eight", "partial", "wildcard")),
    ("http_headers_v1", ("hardening", "not proof of exploitability")),
])
def test_catalog_preserves_accepted_result_limitations(tool, terms):
    limitations = " ".join(catalog.describe_tool(tool)["limitations"]).lower()
    assert all(term in limitations for term in terms)


@pytest.mark.parametrize("tool", [None, True, 1, [], {}, "", "nmap", "kerbrute", "shell",
                                      "http_probe\n--execute", "HTTP_PROBE", "http_probe "])
def test_unknown_or_untyped_ids_do_not_select_a_capability(tool):
    with pytest.raises(ValueError, match="^unknown_catalog_tool$"):
        catalog.describe_tool(tool)


def test_every_return_is_detached_and_deterministically_json_serializable():
    original = json.dumps(catalog.list_tools(), sort_keys=True, ensure_ascii=True, allow_nan=False)
    listing = catalog.list_tools()
    listing["tools"][0]["tool_id"] = "arbitrary"
    listing["tools"].clear()
    assert json.dumps(catalog.list_tools(), sort_keys=True, ensure_ascii=True, allow_nan=False) == original
    for tool in PROGRAMS:
        value = catalog.describe_tool(tool)
        expected = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)
        value["adapter"]["parameters"]["properties"]["port"]["maximum"] = 1
        value["fixed_parameters"][0]["port"] = 1
        value["run"]["actions"][0]["parameters"]["port"] = 1
        value["run"]["session_limits"]["max_steps"] = 100
        value["run"]["dry_run_argv"].append("--execute")
        value["limitations"].clear()
        assert json.dumps(catalog.describe_tool(tool), sort_keys=True, ensure_ascii=True, allow_nan=False) == expected


def test_catalog_import_and_queries_are_portable_read_only_and_do_not_load_execution_dependencies(tmp_path):
    script = r'''
import json, os, pathlib, shutil, sys
sys.path.insert(0, sys.argv[1])
def no_availability_probe(*args, **kwargs):
    raise AssertionError("catalog attempted runtime availability detection")
shutil.which = no_availability_probe
pathlib.Path.exists = no_availability_probe
pathlib.Path.is_file = no_availability_probe
pathlib.Path.is_dir = no_availability_probe
def guard(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")):
        raise AssertionError("catalog attempted execution or networking: " + event)
    if event in {"os.system", "os.mkdir", "os.remove", "os.rename", "os.rmdir", "os.chmod", "os.chown"}:
        raise AssertionError("catalog attempted mutation: " + event)
    if event == "open":
        path, mode, flags = args
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError("catalog attempted a file write")
        if isinstance(path, str) and not path.endswith((".py", ".pyc")):
            raise AssertionError("catalog read runtime or user data: " + path)
sys.addaudithook(guard)
from recon_cockpit.secure_agent import tool_catalog
listing = tool_catalog.list_tools()
details = [tool_catalog.describe_tool(row["tool_id"]) for row in listing["tools"]]
for name in sys.modules:
    if name.startswith("recon_cockpit."):
        assert not any(fragment in name for fragment in (
            "_runtime", "_backend", "_worker", "launcher", "approval", "controller", "evidence", "runner")), name
assert not any("readiness" in row or "installed" in row for row in details)
print(json.dumps({"list":listing,"details":details},sort_keys=True,ensure_ascii=True,allow_nan=False))
'''
    completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script, str(ROOT)],
                               cwd=tmp_path, capture_output=True, text=True, timeout=15,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert completed.returncode == 0, completed.stderr
    assert not completed.stderr and not list(tmp_path.iterdir())
    result = json.loads(completed.stdout)
    assert result["list"] == catalog.list_tools()
    assert result["details"] == [catalog.describe_tool(tool) for tool in sorted(PROGRAMS)]
