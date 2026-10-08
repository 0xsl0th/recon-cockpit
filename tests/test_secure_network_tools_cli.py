"""New lab mode is opt-in and cannot bypass its mandatory launch gates."""
import json
from pathlib import Path

import pytest
from recon_cockpit.secure_agent import cli

GATES = ['--owned-lab','--isolated-audit','--isolated-approvals','--isolated-launch-admission',
         '--isolated-launcher','--require-launch-audit','--require-launch-approval']


def arguments(tmp_path, case="dig-ok"):
    policy = "tls-certificate" if case.startswith("tls-cert-") else "ssh-algorithms" if case.startswith("ssh-algos-") else "snmp-next" if case.startswith("snmp-next-") else "http-options" if case.startswith("http-options-") else "dns-axfr" if case.startswith("dig-axfr-") else "dns-nsid" if case.startswith("dig-nsid-") else "ftp-starttls" if case.startswith("ftp-tls-") else "ldap-starttls" if case.startswith("ldap-tls-") else "smtp-starttls" if case.startswith("smtp-tls-") else "smb2-negotiation" if case.startswith("smb2-") else "rdp-negotiation" if case.startswith("rdp-") else "dns-srv" if case.startswith("dig-srv-") else "whatweb" if case.startswith("whatweb-") else "database-tls" if case.startswith(("postgresql-tls-", "mysql-tls-")) else "redis-snmp" if case.startswith(("redis-", "snmp-")) else "kerberos" if case.startswith("kerberos-") else "nmap-service" if case.startswith("nmap-service-") else "docker-winrm" if case.startswith(("docker-", "winrm-")) else "ftp-smtp" if case.startswith(("ftp-", "smtp-")) else "rpc-nfs" if case.startswith(("rpc-", "nfs-")) else "smb" if case.startswith("smb-") else "ssh-ldap" if case.startswith(("ssh-", "ldap-")) else "network-tools"
    return ['--network-tool-assessment',case,'--assessment-dir',str(tmp_path/'evidence'),
            '--audit',str(tmp_path/'audit.jsonl'),'--policy','examples/secure-agent-' + policy + '-policy.json']


@pytest.mark.parametrize('case', ['dig-ok', 'ssh-ok', 'ldap-ok', 'smb-ok', 'rpc-ok', 'nfs-ok', 'ftp-ok', 'smtp-ok',
    'docker-ping-ok', 'docker-version-ok', 'winrm-ok', 'nmap-service-http', 'kerberos-ok', 'redis-ok', 'snmp-ok', 'postgresql-tls-ok', 'mysql-tls-ok', 'whatweb-ok', 'dig-srv-ok', 'rdp-tls', 'smb2-21-optional', 'smtp-tls-ok', 'ldap-tls-ok', 'ftp-tls-ok', 'dig-nsid-ok', 'dig-axfr-ok', 'http-options-ok', 'snmp-next-ok', 'ssh-algos-ok', 'tls-cert-ok'])
@pytest.mark.parametrize('missing',GATES)
def test_each_launch_gate_required_before_side_effects(tmp_path,missing,case):
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path, case),*(gate for gate in GATES if gate!=missing)])
    assert error.value.code==2
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('option,value',[('--session-max-steps','2'),('--session-max-seconds','61'),
    ('--session-max-output-bytes','8193'),('--session-max-seconds','0')])
def test_overrides_cannot_expand_profile(tmp_path,option,value):
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path),*GATES,option,value])
    assert error.value.code==2
    assert not list(tmp_path.iterdir())


def test_owned_network_tools_policy_keeps_fresh_approval():
    value=json.loads(Path('examples/secure-agent-network-tools-policy.json').read_text())
    assert value['require_approval'] is True
    assert value['allowed_targets']==['127.0.0.1/32']
    assert value['allowed_ports']==[8080]
    assert value['allowed_tools']==['dig_dns_query_v1','openssl_tls_handshake_v1']


@pytest.mark.parametrize('flag',['--assessment-planning-offline','--assessment-planning-owned-tls'])
def test_existing_provider_profiles_cannot_be_selected(tmp_path,flag):
    from recon_cockpit.secure_agent.assessment_planning_contract import SCENARIOS
    from recon_cockpit.secure_agent.assessment_planning_tls_contract import SCENARIOS as TLS
    scenario=next(iter(TLS if flag.endswith('tls') else SCENARIOS))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path),*GATES,flag,scenario])
    assert error.value.code==2
    assert not list(tmp_path.iterdir())


def test_owned_ssh_ldap_policy_keeps_fresh_approval_and_separate_scope():
    value=json.loads(Path('examples/secure-agent-ssh-ldap-policy.json').read_text())
    assert value['require_approval'] is True
    assert value['allowed_targets']==['127.0.0.1/32']
    assert value['allowed_ports']==[8080]
    assert value['allowed_tools']==['ssh_host_keys_v1','ldap_rootdse_v1']


def test_owned_smb_policy_requires_fresh_approval_and_only_share_metadata():
    value=json.loads(Path('examples/secure-agent-smb-policy.json').read_text())
    assert value['require_approval'] is True
    assert value['allowed_targets']==['127.0.0.1/32']
    assert value['allowed_ports']==[8080]
    assert value['allowed_tools']==['smb_share_list_v1']


def test_owned_rpc_nfs_policy_requires_fresh_approval_and_fixed_endpoint():
    value=json.loads(Path('examples/secure-agent-rpc-nfs-policy.json').read_text())
    assert value['require_approval'] is True
    assert value['allowed_targets']==['127.0.0.1/32']
    assert value['allowed_ports']==[111]
    assert value['allowed_tools']==['rpcinfo_dump_v1','showmount_exports_v1']


def test_shipped_ftp_smtp_policy_keeps_fresh_approval_and_fixed_scope():
    value = json.loads(Path('examples/secure-agent-ftp-smtp-policy.json').read_text())
    assert value['require_approval'] is True and value['approval_ttl_seconds'] == 60
    assert value['allowed_targets'] == ['127.0.0.1/32'] and value['allowed_ports'] == [8080]
    assert value['allowed_tools'] == ['curl_ftp_list_v1', 'curl_smtp_capabilities_v1']
    assert value['max_timeout_seconds'] == 5 and value['max_output_bytes'] == 8192


def test_shipped_docker_winrm_policy_keeps_fresh_approval_and_metadata_only_scope():
    value = json.loads(Path('examples/secure-agent-docker-winrm-policy.json').read_text())
    assert value['require_approval'] is True and value['approval_ttl_seconds'] == 60
    assert value['allowed_targets'] == ['127.0.0.1/32'] and value['allowed_ports'] == [8080]
    assert value['allowed_tools'] == ['curl_docker_ping_v1', 'curl_docker_version_v1', 'curl_winrm_metadata_v1']
    assert value['allowed_methods'] == ['GET']
    assert value['max_timeout_seconds'] == 5 and value['max_output_bytes'] == 8192
