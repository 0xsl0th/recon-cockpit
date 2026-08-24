from __future__ import annotations

from datetime import UTC, datetime

import pytest

from recon_cockpit.models import CaseState, Credential, Host, Service
from recon_cockpit.suggestions import (
    build_suggestions,
    classify_services,
    group_suggestions,
    shell_join,
)


def case_with(*services: Service, credentials: list[Credential] | None = None) -> CaseState:
    timestamp = datetime.now(UTC).isoformat()
    return CaseState(
        target="10.10.11.123",
        created_at=timestamp,
        updated_at=timestamp,
        services=list(services),
        credentials=credentials or [],
    )


def service(
    port: int,
    name: str,
    *,
    product: str = "",
    version: str = "",
    extra_info: str = "",
    tunnel: str = "",
    protocol: str = "tcp",
    state: str = "open",
    scripts: dict[str, str] | None = None,
) -> Service:
    return Service(
        host="10.10.11.123",
        port=port,
        protocol=protocol,
        state=state,
        name=name,
        product=product,
        version=version,
        extra_info=extra_info,
        tunnel=tunnel,
        scripts=scripts or {},
    )


def test_smb_options_are_absent_without_smb_evidence() -> None:
    suggestions = build_suggestions(
        case_with(service(22, "ssh"), service(8000, "http-alt"))
    )

    assert "smb" not in {suggestion.category for suggestion in suggestions}
    flattened = [part for suggestion in suggestions for part in suggestion.argv]
    assert "smbclient" not in flattened
    assert "smb" not in flattened
    assert "--rid-brute" not in flattened


def test_http_is_not_inferred_from_an_unrelated_open_port() -> None:
    suggestions = build_suggestions(case_with(service(31337, "unknown")))

    assert "http" not in {suggestion.category for suggestion in suggestions}


@pytest.mark.parametrize(
    "web_service,expected_url",
    [
        (service(80, "unknown"), "http://10.10.11.123"),
        (service(8443, "unknown", tunnel="ssl"), "https://10.10.11.123:8443"),
        (
            service(12345, "unknown", product="Microsoft-IIS/10.0"),
            "http://10.10.11.123:12345",
        ),
    ],
)
def test_http_evidence_creates_both_ready_content_commands(
    web_service: Service, expected_url: str
) -> None:
    commands = [
        item
        for item in build_suggestions(case_with(web_service))
        if item.category == "http"
    ]

    assert {item.argv[0] for item in commands} == {"feroxbuster", "ffuf"}
    assert all(expected_url in item.argv for item in commands if item.argv[0] == "feroxbuster")
    assert any(f"{expected_url}/FUZZ" in item.argv for item in commands)
    ferox = next(item for item in commands if item.argv[0] == "feroxbuster")
    ffuf = next(item for item in commands if item.argv[0] == "ffuf")
    assert not any("{" in part for part in ferox.argv)
    assert "{wordlist}" in ffuf.argv


@pytest.mark.parametrize(
    "observed,category,executable",
    [
        (service(22, "ssh", product="OpenSSH"), "ssh", "ssh-keyscan"),
        (service(21, "ftp", product="vsftpd"), "ftp", "curl"),
        (service(111, "rpcbind"), "nfs_rpc", "nmap"),
        (service(2049, "nfs"), "nfs_rpc", "nmap"),
        (service(53, "domain"), "dns", "nmap"),
        (service(25, "smtp", product="Postfix"), "smtp", "nmap"),
        (service(2375, "http", product="Docker daemon"), "docker", "curl"),
    ],
)
def test_linux_unix_services_create_evidence_gated_enumeration(
    observed: Service, category: str, executable: str
) -> None:
    suggestions = build_suggestions(case_with(observed))
    commands = [item for item in suggestions if item.category == category]

    assert commands
    assert any(command.argv[0] == executable for command in commands)
    assert all(command.active for command in commands)


def test_docker_api_is_not_mistaken_for_a_generic_web_content_target() -> None:
    suggestions = build_suggestions(
        case_with(service(2375, "http", product="Docker daemon 27.0"))
    )
    categories = {item.category for item in suggestions}

    assert "docker" in categories
    assert "http" not in categories


def test_sftp_and_docker_registry_do_not_trigger_wrong_workflows() -> None:
    suggestions = build_suggestions(
        case_with(
            service(2222, "sftp"),
            service(5000, "http", product="Docker Registry"),
        )
    )
    categories = {item.category for item in suggestions}

    assert "ftp" not in categories
    assert "docker" not in categories
    assert "http" in categories


def test_nfs_export_command_queries_rpcbind_instead_of_nfs_data_port() -> None:
    commands = [
        item
        for item in build_suggestions(case_with(service(2049, "nfs")))
        if item.category == "nfs_rpc"
    ]

    assert commands[0].argv == (
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "-p",
        "111",
        "--script",
        "nfs-showmount",
        "10.10.11.123",
    )


def test_alternate_service_ports_receive_version_detection_for_nse_rules() -> None:
    suggestions = build_suggestions(
        case_with(
            service(2222, "ssh"),
            service(2121, "ftp"),
            service(2525, "smtp"),
            service(32767, "mountd"),
        )
    )
    nmap_commands = [
        item.argv
        for item in suggestions
        if item.category in {"ssh", "ftp", "smtp", "nfs_rpc"}
        and item.argv[0] == "nmap"
    ]

    assert len(nmap_commands) == 4
    assert all(command[1:4] == ("-Pn", "-sT", "-sV") for command in nmap_commands)
    assert {command[command.index("-p") + 1] for command in nmap_commands} == {
        "2121",
        "2222",
        "2525",
        "32767",
    }


def test_alternate_port_ftps_uses_an_encrypted_curl_url() -> None:
    command = next(
        item
        for item in build_suggestions(case_with(service(2990, "ftps")))
        if item.category == "ftp" and item.argv[0] == "curl"
    )

    assert command.argv[-1] == "ftps://10.10.11.123:2990/"
    assert "--insecure" in command.argv


def test_remote_script_output_cannot_reclassify_an_http_service() -> None:
    suggestions = build_suggestions(
        case_with(
            service(
                8080,
                "http",
                scripts={"http-title": "Docker API Postfix vsftpd documentation"},
            )
        )
    )
    categories = {item.category for item in suggestions}

    assert "http" in categories
    assert not ({"docker", "ftp", "smtp"} & categories)


def test_iis_winrm_and_smb_produce_windows_adjusted_flow() -> None:
    services = [
        service(80, "http", product="Microsoft-IIS/10.0"),
        service(445, "microsoft-ds", product="Microsoft Windows Server 2019"),
        service(5985, "wsman", product="Microsoft HTTPAPI httpd 2.0"),
    ]
    profile = classify_services(services)
    suggestions = build_suggestions(case_with(*services))
    groups = {group.key: group for group in group_suggestions(suggestions)}

    assert profile.probable_windows is True
    assert profile.windows_stack is True
    assert {"http", "smb", "winrm", "nmap_standard", "nmap_deep"} <= groups.keys()
    assert any(command.argv[0:2] == ("nxc", "smb") for command in groups["smb"].commands)
    assert any(command.argv[0] == "smbclient" for command in groups["smb"].commands)
    assert any("--rid-brute" in command.argv for command in groups["smb"].commands)
    assert "IIS, SMB, and WinRM" in groups["winrm"].evidence
    assert any("probable Windows" in command.description for command in groups["smb"].commands)


def test_winrm_transport_is_not_treated_as_a_content_discovery_target() -> None:
    suggestions = build_suggestions(
        case_with(
            service(5985, "http", product="Microsoft HTTPAPI httpd 2.0"),
        )
    )

    assert "winrm" in {item.category for item in suggestions}
    assert "http" not in {item.category for item in suggestions}


def test_ldap_and_kerberos_suggestions_use_clear_placeholders() -> None:
    suggestions = build_suggestions(
        case_with(service(389, "ldap"), service(88, "kerberos-sec"))
    )
    by_category = {group.key: group for group in group_suggestions(suggestions)}

    ldap = by_category["ldap"].commands
    kerberos = by_category["kerberos"].commands
    assert ldap[0].argv[0] == "ldapsearch"
    assert "" in ldap[0].argv  # RootDSE uses an intentionally empty base DN.
    assert len(ldap) == 2
    assert "{base_dn}" in ldap[1].argv
    assert "(|(objectClass=user)(objectClass=group))" in ldap[1].argv
    assert "{domain}" in kerberos[0].argv
    assert "{user_file}" in kerberos[0].argv
    assert "{password}" not in kerberos[0].argv


def test_credentials_are_only_suggested_when_known_and_supported() -> None:
    smb = service(445, "microsoft-ds")
    without_credentials = build_suggestions(case_with(smb))
    with_credentials = build_suggestions(
        case_with(smb, credentials=[Credential(username="alice", secret="secret")])
    )

    assert "credentials" not in {item.category for item in without_credentials}
    credential_commands = [
        item for item in with_credentials if item.category == "credentials"
    ]
    assert credential_commands
    assert "{local_username}" in credential_commands[0].argv
    assert "{local_password}" in credential_commands[0].argv
    assert "--local-auth" in credential_commands[0].argv
    assert "{domain}" not in credential_commands[0].argv
    assert "secret" not in credential_commands[0].argv


def test_domain_and_local_credentials_get_matching_netexec_modes() -> None:
    suggestions = build_suggestions(
        case_with(
            service(445, "microsoft-ds"),
            credentials=[
                Credential(username="alice", secret="one", domain="CORP.LOCAL"),
                Credential(username="localadmin", secret="two"),
            ],
        )
    )
    commands = [item.argv for item in suggestions if item.category == "credentials"]

    assert any("{domain}" in command and "--local-auth" not in command for command in commands)
    assert any("--local-auth" in command and "{domain}" not in command for command in commands)


def test_username_without_a_secret_does_not_offer_credential_testing() -> None:
    suggestions = build_suggestions(
        case_with(
            service(22, "ssh"),
            credentials=[Credential(username="alice")],
        )
    )

    assert "credentials" not in {item.category for item in suggestions}


def test_known_invalid_credential_is_not_suggested_for_retesting() -> None:
    suggestions = build_suggestions(
        case_with(
            service(445, "microsoft-ds"),
            credentials=[
                Credential(username="alice", secret="wrong", status="invalid")
            ],
        )
    )

    assert "credentials" not in {item.category for item in suggestions}


def test_known_credential_can_be_tested_via_interactive_ssh_prompt() -> None:
    suggestions = build_suggestions(
        case_with(
            service(22, "ssh"),
            credentials=[Credential(username="alice", secret="secret")],
        )
    )
    credential_commands = [
        item for item in suggestions if item.category == "credentials"
    ]

    assert credential_commands[0].argv == (
        "ssh",
        "-p",
        "22",
        "--",
        "{username}@10.10.11.123",
    )
    assert "secret" not in credential_commands[0].argv


def test_closed_services_do_not_create_service_suggestions() -> None:
    closed_smb = service(445, "microsoft-ds")
    closed_smb.state = "closed"

    suggestions = build_suggestions(case_with(closed_smb))

    assert {item.category for item in suggestions} == {"nmap_standard", "nmap_deep"}


@pytest.mark.parametrize(
    "non_actionable_service",
    [
        service(80, "http", state="open|filtered"),
        service(445, "microsoft-ds", state="open|filtered"),
        service(80, "http", protocol="udp"),
        service(445, "microsoft-ds", protocol="udp"),
        service(53, "domain", protocol="udp"),
        service(111, "rpcbind", protocol="udp"),
        service(2049, "nfs", protocol="udp"),
        service(53, "domain", protocol="udp", state="open|filtered"),
        service(111, "rpcbind", protocol="udp", state="open|filtered"),
    ],
)
def test_only_exactly_open_tcp_services_create_service_actions(
    non_actionable_service: Service,
) -> None:
    suggestions = build_suggestions(case_with(non_actionable_service))

    assert {item.category for item in suggestions} == {"nmap_standard", "nmap_deep"}


def test_command_data_is_argv_and_display_is_shell_quoted() -> None:
    command = build_suggestions(case_with(service(445, "microsoft-ds")))[0]

    assert isinstance(command.argv, tuple)
    assert command.active is True
    assert shell_join(("tool", "", "two words", "literal;pipe")) == (
        "tool '' 'two words' 'literal;pipe'"
    )
    assert command.display == shell_join(command.argv)


def test_target_and_services_call_style_is_supported() -> None:
    suggestions = build_suggestions(
        "10.10.11.123", [service(443, "https", tunnel="ssl")]
    )

    assert any(item.category == "http" for item in suggestions)
    assert suggestions[-1].category == "nmap_deep"


def test_full_scan_uses_all_ports_default_scripts_and_versions() -> None:
    command = build_suggestions(case_with(service(22, "ssh")))[-1]

    assert command.category == "nmap_deep"
    assert command.argv == (
        "nmap",
        "-Pn",
        "-p-",
        "-sC",
        "-sV",
        "-vv",
        "10.10.11.123",
    )


def test_standard_scan_uses_default_scripts_and_verbose_versions() -> None:
    suggestions = build_suggestions(case_with(service(22, "ssh")))
    command = next(item for item in suggestions if item.category == "nmap_standard")

    assert command.argv == (
        "nmap",
        "-Pn",
        "-sC",
        "-sV",
        "-vv",
        "--top-ports",
        "1000",
        "10.10.11.123",
    )
    assert command.active is True


def test_explicit_windows_os_guess_adjusts_smb_wording() -> None:
    scan_service = service(445, "microsoft-ds", product="Samba")
    profile = classify_services(
        [scan_service], [Host(address="10.10.11.123", os_guess="Windows Server 2022")]
    )

    assert profile.probable_windows is True
    assert "nmap's OS guess includes Windows" in profile.windows_evidence


def test_linux_posture_requires_explicit_or_corroborating_evidence() -> None:
    ssh = service(22, "ssh", product="OpenSSH")
    ssh_only = classify_services([ssh])
    unix_stack = classify_services([ssh, service(2049, "nfs")])
    explicit = classify_services(
        [ssh],
        [Host(address="10.10.11.123", os_guess="Linux 6.x")],
    )

    assert ssh_only.probable_linux is False
    assert unix_stack.probable_linux is True
    assert "SSH with NFS/RPC" in unix_stack.linux_evidence[0]
    assert explicit.probable_linux is True
    assert "OS guess includes Linux/Unix" in explicit.linux_evidence[0]


def test_linux_service_commands_are_read_only_enumeration() -> None:
    suggestions = build_suggestions(
        case_with(
            service(2049, "nfs"),
            service(25, "smtp"),
            service(2375, "http", product="Docker daemon"),
        )
    )
    commands = [item.argv for item in suggestions]
    flattened = {part for command in commands for part in command}

    assert not any(command[0] == "mount" for command in commands)
    assert "nfs-ls" not in flattened
    assert "smtp-open-relay" not in flattened
    assert "smtp-enum-users" not in flattened
    assert "POST" not in flattened
    assert not ({"create", "exec", "start"} & flattened)
    assert "-sU" not in flattened


def test_architecture_text_does_not_imply_arch_linux() -> None:
    profile = classify_services(
        [service(22, "ssh")],
        [Host(address="10.10.11.123", os_guess="network appliance architecture")],
    )

    assert profile.probable_linux is False


def test_ipv6_linux_commands_use_nmap_flag_and_bracketed_urls() -> None:
    state = case_with()
    state.target = "2001:db8::7"
    state.services = [
        Service(
            host=state.target,
            port=22,
            protocol="tcp",
            state="open",
            name="ssh",
        ),
        Service(
            host=state.target,
            port=2375,
            protocol="tcp",
            state="open",
            name="docker-api",
        ),
    ]
    suggestions = build_suggestions(state)
    ssh_nmap = next(
        item
        for item in suggestions
        if item.category == "ssh" and item.argv[0] == "nmap"
    )
    docker_commands = [item for item in suggestions if item.category == "docker"]

    assert ssh_nmap.argv[1] == "-6"
    assert all("http://[2001:db8::7]:2375" in item.argv[-1] for item in docker_commands)
