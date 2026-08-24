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
    tunnel: str = "",
    protocol: str = "tcp",
    state: str = "open",
) -> Service:
    return Service(
        host="10.10.11.123",
        port=port,
        protocol=protocol,
        state=state,
        name=name,
        product=product,
        tunnel=tunnel,
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
    assert not any("{" in part for item in commands for part in item.argv)


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
    assert {"http", "smb", "winrm", "nmap_deep"} <= groups.keys()
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

    assert {item.category for item in suggestions} == {"nmap_deep"}


@pytest.mark.parametrize(
    "non_actionable_service",
    [
        service(80, "http", state="open|filtered"),
        service(445, "microsoft-ds", state="open|filtered"),
        service(80, "http", protocol="udp"),
        service(445, "microsoft-ds", protocol="udp"),
    ],
)
def test_only_exactly_open_tcp_services_create_service_actions(
    non_actionable_service: Service,
) -> None:
    suggestions = build_suggestions(case_with(non_actionable_service))

    assert {item.category for item in suggestions} == {"nmap_deep"}


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


def test_deep_scan_uses_light_versions_without_default_scripts() -> None:
    command = build_suggestions(case_with(service(22, "ssh")))[-1]

    assert command.category == "nmap_deep"
    assert command.argv == (
        "nmap",
        "-Pn",
        "-p-",
        "-sV",
        "--version-light",
        "10.10.11.123",
    )
    assert "-sC" not in command.argv


def test_explicit_windows_os_guess_adjusts_smb_wording() -> None:
    scan_service = service(445, "microsoft-ds", product="Samba")
    profile = classify_services(
        [scan_service], [Host(address="10.10.11.123", os_guess="Windows Server 2022")]
    )

    assert profile.probable_windows is True
    assert "nmap's OS guess includes Windows" in profile.windows_evidence
