from __future__ import annotations

import io
import stat
from pathlib import Path

import pytest
from rich.console import Console

from recon_cockpit.case import create_case, load_case
from recon_cockpit.cli import (
    _execute_suggestion,
    _generated_user_file,
    _handle_group,
    _materialize_user_file,
    _print_live_line,
    _resolve_command,
    _run_nmap_scan,
    _terminal_safe,
    main,
)
from recon_cockpit.models import Credential
from recon_cockpit.runner import CommandResult, ReconError
from recon_cockpit.suggestions import CommandSuggestion, SuggestionGroup


FIXTURES = Path(__file__).parent / "fixtures"


def test_offline_xml_import_builds_windows_case_without_scanning(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    exit_code = main(
        [
            "10.10.11.123",
            "--nmap-xml",
            str(FIXTURES / "windows_nmap.xml"),
            "--cases-dir",
            str(cases),
            "--no-menu",
        ]
    )

    assert exit_code == 0
    case_dir = cases / "10.10.11.123"
    state = load_case(case_dir)
    assert {service.port for service in state.services} == {22, 80, 445, 5985}
    assert "Enumerate HTTP" in state.next_actions
    assert "Enumerate SMB" in state.next_actions
    assert "Inspect WinRM" in state.next_actions
    assert (case_dir / "notes.md").is_file()


def test_ingest_updates_existing_case_and_rejects_failed_auth(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    assert (
        main(
            [
                "10.10.11.123",
                "--nmap-xml",
                str(FIXTURES / "windows_nmap.xml"),
                "--cases-dir",
                str(cases),
                "--no-menu",
            ]
        )
        == 0
    )

    assert (
        main(
            [
                "--ingest",
                str(FIXTURES / "nxc_smb.txt"),
                "--cases-dir",
                str(cases),
                "--no-menu",
            ]
        )
        == 0
    )

    state = load_case(cases / "10.10.11.123")
    assert state.domains == ["CORP.LOCAL", "CORP"]
    assert {credential.username for credential in state.credentials} == {"alice"}
    assert state.credentials[0].status == "successful (admin)"
    assert "bob" not in state.usernames
    assert {share.name for share in state.shares} == {"ADMIN$", "Public"}
    notes = (cases / "10.10.11.123" / "notes.md").read_text(encoding="utf-8")
    assert "Spring2026!" in notes
    assert "Test known credentials" in notes


def test_declining_service_command_executes_nothing(tmp_path: Path, monkeypatch) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")
    suggestion = CommandSuggestion(
        "Enumerate HTTP",
        ("feroxbuster", "-u", "http://10.10.11.123"),
        "http",
    )
    monkeypatch.setattr("recon_cockpit.cli.Confirm.ask", lambda *args, **kwargs: False)

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("runner was called after a default-deny response")

    monkeypatch.setattr("recon_cockpit.cli.stream_command", unexpected_execution)

    _execute_suggestion(suggestion, state, case_dir, "http")

    assert list((case_dir / "commands").iterdir()) == []
    assert list((case_dir / "loot").iterdir()) == []


def test_declining_deeper_scan_executes_nothing(tmp_path: Path, monkeypatch) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")
    monkeypatch.setattr("recon_cockpit.cli.Confirm.ask", lambda *args, **kwargs: False)

    def unexpected_execution(*args, **kwargs):
        raise AssertionError("runner was called after a default-deny response")

    monkeypatch.setattr("recon_cockpit.cli.stream_command", unexpected_execution)

    assert _run_nmap_scan(state, case_dir, deeper=True) is False
    assert list((case_dir / "scans").iterdir()) == []


def test_initial_scan_runs_without_post_scan_confirmation_and_parses_xml(
    tmp_path: Path, monkeypatch
) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")

    def unexpected_confirmation(*args, **kwargs):
        raise AssertionError("the explicitly allowed initial scan should not prompt")

    def fake_nmap(argv, **kwargs):
        xml_path = Path(argv[argv.index("-oX") + 1])
        text_path = Path(argv[argv.index("-oN") + 1])
        xml_path.write_text(
            (FIXTURES / "windows_nmap.xml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        text_path.write_text("offline fake nmap output\n", encoding="utf-8")
        return CommandResult(tuple(argv), 0, "offline fake nmap output\n", "")

    monkeypatch.setattr("recon_cockpit.cli.Confirm.ask", unexpected_confirmation)
    monkeypatch.setattr("recon_cockpit.cli.stream_command", fake_nmap)

    assert _run_nmap_scan(state, case_dir, deeper=False) is True
    assert {service.port for service in state.services} == {22, 80, 445, 5985}
    assert state.scan_command[0] == "nmap"


def test_ancestor_case_rejects_output_for_a_different_target(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    _state, case_dir = create_case("10.10.11.123", cases)
    output = case_dir / "loot" / "other-target.txt"
    output.write_text(
        "SMB 10.10.11.124 445 OTHER [*] (name:OTHER) (domain:OTHER.LOCAL)\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--ingest",
                str(output),
                "--cases-dir",
                str(cases),
                "--no-menu",
            ]
        )
        == 2
    )
    assert load_case(case_dir).domains == []


def test_stored_secret_is_resolved_without_rendering_it_as_a_prompt_default(
    tmp_path: Path, monkeypatch
) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")
    state.credentials.append(
        Credential("alice", "Sup3rSecret!", "CORP.LOCAL", "successful", "manual")
    )
    prompted: list[str] = []

    def answer_prompt(label: str, **kwargs):
        prompted.append(label)
        return kwargs.get("default") or "value"

    monkeypatch.setattr("recon_cockpit.cli.Prompt.ask", answer_prompt)
    resolved = _resolve_command(
        ("nxc", "smb", "10.10.11.123", "-u", "{username}", "-p", "{password}"),
        state,
        case_dir,
    )

    assert resolved is not None
    command, secrets = resolved
    assert "Sup3rSecret!" in command
    assert secrets == {"Sup3rSecret!"}
    assert "Password" not in prompted


def test_terminal_rendering_strips_controls_and_redacts_known_secrets(
    monkeypatch,
) -> None:
    output = io.StringIO()
    monkeypatch.setattr("recon_cockpit.cli.console", Console(file=output, color_system=None))

    _print_live_line("before\x1b[2J alice:Sup3rSecret!\x00after", {"Sup3rSecret!"})

    rendered = output.getvalue()
    assert rendered == "before alice:********after\n"
    assert "\x1b" not in rendered
    assert "\x00" not in rendered
    assert _terminal_safe("safe\x9b2Jtext\x7f") == "safe2Jtext"


def test_ipv6_suggestion_description_is_rendered_as_literal_text(
    tmp_path: Path, monkeypatch
) -> None:
    state, case_dir = create_case("fd00::7", tmp_path / "cases")
    suggestion = CommandSuggestion(
        "Discover content on http://[fd00::7]",
        ("feroxbuster", "-u", "http://[fd00::7]"),
        "http",
    )
    group = SuggestionGroup(
        "http",
        "Enumerate HTTP",
        "HTTP is open on fd00::7",
        (suggestion,),
    )
    output = io.StringIO()
    monkeypatch.setattr("recon_cockpit.cli.console", Console(file=output, color_system=None))
    monkeypatch.setattr("recon_cockpit.cli.IntPrompt.ask", lambda *args, **kwargs: 0)

    _handle_group(group, state, case_dir)

    assert "http://[fd00::7]" in output.getvalue()


def test_generated_kerberos_user_file_is_absolute_and_deferred_until_consent(
    tmp_path: Path, monkeypatch
) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")
    state.domains = ["CORP.LOCAL"]
    state.usernames = ["alice", "svc_backup"]
    suggestion = CommandSuggestion(
        "Enumerate Kerberos users",
        (
            "kerbrute",
            "userenum",
            "--dc",
            state.target,
            "-d",
            "{domain}",
            "{user_file}",
        ),
        "kerberos",
    )
    monkeypatch.setattr(
        "recon_cockpit.cli.Prompt.ask",
        lambda *args, **kwargs: kwargs.get("default") or "value",
    )
    monkeypatch.setattr("recon_cockpit.cli.Confirm.ask", lambda *args, **kwargs: False)

    generated = _generated_user_file(state, case_dir)
    assert generated is not None
    generated_path, _content = generated
    assert generated_path.is_absolute()

    _execute_suggestion(suggestion, state, case_dir, "kerberos")
    assert not generated_path.exists()

    monkeypatch.setattr("recon_cockpit.cli.Confirm.ask", lambda *args, **kwargs: True)

    def successful_command(argv, **kwargs):
        assert str(generated_path) in argv
        assert generated_path.is_file()
        return CommandResult(tuple(argv), 0, "", "")

    monkeypatch.setattr("recon_cockpit.cli.stream_command", successful_command)
    _execute_suggestion(suggestion, state, case_dir, "kerberos")

    assert generated_path.read_text(encoding="utf-8") == "alice\nsvc_backup\n"
    assert stat.S_IMODE(generated_path.stat().st_mode) == 0o600


def test_generated_user_file_never_overwrites_unexpected_content(
    tmp_path: Path,
) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")
    state.usernames = ["alice"]
    generated = _generated_user_file(state, case_dir)
    assert generated is not None
    generated_path, _content = generated
    generated_path.write_text("analyst-owned data\n", encoding="utf-8")

    with pytest.raises(ReconError, match="Refusing to overwrite"):
        _materialize_user_file(state, case_dir)

    assert generated_path.read_text(encoding="utf-8") == "analyst-owned data\n"


def test_crafted_ssh_username_is_rejected_before_execution(
    tmp_path: Path, monkeypatch
) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")
    state.credentials.append(
        Credential(
            "-oProxyCommand=touch /tmp/pwned",
            "secret",
            status="successful",
        )
    )
    monkeypatch.setattr(
        "recon_cockpit.cli.Prompt.ask",
        lambda *args, **kwargs: kwargs.get("default") or "value",
    )

    assert (
        _resolve_command(
            ("ssh", "-p", "22", "--", "{username}@10.10.11.123"),
            state,
            case_dir,
        )
        is None
    )


def test_local_auth_placeholders_select_only_a_domainless_credential(
    tmp_path: Path, monkeypatch
) -> None:
    state, case_dir = create_case("10.10.11.123", tmp_path / "cases")
    state.credentials = [
        Credential("domain-user", "domain-pass", "CORP.LOCAL", "successful"),
        Credential("local-user", "local-pass", "", "successful"),
    ]
    monkeypatch.setattr(
        "recon_cockpit.cli.Prompt.ask",
        lambda *args, **kwargs: kwargs.get("default") or "value",
    )

    resolved = _resolve_command(
        (
            "nxc",
            "smb",
            state.target,
            "-u",
            "{local_username}",
            "-p",
            "{local_password}",
            "--local-auth",
        ),
        state,
        case_dir,
    )

    assert resolved is not None
    command, secrets = resolved
    assert "local-user" in command
    assert "local-pass" in command
    assert "domain-user" not in command
    assert secrets == {"local-pass"}


def test_ipv6_import_and_ingest_use_canonical_target_identity(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    xml = tmp_path / "ipv6.xml"
    xml.write_text(
        """
        <nmaprun><host><status state="up"/>
        <address addr="2001:0db8:0:0::7" addrtype="ipv6"/>
        <ports><port protocol="tcp" portid="5985"><state state="open"/>
        <service name="wsman" product="Microsoft HTTPAPI httpd"/></port></ports>
        </host></nmaprun>
        """,
        encoding="utf-8",
    )
    assert (
        main(
            [
                "2001:db8::7",
                "--nmap-xml",
                str(xml),
                "--cases-dir",
                str(cases),
                "--no-menu",
            ]
        )
        == 0
    )

    output = tmp_path / "ipv6-nxc.txt"
    output.write_text(
        "WINRM 2001:0db8:0:0::7 5985 DCV6 [+] V6.LAB\\alice:Winter2026!\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "--ingest",
                str(output),
                "--cases-dir",
                str(cases),
                "--no-menu",
            ]
        )
        == 0
    )

    state = load_case(cases / "2001_db8_7")
    assert state.target == "2001:db8::7"
    assert state.hosts[0].address == "2001:db8::7"
    assert state.credentials[0].username == "alice"
