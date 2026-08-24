import stat
import sys
from pathlib import Path

import pytest

from recon_cockpit.runner import (
    ReconError,
    deeper_scan_argv,
    initial_scan_argv,
    standard_scan_argv,
    stream_command,
    validate_target,
)


def test_validate_target_rejects_hostname_and_options() -> None:
    with pytest.raises(ReconError):
        validate_target("example.com")
    with pytest.raises(ReconError):
        validate_target("--script=all")


def test_initial_scan_is_conservative_and_writes_xml() -> None:
    command = initial_scan_argv("10.10.11.123", Path("scan.xml"), Path("scan.nmap"))
    assert command[0] == "nmap"
    assert "-sV" in command
    assert "--version-light" in command
    assert "--top-ports" in command
    assert "-sC" not in command
    assert "-A" not in command
    assert command[-1] == "10.10.11.123"


def test_standard_scan_uses_default_scripts_without_sudo() -> None:
    command = standard_scan_argv(
        "10.10.11.123", Path("scan.xml"), Path("scan.nmap")
    )

    assert command == (
        "nmap",
        "-Pn",
        "-sC",
        "-sV",
        "-vv",
        "--reason",
        "-oX",
        "scan.xml",
        "-oN",
        "scan.nmap",
        "10.10.11.123",
    )
    assert "sudo" not in command


def test_standard_scan_supports_ipv6() -> None:
    command = standard_scan_argv(
        "2001:db8::1", Path("scan.xml"), Path("scan.nmap")
    )

    assert command[1] == "-6"
    assert command[-1] == "2001:db8::1"


def test_deeper_scan_is_all_ports_and_ipv6_uses_flag() -> None:
    command = deeper_scan_argv("2001:db8::1", Path("scan.xml"), Path("scan.nmap"))
    assert command[1] == "-6"
    assert "-p-" in command


def test_stream_command_tees_complete_private_transcript_and_bounds_capture(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "loot" / "output.txt"
    result = stream_command(
        (sys.executable, "-c", "print('first'); print('second')"),
        transcript_path=transcript,
        capture_limit=7,
    )

    assert result.returncode == 0
    assert result.stdout == "first\ns"
    assert result.stdout_truncated is True
    assert transcript.read_text(encoding="utf-8") == "first\nsecond\n"
    assert stat.S_IMODE(transcript.stat().st_mode) == 0o600


def test_stream_command_refuses_to_overwrite_transcript(tmp_path: Path) -> None:
    transcript = tmp_path / "existing.txt"
    transcript.write_text("analyst data", encoding="utf-8")

    with pytest.raises(ReconError, match="Refusing to overwrite"):
        stream_command(
            (sys.executable, "-c", "print('new')"),
            transcript_path=transcript,
        )

    assert transcript.read_text(encoding="utf-8") == "analyst data"
