import stat
import sys
from datetime import datetime as RealDatetime
from pathlib import Path

import pytest

from recon_cockpit.runner import (
    ReconError,
    custom_scan_argv,
    deeper_scan_argv,
    initial_scan_argv,
    scan_paths,
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


def test_custom_scan_controls_executable_target_and_output_paths() -> None:
    command = custom_scan_argv(
        "10.10.11.123",
        ("-sU", "--top-ports", "50", "-sV", "-T4", "-vv"),
        Path("custom.xml"),
        Path("custom.nmap"),
    )

    assert command == (
        "nmap",
        "-Pn",
        "-sU",
        "--top-ports",
        "50",
        "-sV",
        "-T4",
        "-vv",
        "--reason",
        "-oX",
        "custom.xml",
        "-oN",
        "custom.nmap",
        "10.10.11.123",
    )
    assert command.count("10.10.11.123") == 1


def test_custom_scan_supports_ipv6_and_common_attached_values() -> None:
    command = custom_scan_argv(
        "2001:db8::7",
        (
            "-sS",
            "-pU:53,T:80,443",
            "--version-intensity=7",
            "--min-rate=100",
            "--max-rate=500",
            "--host-timeout=5m",
        ),
        Path("custom.xml"),
        Path("custom.nmap"),
    )

    assert command[1:3] == ("-6", "-Pn")
    assert command[-1] == "2001:db8::7"


@pytest.mark.parametrize(
    "extra_args",
    [
        (),
        ("nmap", "-sV"),
        ("sudo", "nmap", "-sV"),
        ("10.10.11.124",),
        ("target.example",),
        ("10.10.11.0/24",),
        (";", "id"),
        ("-oA", "other"),
        ("-oXother.xml",),
        ("-iL", "targets.txt"),
        ("-iR10",),
        ("--resume=old.xml",),
        ("--script=http-title",),
        ("--script-args=user=alice",),
        ("--append-output",),
        ("-oNother.nmap",),
        ("--datadir=/tmp/nmap",),
        ("--proxies=http://127.0.0.1:8080",),
        ("-D", "RND:10"),
        ("-sCV",),
        ("--unknown",),
        ("--open=true",),
        ("-Pn",),
        ("--reason",),
        ("-6",),
        ("-sV\n-oX",),
    ],
)
def test_custom_scan_rejects_scope_output_shell_and_unknown_options(
    extra_args: tuple[str, ...],
) -> None:
    with pytest.raises(ReconError):
        custom_scan_argv(
            "10.10.11.123",
            extra_args,
            Path("custom.xml"),
            Path("custom.nmap"),
        )


@pytest.mark.parametrize(
    "extra_args",
    [
        ("-p", "70000"),
        ("--top-ports=0",),
        ("--version-intensity", "10"),
        ("-T5",),
        ("--port-ratio=1.1",),
        ("--min-rate=10001",),
        ("--max-retries=21",),
        ("--host-timeout=forever",),
        ("--host-timeout=25h",),
        ("-sS", "-sT"),
        ("-p80", "--top-ports=50"),
        ("--version-light", "--version-all"),
        ("--min-rate=500", "--max-rate=100"),
        ("-n", "--system-dns"),
    ],
)
def test_custom_scan_rejects_invalid_or_conflicting_values(
    extra_args: tuple[str, ...],
) -> None:
    with pytest.raises(ReconError):
        custom_scan_argv(
            "10.10.11.123",
            extra_args,
            Path("custom.xml"),
            Path("custom.nmap"),
        )


def test_deeper_scan_is_all_ports_and_ipv6_uses_flag() -> None:
    command = deeper_scan_argv("2001:db8::1", Path("scan.xml"), Path("scan.nmap"))
    assert command[1] == "-6"
    assert "-p-" in command


def test_scan_paths_do_not_reuse_an_existing_artifact(
    tmp_path: Path, monkeypatch
) -> None:
    class FixedDatetime:
        @classmethod
        def now(cls, timezone):
            return RealDatetime(2026, 8, 24, 12, 30, 0, tzinfo=timezone)

    monkeypatch.setattr("recon_cockpit.runner.datetime", FixedDatetime)
    scan_dir = tmp_path / "case" / "scans"
    scan_dir.mkdir(parents=True)
    first_xml, first_text = scan_paths(tmp_path / "case", "custom")
    first_xml.touch()
    first_text.touch()

    second_xml, second_text = scan_paths(tmp_path / "case", "custom")

    assert second_xml != first_xml
    assert second_text != first_text
    assert second_xml.stem.endswith("-2")


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
