"""Subprocess boundaries for scans and user-approved enumeration commands."""

from __future__ import annotations

import io
import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


class ReconError(RuntimeError):
    """A user-facing error raised by the recon workflow."""


@dataclass(slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool = False


def validate_target(value: str) -> str:
    """Return a canonical IP address or raise a concise user-facing error."""

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ReconError(f"Target must be a single IPv4 or IPv6 address: {value!r}") from exc


def initial_scan_argv(target: str, xml_path: Path, text_path: Path) -> tuple[str, ...]:
    """Build the deliberately conservative initial service-detection scan."""

    canonical = validate_target(target)
    args = [
        "nmap",
        "-Pn",
        "-sV",
        "--version-light",
        "--top-ports",
        "1000",
        "--reason",
        "-oX",
        str(xml_path),
        "-oN",
        str(text_path),
    ]
    if ipaddress.ip_address(canonical).version == 6:
        args.insert(1, "-6")
    args.append(canonical)
    return tuple(args)


def deeper_scan_argv(target: str, xml_path: Path, text_path: Path) -> tuple[str, ...]:
    """Build an all-TCP-ports service scan, only run after explicit confirmation."""

    canonical = validate_target(target)
    args = [
        "nmap",
        "-Pn",
        "-sV",
        "--version-light",
        "-p-",
        "--reason",
        "-oX",
        str(xml_path),
        "-oN",
        str(text_path),
    ]
    if ipaddress.ip_address(canonical).version == 6:
        args.insert(1, "-6")
    args.append(canonical)
    return tuple(args)


def scan_paths(case_dir: Path, label: str) -> tuple[Path, Path]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = case_dir.resolve() / "scans" / f"{label}-{timestamp}"
    return base.with_suffix(".xml"), base.with_suffix(".nmap")


def run_command(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    capture: bool = True,
    check_tool: bool = True,
    executor: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> CommandResult:
    """Execute an argv vector without a shell.

    No command substitution, redirection, glob expansion, or implicit pipeline can
    occur at this boundary. The caller remains responsible for the confirmation
    gate required for active enumeration.
    """

    command = tuple(str(part) for part in argv)
    if not command:
        raise ReconError("Refusing to execute an empty command")
    if check_tool and shutil.which(command[0]) is None:
        raise ReconError(
            f"Required tool {command[0]!r} was not found in PATH. "
            "Install it or copy the displayed command to a system that has it."
        )

    try:
        completed = executor(
            list(command),
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=capture,
            check=False,
        )
    except OSError as exc:
        raise ReconError(f"Could not start {command[0]!r}: {exc}") from exc

    return CommandResult(
        argv=command,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def stream_command(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    on_line: Callable[[str], None] | None = None,
    check_tool: bool = True,
    transcript_path: Path | None = None,
    capture_limit: int = 32 * 1024 * 1024,
) -> CommandResult:
    """Run argv without a shell, optionally teeing to a private transcript.

    The returned stdout is bounded to ``capture_limit`` characters so a long
    content-discovery run cannot grow memory without limit. The transcript, when
    requested, is written incrementally and remains available after interruption.
    """

    command = tuple(str(part) for part in argv)
    if not command:
        raise ReconError("Refusing to execute an empty command")
    if check_tool and shutil.which(command[0]) is None:
        raise ReconError(
            f"Required tool {command[0]!r} was not found in PATH. "
            "Install it or copy the displayed command to a system that has it."
        )
    if capture_limit < 0:
        raise ReconError("capture_limit must not be negative")

    transcript = None
    if transcript_path is not None:
        path = transcript_path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            transcript = os.fdopen(
                descriptor, "w", encoding="utf-8", errors="replace", buffering=1
            )
        except FileExistsError as exc:
            raise ReconError(f"Refusing to overwrite transcript: {path}") from exc
        except OSError as exc:
            raise ReconError(f"Could not create transcript {path}: {exc}") from exc

    try:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        if transcript is not None:
            transcript.close()
        raise ReconError(f"Could not start {command[0]!r}: {exc}") from exc

    captured = io.StringIO()
    captured_size = 0
    truncated = False
    try:
        assert process.stdout is not None
        for line in process.stdout:
            if transcript is not None:
                transcript.write(line)
            remaining = capture_limit - captured_size
            if remaining > 0:
                portion = line[:remaining]
                captured.write(portion)
                captured_size += len(portion)
            if len(line) > max(remaining, 0):
                truncated = True
            if on_line:
                on_line(line.rstrip("\n"))
        returncode = process.wait()
    except BaseException:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    finally:
        if transcript is not None:
            transcript.close()

    return CommandResult(
        argv=command,
        returncode=returncode,
        stdout=captured.getvalue(),
        stderr="",
        stdout_truncated=truncated,
    )
