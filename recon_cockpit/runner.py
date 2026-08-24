"""Subprocess boundaries for scans and user-approved enumeration commands."""

from __future__ import annotations

import io
import ipaddress
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


class ReconError(RuntimeError):
    """A user-facing error raised by the recon workflow."""


_CUSTOM_NMAP_SIMPLE_OPTIONS = frozenset(
    {
        "-sC",
        "-sV",
        "--version-light",
        "--version-all",
        "--version-trace",
        "-sT",
        "-sS",
        "-sU",
        "-O",
        "--osscan-limit",
        "--osscan-guess",
        "-F",
        "-r",
        "-n",
        "-R",
        "--system-dns",
        "--traceroute",
        "--open",
        "--packet-trace",
        "--script-trace",
    }
)
_CUSTOM_NMAP_VALUE_OPTIONS = frozenset(
    {
        "-p",
        "-T",
        "--exclude-ports",
        "--top-ports",
        "--port-ratio",
        "--version-intensity",
        "--min-rate",
        "--max-rate",
        "--max-retries",
        "--host-timeout",
        "--scan-delay",
        "--max-scan-delay",
        "--min-rtt-timeout",
        "--max-rtt-timeout",
        "--initial-rtt-timeout",
        "--stats-every",
    }
)
_CUSTOM_NMAP_FORBIDDEN_PREFIXES = (
    "-iL",
    "-iR",
    "-oA",
    "-oG",
    "-oN",
    "-oS",
    "-oX",
)
_CUSTOM_NMAP_FORBIDDEN_OPTIONS = frozenset(
    {
        "--",
        "-6",
        "-Pn",
        "--reason",
        "--append-output",
        "--resume",
        "--exclude",
        "--excludefile",
        "--script",
        "--script-args",
        "--script-args-file",
        "--script-help",
        "--script-updatedb",
        "--datadir",
        "--proxies",
        "-D",
        "-S",
        "-e",
        "-g",
        "--source-port",
        "-sI",
        "-b",
        "-f",
        "--mtu",
        "--data",
        "--data-string",
        "--data-length",
        "--ip-options",
        "--ttl",
        "--spoof-mac",
        "--badsum",
        "--scanflags",
        "--iflist",
        "-h",
        "--help",
        "-V",
        "--version",
    }
)
_PORT_EXPRESSION_RE = re.compile(
    r"(?:(?:[TUSP]):)?(?:\d+|\d*-\d*)(?:,(?:(?:[TUSP]):)?(?:\d+|\d*-\d*))*\Z",
    re.IGNORECASE,
)
_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h)?\Z", re.IGNORECASE)


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


def standard_scan_argv(target: str, xml_path: Path, text_path: Path) -> tuple[str, ...]:
    """Build a default-script scan, only run after explicit confirmation."""

    canonical = validate_target(target)
    args = [
        "nmap",
        "-Pn",
        "-sC",
        "-sV",
        "-vv",
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


def _option_and_inline_value(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        option, value = token.split("=", 1)
        return option, value
    if token.startswith("-p") and token != "-p":
        return "-p", token[2:]
    if token.startswith("-T") and token != "-T":
        return "-T", token[2:]
    return token, None


def _validate_port_expression(value: str, option: str) -> None:
    if not value or not _PORT_EXPRESSION_RE.fullmatch(value):
        raise ReconError(f"{option} requires a numeric port list or range")
    numbers = (int(item) for item in re.findall(r"\d+", value))
    if any(number > 65535 for number in numbers):
        raise ReconError(f"{option} ports must be between 0 and 65535")


def _validate_custom_option_value(option: str, value: str) -> None:
    if not value:
        raise ReconError(f"Custom nmap option {option} requires a value")
    if option in {"-p", "--exclude-ports"}:
        _validate_port_expression(value, option)
        return
    if option == "-T":
        if value not in {"0", "1", "2", "3", "4"}:
            raise ReconError("Custom nmap timing must be between -T0 and -T4")
        return
    if option == "--top-ports":
        if not value.isdecimal() or not 1 <= int(value) <= 65535:
            raise ReconError("--top-ports must be between 1 and 65535")
        return
    if option == "--port-ratio":
        try:
            ratio = float(value)
        except ValueError as exc:
            raise ReconError("--port-ratio must be a number between 0 and 1") from exc
        if not 0 < ratio <= 1:
            raise ReconError("--port-ratio must be a number between 0 and 1")
        return
    if option == "--version-intensity":
        if not value.isdecimal() or not 0 <= int(value) <= 9:
            raise ReconError("--version-intensity must be between 0 and 9")
        return
    if option in {"--min-rate", "--max-rate"}:
        if not value.isdecimal() or not 1 <= int(value) <= 10_000:
            raise ReconError(f"{option} must be between 1 and 10000")
        return
    if option == "--max-retries":
        if not value.isdecimal() or not 0 <= int(value) <= 20:
            raise ReconError("--max-retries must be between 0 and 20")
        return
    duration = _DURATION_RE.fullmatch(value)
    if duration is None:
        raise ReconError(f"{option} requires a duration such as 500ms, 30s, or 5m")
    multipliers = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}
    unit = (duration.group(2) or "s").casefold()
    if float(duration.group(1)) * multipliers[unit] > 24 * 60 * 60:
        raise ReconError(f"{option} cannot exceed 24 hours")


def _validate_custom_nmap_args(extra_args: Sequence[str]) -> tuple[str, ...]:
    """Validate a bounded, options-only custom scan argument vector."""

    tokens = tuple(str(token) for token in extra_args)
    if not tokens:
        raise ReconError("Enter at least one custom nmap option")
    if len(tokens) > 64 or sum(len(token) for token in tokens) > 2048:
        raise ReconError("Custom nmap options are limited to 64 tokens and 2048 characters")
    if any(
        not token
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159
            for character in token
        )
        for token in tokens
    ):
        raise ReconError("Custom nmap options cannot contain empty or control characters")

    validated: list[str] = []
    seen: set[str] = set()
    values: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        option, inline_value = _option_and_inline_value(token)
        if option in _CUSTOM_NMAP_FORBIDDEN_OPTIONS or any(
            token.startswith(prefix) for prefix in _CUSTOM_NMAP_FORBIDDEN_PREFIXES
        ):
            raise ReconError(
                f"Custom nmap option {option!r} is controlled or blocked by the cockpit"
            )
        if option in {"nmap", "sudo", "doas", "env"} or not option.startswith("-"):
            raise ReconError(
                "Enter nmap options only; omit the executable, target, and shell syntax"
            )

        if option in _CUSTOM_NMAP_VALUE_OPTIONS:
            if option in seen:
                raise ReconError(f"Custom nmap option {option} was supplied more than once")
            if inline_value is None:
                index += 1
                if index >= len(tokens):
                    raise ReconError(f"Custom nmap option {option} requires a value")
                inline_value = tokens[index]
            _validate_custom_option_value(option, inline_value)
            seen.add(option)
            values[option] = inline_value
            validated.append(token)
            if token == option:
                validated.append(inline_value)
        elif option in _CUSTOM_NMAP_SIMPLE_OPTIONS or re.fullmatch(r"-v{1,3}", option):
            if inline_value is not None:
                raise ReconError(f"Custom nmap option {option} does not accept a value")
            duplicate_key = "-v" if option.startswith("-v") else option
            if duplicate_key in seen:
                raise ReconError(
                    f"Custom nmap option {duplicate_key} was supplied more than once"
                )
            seen.add(duplicate_key)
            validated.append(token)
        else:
            raise ReconError(
                f"Unsupported custom nmap option {option!r}; use a documented safe option "
                "or run the scan manually and import its XML"
            )
        index += 1

    if "-sS" in seen and "-sT" in seen:
        raise ReconError("Choose either -sS or -sT, not both")
    if "-n" in seen and seen.intersection({"-R", "--system-dns"}):
        raise ReconError("-n cannot be combined with DNS resolution options")
    if len(seen.intersection({"-p", "-F", "--top-ports", "--port-ratio"})) > 1:
        raise ReconError("Choose only one of -p, -F, --top-ports, or --port-ratio")
    if len(
        seen.intersection(
            {"--version-light", "--version-all", "--version-intensity"}
        )
    ) > 1:
        raise ReconError("Choose only one version intensity option")
    if "--min-rate" in values and "--max-rate" in values:
        if int(values["--min-rate"]) > int(values["--max-rate"]):
            raise ReconError("--min-rate cannot exceed --max-rate")

    return tuple(validated)


def custom_scan_argv(
    target: str,
    extra_args: Sequence[str],
    xml_path: Path,
    text_path: Path,
) -> tuple[str, ...]:
    """Build a user-composed scan with a controlled target and output paths."""

    canonical = validate_target(target)
    custom_args = _validate_custom_nmap_args(extra_args)
    args = ["nmap"]
    if ipaddress.ip_address(canonical).version == 6:
        args.append("-6")
    args.extend(
        ("-Pn", *custom_args, "--reason", "-oX", str(xml_path), "-oN", str(text_path))
    )
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
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    scan_dir = case_dir.resolve() / "scans"
    base = scan_dir / f"{label}-{timestamp}"
    counter = 2
    while base.with_suffix(".xml").exists() or base.with_suffix(".nmap").exists():
        base = scan_dir / f"{label}-{timestamp}-{counter}"
        counter += 1
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
