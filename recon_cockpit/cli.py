"""Rich terminal interface for the evidence-driven recon workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from . import __version__
from .case import (
    create_case,
    find_case_for_ingest,
    load_case,
    merge_ingest,
    merge_scan,
    save_case,
)
from .constants import NOTES_FILENAME, STATE_FILENAME
from .models import CaseState, Credential, IngestResult
from .parsers import ingest_command_output, parse_nmap_xml, strip_ansi
from .runner import (
    ReconError,
    custom_scan_argv,
    deeper_scan_argv,
    full_scan_argv,
    initial_scan_argv,
    run_command,
    scan_paths,
    standard_scan_argv,
    stream_command,
    validate_target,
)
from .suggestions import build_suggestions, group_suggestions, shell_join


console = Console(highlight=False)
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
SECRET_PLACEHOLDERS = {"password", "secret", "local_password"}
UNSAFE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
SSH_USERNAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-$]*\Z")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evidence-driven reconnaissance for authorized HTB/THM-style targets. "
            "Interactive launches offer three bounded nmap scan profiles."
        ),
    )
    parser.add_argument("target", nargs="?", help="single target IPv4 or IPv6 address")
    parser.add_argument(
        "--ingest",
        type=Path,
        metavar="FILE",
        help="parse saved command output and merge evidence into its target case",
    )
    parser.add_argument(
        "--nmap-xml",
        type=Path,
        metavar="FILE",
        help="import existing nmap XML instead of choosing a live scan",
    )
    parser.add_argument(
        "--cases-dir",
        type=Path,
        default=Path("cases"),
        help="case storage root (default: ./cases)",
    )
    parser.add_argument(
        "--rescan",
        action="store_true",
        help="choose and run a fresh scan even when the case has service evidence",
    )
    parser.add_argument(
        "--no-menu",
        action="store_true",
        help="skip interactive menus (new cases use the Quick scan profile)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_label(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-.")
    return cleaned or "command"


def _terminal_safe(value: object) -> str:
    """Remove terminal escape/control bytes from untrusted display text."""

    return UNSAFE_CONTROL_RE.sub("", strip_ansi(str(value)))


def _print_live_line(line: str, secrets: Iterable[str] = ()) -> None:
    safe = _terminal_safe(line)
    console.print(Text(_redact_argument(safe, tuple(secrets))))


def _write_command_record(
    case_dir: Path,
    label: str,
    argv: Sequence[str],
    returncode: int,
    *,
    redacted: Sequence[str] | None = None,
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = case_dir / "commands" / f"{timestamp}-{_safe_label(label)}.json"
    counter = 2
    while path.exists():
        path = case_dir / "commands" / f"{timestamp}-{_safe_label(label)}-{counter}.json"
        counter += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": _utc_now(),
        "argv": list(redacted or argv),
        "returncode": returncode,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _refresh_next_actions(state: CaseState) -> list[object]:
    groups = list(group_suggestions(build_suggestions(state)))
    state.next_actions = [group.title for group in groups]
    state.updated_at = _utc_now()
    return groups


def _service_label(name: str, port: int, tunnel: str = "") -> str:
    if port in {5985, 5986}:
        return "WinRM"
    if port in {139, 445}:
        return "SMB"
    if port in {88, 464}:
        return "Kerberos"
    if port in {389, 3268}:
        return "LDAP"
    if port in {636, 3269}:
        return "LDAPS"
    if port == 111:
        return "RPC"
    if port == 2049:
        return "NFS"
    if port == 53:
        return "DNS"
    if port in {21, 990}:
        return "FTPS" if port == 990 or tunnel.lower() in {"ssl", "tls"} else "FTP"
    if port in {25, 465, 587, 2525}:
        return "SMTP"
    if port in {2375, 2376}:
        return "Docker API"
    friendly = {
        "microsoft-ds": "SMB",
        "netbios-ssn": "SMB",
        "ms-wbt-server": "RDP",
        "http": "HTTPS" if tunnel.lower() in {"ssl", "tls"} else "HTTP",
        "https": "HTTPS",
        "ssl/http": "HTTPS",
        "ssh": "SSH",
        "ldap": "LDAP",
        "ldaps": "LDAPS",
        "kerberos-sec": "Kerberos",
        "wsman": "WinRM",
    }
    return friendly.get(name.lower(), name.upper() if name else "UNKNOWN")


def show_summary(state: CaseState, case_dir: Path) -> None:
    console.print()
    console.print(
        Panel.fit(
            Text.assemble(("TARGET  ", "bold cyan"), (state.target, "bold white")),
            border_style="cyan",
        )
    )

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", show_edge=False)
    table.add_column("PORT", justify="right", style="cyan", no_wrap=True)
    table.add_column("SERVICE", style="green")
    table.add_column("VERSION / EVIDENCE")
    services = sorted(
        (
            service
            for service in state.services
            if service.state.casefold() == "open"
        ),
        key=lambda service: (service.host, service.protocol, service.port),
    )
    if services:
        for service in services:
            port = f"{service.port}/{service.protocol}"
            evidence = _terminal_safe(service.banner) or "—"
            table.add_row(
                port,
                Text(_service_label(service.name, service.port, service.tunnel)),
                Text(evidence),
            )
    else:
        table.add_row("—", "No open services recorded", "Run or import an nmap scan")
    console.print(table)

    groups = _refresh_next_actions(state)
    console.print("\n[bold]Suggested next actions:[/bold]\n")
    for index, group in enumerate(groups, start=1):
        evidence = getattr(group, "evidence", "")
        line = Text("  ")
        line.append(f"[{index}]", style="cyan")
        line.append(f" {group.title}")
        if evidence:
            line.append(f" ({_terminal_safe(evidence)})", style="dim")
        console.print(line)
    if not groups:
        console.print("  [dim]No service-specific actions yet; import scan evidence first.[/dim]")
    console.print(Text(f"\nCase: {_terminal_safe(case_dir)}", style="dim"))


def _run_nmap_scan(
    state: CaseState,
    case_dir: Path,
    *,
    profile: str = "initial",
    custom_args: Sequence[str] = (),
) -> bool:
    if profile not in {
        "initial",
        "quick",
        "standard",
        "custom",
        "deep",
        "full",
    }:
        raise ReconError(f"Unknown nmap scan profile: {profile}")
    if profile != "custom" and custom_args:
        raise ReconError("Custom nmap arguments require the custom scan profile")

    label = profile
    xml_path, text_path = scan_paths(case_dir, label)
    builders = {
        "initial": initial_scan_argv,
        "quick": initial_scan_argv,
        "standard": standard_scan_argv,
        "deep": deeper_scan_argv,
        "full": full_scan_argv,
    }
    command = (
        custom_scan_argv(state.target, custom_args, xml_path, text_path)
        if profile == "custom"
        else builders[profile](state.target, xml_path, text_path)
    )
    titles = {
        "initial": "Quick nmap scan",
        "quick": "Quick nmap scan",
        "standard": "Standard nmap scan",
        "custom": "Custom nmap scan",
        "deep": "Full TCP nmap scan",
        "full": "Full TCP nmap scan",
    }
    console.print(f"\n[bold]{titles[profile]}[/bold]")
    console.print(Text(shell_join(command), style="cyan"))
    prompts = {
        "standard": "Run this active default-NSE-script enumeration?",
        "custom": "Run this active custom nmap enumeration command?",
        "deep": (
            "Scan all 65,535 TCP ports, then run default NSE scripts and version "
            "detection on discovered services?"
        ),
        "full": (
            "Scan all 65,535 TCP ports, then run default NSE scripts and version "
            "detection on discovered services?"
        ),
    }
    needs_confirmation = profile in {"standard", "custom", "deep", "full"}
    if needs_confirmation and not Confirm.ask(prompts[profile], default=False):
        console.print("[yellow]Skipped; nothing was executed.[/yellow]")
        return False

    console.print("[dim]Running without a shell. Press Ctrl-C to stop.[/dim]")
    try:
        result = stream_command(
            command,
            cwd=case_dir,
            on_line=_print_live_line,
        )
    finally:
        for artifact in (xml_path, text_path):
            if artifact.exists():
                artifact.chmod(0o600)
    _write_command_record(case_dir, f"nmap-{label}", command, result.returncode)
    if result.returncode != 0:
        console.print(f"[yellow]nmap exited with status {result.returncode}.[/yellow]")
    if not xml_path.is_file():
        raise ReconError(f"nmap did not produce the expected XML file: {xml_path}")

    hosts, services = parse_nmap_xml(xml_path)
    if not any(host.address == state.target for host in hosts):
        raise ReconError("The nmap XML does not contain the selected target")
    hosts = [host for host in hosts if host.address == state.target]
    services = [service for service in services if service.host == state.target]
    merge_scan(state, hosts, services, scan_command=list(command))
    _refresh_next_actions(state)
    save_case(case_dir, state)
    open_count = sum(service.state.casefold() == "open" for service in services)
    console.print(f"[green]Parsed {open_count} open service(s) into notes.md.[/green]")
    return True


def _choose_initial_scan(state: CaseState, case_dir: Path) -> bool:
    """Ask which bounded scan profile to run for a new or rescanned case."""

    console.print("\n[bold]Choose the initial Nmap scan[/bold]\n")
    table = Table(box=box.SIMPLE, show_edge=False, header_style="bold")
    table.add_column("", style="cyan", justify="right", no_wrap=True)
    table.add_column("PROFILE", style="green", no_wrap=True)
    table.add_column("COVERAGE")
    table.add_column("NMAP OPTIONS", style="dim")
    table.add_row(
        "[1]",
        "Quick",
        "Top 1,000 TCP ports; light version probes",
        "-sV --version-light --top-ports 1000",
    )
    table.add_row(
        "[2]",
        "Standard (recommended)",
        "Top 1,000 TCP ports; default scripts + versions",
        "-sC -sV -vv --top-ports 1000",
    )
    table.add_row(
        "[3]",
        "Full TCP",
        "All TCP ports; scripts + versions on open services",
        "-p- -sC -sV -vv",
    )
    console.print(table)
    choice = IntPrompt.ask(
        "Scan profile",
        choices=["1", "2", "3"],
        default=2,
    )
    profile = {1: "quick", 2: "standard", 3: "full"}[choice]
    return _run_nmap_scan(
        state,
        case_dir,
        profile=profile,
    )


def _run_custom_nmap_scan(state: CaseState, case_dir: Path) -> bool:
    console.print("\n[bold]Build a custom nmap scan[/bold]")
    console.print(
        "[dim]Enter options only. The cockpit supplies nmap, -Pn, --reason, "
        "private output paths, and the case target.[/dim]"
    )
    console.print(
        "[dim]Example: -sT --top-ports 50 -sV -T4. "
        "Unknown or scope-changing options are rejected.[/dim]"
    )
    raw_options = Prompt.ask(
        "Nmap options (blank cancels)", default="", show_default=False
    )
    if not raw_options.strip():
        console.print("[yellow]Skipped; nothing was executed.[/yellow]")
        return False
    try:
        custom_args = tuple(shlex.split(raw_options, posix=True))
    except ValueError as exc:
        raise ReconError(f"Could not parse custom nmap options: {exc}") from exc
    return _run_nmap_scan(
        state,
        case_dir,
        profile="custom",
        custom_args=custom_args,
    )


def _import_nmap_xml(state: CaseState, case_dir: Path, source: Path) -> None:
    if not source.is_file():
        raise ReconError(f"Nmap XML file not found: {source}")
    hosts, services = parse_nmap_xml(source)
    if not any(host.address == state.target for host in hosts):
        raise ReconError(f"The XML does not contain target {state.target}")
    hosts = [host for host in hosts if host.address == state.target]
    services = [service for service in services if service.host == state.target]
    merge_scan(state, hosts, services, scan_command=["import", str(source)])
    _refresh_next_actions(state)
    save_case(case_dir, state)
    message = Text("Imported ", style="green")
    open_count = sum(service.state.casefold() == "open" for service in services)
    message.append(f"{open_count} open service(s) from {_terminal_safe(source)}.")
    console.print(message)


def _domain_to_base_dn(domain: str) -> str:
    labels = [label for label in domain.strip(".").split(".") if label]
    return ",".join(f"DC={label}" for label in labels)


def _choose_credential(
    state: CaseState, *, require_domain: bool | None = None
) -> Credential | None:
    credentials = [
        credential
        for credential in state.credentials
        if not any(
            token in credential.status.casefold()
            for token in ("invalid", "fail", "denied")
        )
        and (
            require_domain is None
            or bool(credential.domain.strip()) is require_domain
        )
    ]
    if not credentials:
        return None
    if len(credentials) == 1:
        return credentials[0]
    console.print("\n[bold]Stored credentials[/bold]")
    for index, credential in enumerate(credentials, start=1):
        identity = (
            f"{credential.domain}\\{credential.username}"
            if credential.domain
            else credential.username
        )
        line = Text("  ")
        line.append(f"[{index}]", style="cyan")
        line.append(
            f" {_terminal_safe(identity)} ({_terminal_safe(credential.status)})"
        )
        console.print(line)
    choice = IntPrompt.ask(
        "Credential", choices=[str(i) for i in range(1, len(credentials) + 1)]
    )
    return credentials[choice - 1]


def _generated_user_file(state: CaseState, case_dir: Path) -> tuple[Path, str] | None:
    if not state.usernames:
        return None
    content = "\n".join(sorted(set(state.usernames))) + "\n"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    path = case_dir.resolve() / "loot" / f"users.generated-{digest}.txt"
    return path, content


def _materialize_user_file(state: CaseState, case_dir: Path) -> str | None:
    generated = _generated_user_file(state, case_dir)
    if generated is None:
        return None
    path, content = generated
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8", errors="replace") != content:
            raise ReconError(f"Refusing to overwrite an unexpected generated file: {path}")
    else:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    path.chmod(0o600)
    return str(path)


def _resolve_command(
    template: Sequence[str], state: CaseState, case_dir: Path
) -> tuple[tuple[str, ...], set[str]] | None:
    names = sorted({name for part in template for name in PLACEHOLDER_RE.findall(part)})
    if not names:
        return tuple(template), set()

    if {"local_username", "local_password"}.intersection(names):
        selected = _choose_credential(state, require_domain=False)
    elif {"username", "password", "secret"}.intersection(names):
        selected = _choose_credential(
            state, require_domain=True if "domain" in names else None
        )
    else:
        selected = None
    defaults: dict[str, str] = {
        "target": state.target,
        "domain": (selected.domain if selected else "")
        or (state.domains[0] if state.domains else ""),
        "username": selected.username if selected else "",
        "password": selected.secret if selected else "",
        "secret": selected.secret if selected else "",
        "local_username": selected.username if selected else "",
        "local_password": selected.secret if selected else "",
    }
    defaults["base_dn"] = _domain_to_base_dn(defaults["domain"])
    if {"user_file", "users_file"}.intersection(names):
        generated_users = _generated_user_file(state, case_dir)
        if generated_users:
            generated_path, _content = generated_users
            defaults["user_file"] = str(generated_path)
            defaults["users_file"] = str(generated_path)

    values: dict[str, str] = {}
    for name in names:
        default = defaults.get(name, "")
        if name in SECRET_PLACEHOLDERS and default:
            values[name] = default
            console.print("[dim]Using the selected stored secret.[/dim]")
            continue
        label = name.replace("_", " ").capitalize()
        value = Prompt.ask(
            label,
            default=default or None,
            password=name in SECRET_PLACEHOLDERS,
        )
        if not value:
            console.print("[yellow]A required value was empty; command skipped.[/yellow]")
            return None
        if name.endswith("_file") or name in {"wordlist"}:
            value = str(Path(value).expanduser().resolve())
        if name == "wordlist" and not Path(value).is_file():
            console.print("[yellow]Wordlist file was not found; command skipped.[/yellow]")
            return None
        values[name] = value

    unsafe_name = next(
        (name for name, value in values.items() if UNSAFE_CONTROL_RE.search(value)),
        None,
    )
    if unsafe_name:
        console.print(
            f"[yellow]{unsafe_name.replace('_', ' ').capitalize()} contains "
            "unsupported control characters; command skipped.[/yellow]"
        )
        return None
    if template and template[0] == "ssh":
        username = values.get("username", "")
        if username and not SSH_USERNAME_RE.fullmatch(username):
            console.print(
                "[yellow]SSH username contains unsupported characters; "
                "command skipped.[/yellow]"
            )
            return None

    resolved = tuple(
        PLACEHOLDER_RE.sub(lambda match: values[match.group(1)], part) for part in template
    )
    secrets = {values[name] for name in SECRET_PLACEHOLDERS.intersection(values)}
    return resolved, secrets


def _redact_command(argv: Sequence[str], secrets: Iterable[str]) -> tuple[str, ...]:
    secret_values = [secret for secret in secrets if secret]
    return tuple(
        _redact_argument(argument, secret_values)
        for argument in argv
    )


def _redact_argument(argument: str, secrets: Sequence[str]) -> str:
    redacted = argument
    for secret in secrets:
        redacted = redacted.replace(secret, "********")
    return redacted


def _execute_suggestion(
    suggestion: object, state: CaseState, case_dir: Path, category: str
) -> None:
    resolved = _resolve_command(suggestion.argv, state, case_dir)
    if resolved is None:
        return
    command, secrets = resolved
    redacted = _redact_command(command, secrets)
    console.print("\n[bold]Command preview[/bold]")
    console.print(Text(_terminal_safe(shell_join(redacted)), style="cyan"))
    if secrets:
        console.print("[dim]Secret values are masked in the preview and audit record.[/dim]")
    if not Confirm.ask("Run exactly this active enumeration command?", default=False):
        console.print("[yellow]Skipped; nothing was executed.[/yellow]")
        return

    generated_users = _generated_user_file(state, case_dir)
    if generated_users and str(generated_users[0]) in command:
        _materialize_user_file(state, case_dir)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    transcript = case_dir / "loot" / f"{timestamp}-{_safe_label(category)}.txt"
    console.print("[dim]Running without a shell. Press Ctrl-C to stop.[/dim]")
    if command[0] == "ssh":
        # SSH owns the terminal so its host-key/password prompts remain visible.
        result = run_command(command, cwd=case_dir, capture=False)
        transcript.touch(mode=0o600, exist_ok=False)
    else:
        result = stream_command(
            command,
            cwd=case_dir,
            on_line=lambda line: _print_live_line(line, secrets),
            transcript_path=transcript,
        )
    _write_command_record(
        case_dir,
        category,
        command,
        result.returncode,
        redacted=redacted,
    )
    console.print(
        Text(
            f"Command exited with status {result.returncode}; transcript: "
            f"{_terminal_safe(transcript)}",
            style="green" if result.returncode == 0 else "yellow",
        )
    )
    if result.stdout_truncated:
        console.print(
            "[yellow]The complete transcript was saved; automatic ingest used only "
            "the first 32 MiB.[/yellow]"
        )

    evidence = ingest_command_output(result.stdout, source=str(transcript))
    if _ingest_has_evidence(evidence):
        _validate_ingest_target(evidence, state)
        merge_ingest(state, evidence)
        _refresh_next_actions(state)
        save_case(case_dir, state)
        console.print("[green]Recognized evidence was merged into notes.md.[/green]")


def _ingest_has_evidence(result: IngestResult) -> bool:
    return any(
        (
            result.hostnames,
            result.domains,
            result.usernames,
            result.credentials,
            result.shares,
            result.findings,
        )
    )


def _handle_group(group: object, state: CaseState, case_dir: Path) -> None:
    key = getattr(group, "key", getattr(group, "category", "enumeration"))
    if key in {"nmap_standard", "standard_nmap"}:
        _run_nmap_scan(state, case_dir, profile="standard")
        return
    if key in {"nmap_deep", "deep_nmap", "nmap"}:
        _run_nmap_scan(state, case_dir, profile="full")
        return

    commands = list(group.commands)
    if not commands:
        console.print("[yellow]This action has no commands for the current evidence.[/yellow]")
        return
    console.print(f"\n[bold]{group.title}[/bold]")
    if getattr(group, "evidence", ""):
        console.print(Text(f"Evidence: {_terminal_safe(group.evidence)}", style="dim"))
    for index, suggestion in enumerate(commands, start=1):
        line = Text("\n  ")
        line.append(f"[{index}]", style="cyan")
        line.append(f" {_terminal_safe(suggestion.description)}")
        console.print(line)
        console.print(
            Text(f"      {_terminal_safe(shell_join(suggestion.argv))}", style="dim")
        )
    console.print("\n  [cyan][0][/cyan] Back")
    choice = IntPrompt.ask(
        "Command", choices=[str(i) for i in range(0, len(commands) + 1)], default=0
    )
    if choice:
        _execute_suggestion(commands[choice - 1], state, case_dir, str(key))


def _add_credential(state: CaseState, case_dir: Path) -> None:
    console.print("\n[bold]Add a credential to this case[/bold]")
    domain = Prompt.ask(
        "Domain (optional)", default=state.domains[0] if state.domains else ""
    )
    username = Prompt.ask("Username").strip()
    if not username:
        console.print("[yellow]Username is required; nothing was saved.[/yellow]")
        return
    secret = Prompt.ask("Password / secret (optional)", password=True, default="")
    status = Prompt.ask(
        "Status", choices=["unverified", "valid", "invalid"], default="unverified"
    )
    result = IngestResult(
        domains=[domain] if domain else [],
        usernames=[username],
        credentials=[
            Credential(
                username=username,
                secret=secret,
                domain=domain,
                status=status,
                source="manual",
            )
        ],
    )
    merge_ingest(state, result)
    _refresh_next_actions(state)
    save_case(case_dir, state)
    console.print("[green]Credential saved to the case and notes.md.[/green]")


def _open_notes(case_dir: Path) -> None:
    notes_path = (case_dir / NOTES_FILENAME).resolve()
    editor_value = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor_value:
        console.print(Text(f"\n{_terminal_safe(notes_path)}\n", style="bold"))
        console.print(Markdown(notes_path.read_text(encoding="utf-8")))
        console.print("[dim]Set $VISUAL or $EDITOR to open this file in an editor.[/dim]")
        return
    editor = shlex.split(editor_value)
    if not editor:
        raise ReconError("$VISUAL/$EDITOR is empty")
    # This launches the user's configured local editor; it is not a target action.
    result = run_command([*editor, str(notes_path)], capture=False)
    if result.returncode:
        console.print(f"[yellow]Editor exited with status {result.returncode}.[/yellow]")


def _ingest_file_into_state(path: Path, state: CaseState, case_dir: Path) -> IngestResult:
    if not path.is_file():
        raise ReconError(f"Ingest file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    result = ingest_command_output(text, source=str(path))
    _validate_ingest_target(result, state)
    merge_ingest(state, result)
    _refresh_next_actions(state)
    save_case(case_dir, state)
    return result


def _validate_ingest_target(result: IngestResult, state: CaseState) -> None:
    observed = set(result.target_ips)
    if observed and observed != {state.target}:
        rendered = ", ".join(sorted(observed))
        raise ReconError(
            f"Output target(s) {rendered} do not match this single-target case "
            f"({state.target}); split multi-target output before ingesting it"
        )


def _interactive_menu(state: CaseState, case_dir: Path) -> None:
    while True:
        groups = _refresh_next_actions(state)
        extras = [
            "Run custom Nmap scan",
            "Add a credential",
            "Open target notes",
            "Ingest saved command output",
            "Quit",
        ]
        console.print("\n[bold]Actions[/bold]\n")
        for index, group in enumerate(groups, start=1):
            console.print(f"  [cyan][{index}][/cyan] {group.title}")
        base = len(groups)
        for offset, label in enumerate(extras, start=1):
            console.print(f"  [cyan][{base + offset}][/cyan] {label}")
        choice = IntPrompt.ask(
            "Select", choices=[str(i) for i in range(1, base + len(extras) + 1)]
        )
        try:
            if choice <= base:
                _handle_group(groups[choice - 1], state, case_dir)
            elif choice == base + 1:
                _run_custom_nmap_scan(state, case_dir)
            elif choice == base + 2:
                _add_credential(state, case_dir)
            elif choice == base + 3:
                _open_notes(case_dir)
                state = load_case(case_dir)
            elif choice == base + 4:
                source = Path(Prompt.ask("Output file")).expanduser()
                result = _ingest_file_into_state(source, state, case_dir)
                _print_ingest_result(result, state, case_dir)
            else:
                console.print("[dim]Case saved. Goodbye.[/dim]")
                return
        except (ReconError, ValueError, OSError, ET.ParseError) as exc:
            message = Text("Action failed: ", style="bold red")
            message.append(_terminal_safe(exc))
            console.print(message)
        save_case(case_dir, state)


def _print_ingest_result(result: IngestResult, state: CaseState, case_dir: Path) -> None:
    counts = {
        "hostnames": len(result.hostnames),
        "domains": len(result.domains),
        "usernames": len(result.usernames),
        "credentials": len(result.credentials),
        "shares": len(result.shares),
        "findings": len(result.findings),
    }
    details = ", ".join(f"{value} {name}" for name, value in counts.items() if value)
    if not details:
        details = "no recognized structured evidence"
    console.print(f"[green]Ingest complete:[/green] {details}.")
    console.print(
        Text(
            f"Updated {_terminal_safe(case_dir / NOTES_FILENAME)} for "
            f"{_terminal_safe(state.target)}.",
            style="dim",
        )
    )


def _run_ingest_mode(args: argparse.Namespace) -> int:
    source = args.ingest.expanduser().resolve()
    if not source.is_file():
        raise ReconError(f"Ingest file not found: {source}")
    text = source.read_text(encoding="utf-8", errors="replace")
    parsed = ingest_command_output(text, source=str(source))

    target = validate_target(args.target) if args.target else None
    case_dir = find_case_for_ingest(source, target=target, cases_root=args.cases_dir)
    if case_dir is not None:
        state = load_case(case_dir)
        if target and state.target != target:
            raise ReconError(
                f"Selected case targets {state.target}, but {target} was requested"
            )
    else:
        candidates = [target] if target else parsed.target_ips
        candidates = list(dict.fromkeys(candidate for candidate in candidates if candidate))
        if len(candidates) != 1:
            raise ReconError(
                "Could not identify one target case from the output. "
                "Pass the target explicitly: python recon.py TARGET --ingest FILE"
            )
        state, case_dir = create_case(candidates[0], args.cases_dir)

    _validate_ingest_target(parsed, state)
    merge_ingest(state, parsed)
    _refresh_next_actions(state)
    save_case(case_dir, state)
    _print_ingest_result(parsed, state, case_dir)
    if not args.no_menu and sys.stdin.isatty():
        show_summary(state, case_dir)
        _interactive_menu(state, case_dir)
    return 0


def _run_target_mode(args: argparse.Namespace) -> int:
    if not args.target:
        raise ReconError("Provide a target IP, or use --ingest FILE")
    target = validate_target(args.target)
    state, case_dir = create_case(target, args.cases_dir)

    if args.nmap_xml:
        _import_nmap_xml(state, case_dir, args.nmap_xml.expanduser().resolve())
    elif args.rescan or not state.scan_command:
        if not args.no_menu and sys.stdin.isatty():
            _choose_initial_scan(state, case_dir)
        else:
            console.print(
                "[dim]Interactive scan selection is unavailable; using the Quick "
                "top-1,000 profile. Launch in a terminal without --no-menu to "
                "choose Standard or Full TCP.[/dim]"
            )
            _run_nmap_scan(state, case_dir, profile="quick")
    else:
        console.print(
            Text(
                f"Loaded existing evidence from "
                f"{_terminal_safe(case_dir / STATE_FILENAME)}; "
                "use --rescan to choose a fresh scan.",
                style="dim",
            )
        )

    _refresh_next_actions(state)
    save_case(case_dir, state)
    show_summary(state, case_dir)
    if not args.no_menu and sys.stdin.isatty():
        _interactive_menu(state, case_dir)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        if args.ingest and (args.nmap_xml or args.rescan):
            raise ReconError("--ingest cannot be combined with --nmap-xml or --rescan")
        if args.nmap_xml and args.rescan:
            raise ReconError("Choose either --nmap-xml or --rescan, not both")
        if args.ingest:
            return _run_ingest_mode(args)
        return _run_target_mode(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted; completed case data remains saved.[/yellow]")
        return 130
    except (ReconError, ValueError, OSError, ET.ParseError) as exc:
        message = Text("Error: ", style="bold red")
        message.append(_terminal_safe(exc))
        console.print(message)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
