"""Durable case storage and human-readable case notes.

The scanner and output parsers deliberately return plain dataclasses.  This module
is the small persistence boundary that joins those results together without
discarding evidence collected during an earlier run.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from .constants import (
    MANUAL_NOTES_END,
    MANUAL_NOTES_START,
    NOTES_FILENAME,
    STATE_FILENAME,
)
from .models import (
    CaseState,
    Credential,
    Finding,
    Host,
    IngestResult,
    Service,
    Share,
)
from .parsers import strip_ansi

DEFAULT_CASES_ROOT = Path("cases")
CASE_SUBDIRECTORIES = ("scans", "loot", "commands")

_T = TypeVar("_T")
_MANUAL_SECTION_START_RE = re.compile(
    r"^## Manual notes[ \t]*\r?\n\r?\n" + re.escape(MANUAL_NOTES_START),
    re.MULTILINE,
)
_MANUAL_SECTION_END_RE = re.compile(
    re.escape(MANUAL_NOTES_END) + r"[ \t]*(?:\r?\n)?\Z"
)
_NEUTRALIZED_MANUAL_NOTES_START = MANUAL_NOTES_START.replace(
    "<", "&lt;"
).replace(">", "&gt;")
_NEUTRALIZED_MANUAL_NOTES_END = MANUAL_NOTES_END.replace("<", "&lt;").replace(
    ">", "&gt;"
)
_UNSAFE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def utc_now() -> str:
    """Return a compact, timezone-aware timestamp suitable for the state file."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sanitize_target(target: str) -> str:
    """Turn a target into a safe, deterministic single directory name.

    IP addresses remain readable (``10.10.11.123``), while separators in IPv6
    addresses and accidental path components are replaced.  A digest suffix
    keeps unusually long hostnames deterministic without exceeding common file
    system name limits.
    """

    value = str(target).strip()
    if not value:
        raise ValueError("target must not be empty")

    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-").lower()
    if not safe:
        raise ValueError("target does not contain any usable characters")
    if len(safe) > 120:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        safe = f"{safe[:107]}-{digest}"
    return safe


def case_dir_for_target(
    target: str, cases_root: str | os.PathLike[str] = DEFAULT_CASES_ROOT
) -> Path:
    """Return the directory used to persist ``target``."""

    return Path(cases_root).expanduser() / sanitize_target(target)


def _ensure_layout(case_dir: Path) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    case_dir.chmod(0o700)
    for name in CASE_SUBDIRECTORIES:
        child = case_dir / name
        child.mkdir(exist_ok=True)
        child.chmod(0o700)


def _resolve_case_dir(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path).expanduser()
    if candidate.name in {STATE_FILENAME, NOTES_FILENAME}:
        return candidate.parent
    return candidate


def create_case(
    target: str, cases_root: str | os.PathLike[str] = DEFAULT_CASES_ROOT
) -> tuple[CaseState, Path]:
    """Create (or reopen) a case and return ``(state, directory)``.

    Re-running the command for an existing target is intentionally non-
    destructive: its JSON state, credentials, and manual notes are loaded but
    not rewritten.
    """

    case_dir = case_dir_for_target(target, cases_root)
    _ensure_layout(case_dir)
    state_path = case_dir / STATE_FILENAME
    if state_path.exists():
        state = load_case(case_dir)
        if state.target.casefold() != str(target).strip().casefold():
            raise ValueError(
                f"case directory {case_dir} belongs to {state.target!r}, not {target!r}"
            )
        return state, case_dir
    now = utc_now()
    state = CaseState(target=str(target).strip(), created_at=now, updated_at=now)
    save_case(case_dir, state)
    return state, case_dir


def load_case(path: str | os.PathLike[str]) -> CaseState:
    """Load a case from a case directory or a direct ``case.json`` path."""

    case_dir = _resolve_case_dir(path)
    state_path = case_dir / STATE_FILENAME
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"case state does not exist: {state_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"case state is not valid JSON: {state_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"case state must contain a JSON object: {state_path}")
    try:
        return CaseState.from_dict(raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"case state has an invalid schema: {state_path}: {exc}") from exc


def _atomic_text_write(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Replace ``path`` with a fully written temporary file in the same folder."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", text=True
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        # os.replace removes the temporary path.  On an exception this only
        # removes the private file created by this invocation.
        temporary_path.unlink(missing_ok=True)


def save_case(
    path: str | os.PathLike[str] | CaseState,
    state: CaseState | str | os.PathLike[str],
) -> None:
    """Atomically-ish save JSON state and regenerate its Markdown notes.

    ``save_case(state, path)`` is accepted as a convenience in addition to the
    documented ``save_case(path, state)`` ordering.
    """

    if isinstance(path, CaseState):
        path, state = state, path
    if not isinstance(state, CaseState):
        raise TypeError("state must be a CaseState")

    case_dir = _resolve_case_dir(path)
    _ensure_layout(case_dir)
    state.updated_at = utc_now()

    notes_path = case_dir / NOTES_FILENAME
    try:
        existing_notes = notes_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        existing_notes = ""

    serialized = json.dumps(
        state.to_dict(), indent=2, ensure_ascii=False, sort_keys=True
    ) + "\n"
    notes = render_notes(state, existing_notes=existing_notes)
    _atomic_text_write(case_dir / STATE_FILENAME, serialized)
    _atomic_text_write(notes_path, notes)


@dataclass(frozen=True, slots=True)
class CaseStore:
    """Small object-oriented facade for callers that prefer a bound case path."""

    path: Path

    @classmethod
    def create(
        cls, target: str, cases_root: str | os.PathLike[str] = DEFAULT_CASES_ROOT
    ) -> "CaseStore":
        _state, case_dir = create_case(target, cases_root)
        return cls(case_dir)

    def load(self) -> CaseState:
        return load_case(self.path)

    def save(self, state: CaseState) -> None:
        save_case(self.path, state)

    @property
    def state_path(self) -> Path:
        return self.path / STATE_FILENAME

    @property
    def notes_path(self) -> Path:
        return self.path / NOTES_FILENAME


def _stable_unique(values: Iterable[_T], key) -> list[_T]:
    result: list[_T] = []
    seen: set[object] = set()
    for value in values:
        identity = key(value)
        if identity not in seen:
            seen.add(identity)
            result.append(value)
    return result


def _merge_text_values(existing: Iterable[str], incoming: Iterable[str]) -> list[str]:
    return _stable_unique(
        (value for value in (*existing, *incoming) if str(value).strip()),
        key=lambda value: str(value).strip().casefold(),
    )


def _merge_hosts(existing: Iterable[Host], incoming: Iterable[Host]) -> list[Host]:
    merged: list[Host] = []
    positions: dict[str, int] = {}
    for candidate in (*existing, *incoming):
        key = candidate.address.strip().casefold()
        if not key:
            continue
        if key not in positions:
            positions[key] = len(merged)
            merged.append(
                Host(
                    address=candidate.address.strip(),
                    status=candidate.status,
                    hostnames=_merge_text_values([], candidate.hostnames),
                    os_guess=candidate.os_guess,
                )
            )
            continue
        current = merged[positions[key]]
        current.hostnames = _merge_text_values(current.hostnames, candidate.hostnames)
        if candidate.status:
            current.status = candidate.status
        if candidate.os_guess:
            current.os_guess = candidate.os_guess
    return merged


def _service_key(service: Service) -> tuple[str, int, str]:
    return (service.host.strip().casefold(), int(service.port), service.protocol.casefold())


def _merge_services(
    existing: Iterable[Service], incoming: Iterable[Service]
) -> list[Service]:
    merged: list[Service] = []
    positions: dict[tuple[str, int, str], int] = {}
    for candidate in (*existing, *incoming):
        key = _service_key(candidate)
        if key not in positions:
            positions[key] = len(merged)
            merged.append(
                Service(
                    host=candidate.host,
                    port=int(candidate.port),
                    protocol=candidate.protocol,
                    state=candidate.state,
                    name=candidate.name,
                    product=candidate.product,
                    version=candidate.version,
                    extra_info=candidate.extra_info,
                    tunnel=candidate.tunnel,
                    scripts=dict(candidate.scripts),
                )
            )
            continue

        current = merged[positions[key]]
        for attribute in (
            "host",
            "protocol",
            "state",
            "product",
            "version",
            "extra_info",
            "tunnel",
        ):
            value = getattr(candidate, attribute)
            if value:
                setattr(current, attribute, value)
        if candidate.name and candidate.name.casefold() != "unknown":
            current.name = candidate.name
        for script_name, output in candidate.scripts.items():
            if output or script_name not in current.scripts:
                current.scripts[script_name] = output
    return merged


def _finding_key(finding: Finding) -> tuple[str, str]:
    return (finding.category.strip().casefold(), finding.detail.strip().casefold())


def _merge_findings(
    existing: Iterable[Finding], incoming: Iterable[Finding]
) -> list[Finding]:
    merged: list[Finding] = []
    positions: dict[tuple[str, str], int] = {}
    for candidate in (*existing, *incoming):
        key = _finding_key(candidate)
        if key not in positions:
            positions[key] = len(merged)
            merged.append(
                Finding(
                    category=candidate.category,
                    detail=candidate.detail,
                    source=candidate.source,
                )
            )
        elif not merged[positions[key]].source and candidate.source:
            merged[positions[key]].source = candidate.source
    return merged


def _credential_key(credential: Credential) -> tuple[str, str, str]:
    return (
        credential.domain.strip().casefold(),
        credential.username.strip().casefold(),
        credential.secret,
    )


def _credential_status_rank(status: str) -> int:
    normalized = status.strip().casefold()
    if any(token in normalized for token in ("success", "pwned", "admin")) or re.search(
        r"\bvalid\b", normalized
    ):
        return 4
    if any(token in normalized for token in ("locked", "expired", "disabled")):
        return 3
    if any(token in normalized for token in ("fail", "invalid", "denied")):
        return 2
    if normalized and normalized != "unverified":
        return 1
    return 0


def _merge_credentials(
    existing: Iterable[Credential], incoming: Iterable[Credential]
) -> list[Credential]:
    merged: list[Credential] = []
    positions: dict[tuple[str, str, str], int] = {}
    for candidate in (*existing, *incoming):
        key = _credential_key(candidate)
        if key not in positions:
            positions[key] = len(merged)
            merged.append(
                Credential(
                    username=candidate.username,
                    secret=candidate.secret,
                    domain=candidate.domain,
                    status=candidate.status,
                    source=candidate.source,
                )
            )
            continue

        current = merged[positions[key]]
        if _credential_status_rank(candidate.status) > _credential_status_rank(
            current.status
        ):
            current.status = candidate.status
        # A manually entered credential should remain visibly manual even if an
        # ingest later confirms it.  Otherwise keep the first evidence source.
        if candidate.source.casefold() == "manual" and current.source.casefold() != "manual":
            current.source = candidate.source
        elif not current.source and candidate.source:
            current.source = candidate.source
    return merged


def _share_key(share: Share) -> tuple[str, str]:
    return (share.host.strip().casefold(), share.name.strip().casefold())


def _merge_shares(existing: Iterable[Share], incoming: Iterable[Share]) -> list[Share]:
    merged: list[Share] = []
    positions: dict[tuple[str, str], int] = {}
    for candidate in (*existing, *incoming):
        key = _share_key(candidate)
        if key not in positions:
            positions[key] = len(merged)
            merged.append(
                Share(
                    host=candidate.host,
                    name=candidate.name,
                    permissions=candidate.permissions,
                    remark=candidate.remark,
                    source=candidate.source,
                )
            )
            continue
        current = merged[positions[key]]
        if candidate.permissions:
            current.permissions = candidate.permissions
        if candidate.remark:
            current.remark = candidate.remark
        if not current.source and candidate.source:
            current.source = candidate.source
    return merged


def merge_scan(
    state: CaseState,
    hosts: Iterable[Host],
    services: Iterable[Service],
    *,
    findings: Iterable[Finding] = (),
    next_actions: Iterable[str] = (),
    scan_command: Sequence[str] | None = None,
) -> CaseState:
    """Merge parsed scan evidence into ``state`` with stable de-duplication."""

    state.hosts = _merge_hosts(state.hosts, hosts)
    state.services = _merge_services(state.services, services)
    state.findings = _merge_findings(state.findings, findings)
    state.next_actions = _merge_text_values(state.next_actions, next_actions)
    if scan_command is not None:
        state.scan_command = [str(part) for part in scan_command]
    state.updated_at = utc_now()
    return state


def merge_ingest(state: CaseState, result: IngestResult) -> CaseState:
    """Merge safely parsed command output into an existing case.

    Existing values always retain their position.  A repeated credential can be
    promoted from unverified to successful, but a new ingest never clears manual
    credentials or findings.
    """

    ingested_addresses = [*result.target_ips, *(share.host for share in result.shares)]
    ingested_hosts = [Host(address=address) for address in ingested_addresses if address]
    state.hosts = _merge_hosts(state.hosts, ingested_hosts)

    hostnames = _merge_text_values([], result.hostnames)
    if hostnames:
        preferred_addresses = {value.casefold() for value in result.target_ips}
        preferred_addresses.add(state.target.casefold())
        host = next(
            (
                candidate
                for candidate in state.hosts
                if candidate.address.casefold() in preferred_addresses
            ),
            state.hosts[0] if state.hosts else None,
        )
        if host is None:
            host = Host(address=state.target)
            state.hosts.append(host)
        host.hostnames = _merge_text_values(host.hostnames, hostnames)

    state.domains = _merge_text_values(state.domains, result.domains)
    state.usernames = _merge_text_values(state.usernames, result.usernames)
    state.credentials = _merge_credentials(state.credentials, result.credentials)
    state.shares = _merge_shares(state.shares, result.shares)
    state.findings = _merge_findings(state.findings, result.findings)

    # Credential identities are also useful in the non-secret domain/user index.
    state.domains = _merge_text_values(
        state.domains, (credential.domain for credential in result.credentials)
    )
    state.usernames = _merge_text_values(
        state.usernames, (credential.username for credential in result.credentials)
    )
    state.updated_at = utc_now()
    return state


def _manual_content(existing_notes: str) -> str:
    """Extract only the marker pair owned by the final manual-notes section.

    Scanner-controlled table cells can contain arbitrary text, including the
    marker literals.  They must never be mistaken for the managed block.  The
    opening marker therefore has to immediately follow our section heading and
    the closing marker has to be the final non-newline content in the document.
    """

    section_start = _MANUAL_SECTION_START_RE.search(existing_notes)
    if section_start is None:
        return "\n\n"
    section_end = _MANUAL_SECTION_END_RE.search(existing_notes, section_start.end())
    if section_end is None:
        return "\n\n"
    return existing_notes[section_start.end() : section_end.start()]


def _redact(value: object, secrets: Sequence[str]) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def _markdown_cell(value: object, secrets: Sequence[str] = ()) -> str:
    text = _UNSAFE_CONTROL_RE.sub("", strip_ansi(_redact(value, secrets)))
    # Managed markers are control syntax, not display data.  Encoding their
    # angle brackets keeps the text recognizable to a reader while preventing
    # scanner output from creating an active marker pair in notes.md.
    text = text.replace(MANUAL_NOTES_START, _NEUTRALIZED_MANUAL_NOTES_START)
    text = text.replace(MANUAL_NOTES_END, _NEUTRALIZED_MANUAL_NOTES_END)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
        .replace("\r", "<br>")
    )


def _table(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    *,
    secrets: Sequence[str] = (),
    secret_column: int | None = None,
) -> str:
    rendered_rows = list(rows)
    if not rendered_rows:
        return "_None recorded._"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rendered_rows:
        cells = []
        for index, value in enumerate(row):
            cells.append(
                _markdown_cell(value, () if index == secret_column else secrets)
            )
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def render_notes(state: CaseState, *, existing_notes: str = "") -> str:
    """Render a complete ``notes.md``, preserving its manual marker block."""

    secrets = tuple(
        sorted(
            {credential.secret for credential in state.credentials if credential.secret},
            key=len,
            reverse=True,
        )
    )
    hosts = _table(
        ("Address", "Status", "Hostnames", "OS guess"),
        (
            (host.address, host.status, ", ".join(host.hostnames), host.os_guess)
            for host in state.hosts
        ),
        secrets=secrets,
    )
    services = _table(
        ("Host", "Port", "Protocol", "State", "Service", "Version", "Scripts"),
        (
            (
                service.host,
                service.port,
                service.protocol,
                service.state,
                service.name,
                service.banner,
                "; ".join(
                    f"{name}: {output}" for name, output in service.scripts.items()
                ),
            )
            for service in state.services
        ),
        secrets=secrets,
    )
    findings = _table(
        ("Category", "Finding", "Source"),
        ((item.category, item.detail, item.source) for item in state.findings),
        secrets=secrets,
    )
    identities = _table(
        ("Domains", "Users"),
        [(", ".join(state.domains), ", ".join(state.usernames))]
        if state.domains or state.usernames
        else [],
        secrets=secrets,
    )
    credentials = _table(
        ("Domain", "Username", "Secret", "Status", "Source"),
        (
            (
                credential.domain,
                credential.username,
                credential.secret,
                credential.status,
                credential.source,
            )
            for credential in state.credentials
        ),
        secrets=secrets,
        secret_column=2,
    )
    shares = _table(
        ("Host", "Share", "Permissions", "Remark", "Source"),
        (
            (share.host, share.name, share.permissions, share.remark, share.source)
            for share in state.shares
        ),
        secrets=secrets,
    )
    actions = (
        "\n".join(
            f"- [ ] {_markdown_cell(action, secrets)}"
            for action in state.next_actions
        )
        or "_None queued._"
    )
    scan_command = (
        " ".join(_redact(part, secrets) for part in state.scan_command)
        if state.scan_command
        else "Not recorded"
    )
    manual = _manual_content(existing_notes)

    return (
        f"# Recon case: {_markdown_cell(state.target, secrets)}\n\n"
        f"- Target: `{_markdown_cell(state.target, secrets)}`\n"
        f"- Created: `{_markdown_cell(state.created_at)}`\n"
        f"- Updated: `{_markdown_cell(state.updated_at)}`\n"
        f"- Last scan command: `{_markdown_cell(scan_command, secrets)}`\n\n"
        f"## Hosts\n\n{hosts}\n\n"
        f"## Ports and services\n\n{services}\n\n"
        f"## Findings\n\n{findings}\n\n"
        f"## Domains and users\n\n{identities}\n\n"
        f"## Credentials\n\n{credentials}\n\n"
        f"## Shares\n\n{shares}\n\n"
        f"## Next actions\n\n{actions}\n\n"
        f"## Manual notes\n\n{MANUAL_NOTES_START}{manual}{MANUAL_NOTES_END}\n"
    )


def _target_values(target: str | Iterable[str] | None) -> list[str]:
    if target is None:
        return []
    if isinstance(target, str):
        return [target]
    return [str(value) for value in target]


def _case_search_terms(state: CaseState, case_dir: Path) -> set[str]:
    terms = {state.target.casefold(), case_dir.name.casefold()}
    for host in state.hosts:
        terms.add(host.address.casefold())
        terms.update(hostname.casefold() for hostname in host.hostnames)
    return {term for term in terms if term}


def _valid_ip_tokens(text: str) -> set[str]:
    candidates = set(re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text))
    candidates.update(re.findall(r"(?<![\w:])[0-9A-Fa-f:]{3,}(?![\w:])", text))
    valid: set[str] = set()
    for candidate in candidates:
        try:
            valid.add(str(ipaddress.ip_address(candidate)).casefold())
        except ValueError:
            continue
    return valid


def _contains_complete_term(text: str, term: str) -> bool:
    """Match a host token without treating one IP/hostname as a prefix of another."""

    return re.search(
        rf"(?<![A-Za-z0-9_.:-]){re.escape(term)}(?![A-Za-z0-9_.:-])", text
    ) is not None


def find_case_for_ingest(
    path: str | os.PathLike[str],
    target: str | Iterable[str] | None = None,
    cases_root: str | os.PathLike[str] = DEFAULT_CASES_ROOT,
) -> Path | None:
    """Locate the case to update for an ingested output file.

    An ancestor containing ``case.json`` is authoritative.  Otherwise explicit
    parser-extracted target values are matched against case targets and hosts.  As
    a final convenience, known targets are looked for in the input path and in up
    to the first four MiB of a regular output file.  Ambiguous inferred matches
    return ``None`` instead of updating the wrong case.
    """

    source = Path(path).expanduser()
    start = source if source.is_dir() else source.parent
    try:
        current = start.resolve(strict=False)
    except OSError:
        current = start.absolute()
    for ancestor in (current, *current.parents):
        if (ancestor / STATE_FILENAME).is_file():
            return ancestor

    root = Path(cases_root).expanduser().resolve(strict=False)
    if not root.is_dir():
        return None

    cases: list[tuple[Path, CaseState, set[str]]] = []
    for state_path in sorted(root.glob(f"*/{STATE_FILENAME}")):
        try:
            state = load_case(state_path)
        except (OSError, ValueError):
            continue
        case_dir = state_path.parent.resolve(strict=False)
        cases.append((case_dir, state, _case_search_terms(state, case_dir)))

    requested = {value.strip().casefold() for value in _target_values(target) if value.strip()}
    if requested:
        matches = [
            case_dir
            for case_dir, _state, terms in cases
            if terms.intersection(requested)
        ]
        unique = list(dict.fromkeys(matches))
        return unique[0] if len(unique) == 1 else None

    evidence = str(source).casefold()
    try:
        if source.is_file():
            with source.open("r", encoding="utf-8", errors="replace") as handle:
                evidence += "\n" + handle.read(4 * 1024 * 1024).casefold()
    except OSError:
        pass
    evidence_ips = _valid_ip_tokens(evidence)

    matches = []
    for case_dir, _state, terms in cases:
        if evidence_ips.intersection(terms) or any(
            _contains_complete_term(evidence, term)
            for term in terms
            if len(term) >= 3
        ):
            matches.append(case_dir)
    unique = list(dict.fromkeys(matches))
    return unique[0] if len(unique) == 1 else None


__all__ = [
    "CASE_SUBDIRECTORIES",
    "DEFAULT_CASES_ROOT",
    "CaseStore",
    "case_dir_for_target",
    "create_case",
    "find_case_for_ingest",
    "load_case",
    "merge_ingest",
    "merge_scan",
    "render_notes",
    "sanitize_target",
    "save_case",
]
