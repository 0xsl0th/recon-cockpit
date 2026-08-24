"""Parsers for scanner XML and saved enumeration output.

The functions in this module only interpret already-produced output.  They do
not execute scanners or otherwise interact with a target.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import ipaddress
import re
import xml.etree.ElementTree as ET

from .models import Credential, Finding, Host, IngestResult, Service, Share


NmapResult = tuple[list[Host], list[Service]]


# CSI sequences cover colour/style output, while OSC sequences cover terminal
# title and hyperlink escapes sometimes retained by ``tee``.
_ANSI_RE = re.compile(
    r"\x1b(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|[@-_]"
    r")"
)

_IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)

_NXC_PREFIX_RE = re.compile(
    r"(?i)\b(?P<protocol>SMB|LDAP|WINRM|SSH|RDP|MSSQL|WMI|NFS|FTP)\s+"
    r"(?P<ip>\S+)\s+(?P<port>\d+)\s+"
    r"(?P<hostname>\S+)\s*(?P<message>.*)$"
)

_NAME_TAG_RE = re.compile(r"\(name\s*:\s*([^)]*?)\)", re.IGNORECASE)
_DOMAIN_TAG_RE = re.compile(r"\(domain\s*:\s*([^)]*?)\)", re.IGNORECASE)
_SUCCESS_RE = re.compile(r"^\s*\[\+\]\s+(?P<identity>[^:\r\n]+?):(?P<secret>.*)$")
_AUTH_IDENTITY_RE = re.compile(
    r"[A-Za-z0-9_.-]+[\\/][A-Za-z0-9_][A-Za-z0-9_.@$-]*\Z"
)
_PWNED_RE = re.compile(r"\s*\(Pwn3d!\)\s*$", re.IGNORECASE)
_RID_RE = re.compile(
    r"(?<!\d)(?P<rid>\d+)\s*:\s*"
    r"(?:(?P<domain>[^\\\s:]+)\\)?"
    r"(?P<username>.+?)\s*"
    r"\((?P<sid_type>SidTypeUser)\)",
    re.IGNORECASE,
)

_INVALID_HOST_COLUMNS = {"-", "n/a", "none", "unknown"}
_PERMISSION_WORDS = {
    "read",
    "write",
    "read,write",
    "write,read",
    "full",
    "change",
    "deny",
    "no access",
}


def parse_nmap_xml(source: str | Path) -> NmapResult:
    """Parse nmap XML from a path, or directly from an XML string.

    A :class:`pathlib.Path` is always treated as a file.  A string whose first
    non-whitespace character is ``<`` is treated as XML; other strings are
    treated as paths.  Invalid XML and unreadable paths intentionally surface
    the standard ``ElementTree``/filesystem exceptions to the caller.
    """

    if isinstance(source, Path):
        root = ET.parse(source).getroot()
    elif source.lstrip().startswith("<"):
        root = ET.fromstring(source)
    else:
        root = ET.parse(source).getroot()
    return _parse_nmap_root(root)


def parse_nmap_xml_text(xml_text: str) -> NmapResult:
    """Parse nmap XML already loaded into memory."""

    return _parse_nmap_root(ET.fromstring(xml_text))


def _parse_nmap_root(root: ET.Element) -> NmapResult:
    hosts: list[Host] = []
    services: list[Service] = []

    host_elements = [root] if root.tag == "host" else root.findall(".//host")
    for host_element in host_elements:
        address = _host_address(host_element)
        status_element = host_element.find("status")
        status = (
            status_element.get("state", "unknown")
            if status_element is not None
            else "unknown"
        )
        hostnames = _ordered_unique(
            name
            for element in host_element.findall("./hostnames/hostname")
            if (name := element.get("name", "").strip())
        )
        host = Host(
            address=address,
            status=status,
            hostnames=hostnames,
            os_guess=_os_guess(host_element),
        )
        hosts.append(host)

        for port_element in host_element.findall("./ports/port"):
            port_text = port_element.get("portid", "")
            try:
                port = int(port_text)
            except (TypeError, ValueError):
                # A malformed/missing port id cannot be represented by Service.
                continue

            state_element = port_element.find("state")
            service_element = port_element.find("service")
            scripts: dict[str, str] = {}
            for index, script in enumerate(port_element.findall("script"), start=1):
                script_id = script.get("id", "").strip() or f"script-{index}"
                output = _nse_script_output(script)
                if script_id not in scripts:
                    scripts[script_id] = output
                elif output:
                    scripts[script_id] = "\n".join(
                        part for part in (scripts[script_id], output) if part
                    )

            services.append(
                Service(
                    host=address,
                    port=port,
                    protocol=port_element.get("protocol", "tcp") or "tcp",
                    state=(
                        state_element.get("state", "unknown")
                        if state_element is not None
                        else "unknown"
                    ),
                    name=(
                        service_element.get("name", "unknown")
                        if service_element is not None
                        else "unknown"
                    )
                    or "unknown",
                    product=(
                        service_element.get("product", "")
                        if service_element is not None
                        else ""
                    ),
                    version=(
                        service_element.get("version", "")
                        if service_element is not None
                        else ""
                    ),
                    extra_info=(
                        service_element.get("extrainfo", "")
                        if service_element is not None
                        else ""
                    ),
                    tunnel=(
                        service_element.get("tunnel", "")
                        if service_element is not None
                        else ""
                    ),
                    scripts=scripts,
                )
            )

    return hosts, services


def _host_address(host: ET.Element) -> str:
    """Choose a routable address, preferring IPv4 and avoiding a MAC."""

    addresses = host.findall("address")
    for address_type in ("ipv4", "ipv6"):
        for element in addresses:
            if element.get("addrtype", "").lower() == address_type:
                value = element.get("addr", "").strip()
                if value:
                    return _canonical_ip(value)
    for element in addresses:
        if element.get("addrtype", "").lower() != "mac":
            value = element.get("addr", "").strip()
            if value:
                return _canonical_ip(value)
    return ""


def _canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _os_guess(host: ET.Element) -> str:
    candidates: list[tuple[int, int, str]] = []
    order = 0
    for match in host.findall("./os/osmatch"):
        name = match.get("name", "").strip()
        if name:
            candidates.append((_accuracy(match.get("accuracy")), -order, name))
            order += 1

    if candidates:
        return max(candidates)[2]

    # Some XML producers include osclass without a parent osmatch.
    for os_class in host.findall("./os//osclass"):
        parts = _ordered_unique(
            value
            for key in ("vendor", "osfamily", "osgen", "type")
            if (value := os_class.get(key, "").strip())
        )
        if parts:
            candidates.append(
                (_accuracy(os_class.get("accuracy")), -order, " ".join(parts))
            )
            order += 1
    return max(candidates)[2] if candidates else ""


def _accuracy(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _nse_script_output(script: ET.Element) -> str:
    output = script.get("output")
    if output is not None:
        return output.strip()
    return " ".join(text.strip() for text in script.itertext() if text.strip())


def strip_ansi(text: str) -> str:
    """Remove terminal ANSI control sequences from captured command output."""

    return _ANSI_RE.sub("", text)


def ingest_command_output(text: str, source: str = "ingest") -> IngestResult:
    """Extract reusable evidence from saved NetExec/NXC SMB output.

    Successful ``[+]`` authentications, RID-brute users, SMB identity/banner
    details, and enumerated shares are supported.  Failed ``[-]`` attempts are
    deliberately ignored as credentials.  Results retain first-seen order and
    are deduplicated case-insensitively where appropriate.
    """

    cleaned = strip_ansi(text).replace("\r", "")
    result = IngestResult()
    seen_ips: set[str] = set()
    seen_hostnames: set[str] = set()
    seen_domains: set[str] = set()
    seen_usernames: set[str] = set()
    credential_indexes: dict[tuple[str, str, str], int] = {}
    share_indexes: dict[tuple[str, str], int] = {}
    seen_findings: set[tuple[str, str]] = set()

    # host -> (permissions column, remark column), where None means that share
    # enumeration started but its header has not been observed yet.
    share_tables: dict[str, tuple[int, int] | None] = {}

    def add_unique(values: list[str], seen: set[str], value: str) -> None:
        value = value.strip()
        key = value.casefold()
        if value and key not in seen:
            seen.add(key)
            values.append(value)

    def add_finding(category: str, detail: str) -> None:
        key = (category.casefold(), detail.casefold())
        if key not in seen_findings:
            seen_findings.add(key)
            result.findings.append(Finding(category, detail, source))

    for line in cleaned.splitlines():
        prefix = _NXC_PREFIX_RE.search(line)
        if prefix:
            try:
                host_ip = str(ipaddress.ip_address(prefix.group("ip").strip("[]")))
            except ValueError:
                prefix = None
                host_ip = ""
        else:
            host_ip = ""
        protocol = prefix.group("protocol").casefold() if prefix else ""
        message = prefix.group("message") if prefix else line.strip()

        # On structured NXC rows the first IP column is the target.  Avoid
        # misclassifying an IP-shaped password or banner value as another host.
        candidate_ips = [host_ip] if host_ip else _unstructured_ip_candidates(line)
        for raw_ip in candidate_ips:
            try:
                ip = str(ipaddress.ip_address(raw_ip.strip("[]")))
            except ValueError:
                continue
            if ip not in seen_ips:
                seen_ips.add(ip)
                result.target_ips.append(ip)

        if prefix:
            column_hostname = prefix.group("hostname").strip()
            if (
                column_hostname.casefold() not in _INVALID_HOST_COLUMNS
                and not _is_ip_address(column_hostname)
            ):
                add_unique(result.hostnames, seen_hostnames, column_hostname)

        if prefix:
            for match in _NAME_TAG_RE.finditer(message):
                value = match.group(1).strip()
                if value.casefold() not in _INVALID_HOST_COLUMNS:
                    add_unique(result.hostnames, seen_hostnames, value)
            for match in _DOMAIN_TAG_RE.finditer(message):
                value = match.group(1).strip()
                if value.casefold() not in _INVALID_HOST_COLUMNS:
                    add_unique(result.domains, seen_domains, value)

        if prefix and protocol == "smb" and "enumerated shares" in message.casefold():
            share_tables[host_ip] = None
            continue

        rid_match = _RID_RE.search(message) if prefix and protocol == "smb" else None
        success_match = _SUCCESS_RE.search(message) if prefix else None
        if success_match and not _is_auth_identity(success_match.group("identity")):
            success_match = None
        if host_ip in share_tables:
            table_message = message.expandtabs()
            if _is_share_header(table_message):
                lowered = table_message.casefold()
                share_tables[host_ip] = (
                    lowered.index("permissions"),
                    lowered.index("remark"),
                )
                continue
            if _is_share_divider(table_message) or not table_message.strip():
                continue
            if (
                table_message.lstrip().startswith("[")
                or rid_match is not None
                or success_match is not None
            ):
                share_tables.pop(host_ip, None)
            else:
                parsed_share = _parse_share_row(
                    table_message, share_tables[host_ip]
                )
                if parsed_share is not None:
                    name, permissions, remark = parsed_share
                    key = (host_ip.casefold(), name.casefold())
                    if key in share_indexes:
                        existing = result.shares[share_indexes[key]]
                        if not existing.permissions and permissions:
                            existing.permissions = permissions
                        if not existing.remark and remark:
                            existing.remark = remark
                    else:
                        share_indexes[key] = len(result.shares)
                        result.shares.append(
                            Share(host_ip, name, permissions, remark, source)
                        )
                    continue

        if rid_match:
            username = rid_match.group("username").strip()
            domain = (rid_match.group("domain") or "").strip()
            add_unique(result.usernames, seen_usernames, username)
            if domain:
                add_unique(result.domains, seen_domains, domain)
            qualified = f"{domain}\\{username}" if domain else username
            location = f"{host_ip}: " if host_ip else ""
            add_finding(
                "RID enumeration",
                f"{location}{rid_match.group('rid')} -> {qualified} (SidTypeUser)",
            )

        # Only [+] lines reach the credential parser; in particular, a nearby
        # failed [-] attempt can never be promoted to a credential.
        if success_match:
            identity = success_match.group("identity").strip()
            secret_with_marker = success_match.group("secret").strip()
            pwned = bool(_PWNED_RE.search(secret_with_marker))
            secret = _PWNED_RE.sub("", secret_with_marker).strip()
            domain, username = _split_identity(identity)
            if username and secret:
                add_unique(result.usernames, seen_usernames, username)
                if domain:
                    add_unique(result.domains, seen_domains, domain)
                key = (domain.casefold(), username.casefold(), secret)
                status = "successful (admin)" if pwned else "successful"
                if key in credential_indexes:
                    credential = result.credentials[credential_indexes[key]]
                    if pwned:
                        credential.status = "successful (admin)"
                else:
                    credential_indexes[key] = len(result.credentials)
                    result.credentials.append(
                        Credential(username, secret, domain, status, source)
                    )
                if pwned:
                    principal = f"{domain}\\{username}" if domain else username
                    location = f" on {host_ip}" if host_ip else ""
                    add_finding(
                        "Administrative authentication",
                        (
                            f"{principal} authenticated with administrative "
                            f"access{location}"
                        ),
                    )

        banner = _smb_banner(message) if prefix and protocol == "smb" else ""
        if banner:
            detail = f"{host_ip}: {banner}" if host_ip else banner
            add_finding("SMB banner", detail)

    return result


def _split_identity(identity: str) -> tuple[str, str]:
    for separator in ("\\", "/"):
        if separator in identity:
            domain, username = identity.split(separator, 1)
            return domain.strip(), username.strip()
    return "", identity.strip()


def _is_auth_identity(identity: str) -> bool:
    # NetExec reports successful principals as DOMAIN\user (or DOMAIN/user).
    # Requiring that qualification prevents generic `[+] Result:42` messages
    # from manufacturing credentials. Unqualified identities can still be added
    # deliberately through the manual-credential workflow.
    return bool(_AUTH_IDENTITY_RE.fullmatch(identity.strip()))


def _unstructured_ip_candidates(line: str) -> list[str]:
    """Find standalone IPs when no validated NetExec prefix is available."""

    candidates = list(_IPV4_RE.findall(line))
    for token in re.split(r"\s+", line):
        candidate = token.strip("[](),;")
        if ":" not in candidate:
            continue
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.version == 6:
            candidates.append(str(parsed))
    return _ordered_unique(candidates)


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _smb_banner(message: str) -> str:
    marker = re.match(r"\s*\[\*\]\s*(.+)$", message)
    if not marker:
        return ""
    detail = marker.group(1).strip()
    if detail.casefold().startswith("enumerated shares"):
        return ""
    lowered = detail.casefold()
    indicators = (
        "windows",
        "samba",
        "linux",
        "unix",
        "macos",
        "build ",
        "(name:",
        "(domain:",
        "(signing:",
        "(smbv1:",
    )
    return detail if any(indicator in lowered for indicator in indicators) else ""


def _is_share_header(message: str) -> bool:
    lowered = message.casefold()
    return all(column in lowered for column in ("share", "permissions", "remark"))


def _is_share_divider(message: str) -> bool:
    compact = message.replace(" ", "").replace("\t", "")
    return bool(compact) and set(compact) <= {"-"}


def _parse_share_row(
    message: str, columns: tuple[int, int] | None
) -> tuple[str, str, str] | None:
    if columns is not None:
        permission_column, remark_column = columns
        name = message[:permission_column].strip()
        permissions = message[permission_column:remark_column].strip()
        remark = message[remark_column:].strip()
    else:
        fields = [field.strip() for field in re.split(r"\s{2,}|\t+", message.strip())]
        if not fields or not fields[0]:
            return None
        name = fields[0]
        permissions = ""
        remark = ""
        if len(fields) >= 3:
            permissions, remark = fields[1], "  ".join(fields[2:])
        elif len(fields) == 2:
            if fields[1].casefold() in _PERMISSION_WORDS:
                permissions = fields[1]
            else:
                remark = fields[1]

    if not name or name.casefold() in {"share", "-----"}:
        return None
    return name, permissions, remark


def _ordered_unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


__all__ = [
    "NmapResult",
    "ingest_command_output",
    "parse_nmap_xml",
    "parse_nmap_xml_text",
    "strip_ansi",
]
