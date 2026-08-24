"""Evidence-driven, inert command suggestions.

This module never executes a command.  It translates services observed by nmap
into argv tuples that the UI may display and, after an explicit confirmation,
hand to a process runner.  Keeping argv structured is intentional: callers do
not need a shell and user supplied values cannot turn into shell pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass
from shlex import join as _shlex_join
from typing import Iterable, Sequence

from .models import CaseState, Credential, Host, Service


HTTP_PORTS = frozenset(
    {
        80,
        443,
        3000,
        5000,
        5601,
        7001,
        8000,
        8008,
        8080,
        8081,
        8088,
        8181,
        8443,
        8888,
        9000,
        9090,
        9443,
        10000,
    }
)
HTTPS_PORTS = frozenset({443, 8443, 9443})
SMB_PORTS = frozenset({139, 445})
LDAP_PORTS = frozenset({389, 636, 3268, 3269})
LDAPS_PORTS = frozenset({636, 3269})
KERBEROS_PORTS = frozenset({88, 464})
WINRM_PORTS = frozenset({5985, 5986})

_CATEGORY_ORDER = (
    "http",
    "smb",
    "ldap",
    "kerberos",
    "winrm",
    "credentials",
    "nmap_deep",
)
_GROUP_TITLES = {
    "http": "Enumerate HTTP",
    "smb": "Enumerate SMB",
    "ldap": "Enumerate LDAP",
    "kerberos": "Enumerate Kerberos",
    "winrm": "Inspect WinRM",
    "credentials": "Test known credentials",
    "nmap_deep": "Run deeper nmap scan",
}


@dataclass(frozen=True, slots=True)
class CommandSuggestion:
    """A command proposal; ``active`` means it needs affirmative consent."""

    description: str
    argv: tuple[str, ...]
    category: str
    active: bool = True
    evidence: str = ""

    @property
    def title(self) -> str:
        """Compatibility alias useful to menu renderers."""

        return self.description

    @property
    def display(self) -> str:
        """Return a safely quoted representation for display, not execution."""

        return shell_join(self.argv)


# A readable alias for integrations that use the noun before the qualifier.
SuggestedCommand = CommandSuggestion


@dataclass(frozen=True, slots=True)
class SuggestionGroup:
    """A stable menu group containing one or more related suggestions."""

    key: str
    title: str
    evidence: str
    commands: tuple[CommandSuggestion, ...]


@dataclass(frozen=True, slots=True)
class ServiceClassification:
    """Relevant services and the Windows posture inferred from scan evidence."""

    http: tuple[Service, ...]
    smb: tuple[Service, ...]
    ldap: tuple[Service, ...]
    kerberos: tuple[Service, ...]
    winrm: tuple[Service, ...]
    probable_windows: bool
    windows_stack: bool
    windows_evidence: tuple[str, ...]


def shell_join(argv: Sequence[str]) -> str:
    """Quote an argv sequence for clean terminal display.

    The returned string must not be used as an execution primitive.  Consumers
    should execute the original argv sequence without ``shell=True``.
    """

    return _shlex_join(list(argv))


def _is_open(service: Service) -> bool:
    """Return whether a service is actionable in the TCP-oriented cockpit."""

    return service.state.casefold() == "open" and service.protocol.casefold() == "tcp"


def _fingerprint(service: Service) -> str:
    script_text = " ".join(
        [*service.scripts.keys(), *service.scripts.values()]
    )
    return " ".join(
        (
            service.name,
            service.product,
            service.version,
            service.extra_info,
            service.tunnel,
            script_text,
        )
    ).casefold()


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    return any(needle in text for needle in needles)


def _is_http(service: Service) -> bool:
    text = _fingerprint(service)
    service_name = service.name.casefold().replace("_", "-")
    named_http = (
        service_name in {"http", "https", "http-alt", "https-alt", "ssl/http"}
        or service_name.startswith("http-")
        or service_name.endswith("/http")
    )
    web_product = _contains_any(
        text,
        (
            "apache http",
            "apache tomcat",
            "caddy",
            "gunicorn",
            "jetty",
            "lighttpd",
            "iis",
            "microsoft iis",
            "microsoft-iis",
            "nginx",
            "openresty",
            "werkzeug",
            "weblogic",
        ),
    )
    # TLS alone is not HTTP evidence (it could be IMAPS, LDAPS, etc.), but a
    # TLS tunnel on a customary web port is useful corroborating evidence.
    tunneled_web = service.tunnel.casefold() in {"ssl", "tls"} and (
        service.port in HTTP_PORTS or named_http
    )
    return service.port in HTTP_PORTS or named_http or web_product or tunneled_web


def _is_smb(service: Service) -> bool:
    text = _fingerprint(service)
    service_name = service.name.casefold().replace("_", "-")
    named_smb = service_name in {"smb", "smb2", "microsoft-ds", "netbios-ssn"}
    return service.port in SMB_PORTS or named_smb or _contains_any(
        text,
        (
            "microsoft-ds",
            "netbios-ssn",
            "samba",
            "samba smbd",
            "smb server",
            "smb2",
        ),
    )


def _is_ldap(service: Service) -> bool:
    text = _fingerprint(service)
    return service.port in LDAP_PORTS or _contains_any(
        text, ("ldap", "active directory ldap")
    )


def _is_kerberos(service: Service) -> bool:
    text = _fingerprint(service)
    return service.port in KERBEROS_PORTS or _contains_any(
        text, ("kerberos", "krb5", "kpasswd")
    )


def _is_winrm(service: Service) -> bool:
    text = _fingerprint(service)
    return service.port in WINRM_PORTS or _contains_any(text, ("winrm", "wsman"))


def _is_ssh(service: Service) -> bool:
    name = service.name.casefold()
    return service.port == 22 or name == "ssh" or name.startswith("ssh-")


def _credential_is_testable(credential: Credential) -> bool:
    status = credential.status.casefold()
    known_bad = any(token in status for token in ("invalid", "fail", "denied"))
    return bool(credential.username.strip() and credential.secret and not known_bad)


def _service_label(service: Service) -> str:
    label = service.name or "unknown"
    if service.product:
        label = f"{label} ({service.product})"
    return f"{service.port}/{service.protocol} {label}"


def classify_services(
    services: Iterable[Service], hosts: Iterable[Host] = ()
) -> ServiceClassification:
    """Classify only open services and infer a conservative Windows posture."""

    open_services = tuple(service for service in services if _is_open(service))
    smb = tuple(service for service in open_services if _is_smb(service))
    ldap = tuple(service for service in open_services if _is_ldap(service))
    kerberos = tuple(service for service in open_services if _is_kerberos(service))
    winrm = tuple(service for service in open_services if _is_winrm(service))

    iis = tuple(
        service
        for service in open_services
        if "iis" in _fingerprint(service)
    )
    # A WSMan listener uses HTTP as a transport, but it is not a content
    # discovery target.  Treat it as web content only when IIS is independently
    # identified on that service.
    http = tuple(
        service
        for service in open_services
        if _is_http(service) and (not _is_winrm(service) or service in iis)
    )
    explicit_windows = tuple(
        host.os_guess for host in hosts if "windows" in host.os_guess.casefold()
    )
    windows_products = tuple(
        service
        for service in open_services
        if _contains_any(
            _fingerprint(service),
            ("microsoft windows", "windows server", "windows rpc"),
        )
    )

    evidence: list[str] = []
    if smb:
        evidence.append("SMB is exposed")
    if winrm:
        evidence.append("WinRM is exposed")
    if iis:
        evidence.append("a Microsoft IIS/HTTP service was identified")
    if explicit_windows:
        evidence.append("nmap's OS guess includes Windows")
    if windows_products:
        evidence.append("a service product identifies Microsoft Windows")
    if ldap and kerberos:
        evidence.append("LDAP and Kerberos are both exposed")

    # SMB alone can be Samba, and LDAP+Kerberos alone can be a Unix realm.
    # WinRM, an explicit OS guess, or two independent Microsoft-facing signals
    # are enough to tailor the workflow while still presenting it as probable.
    windows_stack = bool(smb and winrm and iis)
    probable_windows = bool(
        winrm
        or explicit_windows
        or windows_products
        or (iis and smb)
        or (smb and ldap and kerberos)
    )
    return ServiceClassification(
        http=http,
        smb=smb,
        ldap=ldap,
        kerberos=kerberos,
        winrm=winrm,
        probable_windows=probable_windows,
        windows_stack=windows_stack,
        windows_evidence=tuple(evidence),
    )


def _host_for(service: Service, fallback: str) -> str:
    return service.host.strip() or fallback


def _url_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _is_tls(service: Service) -> bool:
    name = service.name.casefold()
    return (
        service.port in HTTPS_PORTS
        or service.tunnel.casefold() in {"ssl", "tls"}
        or "https" in name
        or name.startswith("ssl/")
    )


def _http_url(service: Service, fallback_host: str) -> str:
    scheme = "https" if _is_tls(service) else "http"
    host = _url_host(_host_for(service, fallback_host))
    default_port = 443 if scheme == "https" else 80
    port = "" if service.port == default_port else f":{service.port}"
    return f"{scheme}://{host}{port}"


def _ldap_url(service: Service, fallback_host: str) -> str:
    secure = service.port in LDAPS_PORTS or _is_tls(service)
    scheme = "ldaps" if secure else "ldap"
    host = _url_host(_host_for(service, fallback_host))
    default_port = 636 if secure else 389
    port = "" if service.port == default_port else f":{service.port}"
    return f"{scheme}://{host}{port}"


def _append_unique(
    commands: list[CommandSuggestion], suggestion: CommandSuggestion
) -> None:
    if not any(
        existing.category == suggestion.category
        and existing.argv == suggestion.argv
        for existing in commands
    ):
        commands.append(suggestion)


def _unpack_input(
    state_or_target: CaseState | str,
    services: Iterable[Service] | None,
    credentials: Iterable[Credential] | None,
    hosts: Iterable[Host] | None,
) -> tuple[str, tuple[Service, ...], tuple[Credential, ...], tuple[Host, ...]]:
    if isinstance(state_or_target, CaseState):
        if services is not None or credentials is not None or hosts is not None:
            raise TypeError(
                "services, credentials, and hosts must be omitted with CaseState"
            )
        return (
            state_or_target.target,
            tuple(state_or_target.services),
            tuple(state_or_target.credentials),
            tuple(state_or_target.hosts),
        )
    if services is None:
        raise TypeError("services are required when the first argument is a target")
    return (
        state_or_target,
        tuple(services),
        tuple(credentials or ()),
        tuple(hosts or ()),
    )


def build_suggestions(
    state_or_target: CaseState | str,
    services: Iterable[Service] | None = None,
    *,
    credentials: Iterable[Credential] | None = None,
    hosts: Iterable[Host] | None = None,
) -> list[CommandSuggestion]:
    """Build inert command suggestions from a case or target/service pair.

    All returned commands are active enumeration and therefore carry
    ``active=True``.  This function performs no subprocess or filesystem work.
    """

    target, observed, known_credentials, known_hosts = _unpack_input(
        state_or_target, services, credentials, hosts
    )
    profile = classify_services(observed, known_hosts)
    commands: list[CommandSuggestion] = []

    for service in profile.http:
        url = _http_url(service, target)
        evidence = f"nmap identified HTTP evidence at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description=f"Discover content with feroxbuster on {url}",
                argv=("feroxbuster", "-u", url),
                category="http",
                evidence=evidence,
            ),
        )
        _append_unique(
            commands,
            CommandSuggestion(
                description=f"Discover content with ffuf on {url}",
                argv=(
                    "ffuf",
                    "-u",
                    f"{url}/FUZZ",
                    "-w",
                    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
                ),
                category="http",
                evidence=evidence,
            ),
        )

    for service in profile.smb:
        host = _host_for(service, target)
        posture = "probable Windows host" if profile.probable_windows else "SMB host"
        evidence = f"{_service_label(service)} supports SMB enumeration"
        _append_unique(
            commands,
            CommandSuggestion(
                description=f"List anonymous shares with NetExec on the {posture}",
                argv=("nxc", "smb", host, "-u", "", "-p", "", "--shares"),
                category="smb",
                evidence=evidence,
            ),
        )
        _append_unique(
            commands,
            CommandSuggestion(
                description="List anonymous shares with smbclient",
                argv=("smbclient", "-N", "-L", f"//{host}"),
                category="smb",
                evidence=evidence,
            ),
        )
        _append_unique(
            commands,
            CommandSuggestion(
                description="Attempt anonymous RID enumeration",
                argv=("nxc", "smb", host, "-u", "", "-p", "", "--rid-brute"),
                category="smb",
                evidence=evidence,
            ),
        )

    for service in profile.ldap:
        url = _ldap_url(service, target)
        evidence = f"nmap identified LDAP at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description=f"Query the anonymous LDAP RootDSE at {url}",
                argv=(
                    "ldapsearch",
                    "-x",
                    "-H",
                    url,
                    "-s",
                    "base",
                    "-b",
                    "",
                    "namingContexts",
                    "defaultNamingContext",
                    "dnsHostName",
                ),
                category="ldap",
                evidence=evidence,
            ),
        )
        _append_unique(
            commands,
            CommandSuggestion(
                description=f"Enumerate anonymous LDAP users and groups at {url}",
                argv=(
                    "ldapsearch",
                    "-x",
                    "-H",
                    url,
                    "-b",
                    "{base_dn}",
                    "(|(objectClass=user)(objectClass=group))",
                    "dn",
                    "cn",
                    "sAMAccountName",
                    "userPrincipalName",
                    "memberOf",
                ),
                category="ldap",
                evidence=evidence,
            ),
        )

    for service in profile.kerberos:
        host = _host_for(service, target)
        evidence = f"nmap identified Kerberos at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description="Enumerate supplied usernames against Kerberos",
                argv=(
                    "kerbrute",
                    "userenum",
                    "--dc",
                    host,
                    "-d",
                    "{domain}",
                    "{user_file}",
                ),
                category="kerberos",
                evidence=evidence,
            ),
        )

    for service in profile.winrm:
        host = _url_host(_host_for(service, target))
        secure = service.port == 5986 or _is_tls(service)
        scheme = "https" if secure else "http"
        url = f"{scheme}://{host}:{service.port}/wsman"
        evidence_parts = [f"nmap identified WinRM at {_service_label(service)}"]
        if profile.windows_stack:
            evidence_parts.append("IIS, SMB, and WinRM indicate a Windows workflow")
        argv = ("curl", "-i", url)
        if secure:
            argv = ("curl", "-k", "-i", url)
        _append_unique(
            commands,
            CommandSuggestion(
                description="Inspect the WinRM endpoint and authentication headers",
                argv=argv,
                category="winrm",
                evidence="; ".join(evidence_parts),
            ),
        )

    testable_credentials = any(
        _credential_is_testable(credential) for credential in known_credentials
    )
    domain_credentials = any(
        _credential_is_testable(credential) and credential.domain.strip()
        for credential in known_credentials
    )
    local_credentials = any(
        _credential_is_testable(credential) and not credential.domain.strip()
        for credential in known_credentials
    )
    if testable_credentials:
        for service in profile.smb:
            host = _host_for(service, target)
            if domain_credentials:
                _append_unique(
                    commands,
                    CommandSuggestion(
                        description="Validate a known domain credential against SMB",
                        argv=(
                            "nxc",
                            "smb",
                            host,
                            "-u",
                            "{username}",
                            "-p",
                            "{password}",
                            "-d",
                            "{domain}",
                        ),
                        category="credentials",
                        evidence="the case contains a domain credential and SMB is exposed",
                    ),
                )
            if local_credentials:
                _append_unique(
                    commands,
                    CommandSuggestion(
                        description="Validate a known local credential against SMB",
                        argv=(
                            "nxc",
                            "smb",
                            host,
                            "-u",
                            "{local_username}",
                            "-p",
                            "{local_password}",
                            "--local-auth",
                        ),
                        category="credentials",
                        evidence="the case contains a local credential and SMB is exposed",
                    ),
                )
        for service in profile.winrm:
            host = _host_for(service, target)
            if domain_credentials:
                _append_unique(
                    commands,
                    CommandSuggestion(
                        description="Validate a known domain credential against WinRM",
                        argv=(
                            "nxc",
                            "winrm",
                            host,
                            "-u",
                            "{username}",
                            "-p",
                            "{password}",
                            "-d",
                            "{domain}",
                        ),
                        category="credentials",
                        evidence="the case contains a domain credential and WinRM is exposed",
                    ),
                )
            if local_credentials:
                _append_unique(
                    commands,
                    CommandSuggestion(
                        description="Validate a known local credential against WinRM",
                        argv=(
                            "nxc",
                            "winrm",
                            host,
                            "-u",
                            "{local_username}",
                            "-p",
                            "{local_password}",
                            "--local-auth",
                        ),
                        category="credentials",
                        evidence="the case contains a local credential and WinRM is exposed",
                    ),
                )
        for service in (profile.ldap if domain_credentials else ()):
            url = _ldap_url(service, target)
            _append_unique(
                commands,
                CommandSuggestion(
                    description="Query LDAP RootDSE with a known credential",
                    argv=(
                        "ldapsearch",
                        "-x",
                        "-H",
                        url,
                        "-D",
                        "{username}@{domain}",
                        "-w",
                        "{password}",
                        "-s",
                        "base",
                        "-b",
                        "",
                        "defaultNamingContext",
                    ),
                    category="credentials",
                    evidence="the case contains a credential and LDAP is exposed",
                ),
            )
        for service in observed:
            if not _is_open(service) or not _is_ssh(service):
                continue
            host = _host_for(service, target)
            _append_unique(
                commands,
                CommandSuggestion(
                    description="Validate a known username through SSH's password prompt",
                    argv=(
                        "ssh",
                        "-p",
                        str(service.port),
                        "--",
                        "{username}@" + host,
                    ),
                    category="credentials",
                    evidence="the case contains a credential and SSH is exposed",
                ),
            )

    if target.strip():
        _append_unique(
            commands,
            CommandSuggestion(
                description="Scan all TCP ports with light version detection",
                argv=("nmap", "-Pn", "-p-", "-sV", "--version-light", target),
                category="nmap_deep",
                evidence="a target is defined; deeper coverage requires explicit approval",
            ),
        )

    return commands


def group_suggestions(
    suggestions: Iterable[CommandSuggestion],
) -> list[SuggestionGroup]:
    """Group suggestions in deterministic UI order."""

    buckets: dict[str, list[CommandSuggestion]] = {}
    for suggestion in suggestions:
        buckets.setdefault(suggestion.category, []).append(suggestion)

    ordered_categories = [category for category in _CATEGORY_ORDER if category in buckets]
    ordered_categories.extend(
        sorted(category for category in buckets if category not in _CATEGORY_ORDER)
    )

    groups: list[SuggestionGroup] = []
    for category in ordered_categories:
        commands = tuple(buckets[category])
        evidence = "; ".join(
            dict.fromkeys(command.evidence for command in commands if command.evidence)
        )
        groups.append(
            SuggestionGroup(
                key=category,
                title=_GROUP_TITLES.get(category, category.replace("_", " ").title()),
                evidence=evidence,
                commands=commands,
            )
        )
    return groups


__all__ = [
    "CommandSuggestion",
    "ServiceClassification",
    "SuggestedCommand",
    "SuggestionGroup",
    "build_suggestions",
    "classify_services",
    "group_suggestions",
    "shell_join",
]
