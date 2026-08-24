"""Evidence-driven, inert command suggestions.

This module never executes a command.  It translates services observed by nmap
into argv tuples that the UI may display and, after an explicit confirmation,
hand to a process runner.  Keeping argv structured is intentional: callers do
not need a shell and user supplied values cannot turn into shell pipelines.
"""

from __future__ import annotations

import ipaddress
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
FTP_PORTS = frozenset({21, 990})
RPC_PORTS = frozenset({111})
NFS_PORTS = frozenset({2049})
DNS_PORTS = frozenset({53})
SMTP_PORTS = frozenset({25, 465, 587, 2525})
DOCKER_API_PORTS = frozenset({2375, 2376})

_CATEGORY_ORDER = (
    "http",
    "ssh",
    "ftp",
    "nfs_rpc",
    "dns",
    "smtp",
    "docker",
    "smb",
    "ldap",
    "kerberos",
    "winrm",
    "credentials",
    "nmap_standard",
    "nmap_deep",
)
_GROUP_TITLES = {
    "http": "Enumerate HTTP",
    "ssh": "Enumerate SSH",
    "ftp": "Enumerate FTP",
    "nfs_rpc": "Enumerate NFS / RPC",
    "dns": "Enumerate DNS",
    "smtp": "Enumerate SMTP",
    "docker": "Inspect Docker API",
    "smb": "Enumerate SMB",
    "ldap": "Enumerate LDAP",
    "kerberos": "Enumerate Kerberos",
    "winrm": "Inspect WinRM",
    "credentials": "Test known credentials",
    "nmap_standard": "Run standard Nmap scripts",
    "nmap_deep": "Run full TCP Nmap scan",
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
    """Relevant services and conservative OS postures inferred from evidence."""

    http: tuple[Service, ...]
    ssh: tuple[Service, ...]
    ftp: tuple[Service, ...]
    rpc: tuple[Service, ...]
    nfs: tuple[Service, ...]
    dns: tuple[Service, ...]
    smtp: tuple[Service, ...]
    docker_api: tuple[Service, ...]
    smb: tuple[Service, ...]
    ldap: tuple[Service, ...]
    kerberos: tuple[Service, ...]
    winrm: tuple[Service, ...]
    probable_windows: bool
    windows_stack: bool
    windows_evidence: tuple[str, ...]
    probable_linux: bool
    linux_evidence: tuple[str, ...]


def shell_join(argv: Sequence[str]) -> str:
    """Quote an argv sequence for clean terminal display.

    The returned string must not be used as an execution primitive.  Consumers
    should execute the original argv sequence without ``shell=True``.
    """

    return _shlex_join(list(argv))


def _is_exactly_open(service: Service) -> bool:
    return (
        service.state.casefold() == "open"
        and service.protocol.casefold() in {"tcp", "udp"}
    )


def _is_open(service: Service) -> bool:
    """Return whether a service is actionable in the TCP-oriented cockpit."""

    return service.state.casefold() == "open" and service.protocol.casefold() == "tcp"


def _fingerprint(service: Service) -> str:
    # Script identifiers are useful protocol evidence (for example
    # ``smb2-security-mode``), but script output is arbitrary remote text and
    # must not be allowed to reclassify a service.
    script_ids = " ".join(service.scripts.keys())
    return " ".join(
        (
            service.name,
            service.product,
            service.version,
            service.extra_info,
            service.tunnel,
            script_ids,
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
    name = service.name.casefold().replace("_", "-")
    return service.port == 22 or name == "ssh" or name.startswith("ssh-")


def _is_ftp(service: Service) -> bool:
    name = service.name.casefold().replace("_", "-")
    if name == "sftp" or name.startswith("sftp-"):
        return False
    text = _fingerprint(service)
    return (
        service.port in FTP_PORTS
        or name in {"ftp", "ftps", "ssl/ftp"}
        or _contains_any(text, ("vsftpd", "proftpd", "pure-ftpd"))
    )


def _is_rpc(service: Service) -> bool:
    # Nmap's safe rpcinfo script is intentionally hard-coded to port 111.
    return service.port in RPC_PORTS


def _is_nfs(service: Service) -> bool:
    name = service.name.casefold().replace("_", "-")
    return (
        service.port in NFS_PORTS
        or name in {"nfs", "nfs-acl", "mountd"}
        or name.startswith("nfs-")
    )


def _is_dns(service: Service) -> bool:
    name = service.name.casefold().replace("_", "-")
    return service.port in DNS_PORTS or name in {
        "domain",
        "domain-s",
        "dns",
        "dns-tcp",
    }


def _is_smtp(service: Service) -> bool:
    name = service.name.casefold().replace("_", "-")
    text = _fingerprint(service)
    return (
        service.port in SMTP_PORTS
        or name in {"smtp", "smtps", "submission"}
        or _contains_any(text, ("postfix", "exim", "sendmail", "opensmtpd"))
    )


def _is_docker_api(service: Service) -> bool:
    name = service.name.casefold().replace("_", "-")
    text = _fingerprint(service)
    if "docker registry" in text or name in {"docker-registry", "registry"}:
        return False
    return (
        service.port in DOCKER_API_PORTS
        or name in {"docker", "docker-api", "docker-daemon"}
        or "docker daemon" in text
        or "docker api" in text
    )


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
    """Classify exact-open services and infer conservative host postures."""

    exact_open_services = tuple(
        service for service in services if _is_exactly_open(service)
    )
    tcp_services = tuple(
        service for service in exact_open_services if _is_open(service)
    )
    ssh = tuple(service for service in tcp_services if _is_ssh(service))
    ftp = tuple(service for service in tcp_services if _is_ftp(service))
    rpc = tuple(service for service in tcp_services if _is_rpc(service))
    nfs = tuple(service for service in tcp_services if _is_nfs(service))
    dns = tuple(service for service in tcp_services if _is_dns(service))
    smtp = tuple(service for service in tcp_services if _is_smtp(service))
    docker_api = tuple(
        service for service in tcp_services if _is_docker_api(service)
    )
    smb = tuple(service for service in tcp_services if _is_smb(service))
    ldap = tuple(service for service in tcp_services if _is_ldap(service))
    kerberos = tuple(service for service in tcp_services if _is_kerberos(service))
    winrm = tuple(service for service in tcp_services if _is_winrm(service))

    iis = tuple(
        service
        for service in tcp_services
        if "iis" in _fingerprint(service)
    )
    # A WSMan listener uses HTTP as a transport, but it is not a content
    # discovery target.  Treat it as web content only when IIS is independently
    # identified on that service.
    http = tuple(
        service
        for service in tcp_services
        if _is_http(service)
        and (not _is_winrm(service) or service in iis)
        and not _is_docker_api(service)
    )
    explicit_windows = tuple(
        host.os_guess for host in hosts if "windows" in host.os_guess.casefold()
    )
    windows_products = tuple(
        service
        for service in tcp_services
        if _contains_any(
            _fingerprint(service),
            ("microsoft windows", "windows server", "windows rpc"),
        )
    )

    windows_evidence: list[str] = []
    if smb:
        windows_evidence.append("SMB is exposed")
    if winrm:
        windows_evidence.append("WinRM is exposed")
    if iis:
        windows_evidence.append("a Microsoft IIS/HTTP service was identified")
    if explicit_windows:
        windows_evidence.append("nmap's OS guess includes Windows")
    if windows_products:
        windows_evidence.append("a service product identifies Microsoft Windows")
    if ldap and kerberos:
        windows_evidence.append("LDAP and Kerberos are both exposed")

    explicit_linux = tuple(
        host.os_guess
        for host in hosts
        if _contains_any(
            host.os_guess.casefold(),
            (
                "linux",
                "ubuntu",
                "debian",
                "red hat",
                "rhel",
                "centos",
                "fedora",
                "rocky",
                "alma",
                "suse",
                "arch linux",
                "gentoo",
            ),
        )
    )
    linux_products = tuple(
        service
        for service in exact_open_services
        if _contains_any(
            _fingerprint(service),
            (
                "linux",
                "ubuntu",
                "debian",
                "red hat",
                "rhel",
                "centos",
                "fedora",
                "rocky linux",
                "almalinux",
                "opensuse",
                "suse linux",
                "arch linux",
                "gentoo",
            ),
        )
    )
    linux_stack = bool(ssh and (nfs or rpc))
    linux_evidence: list[str] = []
    if explicit_linux:
        linux_evidence.append("nmap's OS guess includes Linux/Unix")
    if linux_products:
        linux_evidence.append("a service fingerprint identifies a Linux distribution")
    if linux_stack:
        linux_evidence.append("SSH with NFS/RPC indicates a Unix-style service stack")

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
    probable_linux = bool(explicit_linux or linux_products or linux_stack)
    return ServiceClassification(
        http=http,
        ssh=ssh,
        ftp=ftp,
        rpc=rpc,
        nfs=nfs,
        dns=dns,
        smtp=smtp,
        docker_api=docker_api,
        smb=smb,
        ldap=ldap,
        kerberos=kerberos,
        winrm=winrm,
        probable_windows=probable_windows,
        windows_stack=windows_stack,
        windows_evidence=tuple(windows_evidence),
        probable_linux=probable_linux,
        linux_evidence=tuple(linux_evidence),
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
        or name in {"ftps", "ssl/ftp"}
        or name.startswith("ssl/")
    )


def _http_url(service: Service, fallback_host: str) -> str:
    scheme = "https" if _is_tls(service) else "http"
    host = _url_host(_host_for(service, fallback_host))
    default_port = 443 if scheme == "https" else 80
    port = "" if service.port == default_port else f":{service.port}"
    return f"{scheme}://{host}{port}"


def _ftp_url(service: Service, fallback_host: str) -> str:
    scheme = "ftps" if _is_tls(service) or service.port == 990 else "ftp"
    host = _url_host(_host_for(service, fallback_host))
    return f"{scheme}://{host}:{service.port}/"


def _docker_url(service: Service, fallback_host: str, path: str) -> str:
    scheme = "https" if _is_tls(service) or service.port == 2376 else "http"
    host = _url_host(_host_for(service, fallback_host))
    return f"{scheme}://{host}:{service.port}{path}"


def _nmap_target_argv(host: str, port: int, scripts: str) -> tuple[str, ...]:
    args = ["nmap"]
    try:
        if ipaddress.ip_address(host).version == 6:
            args.append("-6")
    except ValueError:
        pass
    args.extend(
        (
            "-Pn",
            "-sT",
            "-sV",
            "-p",
            str(port),
            "--script",
            scripts,
            host,
        )
    )
    return tuple(args)


def _nmap_service_argv(
    service: Service,
    fallback_host: str,
    scripts: str,
) -> tuple[str, ...]:
    return _nmap_target_argv(
        _host_for(service, fallback_host),
        service.port,
        scripts,
    )


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
                    "{wordlist}",
                ),
                category="http",
                evidence=evidence,
            ),
        )

    for service in profile.ssh:
        host = _host_for(service, target)
        posture = (
            "probable Linux/Unix host"
            if profile.probable_linux and not profile.probable_windows
            else "SSH host"
        )
        evidence = f"nmap identified SSH at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description=f"Collect SSH host keys from the {posture}",
                argv=("ssh-keyscan", "-T", "5", "-p", str(service.port), host),
                category="ssh",
                evidence=evidence,
            ),
        )
        _append_unique(
            commands,
            CommandSuggestion(
                description="Enumerate SSH host keys and supported algorithms",
                argv=_nmap_service_argv(
                    service,
                    target,
                    "ssh-hostkey,ssh2-enum-algos",
                ),
                category="ssh",
                evidence=evidence,
            ),
        )

    for service in profile.ftp:
        url = _ftp_url(service, target)
        evidence = f"nmap identified FTP at {_service_label(service)}"
        curl_args = [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "--list-only",
            "--user",
            "anonymous:anonymous@",
        ]
        if url.startswith("ftps://"):
            curl_args.append("--insecure")
        curl_args.append(url)
        _append_unique(
            commands,
            CommandSuggestion(
                description=f"Try a bounded anonymous directory listing at {url}",
                argv=tuple(curl_args),
                category="ftp",
                evidence=evidence,
            ),
        )
        _append_unique(
            commands,
            CommandSuggestion(
                description="Check anonymous FTP access and server type with Nmap",
                argv=_nmap_service_argv(service, target, "ftp-anon,ftp-syst"),
                category="ftp",
                evidence=evidence,
            ),
        )

    for service in profile.rpc:
        evidence = f"nmap identified RPC bind at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description="Enumerate registered RPC programs with Nmap",
                argv=_nmap_service_argv(service, target, "rpcinfo"),
                category="nfs_rpc",
                evidence=evidence,
            ),
        )

    for service in profile.nfs:
        host = _host_for(service, target)
        name = service.name.casefold().replace("_", "-")
        rpc_endpoint = next(
            (
                candidate
                for candidate in profile.rpc
                if _host_for(candidate, target) == host
            ),
            None,
        )
        # nfs-showmount runs against rpcbind (111) or a detected mountd
        # service, not against the common NFS data port 2049.
        query_port = (
            service.port
            if name == "mountd"
            else rpc_endpoint.port if rpc_endpoint is not None else 111
        )
        evidence = f"nmap identified NFS at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description="List advertised NFS exports without mounting them",
                argv=_nmap_target_argv(host, query_port, "nfs-showmount"),
                category="nfs_rpc",
                evidence=evidence,
            ),
        )

    for service in profile.dns:
        evidence = f"nmap identified DNS at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description="Query DNS server identity metadata with Nmap",
                argv=_nmap_service_argv(service, target, "dns-nsid"),
                category="dns",
                evidence=evidence,
            ),
        )

    for service in profile.smtp:
        evidence = f"nmap identified SMTP at {_service_label(service)}"
        _append_unique(
            commands,
            CommandSuggestion(
                description="Enumerate advertised SMTP commands without sending mail",
                argv=_nmap_service_argv(service, target, "smtp-commands"),
                category="smtp",
                evidence=evidence,
            ),
        )

    for service in profile.docker_api:
        evidence = f"nmap identified a Docker API at {_service_label(service)}"
        for path, description in (
            ("/_ping", "Check whether the Docker API responds"),
            ("/version", "Read Docker daemon version metadata"),
            ("/info", "Read Docker daemon configuration metadata"),
            ("/containers/json?all=1", "List Docker container metadata (read-only)"),
        ):
            url = _docker_url(service, target, path)
            curl_args = ["curl", "--silent", "--show-error", "--max-time", "15"]
            if url.startswith("https://"):
                curl_args.append("--insecure")
            curl_args.append(url)
            _append_unique(
                commands,
                CommandSuggestion(
                    description=description,
                    argv=tuple(curl_args),
                    category="docker",
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
                description="Run default NSE scripts with service detection",
                argv=(
                    "nmap",
                    "-Pn",
                    "-sC",
                    "-sV",
                    "-vv",
                    "--top-ports",
                    "1000",
                    target,
                ),
                category="nmap_standard",
                evidence=(
                    "default NSE scripts actively query services and require "
                    "explicit approval"
                ),
            ),
        )
        _append_unique(
            commands,
            CommandSuggestion(
                description="Scan all TCP ports with default scripts and versions",
                argv=("nmap", "-Pn", "-p-", "-sC", "-sV", "-vv", target),
                category="nmap_deep",
                evidence=(
                    "all 65,535 TCP ports and default NSE scripts require "
                    "explicit approval"
                ),
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
