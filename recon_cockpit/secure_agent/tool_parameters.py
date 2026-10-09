"""Pure, strict parameter types for the reviewed bundled tool adapters.

These objects describe syntax, never operator scope or execution permission.
The public names remain re-exported by models for existing callers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any


MAX_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 65_536
SUPPORTED_METHODS = ("GET", "HEAD")


class ValidationError(ValueError):
    """A machine-readable rejection that never echoes untrusted input."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise ValidationError(code)


def _integer(value: Any, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(f"invalid_{name}")


def _string(value: Any, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _reject(f"invalid_{name}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _reject(f"invalid_{name}")


def _fields(value: Any, names: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict:
        _reject(f"invalid_{name}")
    if set(value) - names:
        _reject(f"unknown_{name}_fields")
    if names - set(value):
        _reject(f"missing_{name}_fields")
    return value


@dataclass(frozen=True, slots=True)
class HTTPParameters:
    port: int
    method: str
    path: str
    timeout_seconds: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _integer(self.port, "port", 1, 65_535)
        if type(self.method) is not str or self.method not in SUPPORTED_METHODS:
            _reject("unsupported_http_method")
        _string(self.path, "path", 1, 256)
        if not re.fullmatch(r"/[A-Za-z0-9/_.-]*", self.path) or "//" in self.path:
            _reject("invalid_path")
        if any(segment in (".", "..") for segment in self.path.split("/")):
            _reject("invalid_path")
        _integer(self.timeout_seconds, "timeout_seconds", 1, MAX_TIMEOUT_SECONDS)
        _integer(self.max_output_bytes, "max_output_bytes", 1, MAX_OUTPUT_BYTES)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HTTPHeadersParameters(HTTPParameters):
    """HTTP syntax for the versioned raw-response capability, not permission.

    The reviewed executor independently narrows this to one fixed GET request.
    Keeping a separate concrete type prevents accidental legacy dispatch.
    """


@dataclass(frozen=True, slots=True)
class CurlHTTPSParameters(HTTPParameters):
    """Typed HTTPS request syntax; the reviewed profile fixes every value."""


@dataclass(frozen=True, slots=True)
class FFufParameters:
    """Bounds for one immutable dictionary against one reviewed HTTP origin."""

    port: int
    timeout_seconds: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _integer(self.port, "port", 1, 65_535)
        _integer(self.timeout_seconds, "timeout_seconds", 1, MAX_TIMEOUT_SECONDS)
        _integer(self.max_output_bytes, "max_output_bytes", 1, MAX_OUTPUT_BYTES)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TCPParameters:
    """One bounded connection attempt; no payload, banner read, or port list."""

    port: int
    timeout_seconds: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _integer(self.port, "port", 1, 65_535)
        _integer(self.timeout_seconds, "timeout_seconds", 1, MAX_TIMEOUT_SECONDS)
        _integer(self.max_output_bytes, "max_output_bytes", 1, MAX_OUTPUT_BYTES)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HTTPOptionsParameters(TCPParameters):
    """Bounds for one fixed OPTIONS request; no caller method, path or headers."""


@dataclass(frozen=True, slots=True)
class NmapTCPParameters:
    """Typed scan bounds; the selected runtime enforces its fixed owned profile."""

    port: int
    timeout_seconds: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _integer(self.port, "port", 1, 65_535)
        _integer(self.timeout_seconds, "timeout_seconds", 1, MAX_TIMEOUT_SECONDS)
        _integer(self.max_output_bytes, "max_output_bytes", 1, MAX_OUTPUT_BYTES)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DigDNSParameters(TCPParameters):
    """Bounds for the fixed owned DNS-over-TCP query; no caller query syntax."""


@dataclass(frozen=True, slots=True)
class DigMXParameters(TCPParameters):
    """Bounds for one fixed owned MX question; exchange names remain inert."""


@dataclass(frozen=True, slots=True)
class DigSRVParameters(TCPParameters):
    """Bounds for one fixed owned SRV question; advertised endpoints stay inert."""


@dataclass(frozen=True, slots=True)
class DigAXFRParameters(TCPParameters):
    """Bounds for one fixed owned AXFR request; transferred records confer no authority."""


@dataclass(frozen=True, slots=True)
class DigNSIDParameters(TCPParameters):
    """Bounds for one fixed owned NSID question; returned bytes confer no authority."""


@dataclass(frozen=True, slots=True)
class OpenSSLTLSParameters(TCPParameters):
    """Bounds for the fixed verified TLS handshake; no caller TLS options."""


@dataclass(frozen=True, slots=True)
class TLSCertificateParameters(TCPParameters):
    """Bounds for one owned TLS peer certificate observation; no caller trust inputs."""


@dataclass(frozen=True, slots=True)
class TLSPostureParameters(TCPParameters):
    """Bounds for one separately authorized fixed-version owned TLS probe."""


@dataclass(frozen=True, slots=True)
class SSHHostKeysParameters(TCPParameters):
    """Bounds for one fixed RSA host-key observation, without authentication."""


@dataclass(frozen=True, slots=True)
class SSHAlgorithmsParameters(TCPParameters):
    """One fixed SSH identification/KEXINIT; no completed exchange or authentication."""


@dataclass(frozen=True, slots=True)
class SSHPolicyParameters(TCPParameters):
    """One fixed pre-authentication advertisement assessed against a pinned local policy."""


@dataclass(frozen=True, slots=True)
class LDAPRootDSEParameters(TCPParameters):
    """Bounds for one fixed anonymous RootDSE query, without follow-up searches."""


@dataclass(frozen=True, slots=True)
class SMBShareListParameters(TCPParameters):
    """Bounds for one fixed anonymous share listing, without share access."""


@dataclass(frozen=True, slots=True)
class RPCInfoDumpParameters(TCPParameters):
    """Bounds for one fixed RPC registration dump, without service follow-up."""


@dataclass(frozen=True, slots=True)
class ShowmountExportsParameters(TCPParameters):
    """Bounds for fixed export metadata at one endpoint, without mounting."""


@dataclass(frozen=True, slots=True)
class CurlFTPListParameters(TCPParameters):
    """Bounds for one fixed anonymous filename listing, without file transfer."""


@dataclass(frozen=True, slots=True)
class CurlSMTPCapabilitiesParameters(TCPParameters):
    """Bounds for one fixed SMTP capability query, without authentication or mail."""


@dataclass(frozen=True, slots=True)
class CurlDockerPingParameters(TCPParameters):
    """Bounds for the fixed unauthenticated Docker-compatible ping request."""


@dataclass(frozen=True, slots=True)
class CurlDockerVersionParameters(TCPParameters):
    """Bounds for fixed advertised version metadata without daemon control."""


@dataclass(frozen=True, slots=True)
class CurlWinRMMetadataParameters(TCPParameters):
    """Bounds for one unauthenticated metadata GET, without WS-Man operations."""


@dataclass(frozen=True, slots=True)
class NmapServiceParameters(TCPParameters):
    """Bounds for finite compiled service probes, with no caller scan options."""


@dataclass(frozen=True, slots=True)
class KerbruteUserenumParameters(TCPParameters):
    """Bounds for two compiled synthetic names; no caller realm, list or secrets."""


@dataclass(frozen=True, slots=True)
class RedisServerInfoParameters(TCPParameters):
    """Bounds for one fixed INFO server, without authentication or key access."""


@dataclass(frozen=True, slots=True)
class SNMPSystemGetParameters(TCPParameters):
    """Bounds for one fixed TCP system GET with a public synthetic community."""


@dataclass(frozen=True, slots=True)
class SNMPInterfaceNextParameters(TCPParameters):
    """Bounds for one fixed interface GETNEXT; no caller OID or community."""


@dataclass(frozen=True, slots=True)
class PostgreSQLTLSParameters(TCPParameters):
    """Fixed PostgreSQL pre-auth TLS negotiation parameters."""


@dataclass(frozen=True, slots=True)
class MySQLTLSParameters(TCPParameters):
    """Fixed MySQL pre-auth TLS negotiation parameters."""


@dataclass(frozen=True, slots=True)
class WhatWebParameters(TCPParameters):
    """One fixed owned HTTP GET; callers cannot select plugins or a URL."""


@dataclass(frozen=True, slots=True)
class RDPInitialParameters(TCPParameters):
    """One fixed RDP negotiation offer; no authentication or remote session."""


@dataclass(frozen=True, slots=True)
class SMB2NegotiateParameters(TCPParameters):
    """One fixed SMB2 negotiation offer; no authentication or share access."""


@dataclass(frozen=True, slots=True)
class SMTPStartTLSParameters(TCPParameters):
    """Fixed SMTP STARTTLS handshake; no authentication or mail commands."""


@dataclass(frozen=True, slots=True)
class LDAPStartTLSParameters(TCPParameters):
    """One fixed LDAP StartTLS operation; no bind, search or client credentials."""


@dataclass(frozen=True, slots=True)
class FTPStartTLSParameters(TCPParameters):
    """One fixed FTP AUTH TLS operation; no login or data connection."""


@dataclass(frozen=True, slots=True)
class NucleiParameters(TCPParameters):
    """One compiled owned HTTP check; no caller-selected template or runtime."""
