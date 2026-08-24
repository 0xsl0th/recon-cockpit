"""Shared data structures used by scanners, parsers, and case storage."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Host:
    address: str
    status: str = "up"
    hostnames: list[str] = field(default_factory=list)
    os_guess: str = ""


@dataclass(slots=True)
class Service:
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def banner(self) -> str:
        return " ".join(
            part for part in (self.product, self.version, self.extra_info) if part
        )


@dataclass(slots=True)
class Finding:
    category: str
    detail: str
    source: str = "manual"


@dataclass(slots=True)
class Credential:
    username: str
    secret: str = ""
    domain: str = ""
    status: str = "unverified"
    source: str = "manual"


@dataclass(slots=True)
class Share:
    host: str
    name: str
    permissions: str = ""
    remark: str = ""
    source: str = "ingest"


@dataclass(slots=True)
class IngestResult:
    target_ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    shares: list[Share] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass(slots=True)
class CaseState:
    target: str
    created_at: str
    updated_at: str
    hosts: list[Host] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    shares: list[Share] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    scan_command: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CaseState":
        return cls(
            target=data["target"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            hosts=[Host(**item) for item in data.get("hosts", [])],
            services=[Service(**item) for item in data.get("services", [])],
            findings=[Finding(**item) for item in data.get("findings", [])],
            credentials=[Credential(**item) for item in data.get("credentials", [])],
            shares=[Share(**item) for item in data.get("shares", [])],
            domains=list(data.get("domains", [])),
            usernames=list(data.get("usernames", [])),
            next_actions=list(data.get("next_actions", [])),
            scan_command=list(data.get("scan_command", [])),
        )
