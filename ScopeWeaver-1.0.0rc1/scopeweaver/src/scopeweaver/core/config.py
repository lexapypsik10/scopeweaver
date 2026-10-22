from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Self

from pydantic import Field, field_validator, model_validator

from scopeweaver.core.models import StrictModel


def normalize_domain(value: str) -> str:
    if not value or value != value.strip() or any(ord(c) < 33 for c in value):
        raise ValueError("empty domain, whitespace or control character")
    host = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in host.split(".")
    ):
        raise ValueError(f"invalid DNS name: {value!r}")
    return host


class DNSConfig(StrictModel):
    servers: list[str] = Field(default_factory=list, max_length=4)
    port: int = Field(default=53, ge=1, le=65535)

    @field_validator("servers")
    @classmethod
    def numeric_servers(cls, values: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(v)) for v in values]


class WhoisEndpoint(StrictModel):
    ip: str
    port: int = Field(default=43, ge=1, le=65535)

    @field_validator("ip")
    @classmethod
    def numeric_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))


class ScopeConfig(StrictModel):
    domains: list[str] = Field(default_factory=list, max_length=1000)
    networks: list[str] = Field(default_factory=list, max_length=1000)
    ports: list[int] = Field(default_factory=lambda: [80, 443], min_length=1, max_length=4096)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    whois: dict[str, WhoisEndpoint] = Field(default_factory=dict)

    @field_validator("domains")
    @classmethod
    def domains_valid(cls, values: list[str]) -> list[str]:
        return [
            "*." + normalize_domain(v[2:]) if v.startswith("*.") else normalize_domain(v)
            for v in values
        ]

    @field_validator("networks")
    @classmethod
    def networks_valid(cls, values: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(v, strict=True)) for v in values]

    @field_validator("ports")
    @classmethod
    def ports_valid(cls, values: list[int]) -> list[int]:
        if any(isinstance(v, bool) or not 1 <= v <= 65535 for v in values):
            raise ValueError("ports must be integers from 1 to 65535")
        return sorted(set(values))

    @field_validator("whois")
    @classmethod
    def whois_names(cls, values: dict[str, WhoisEndpoint]) -> dict[str, WhoisEndpoint]:
        return {normalize_domain(k): v for k, v in values.items()}


class Limits(StrictModel):
    concurrency: int = Field(default=4, ge=1, le=32)
    requests_per_second: float = Field(default=2, gt=0, le=50)
    max_operations: int = Field(default=200, ge=1, le=100_000)
    timeout: float = Field(default=4, gt=0, le=60)
    max_response_bytes: int = Field(default=131072, ge=256, le=1048576)
    max_targets: int = Field(default=32, ge=1, le=1000)


class Config(StrictModel):
    schema_version: str = "1.0"
    scope: ScopeConfig
    limits: Limits = Field(default_factory=Limits)
    scan_ports: list[int] = Field(default_factory=lambda: [80, 443], max_length=4096)
    dns_types: list[str] = Field(default_factory=lambda: ["A", "AAAA", "MX", "NS", "TXT", "SOA"])
    subdomains: list[str] = Field(default_factory=list, max_length=100)
    whois_enabled: bool = False
    tls_legacy_probes: bool = False
    ca_file: Path | None = None
    audit_log: Path = Path("scopeweaver-audit.jsonl")
    stop_file: Path | None = None
    enabled_plugins: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.schema_version != "1.0":
            raise ValueError("unsupported config schema version")
        if not set(self.scan_ports) <= set(self.scope.ports):
            raise ValueError("scan_ports must be a subset of scope.ports")
        if not self.scan_ports:
            raise ValueError("scan_ports must not be empty")
        allowed = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME", "SRV"}
        if not self.dns_types or not set(self.dns_types) <= allowed:
            raise ValueError("unsupported DNS type (AXFR and ANY are intentionally unavailable)")
        for label in self.subdomains:
            if normalize_domain(label) != label.lower() or "." in label:
                raise ValueError("subdomains must contain single DNS labels")
        return self


def load_config(path: Path) -> Config:
    if path.stat().st_size > 1_048_576:
        raise ValueError("configuration exceeds 1 MiB")
    return Config.model_validate_json(path.read_text(encoding="utf-8"))
