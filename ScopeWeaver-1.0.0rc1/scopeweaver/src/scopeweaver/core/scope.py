from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from scopeweaver.core.config import ScopeConfig, normalize_domain
from scopeweaver.core.errors import ScopeViolation


@dataclass(frozen=True)
class Target:
    host: str
    port: int | None = None
    url: str | None = None

    @classmethod
    def parse(cls, value: str) -> Target:
        if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
            raise ValueError("target contains whitespace, control characters or backslashes")
        if "://" in value:
            parts = urlsplit(value)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError("only http:// and https:// URLs are supported")
            if parts.username is not None or parts.password is not None:
                raise ValueError("URL credentials are prohibited")
            if parts.query or parts.fragment:
                raise ValueError("URL queries and fragments are prohibited; supply a path only")
            host = canonical_host(parts.hostname)
            port = (
                parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
            )
            if not 1 <= port <= 65535:
                raise ValueError("URL port must be from 1 to 65535")
            authority = f"[{host}]" if ":" in host else host
            authority += f":{port}"
            return cls(host, port, urlunsplit((parts.scheme, authority, parts.path or "/", "", "")))
        return cls(canonical_host(value))


def canonical_host(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return normalize_domain(value)
    if "%" in str(ip):
        raise ValueError("IPv6 zone identifiers are not supported")
    return str(ip)


class ScopeManager:
    def __init__(self, config: ScopeConfig) -> None:
        self.config = config
        self.networks = [ipaddress.ip_network(n) for n in config.networks]

    def host(self, host: str) -> None:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            name = normalize_domain(host)
            if not any(
                name == rule
                if not rule.startswith("*.")
                else name.endswith(rule[1:]) and name != rule[2:]
                for rule in self.config.domains
            ):
                raise ScopeViolation(f"domain is outside scope: {name}") from None
        else:
            self.ip(host)

    def ip(self, address: str) -> None:
        ip = ipaddress.ip_address(address)
        if ip.is_unspecified or ip.is_multicast or "%" in address:
            raise ScopeViolation(f"unusable destination address: {address}")
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            raise ScopeViolation("IPv4-mapped IPv6 addresses are not supported")
        if not any(ip in net for net in self.networks):
            raise ScopeViolation(f"IP address is outside scope: {address}")

    def port(self, port: int) -> None:
        if port not in self.config.ports:
            raise ScopeViolation(f"port is outside scope: {port}")

    def endpoint(self, host: str, address: str, port: int) -> None:
        self.host(host)
        self.ip(address)
        self.port(port)

    def dns_server(self, ip: str, port: int) -> None:
        if ip not in self.config.dns.servers or port != self.config.dns.port:
            raise ScopeViolation("DNS infrastructure endpoint is not explicitly approved")

    def whois_server(self, domain: str, ip: str, port: int) -> None:
        self.host(domain)
        endpoint = self.config.whois.get(domain)
        if endpoint is None or endpoint.ip != ip or endpoint.port != port:
            raise ScopeViolation("WHOIS endpoint is not explicitly approved for this domain")
