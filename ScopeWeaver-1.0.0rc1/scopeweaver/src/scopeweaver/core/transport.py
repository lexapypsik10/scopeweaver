from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from time import monotonic
from typing import Any

import aiohttp
import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode
from aiohttp.abc import AbstractResolver, ResolveResult

from scopeweaver import __version__
from scopeweaver.core.config import Config
from scopeweaver.core.errors import (
    BudgetExceeded,
    NetworkError,
    ScopeViolation,
    StopRequested,
)
from scopeweaver.core.logger import AuditLogger
from scopeweaver.core.scope import ScopeManager, Target


@dataclass(frozen=True)
class HTTPResponse:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: str
    truncated: bool
    ip: str

    def values(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def header(self, name: str) -> str:
        return ", ".join(self.values(name))


class PinnedResolver(AbstractResolver):
    """A single vetted numeric IP; aiohttp never consults the system resolver."""

    def __init__(self, host: str, ip: str) -> None:
        self.host = host
        self.ip = ip

    async def resolve(self, host: str, port: int = 0, family: int = 0) -> list[ResolveResult]:
        if host != self.host:
            raise ScopeViolation("unexpected hostname in pinned resolver")
        return [
            ResolveResult(
                hostname=host,
                host=self.ip,
                port=port,
                family=socket.AF_INET6 if ":" in self.ip else socket.AF_INET,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_NUMERICHOST,
            )
        ]

    async def close(self) -> None:
        return None


class Transport:
    """All built-in network I/O passes through this bounded, audited transport."""

    def __init__(self, config: Config, audit: AuditLogger) -> None:
        self.config = config
        self.scope = ScopeManager(config.scope)
        self.audit = audit
        self.operations = 0
        self.stopped = asyncio.Event()
        self._semaphore = asyncio.Semaphore(config.limits.concurrency)
        self._pace_lock = asyncio.Lock()
        self._last_start = 0.0

    def stop_check(self) -> None:
        if self.stopped.is_set() or (
            self.config.stop_file is not None and self.config.stop_file.exists()
        ):
            self.stopped.set()
            raise StopRequested("stop requested")

    def authorize(self, check: Callable[[], None], action: str) -> None:
        try:
            self.stop_check()
            check()
        except (ScopeViolation, StopRequested) as exc:
            self.audit.event("denied", operation=action, reason=str(exc))
            raise

    @asynccontextmanager
    async def operation(
        self,
        action: str,
        check: Callable[[], None],
        **details: Any,
    ) -> AsyncIterator[None]:
        self.authorize(check, action)
        async with self._semaphore:
            async with self._pace_lock:
                delay = 1 / self.config.limits.requests_per_second - (
                    monotonic() - self._last_start
                )
                if delay > 0:
                    await asyncio.sleep(delay)
                self.authorize(check, action)
                if self.operations >= self.config.limits.max_operations:
                    self.audit.event("budget_exhausted", operation=action)
                    raise BudgetExceeded("global network-operation budget exhausted")
                self.operations += 1
                self._last_start = monotonic()
            self.audit.event("network_start", operation=action, number=self.operations, **details)
            try:
                async with asyncio.timeout(self.config.limits.timeout):
                    yield
            except asyncio.CancelledError:
                self.audit.event("network_cancelled", operation=action, **details)
                raise
            except Exception as exc:
                self.audit.event(
                    "network_error", operation=action, error=type(exc).__name__, **details
                )
                raise
            else:
                self.audit.event("network_complete", operation=action, **details)

    async def dns_query(self, name: str, kind: str) -> dict[str, Any]:
        self.authorize(lambda: self.scope.host(name), "dns")
        servers = self.config.scope.dns.servers
        if not servers:
            raise NetworkError(
                "DNS requires an explicitly approved numeric scope.dns.servers entry"
            )
        server, port = servers[0], self.config.scope.dns.port
        query = dns.message.make_query(name + ".", kind)

        def check() -> None:
            self.scope.host(name)
            self.scope.dns_server(server, port)

        try:
            async with self.operation("dns_udp", check, name=name, kind=kind, ip=server, port=port):
                response = await dns.asyncquery.udp(
                    query, server, port=port, timeout=self.config.limits.timeout
                )
            if response.flags & dns.flags.TC:
                async with self.operation(
                    "dns_tcp", check, name=name, kind=kind, ip=server, port=port
                ):
                    response = await dns.asyncquery.tcp(
                        query, server, port=port, timeout=self.config.limits.timeout
                    )
        except (OSError, TimeoutError, dns.exception.DNSException) as exc:
            raise NetworkError(f"DNS {kind} failed for {name}: {type(exc).__name__}") from exc
        records = [
            r.to_text()[:4096]
            for rrset in response.answer
            if dns.rdatatype.to_text(rrset.rdtype) == kind
            for r in rrset
        ][:100]
        return {
            "name": name,
            "type": kind,
            "rcode": dns.rcode.to_text(response.rcode()),
            "records": records,
        }

    async def resolve(self, host: str) -> list[str]:
        self.authorize(lambda: self.scope.host(host), "resolve")
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            addresses: list[str] = []
            for kind in ("A", "AAAA"):
                answer = await self.dns_query(host, kind)
                if answer["rcode"] not in {"NOERROR", "NXDOMAIN"}:
                    raise NetworkError(f"DNS resolution failed: {answer['rcode']}") from None
                addresses.extend(answer["records"])
            if not addresses:
                raise NetworkError(f"no A or AAAA records for {host}") from None
        else:
            addresses = [address]
        # Reject mixed allowed/disallowed answers, rather than filtering away a dangerous answer.
        for address in addresses:
            self.authorize(partial(self.scope.ip, address), "resolve_result")
        return sorted(set(addresses))

    async def exchange(
        self,
        host: str,
        ip: str,
        port: int,
        payload: bytes = b"",
        *,
        ssl_context: ssl.SSLContext | None = None,
        connect_only: bool = False,
        whois_domain: str | None = None,
    ) -> tuple[bytes, dict[str, Any]]:
        def check() -> None:
            if whois_domain is None:
                self.scope.endpoint(host, ip, port)
            else:
                self.scope.whois_server(whois_domain, ip, port)

        writer: asyncio.StreamWriter | None = None
        try:
            async with self.operation(
                "whois" if whois_domain else "tcp",
                check,
                host=host,
                ip=ip,
                port=port,
                tls=ssl_context is not None,
            ):
                reader, writer = await asyncio.open_connection(
                    ip,
                    port,
                    family=socket.AF_INET6 if ":" in ip else socket.AF_INET,
                    ssl=ssl_context,
                    server_hostname=host if ssl_context else None,
                )
                metadata: dict[str, Any] = {}
                tls = writer.get_extra_info("ssl_object")
                if tls is not None:
                    metadata = {
                        "version": tls.version(),
                        "cipher": tls.cipher(),
                        "certificate_der": tls.getpeercert(binary_form=True),
                    }
                if payload:
                    writer.write(payload)
                    await writer.drain()
                if connect_only:
                    data = b""
                elif whois_domain:
                    try:
                        data = await reader.readexactly(self.config.limits.max_response_bytes)
                    except asyncio.IncompleteReadError as exc:
                        data = exc.partial
                else:
                    try:
                        async with asyncio.timeout(min(1.0, self.config.limits.timeout / 2)):
                            data = await reader.read(
                                min(self.config.limits.max_response_bytes, 4096)
                            )
                    except TimeoutError:
                        data = b""
                return data, metadata
        except (OSError, TimeoutError) as exc:
            raise NetworkError(f"TCP {ip}:{port} failed: {type(exc).__name__}") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    async with asyncio.timeout(0.5):
                        await writer.wait_closed()
                except (OSError, TimeoutError):
                    pass

    async def request(
        self,
        url: str,
        *,
        method: str = "GET",
        origin: str | None = None,
    ) -> HTTPResponse:
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ScopeViolation("only GET, HEAD and OPTIONS are available")
        target = Target.parse(url)
        if target.url is None or target.port is None:
            raise ValueError("HTTP requests require a URL")
        self.authorize(lambda: self.scope.port(target.port or 0), "http")
        addresses = await self.resolve(target.host)
        ip = addresses[0]

        def check() -> None:
            self.scope.endpoint(target.host, ip, target.port or 0)

        context = ssl.create_default_context(cafile=self.config.ca_file)
        headers = {
            "User-Agent": f"ScopeWeaver/{__version__} (authorized security audit)",
            "Accept-Encoding": "identity",
        }
        if origin:
            headers["Origin"] = origin
        try:
            async with self.operation("http", check, url=target.url, method=method, ip=ip):
                connector = aiohttp.TCPConnector(
                    resolver=PinnedResolver(target.host, ip),
                    use_dns_cache=False,
                    force_close=True,
                    limit=1,
                    happy_eyeballs_delay=None,
                    ssl=context,
                )
                async with aiohttp.ClientSession(
                    connector=connector,
                    trust_env=False,
                    cookie_jar=aiohttp.DummyCookieJar(),
                    auto_decompress=False,
                    timeout=aiohttp.ClientTimeout(total=self.config.limits.timeout),
                ) as session:
                    async with session.request(
                        method,
                        target.url,
                        headers=headers,
                        allow_redirects=False,
                        max_field_size=16384,
                        max_line_size=16384,
                    ) as response:
                        limit = self.config.limits.max_response_bytes
                        try:
                            raw = await response.content.readexactly(limit + 1)
                        except asyncio.IncompleteReadError as exc:
                            raw = exc.partial
                        encoding = response.charset or "utf-8"
                        try:
                            body = raw[:limit].decode(encoding, errors="replace")
                        except LookupError:
                            body = raw[:limit].decode("utf-8", errors="replace")
                        if (
                            response.headers.get("Content-Encoding", "identity").lower()
                            != "identity"
                        ):
                            body = ""  # Never decompress untrusted data in an audit process.
                        return HTTPResponse(
                            target.url,
                            response.status,
                            tuple(response.headers.items()),
                            body,
                            len(raw) > limit,
                            ip,
                        )
        except (aiohttp.ClientError, OSError, TimeoutError) as exc:
            raise NetworkError(f"HTTP request failed: {type(exc).__name__}") from exc
