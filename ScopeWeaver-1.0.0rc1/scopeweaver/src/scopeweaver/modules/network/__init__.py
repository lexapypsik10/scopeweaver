from __future__ import annotations

import asyncio
import re
from functools import partial
from typing import Any

from scopeweaver.core.errors import BudgetExceeded, NetworkError, StopRequested
from scopeweaver.core.models import ModuleResult, Service, Severity, finding
from scopeweaver.core.scope import Target
from scopeweaver.core.transport import Transport
from scopeweaver.utils.text import safe_text

PORT_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    389: "ldap",
    636: "ldaps",
    3389: "rdp",
    8080: "http",
    8443: "https",
}


def identify(port: int, banner: str) -> tuple[str, str]:
    if banner.startswith("SSH-"):
        return "ssh", "protocol banner"
    if banner.startswith("HTTP/"):
        return "http", "protocol banner"
    if re.match(r"^220[ -].*(?:FTP|FileZilla|vsFTP)", banner, re.I):
        return "ftp", "protocol banner"
    if re.match(r"^220[ -].*(?:SMTP|Postfix|Exim)", banner, re.I):
        return "smtp", "protocol banner"
    return PORT_HINTS.get(port, "unknown"), "port convention only; not verified"


class NetworkPlugin:
    name = "network"
    description = "Bounded TCP connect inventory and passive service banners"

    async def run(self, target: Target, transport: Transport) -> ModuleResult:
        result = ModuleResult(module=self.name, target=target.host)
        addresses = await transport.resolve(target.host)
        ports = [target.port] if target.port else transport.config.scan_ports
        # Prevalidate every port before beginning a scan.
        for port in ports:
            transport.authorize(partial(transport.scope.port, port), "network")
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        for ip in addresses:
            for port in ports:
                queue.put_nowait((ip, port))

        async def worker() -> None:
            while not queue.empty():
                ip, port = queue.get_nowait()
                try:
                    data, _ = await transport.exchange(target.host, ip, port)
                except (BudgetExceeded, StopRequested) as exc:
                    result.errors.append(str(exc))
                    result.status = "interrupted"
                    transport.stopped.set()
                    break
                except NetworkError as exc:
                    cause = exc.__cause__
                    state = "closed" if isinstance(cause, ConnectionRefusedError) else "unreachable"
                    result.services.append(
                        Service(
                            host=target.host,
                            ip=ip,
                            port=port,
                            state=state,
                            metadata={"reason": type(cause).__name__},
                        )
                    )
                else:
                    banner = safe_text(data)
                    name, detection = identify(port, banner)
                    result.services.append(
                        Service(
                            host=target.host,
                            ip=ip,
                            port=port,
                            state="open",
                            name=name,
                            detection=detection,
                            banner=banner or None,
                        )
                    )
                    if banner.startswith("SSH-1.") and not banner.startswith("SSH-1.99"):
                        result.findings.append(
                            finding(
                                self.name,
                                f"{target.host}:{port}",
                                "ssh-v1",
                                "SSH protocol 1 advertised",
                                Severity.HIGH,
                                "The server banner advertises the obsolete SSH version 1.",
                                {"banner": banner},
                                "Disable SSHv1 and require SSHv2.",
                                "CWE-327",
                            )
                        )
                    if port in {21, 23, 110, 143, 389}:
                        evidence: dict[str, Any] = {
                            "port": port,
                            "service_hint": name,
                            "detection": detection,
                        }
                        result.findings.append(
                            finding(
                                self.name,
                                f"{target.host}:{port}",
                                "plaintext-review",
                                "Potential plaintext service requires review",
                                Severity.INFO,
                                "An open port conventionally hosts a plaintext-capable service. "
                                "This does not establish that encryption or STARTTLS is unavailable.",
                                evidence,
                                "Verify mandatory encryption and disable plaintext authentication.",
                                "CWE-319",
                            )
                        )

        workers = [
            asyncio.create_task(worker())
            for _ in range(min(transport.config.limits.concurrency, queue.qsize()))
        ]
        try:
            await asyncio.gather(*workers)
        finally:
            for task in workers:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        result.services.sort(key=lambda s: (s.ip, s.port))
        result.observations = {
            "technique": "TCP connect; no authentication; passive banners",
            "attempted": len(result.services),
            "unattempted": queue.qsize(),
        }
        return result
