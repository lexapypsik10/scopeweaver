from __future__ import annotations

import ipaddress
import re

from scopeweaver.core.errors import BudgetExceeded, ScopeWeaverError, StopRequested
from scopeweaver.core.models import ModuleResult
from scopeweaver.core.scope import Target
from scopeweaver.core.transport import HTTPResponse, Transport
from scopeweaver.modules.network import NetworkPlugin
from scopeweaver.utils.text import safe_text
from scopeweaver.utils.tls import audit_tls


def technologies(response: HTTPResponse) -> list[dict[str, str]]:
    hints = []
    for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        if response.header(header):
            hints.append(
                {
                    "technology": safe_text(response.header(header)),
                    "source": header,
                    "confidence": "self-reported",
                }
            )
    generator = re.search(
        r'<meta\s+[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', response.body, re.I
    )
    if generator:
        hints.append(
            {
                "technology": safe_text(generator[1]),
                "source": "HTML meta generator",
                "confidence": "self-reported",
            }
        )
    for name, pattern in (
        ("WordPress", "/wp-content/"),
        ("Next.js", "/_next/"),
        ("Drupal", "drupalSettings"),
    ):
        if pattern in response.body:
            hints.append({"technology": name, "source": pattern, "confidence": "heuristic"})
    return hints


class ReconPlugin:
    name = "recon"
    description = "DNS records, explicit WHOIS, HTTP technology hints, TLS and TCP inventory"

    async def run(self, target: Target, transport: Transport) -> ModuleResult:
        result = ModuleResult(module=self.name, target=target.url or target.host)
        try:
            try:
                ipaddress.ip_address(target.host)
                is_domain = False
            except ValueError:
                is_domain = True
            if is_domain:
                records = []
                names = [target.host, *[f"{s}.{target.host}" for s in transport.config.subdomains]]
                for name in names:
                    for kind in transport.config.dns_types:
                        try:
                            records.append(await transport.dns_query(name, kind))
                        except (BudgetExceeded, StopRequested):
                            raise
                        except ScopeWeaverError as exc:
                            result.errors.append(str(exc))
                result.observations["dns"] = records
                if transport.config.whois_enabled:
                    endpoint = transport.config.scope.whois.get(target.host)
                    if endpoint is None:
                        result.errors.append("WHOIS skipped: no approved endpoint for this domain")
                    else:
                        data, _ = await transport.exchange(
                            endpoint.ip,
                            endpoint.ip,
                            endpoint.port,
                            (target.host + "\r\n").encode("ascii"),
                            whois_domain=target.host,
                        )
                        result.observations["whois"] = {
                            "response": safe_text(data, transport.config.limits.max_response_bytes),
                            "endpoint": endpoint.model_dump(),
                            "referrals_followed": False,
                        }
            network = await NetworkPlugin().run(target, transport)
            result.services = network.services
            result.findings.extend(network.findings)
            result.errors.extend(network.errors)
            if network.status == "interrupted":
                result.status = "interrupted"
                return result
            # HTTP and TLS only for an explicit URL, never guess a protocol from a port.
            if target.url:
                if target.url.startswith("https://") and target.port:
                    metadata, tls_findings = await audit_tls(
                        transport, target.host, target.port, self.name
                    )
                    result.observations["tls"] = metadata
                    result.findings.extend(tls_findings)
                response = await transport.request(target.url)
                metadata_headers = {
                    "server",
                    "x-powered-by",
                    "x-aspnet-version",
                    "x-generator",
                    "content-type",
                    "content-length",
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "permissions-policy",
                    "allow",
                }
                safe_headers = {
                    k: safe_text(v) for k, v in response.headers if k.lower() in metadata_headers
                }
                result.observations["http"] = {
                    "status": response.status,
                    "headers": safe_headers,
                    "technologies": technologies(response),
                    "body_truncated": response.truncated,
                    "redirect_followed": False,
                }
        except (BudgetExceeded, StopRequested) as exc:
            result.status = "interrupted"
            result.errors.append(str(exc))
            transport.stopped.set()
        except ScopeWeaverError as exc:
            result.errors.append(str(exc))
        if result.errors and result.status != "interrupted":
            result.status = "partial" if result.services or result.observations else "error"
        return result
