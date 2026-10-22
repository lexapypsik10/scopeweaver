import asyncio
import ssl

import pytest
from aiohttp import web

from scopeweaver.core.config import WhoisEndpoint
from scopeweaver.core.scope import Target
from scopeweaver.core.transport import HTTPResponse
from scopeweaver.modules.network import NetworkPlugin, identify
from scopeweaver.modules.recon import ReconPlugin, technologies
from scopeweaver.utils.text import safe_text
from scopeweaver.utils.tls import audit_tls


@pytest.mark.parametrize(
    "port,banner,name,confidence",
    [
        (9876, "SSH-2.0-Fixture", "ssh", "protocol banner"),
        (9876, "HTTP/1.1 200 OK", "http", "protocol banner"),
        (9876, "220 vsFTP ready", "ftp", "protocol banner"),
        (9876, "220 Postfix SMTP", "smtp", "protocol banner"),
        (443, "", "https", "port convention only; not verified"),
        (9876, "", "unknown", "port convention only; not verified"),
    ],
)
def test_detection_is_evidence_based(port, banner, name, confidence):
    assert identify(port, banner) == (name, confidence)


@pytest.mark.integration
async def test_real_tcp_scan_open_closed_and_obsolete_ssh(config, tcp_server, transport_factory):
    port = await tcp_server(b"SSH-1.5-fixture\r\n")
    temp = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    closed = temp.sockets[0].getsockname()[1]
    temp.close()
    await temp.wait_closed()
    config.scope.ports = config.scan_ports = [port, closed]
    result = await NetworkPlugin().run(Target.parse("127.0.0.1"), transport_factory())
    assert {s.port: s.state for s in result.services} == {port: "open", closed: "closed"}
    assert any(f.title == "SSH protocol 1 advertised" for f in result.findings)
    assert next(s for s in result.services if s.state == "open").name == "ssh"


@pytest.mark.integration
async def test_silent_tcp_service_is_open(config, tcp_server, transport_factory):
    port = await tcp_server(b"")
    config.scope.ports = config.scan_ports = [port]
    config.limits.timeout = 0.2
    result = await NetworkPlugin().run(Target.parse("127.0.0.1"), transport_factory())
    assert result.services[0].state == "open"
    assert result.services[0].banner is None


def test_technology_hints_and_terminal_control_sanitization():
    response = HTTPResponse(
        "http://lab.test:8000/",
        200,
        (("Server", "nginx/fixture"), ("X-Powered-By", "Fixture")),
        '<meta name="generator" content="Lab"><script src="/_next/a"></script>',
        False,
        "127.0.0.1",
    )
    names = {t["technology"] for t in technologies(response)}
    assert {"nginx/fixture", "Lab", "Next.js"} <= names
    assert safe_text(b"\x1b[31mtest\x00\x07") == "test"


@pytest.mark.integration
async def test_recon_dns_whois_http_inventory(
    config, dns_server, tcp_server, web_server, transport_factory
):
    async def whois(reader, writer):
        assert await reader.readline() == b"lab.test\r\n"
        for chunk in (b"Domain: lab.test\r\n", b"Whois Server: evil.test\r\n", b"Status: lab\r\n"):
            writer.write(chunk)
            await writer.drain()
            await asyncio.sleep(0.001)

    async def http(request):
        return web.Response(
            text="<html>fixture</html>", content_type="text/html", headers={"X-Powered-By": "Lab"}
        )

    whois_port = await tcp_server(handler=whois)
    _, port = await web_server(http)
    config.scope.dns, _ = await dns_server()
    config.scope.whois["lab.test"] = WhoisEndpoint(ip="127.0.0.1", port=whois_port)
    config.whois_enabled = True
    config.scope.ports = config.scan_ports = [port]
    config.dns_types = ["A", "TXT"]
    config.subdomains = ["www"]
    result = await ReconPlugin().run(Target.parse(f"http://lab.test:{port}/"), transport_factory())
    assert result.status == "completed"
    assert len(result.observations["dns"]) == 4
    assert "Status: lab" in result.observations["whois"]["response"]
    assert result.observations["whois"]["referrals_followed"] is False
    assert result.observations["http"]["technologies"]
    assert result.services[0].state == "open"


@pytest.mark.integration
async def test_tls_certificate_verified_and_expiry(
    config, tls_certificate, tcp_server, transport_factory
):
    context, cert_path = tls_certificate
    port = await tcp_server(b"", ssl_context=context)
    config.ca_file = cert_path
    config.scope.ports = [port]
    metadata, findings = await audit_tls(transport_factory(), "127.0.0.1", port, "web")
    assert metadata["verified"] is True
    assert metadata["version"] in {"TLSv1.2", "TLSv1.3"}
    assert "certificate_der" not in metadata
    assert any(f.title == "TLS certificate expires soon" for f in findings)
    assert metadata["legacy_protocols"]["status"] == "not_tested"


@pytest.mark.integration
async def test_untrusted_certificate_is_reported(
    config, tls_certificate, tcp_server, transport_factory
):
    context, _ = tls_certificate
    port = await tcp_server(b"", ssl_context=context)
    config.scope.ports = [port]
    metadata, findings = await audit_tls(transport_factory(), "127.0.0.1", port, "web")
    assert metadata["verified"] is False
    assert any(f.title == "TLS certificate validation failed" for f in findings)


@pytest.mark.integration
async def test_legacy_probes_are_explicit_and_failures_are_inconclusive(
    config, tls_certificate, tcp_server, transport_factory
):
    context, cert_path = tls_certificate
    port = await tcp_server(b"", ssl_context=context)
    config.ca_file = cert_path
    config.scope.ports = [port]
    config.tls_legacy_probes = True
    metadata, findings = await audit_tls(transport_factory(), "127.0.0.1", port, "web")
    assert "inconclusive" in metadata["legacy_protocols"][ssl.TLSVersion.TLSv1.name]
    assert not any(f.title == "Deprecated TLS protocol accepted" for f in findings)
