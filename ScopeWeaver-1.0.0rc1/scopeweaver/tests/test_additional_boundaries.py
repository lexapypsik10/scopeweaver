import asyncio
import ssl
import warnings

import dns.flags
import dns.message
import dns.rrset
import pytest
from aiohttp import web

from scopeweaver.core.engine import Engine
from scopeweaver.core.errors import BudgetExceeded
from scopeweaver.core.models import ModuleResult
from scopeweaver.core.plugins import PluginRegistry, builtin_registry
from scopeweaver.core.scope import Target
from scopeweaver.utils.tls import audit_tls


@pytest.mark.integration
async def test_legacy_only_tls_server_can_be_detected(
    config, tls_certificate, tcp_server, transport_factory
):
    context, _ = tls_certificate
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    port = await tcp_server(b"", ssl_context=context)
    config.scope.ports = [port]
    config.tls_legacy_probes = True
    metadata, findings = await audit_tls(transport_factory(), "127.0.0.1", port, "web")
    assert metadata["verified"] is False
    assert "modern_handshake_error" in metadata
    assert any(f.title == "Deprecated TLS protocol accepted" for f in findings)


@pytest.mark.integration
async def test_dns_tcp_fallback_is_scoped_and_counted(config, transport_factory):
    messages = []

    def answer(query):
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text("lab.test.", 60, "IN", "A", "127.0.0.1"))
        return response

    async def tcp(reader, writer):
        try:
            size = int.from_bytes(await reader.readexactly(2))
            query = dns.message.from_wire(await reader.readexactly(size))
            messages.append("tcp")
            wire = answer(query).to_wire()
            writer.write(len(wire).to_bytes(2) + wire)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(tcp, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    class TruncatedServer(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, peer):
            messages.append("udp")
            response = dns.message.make_response(dns.message.from_wire(data))
            response.flags |= dns.flags.TC
            self.transport.sendto(response.to_wire(), peer)

    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        TruncatedServer,
        local_addr=("127.0.0.1", port),
    )
    config.scope.dns.servers = ["127.0.0.1"]
    config.scope.dns.port = port
    transport = transport_factory()
    try:
        result = await transport.dns_query("lab.test", "A")
        assert result["records"] == ["127.0.0.1"]
        assert messages == ["udp", "tcp"] and transport.operations == 2
    finally:
        udp.close()
        server.close()
        await server.wait_closed()


@pytest.mark.integration
async def test_http_does_not_decompress_and_uses_pinned_dns(
    config, dns_server, web_server, transport_factory
):
    async def handler(request):
        return web.Response(body=b"not really gzip", headers={"Content-Encoding": "gzip"})

    _, port = await web_server(handler)
    config.scope.ports = [port]
    config.scope.dns, _ = await dns_server()
    result = await transport_factory().request(f"http://lab.test:{port}/")
    assert result.status == 200 and result.ip == "127.0.0.1" and result.body == ""


def test_external_plugin_is_loaded_only_when_enabled(monkeypatch):
    imports = []

    class Plugin:
        name = "fixture"
        description = "A trusted local test plugin"

        async def run(self, target, transport):
            return ModuleResult(module=self.name, target=target.host)

    class EntryPoint:
        name = "fixture"

        def load(self):
            imports.append(self.name)
            return Plugin

    monkeypatch.setattr("scopeweaver.core.plugins.entry_points", lambda **kwargs: [EntryPoint()])
    registry = PluginRegistry()
    registry.load_external([])
    assert imports == []
    registry.load_external(["fixture"])
    assert imports == ["fixture"] and "fixture" in registry.plugins


async def test_engine_handles_plugin_budget_exception(config):
    class Plugin:
        name = "budget"
        description = "Budget exhaustion fixture"

        async def run(self, target, transport):
            raise BudgetExceeded("test budget exhausted")

    registry = PluginRegistry()
    registry.register(Plugin())
    report = await Engine(config, registry).run([Target.parse("127.0.0.1")], ["budget"])
    assert report.interrupted and report.network_operations == 0


@pytest.mark.integration
async def test_https_recon_keeps_certificate_evidence_on_http_rejection(
    config, tls_certificate, web_server
):
    async def handler(request):
        return web.Response(text="fixture")

    context, _ = tls_certificate
    url, port = await web_server(handler, ssl_context=context)
    config.scope.ports = config.scan_ports = [port]
    report = await Engine(config, builtin_registry()).run([Target.parse(url)], ["recon"])
    result = report.results[0]
    assert result.status == "partial"
    assert result.observations["tls"]["verified"] is False
    assert any(f.title == "TLS certificate validation failed" for f in result.findings)
    assert result.errors
