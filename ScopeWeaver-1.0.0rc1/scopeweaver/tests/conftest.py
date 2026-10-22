from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import UTC, datetime, timedelta

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scopeweaver.core.config import Config, DNSConfig, Limits, ScopeConfig
from scopeweaver.core.logger import AuditLogger
from scopeweaver.core.transport import Transport


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    """Fail tests if an implementation accidentally attempts external egress or OS DNS."""
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    original_getaddrinfo = socket.getaddrinfo

    def check(address):
        if isinstance(address, tuple):
            try:
                assert ipaddress.ip_address(address[0]).is_loopback, address
            except ValueError as exc:
                raise AssertionError(f"unexpected OS DNS/network use: {address}") from exc

    def connect(sock, address):
        check(address)
        return original_connect(sock, address)

    def connect_ex(sock, address):
        check(address)
        return original_connect_ex(sock, address)

    def sendto(sock, data, *args):
        check(args[-1])
        return original_sendto(sock, data, *args)

    def getaddrinfo(host, port, *args, **kwargs):
        check((host, port))
        return original_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


@pytest.fixture
def config(tmp_path):
    return Config(
        scope=ScopeConfig(
            domains=["lab.test", "*.lab.test"], networks=["127.0.0.1/32", "::1/128"], ports=[8000]
        ),
        scan_ports=[8000],
        limits=Limits(concurrency=3, requests_per_second=50, max_operations=100, timeout=1),
        audit_log=tmp_path / "audit.jsonl",
    )


@pytest.fixture
def transport_factory(config, tmp_path):
    loggers = []

    def make(settings=None):
        selected = settings or config
        audit = AuditLogger(tmp_path / f"audit-{len(loggers)}.jsonl", "test-run")
        loggers.append(audit)
        return Transport(selected, audit)

    yield make
    for logger in loggers:
        logger.close()


@pytest.fixture
async def web_server():
    runners = []

    async def start(handler, ssl_context=None):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
        await site.start()
        runners.append(runner)
        port = site._server.sockets[0].getsockname()[1]
        return f"{'https' if ssl_context else 'http'}://127.0.0.1:{port}/", port

    yield start
    for runner in runners:
        await runner.cleanup()


@pytest.fixture
async def tcp_server():
    servers = []
    handlers = set()

    async def start(banner=b"SSH-2.0-TestFixture\r\n", *, handler=None, ssl_context=None):
        async def respond(reader, writer):
            handlers.add(asyncio.current_task())
            try:
                if handler:
                    await handler(reader, writer)
                elif banner:
                    writer.write(banner)
                    await writer.drain()
                else:
                    await reader.read(1)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    pass
                handlers.discard(asyncio.current_task())

        server = await asyncio.start_server(respond, "127.0.0.1", 0, ssl=ssl_context)
        servers.append(server)
        return server.sockets[0].getsockname()[1]

    yield start
    for server in servers:
        server.close()
    for task in list(handlers):
        task.cancel()
    await asyncio.gather(*handlers, return_exceptions=True)
    for server in servers:
        await server.wait_closed()


@pytest.fixture
async def dns_server():
    transports = []

    async def start(address="127.0.0.1", rcode="NOERROR"):
        requests = []

        class Server(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, peer):
                query = dns.message.from_wire(data)
                requests.append(query)
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.from_text(rcode))
                question = query.question[0]
                if question.rdtype == dns.rdatatype.A and rcode == "NOERROR":
                    response.answer.append(
                        dns.rrset.from_text(question.name, 60, "IN", "A", address)
                    )
                if question.rdtype == dns.rdatatype.TXT and rcode == "NOERROR":
                    response.answer.append(
                        dns.rrset.from_text(question.name, 60, "IN", "TXT", '"fixture"')
                    )
                self.transport.sendto(response.to_wire(), peer)

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            Server,
            local_addr=("127.0.0.1", 0),
        )
        transports.append(transport)
        return DNSConfig(
            servers=["127.0.0.1"], port=transport.get_extra_info("sockname")[1]
        ), requests

    yield start
    for transport in transports:
        transport.close()


@pytest.fixture
def tls_certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ScopeWeaver loopback fixture")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=15))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("lab.test")]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    return context, cert_path
