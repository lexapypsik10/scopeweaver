import asyncio
import json
from time import monotonic

import pytest
from aiohttp import web

from scopeweaver.core.errors import BudgetExceeded, NetworkError, ScopeViolation, StopRequested
from scopeweaver.core.transport import PinnedResolver


@pytest.mark.integration
async def test_dns_uses_only_explicit_server(config, dns_server, transport_factory):
    config.scope.dns, queries = await dns_server()
    transport = transport_factory()
    assert await transport.resolve("lab.test") == ["127.0.0.1"]
    assert len(queries) == 2
    assert transport.operations == 2
    answer = await transport.dns_query("lab.test", "TXT")
    assert answer["records"] == ['"fixture"']
    with pytest.raises(ScopeViolation):
        await transport.dns_query("evil.test", "A")
    assert len(queries) == 3


@pytest.mark.integration
async def test_dns_rebinding_answer_is_rejected(config, dns_server, transport_factory):
    config.scope.dns, _ = await dns_server(address="203.0.113.5")
    transport = transport_factory()
    with pytest.raises(ScopeViolation):
        await transport.resolve("lab.test")
    assert transport.operations == 2  # DNS only; no TCP/HTTP is permitted.


async def test_missing_dns_never_uses_system_resolver(transport_factory):
    transport = transport_factory()
    with pytest.raises(NetworkError, match="explicitly approved"):
        await transport.resolve("lab.test")
    assert transport.operations == 0


@pytest.mark.integration
async def test_dns_failure_not_converted_to_success(config, dns_server, transport_factory):
    config.scope.dns, _ = await dns_server(rcode="SERVFAIL")
    with pytest.raises(NetworkError, match="SERVFAIL"):
        await transport_factory().resolve("lab.test")


async def test_pinned_resolver_never_resolves_another_host():
    resolver = PinnedResolver("lab.test", "127.0.0.1")
    assert (await resolver.resolve("lab.test", 80))[0]["host"] == "127.0.0.1"
    with pytest.raises(ScopeViolation):
        await resolver.resolve("evil.test", 80)
    await resolver.close()


@pytest.mark.integration
async def test_redirect_is_not_followed(config, web_server, transport_factory):
    calls = []

    async def handler(request):
        calls.append(request.path)
        return web.Response(status=302, headers={"Location": "http://203.0.113.1:9999/secret"})

    url, port = await web_server(handler)
    config.scope.ports = [port]
    response = await transport_factory().request(url)
    assert response.status == 302
    assert calls == ["/"]


@pytest.mark.integration
async def test_body_limit_cookie_isolation_and_env_proxy(
    config, web_server, transport_factory, monkeypatch
):
    received = []

    async def handler(request):
        received.append(dict(request.headers))
        return web.Response(text="x" * 1000, headers={"Set-Cookie": "secret=value; Path=/"})

    url, port = await web_server(handler)
    config.scope.ports = [port]
    config.limits.max_response_bytes = 256
    monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.9:8888")
    transport = transport_factory()
    first = await transport.request(url)
    await transport.request(url)
    assert first.truncated and len(first.body) == 256
    assert all("Cookie" not in headers for headers in received)
    assert transport.operations == 2


async def test_denied_before_connection_and_audited(config, transport_factory):
    transport = transport_factory()
    with pytest.raises(ScopeViolation):
        await transport.exchange("127.0.0.1", "127.0.0.1", 22)
    with pytest.raises(ScopeViolation):
        await transport.request("http://127.0.0.1:8000", method="DELETE")
    assert transport.operations == 0
    events = [
        json.loads(line)
        for line in (config.audit_log.parent / "audit-0.jsonl").read_text().splitlines()
    ]
    assert any(event["action"] == "denied" for event in events)


async def test_budget_is_global_under_concurrency(config, transport_factory):
    config.limits.max_operations = 2
    transport = transport_factory()

    async def operation():
        async with transport.operation("test", lambda: None):
            await asyncio.sleep(0.001)

    results = await asyncio.gather(*(operation() for _ in range(7)), return_exceptions=True)
    assert transport.operations == 2
    assert sum(isinstance(r, BudgetExceeded) for r in results) == 5


async def test_rate_limiter_and_stop_file(config, transport_factory, tmp_path):
    config.limits.requests_per_second = 10
    transport = transport_factory()
    start = monotonic()
    for _ in range(3):
        async with transport.operation("test", lambda: None):
            pass
    assert monotonic() - start >= 0.18
    config.stop_file = tmp_path / "STOP"
    config.stop_file.touch()
    with pytest.raises(StopRequested):
        async with transport.operation("test", lambda: None):
            pytest.fail("must not run")
    assert transport.operations == 3


@pytest.mark.integration
async def test_timeout_is_bounded(config, tcp_server, transport_factory):
    async def never_answer(reader, writer):
        await asyncio.Event().wait()

    port = await tcp_server(handler=never_answer)
    from scopeweaver.core.config import WhoisEndpoint

    config.scope.whois["lab.test"] = WhoisEndpoint(ip="127.0.0.1", port=port)
    config.limits.timeout = 0.1
    with pytest.raises(NetworkError, match="TimeoutError"):
        await transport_factory().exchange(
            "127.0.0.1", "127.0.0.1", port, b"lab.test\r\n", whois_domain="lab.test"
        )
