import asyncio
import json

import pytest
from aiohttp import web

from scopeweaver.core.engine import Engine
from scopeweaver.core.models import ModuleResult
from scopeweaver.core.plugins import PluginRegistry, builtin_registry
from scopeweaver.core.scope import Target


class GoodPlugin:
    name = "test"
    description = "Offline fixture"

    async def run(self, target, transport):
        return ModuleResult(module=self.name, target=target.host)


def test_registry_builtin_external_opt_in_and_duplicate():
    registry = builtin_registry()
    assert set(registry.plugins) == {"web", "network", "recon"}
    registry.load_external([])
    with pytest.raises(ValueError, match="not installed"):
        registry.load_external(["not-installed"])
    registry.register(GoodPlugin())
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(GoodPlugin())


async def test_engine_isolates_plugin_failure_and_denies_scope(config):
    class BrokenPlugin(GoodPlugin):
        name = "broken"

        async def run(self, target, transport):
            raise RuntimeError("fixture failure")

    registry = PluginRegistry()
    registry.register(GoodPlugin())
    registry.register(BrokenPlugin())
    report = await Engine(config, registry).run([Target.parse("127.0.0.1")], ["test", "broken"])
    assert len(report.results) == 2
    assert {r.status for r in report.results} == {"completed", "error"}
    outside = await Engine(config, registry).run([Target.parse("203.0.113.3")], ["test"])
    assert outside.network_operations == 0 and outside.results[0].status == "error"
    for targets, modules in [([], ["test"]), ([Target.parse("127.0.0.1")], ["missing"])]:
        with pytest.raises(ValueError):
            await Engine(config, registry).run(targets, modules)
    events = [json.loads(line) for line in config.audit_log.read_text().splitlines()]
    assert any(e["action"] == "denied" for e in events)
    assert any(e["action"] == "plugin_error" for e in events)


@pytest.mark.integration
async def test_budget_retains_completed_web_evidence(config, web_server):
    async def handler(request):
        return web.Response(text="<html>fixture</html>", content_type="text/html")

    url, port = await web_server(handler)
    config.scope.ports = config.scan_ports = [port]
    config.limits.max_operations = 1
    report = await Engine(config, builtin_registry()).run([Target.parse(url)], ["web"])
    assert report.interrupted
    assert report.network_operations == 1
    assert report.findings
    assert report.results[0].status == "interrupted"


async def test_stop_file_cancels_in_flight_plugin(config, tmp_path):
    class SlowPlugin(GoodPlugin):
        async def run(self, target, transport):
            await asyncio.Event().wait()

    config.stop_file = tmp_path / "STOP"
    registry = PluginRegistry()
    registry.register(SlowPlugin())

    async def stop():
        await asyncio.sleep(0.05)
        config.stop_file.touch()

    stopping = asyncio.create_task(stop())
    report = await asyncio.wait_for(
        Engine(config, registry).run([Target.parse("127.0.0.1")], ["test"]), 1
    )
    await stopping
    assert report.interrupted and report.network_operations == 0


async def test_operator_cancellation_returns_partial_report(config):
    class SlowPlugin(GoodPlugin):
        async def run(self, target, transport):
            await asyncio.Event().wait()

    registry = PluginRegistry()
    registry.register(SlowPlugin())
    task = asyncio.create_task(Engine(config, registry).run([Target.parse("127.0.0.1")], ["test"]))
    await asyncio.sleep(0.02)
    task.cancel()
    report = await task
    assert report.interrupted
