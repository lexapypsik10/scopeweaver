from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from scopeweaver.core.config import Config
from scopeweaver.core.errors import BudgetExceeded, ScopeWeaverError, StopRequested
from scopeweaver.core.logger import AuditLogger
from scopeweaver.core.models import Assessment, ModuleResult
from scopeweaver.core.plugins import PluginRegistry
from scopeweaver.core.scope import Target
from scopeweaver.core.transport import Transport


class Engine:
    def __init__(self, config: Config, registry: PluginRegistry) -> None:
        self.config = config
        self.registry = registry

    async def run(
        self,
        targets: list[Target],
        modules: list[str],
        on_complete: Callable[[str, str], None] | None = None,
    ) -> Assessment:
        if not targets or len(targets) > self.config.limits.max_targets:
            raise ValueError("target count is empty or exceeds limits.max_targets")
        if not modules or any(m not in self.registry.plugins for m in modules):
            raise ValueError("unknown or empty module selection")
        report = Assessment(scope=self.config.scope.model_dump(mode="json"))
        audit = AuditLogger(self.config.audit_log, report.run_id)
        transport = Transport(self.config, audit)
        tasks: list[asyncio.Task[None]] = []

        async def execute(module: str, target: Target) -> None:
            label = target.url or target.host
            try:
                transport.authorize(lambda: transport.scope.host(target.host), module)
                result = await self.registry.plugins[module].run(target, transport)
            except (BudgetExceeded, StopRequested):
                transport.stopped.set()
                raise
            except ScopeWeaverError as exc:
                result = ModuleResult(
                    module=module, target=label, status="error", errors=[str(exc)]
                )
            except Exception as exc:
                # A failed trusted plugin must not discard completed module evidence.
                audit.event("plugin_error", module=module, error=type(exc).__name__)
                result = ModuleResult(
                    module=module,
                    target=label,
                    status="error",
                    errors=[f"plugin failed: {type(exc).__name__}: {exc}"],
                )
            if result.status == "interrupted":
                report.interrupted = True
                transport.stopped.set()
            report.results.append(result)
            audit.event("module_complete", module=module, target=label, status=result.status)
            if on_complete:
                on_complete(module, result.status)

        async def watch_stop() -> None:
            while not transport.stopped.is_set():
                if self.config.stop_file and self.config.stop_file.exists():
                    transport.stopped.set()
                    break
                try:
                    await asyncio.wait_for(transport.stopped.wait(), timeout=0.1)
                except TimeoutError:
                    continue

        watcher = asyncio.create_task(watch_stop())
        audit.event("run_start", modules=modules, targets=[t.url or t.host for t in targets])
        try:
            tasks = [
                asyncio.create_task(execute(m, t)) for t in targets for m in dict.fromkeys(modules)
            ]

            async def wait_all() -> None:
                await asyncio.gather(*tasks)

            all_done = asyncio.create_task(wait_all())
            done, _ = await asyncio.wait([all_done, watcher], return_when=asyncio.FIRST_COMPLETED)
            if watcher in done and not all_done.done():
                report.interrupted = True
                all_done.cancel()
            try:
                await all_done
            except (BudgetExceeded, StopRequested, asyncio.CancelledError):
                report.interrupted = True
        except asyncio.CancelledError:
            report.interrupted = True
        finally:
            for task in [*tasks, watcher]:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, watcher, return_exceptions=True)
            report.network_operations = transport.operations
            report.finished_at = datetime.now(UTC)
            report.results.sort(key=lambda r: (r.target, r.module))
            audit.event(
                "run_complete",
                interrupted=report.interrupted,
                operations=report.network_operations,
                results=len(report.results),
            )
            audit.close()
        return report
