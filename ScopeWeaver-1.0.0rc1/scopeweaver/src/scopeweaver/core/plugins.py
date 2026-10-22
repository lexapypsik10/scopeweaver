from __future__ import annotations

from importlib.metadata import entry_points
from typing import Protocol, cast

from scopeweaver.core.models import ModuleResult
from scopeweaver.core.scope import Target
from scopeweaver.core.transport import Transport


class Plugin(Protocol):
    name: str
    description: str

    async def run(self, target: Target, transport: Transport) -> ModuleResult: ...


class PluginRegistry:
    def __init__(self) -> None:
        self.plugins: dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        if not plugin.name or plugin.name in self.plugins:
            raise ValueError(f"empty or duplicate plugin name: {plugin.name!r}")
        if not callable(getattr(plugin, "run", None)):
            raise ValueError("a plugin must implement async run(target, transport)")
        self.plugins[plugin.name] = plugin

    def load_external(self, allowed: list[str]) -> None:
        available = {ep.name: ep for ep in entry_points(group="scopeweaver.plugins")}
        for name in allowed:
            if name not in available:
                raise ValueError(f"enabled plugin is not installed: {name}")
            plugin = cast(Plugin, available[name].load()())
            if plugin.name != name:
                raise ValueError("plugin name must match its entry point")
            self.register(plugin)


def builtin_registry() -> PluginRegistry:
    from scopeweaver.modules.network import NetworkPlugin
    from scopeweaver.modules.recon import ReconPlugin
    from scopeweaver.modules.web import WebPlugin

    registry = PluginRegistry()
    for plugin in (ReconPlugin(), NetworkPlugin(), WebPlugin()):
        registry.register(plugin)
    return registry
