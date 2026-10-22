# Writing a trusted plugin

A minimal working extension can inspect a safely fetched response:

```python
from scopeweaver.core.models import ModuleResult
from scopeweaver.core.scope import Target
from scopeweaver.core.transport import Transport


class ContentTypePlugin:
    name = "content-type"
    description = "Record an approved web target's media type"

    async def run(self, target: Target, transport: Transport) -> ModuleResult:
        if target.url is None:
            raise ValueError("an explicit HTTP(S) URL is required")
        response = await transport.request(target.url, method="HEAD")
        return ModuleResult(
            module=self.name,
            target=target.url,
            observations={"content_type": response.header("Content-Type")},
        )
```

Publish the class as a no-argument entry point in the extension package:

```toml
[project.entry-points."scopeweaver.plugins"]
content-type = "my_checks:ContentTypePlugin"
```

Install that package into the same environment, add `"content-type"` to `enabled_plugins`
in the JSON config and select `--module content-type`. Installed entry points are not
imported unless enabled. Duplicate names, missing distributions and mismatched entry-point
names fail registration.

Use the supplied transport for every operation; it applies the run's scope and shared
budget. Return contextual errors and evidence instead of inventing scan results. Never
serialize credentials. Add a loopback integration test before distributing the extension.
Only enable plugins whose code and dependencies you trust; plugins are not sandboxed.
