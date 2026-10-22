# Contributing to ScopeWeaver

Keep checks explainable, bounded and useful to a human reviewer. A result must distinguish
an observed configuration from an inferred vulnerability. Include the evidence, a practical
remediation and a primary reference with any new rule.

## Development

Use Python 3.12 or newer in a virtual environment:

```sh
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy src
pytest --cov=scopeweaver --cov-report=term-missing --cov-report=xml
python -m build
```

Coverage includes branches and has an 85% gate. Do not lower the gate to merge a change.
Tests are guarded against external network use. Add actual loopback services for transport
behavior and narrow pure tests for analysis rules. Do not add a public host to a test fixture.

## Pull requests

Explain the concrete input, previous behavior, new behavior and verification. Keep scope
policy changes separate from unrelated checks. For a false positive, provide the smallest
sanitized response or export that reproduces it. Never attach actual passwords, session
cookies, private AD exports or production assessment reports to an issue.

Network modules must use `Transport`; do not create sockets, HTTP clients, DNS resolvers,
subprocesses or implicit proxy connections in a built-in module. Account for each extra
request in its documentation. Plugins are trusted local Python code, not sandboxed code.

Do not add credential extraction, exploitation, authentication guessing, persistence,
evasion or automatic traversal into services discovered outside scope. Preserve the
operator's ability to stop a run and retain completed evidence.

## Compatibility and releases

CI is configured for Ubuntu and Windows on Python 3.12–3.14. A configured workflow is not
evidence that it ran. Follow [the release checklist](docs/RELEASING.md) before promoting a
candidate to a stable version. Keep config/export schemas versioned and document changes.
