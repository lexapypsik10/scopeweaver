# Local validation record

Date: 2026-10-22. Version: 1.0.0rc1. This record describes executed checks,
not an assurance that all possible targets or platforms behave identically.

## Environment

- Python: 3.12.14
- Platform: Linux x86_64
- Source-tree SHA-256 (relative path, NUL, file bytes, NUL, sorted Python sources):
  `ab1d8b754bb815f37b7e56e35303366c77abcf756172547a1c4eeb57c35e1c63`

## Executed checks

| Check | Observed result |
| --- | --- |
| `pytest -q --cov=scopeweaver --cov-report=term-missing:skip-covered --cov-report=xml` | 123 passed; 95.48% combined statement/branch coverage; 85% gate passed |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed |
| `mypy src` | Passed; 23 source files, strict mode |
| `python -m build` | Built sdist and platform-independent wheel |
| Clean-environment wheel installation | Installed into a separate venv; import came from site-packages |
| Clean wheel smoke checks | `python -m scopeweaver --version`, `lab`, and JSON-to-HTML `report` |
| `uv pip check` in wheel environment | All installed dependencies compatible |
| Eight captured CLI scenarios | All exited 0; local web fixture plus offline synthetic inputs |

See `CLI_TRANSCRIPT.txt` for captured command output and `examples/sample-reports/` for
actual reports from the intentionally misconfigured loopback web fixture. Sample counts
are laboratory observations, not a benchmark or an estimate of production vulnerabilities.

## Scope of verification

Tests use real loopback TCP/UDP/HTTP/TLS services and guard socket egress against external
addresses. They cover domain/IP/port rejection, DNS rebinding answers, UDP-to-TCP fallback,
HTTP redirect refusal, proxy/cookie isolation, operation budgets, pacing, stop/cancellation,
trusted plugin opt-in, offline policies, nested groups, legacy TLS handshakes, report
counts, HTML escaping and Markdown evidence-fence injection.

No real third-party network, production domain, password corpus or live WHOIS provider
was scanned. WHOIS transport was tested with a fragmented local fixture. No authentication
attacks, credential collection, exploitation or hidden access is implemented.

## Not executed here

- GitHub-hosted CI; workflows are configured, not recorded as green.
- Native Windows, Kali, Debian or Ubuntu distribution-specific installation runs.
- The optional RSAT PowerShell collector against an Active Directory environment.
- Independent penetration testing of this framework or exhaustive TLS/cipher analysis.

These gaps are why the delivered release is a candidate. See RELEASING.md before a stable
v1.0.0 announcement. The framework and distributions are ready for source review and
publication to a new repository; no GitHub repository or visibility was modified.
