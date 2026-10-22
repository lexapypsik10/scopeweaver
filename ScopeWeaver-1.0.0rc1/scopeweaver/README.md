# ScopeWeaver

**Scope-enforced security assessments with evidence you can review.**

ScopeWeaver combines explicit-target reconnaissance, TCP inventory, safe web configuration
checks, offline Active Directory review and synthetic password analysis. Every built-in
network operation shares a scope policy, rate limit, operation budget and audit log.
Reports distinguish verified observations from hints requiring a human review.

**1.0.0rc1 · Python 3.12+ · MIT**

This is a working release candidate, not a published GitHub/PyPI release. Local verification
is recorded in [VALIDATION.md](docs/VALIDATION.md). CI is configured for Ubuntu and Windows;
remote CI success is not claimed. No build-status or coverage-service badge is fabricated.

## Implemented modules

| Module | Behavior | Boundary |
| --- | --- | --- |
| Reconnaissance | Explicit DNS record/subdomain queries, direct WHOIS, HTTP stack hints, TLS metadata, TCP inventory | No search-engine scraping, automatic referrals or scope expansion |
| Network | Async TCP connect scan, passive banners, service hints, reachability, obsolete SSH banner review | No SYN scans, authentication, version-to-CVE guessing or evasion |
| Web | Headers, two-origin CORS, cookie flags, TLS, directory indexes, debug disclosures, OPTIONS | GET/OPTIONS only; advertised unsafe methods are never executed |
| Active Directory | Exported policy, flags, Kerberos settings, nested privileged groups, delegation and normalized ACEs | Offline JSON; no domain authentication or effective-access simulation |
| Passwords | Policy review, common fragments, substitutions, repetition, keyboard/year/season/context patterns | Synthetic data only; heuristic scores are not entropy or cracking time |
| Reporting | Executive summary, scope, inventory, severity, CWE, evidence, remediation, statistics | JSON, Markdown, escaped self-contained HTML; CVSS remains null without context |

## Install

Extract the archive and enter its `scopeweaver` directory. On Kali, Ubuntu or Debian,
use an available Python **3.12 or newer** in a virtual environment:

```sh
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
scopeweaver --help
scopeweaver --version
```

If the distribution separates venv support, install its `python3-venv` package first.
Do not replace the system Python or use `sudo pip`.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\scopeweaver.exe --help
```

Installation requires a configured Python package index or an offline wheel cache.
DNS/WHOIS require separately approved infrastructure; offline audits make no requests
after installation. Target platforms are Kali, Ubuntu, Debian and Windows. See the
validation record for the narrower set actually exercised in this delivery.

## First run: offline laboratory

```sh
scopeweaver modules
scopeweaver lab --output reports/lab
scopeweaver report reports/lab/assessment.json --format html --output reports/reexport
```

Open `reports/lab/assessment.html`. The lab uses explicitly synthetic samples; password
values and hashes never appear in results. [CLI_TRANSCRIPT.txt](docs/CLI_TRANSCRIPT.txt)
contains captured command output. [examples](examples/) contains reproducible inputs.

## Local web and network assessment

Start the intentionally misconfigured loopback fixture in one terminal:

```sh
python examples/local_web_lab.py --port 8000
```

In another terminal:

```sh
scopeweaver validate --config examples/scope-loopback.json
scopeweaver run --config examples/scope-loopback.json \
  --target http://127.0.0.1:8000/ --module web --module network \
  --output reports/local-web
```

The fixture binds only to `127.0.0.1` and contains no real files or credentials. A silent
TCP service is still reported open. A conventional port is a service hint until actual
protocol evidence exists; the scanner does not invent product versions.

For another approved environment, create and review a configuration first:

```sh
scopeweaver init-config scope.json
scopeweaver validate --config scope.json
scopeweaver run --config scope.json --target 127.0.0.1 --module network --output reports/inventory
```

`init-config` allows loopback and ports 8000/8443 only. It approves no real environment.
Read [CONFIGURATION.md](docs/CONFIGURATION.md) before replacing values. Repeat `--target`
or `--module` for explicit inputs; there is no automatic CIDR expansion.

## Explicit scope

- Numeric targets require an allowed IP/CIDR and port.
- Hostnames require a matching domain rule and **every A/AAAA answer** to fit the IP
  allowlist. Mixed allowed/disallowed answers are rejected in full.
- DNS uses an approved numeric resolver; system DNS is never a fallback.
- WHOIS requires an approved endpoint per exact domain; referrals are not followed.
- HTTP connections are pinned. Redirects are not followed, cookies are not replayed
  and environment proxies are ignored.
- The operation budget counts DNS, TCP attempts, HTTP and TLS globally.
- Legacy TLS probes are opt-in. Failed negotiation is inconclusive; cipher-suite
  enumeration is not implemented.

Isolated-lab example addresses are documentation values, not discovered infrastructure.
Use only with authorization covering both targets and auxiliary services.

## Offline AD and password audits

```sh
scopeweaver ad audit --input examples/ad-synthetic.json --output reports/ad
scopeweaver passwords audit --input examples/passwords-synthetic.json --output reports/passwords
```

AD accepts the normalized schema in [AD_EXPORT.md](docs/AD_EXPORT.md), not arbitrary
BloodHound/LDAP dumps. The optional read-only PowerShell collector requires RSAT; its
execution was not tested in this Linux session. Unknown encryption settings remain unknown.
Group cycles terminate, unresolved members make evidence partial, and ACEs are review
items rather than proven effective privileges.

Password files must declare `"synthetic": true`; do not supply production credentials.
The analyzer uses a small explainable pattern set. A high score is not proof of strength.
Policy review distinguishes MFA context and treats composition/rotation rules as review
items rather than reliable substitutes for length, blocklists and MFA.

## Reports, logs and exit codes

Runs write `assessment.json`, `assessment.md` and `assessment.html`. Existing reports are
refused unless `--overwrite` is explicit. Stable finding IDs deduplicate summary counts.
No context-free CVSS number is invented. HTML autoescapes evidence and has a restrictive
CSP with no external assets.

Network runs append JSONL to `audit_log`. Offline commands write `audit.jsonl` in their
output directory. Cookies are redacted; AD/WHOIS metadata can still be sensitive.

| Code | Meaning |
| --- | --- |
| 0 | Selected checks completed; findings may exist |
| 1 | At least one module failed or has incomplete evidence |
| 2 | Invalid input/configuration, unavailable plugin or file/output error |
| 130 | Operator cancellation, stop file or global budget exhaustion |

Press Ctrl+C once to stop and retain completed module results. The configured stop file
is checked every 100 ms during execution. Forced termination can prevent final output.
See [SECURITY.md](SECURITY.md) for the trust model and data-handling limits.

## Development

```sh
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy src
pytest --cov=scopeweaver --cov-report=term-missing --cov-report=xml
python -m build
```

Tests use actual loopback DNS/TCP/HTTP/TLS fixtures and reject accidental external egress.
The coverage gate is 85%, including branches. CI has read-only repository permissions and
does not publish packages or change settings.

[ARCHITECTURE.md](docs/ARCHITECTURE.md) explains design and scope;
[PLUGINS.md](docs/PLUGINS.md) documents opt-in entry points. Plugins run trusted local
Python code and are not sandboxed. See [CONTRIBUTING.md](CONTRIBUTING.md),
[RELEASING.md](docs/RELEASING.md) and the [MIT license](LICENSE).

## Primary references

- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Microsoft UserAccountControl](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)
- [Microsoft constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft RC4 remediation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
