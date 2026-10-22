<div align="center">

# 🔴 SCOPEWEAVER

### Authorized Security Assessment Framework

**Explicit scope · Read-only checks · Reviewable evidence**

Python 3.12+ · AsyncIO · Typer · Rich · MIT

[Overview](#-overview) · [Modules](#-modules) · [Installation](#-installation) · [Usage](#-usage) · [Documentation](#-documentation)

</div>

---

> [!CAUTION]
> **AUTHORIZED TESTING ONLY**
>
> Use ScopeWeaver only within an explicitly approved scope.
> Authorization must cover both target systems and auxiliary DNS/WHOIS services.

## 🔴 Overview

ScopeWeaver is a modular Python framework for security assessments, reconnaissance and configuration audits.

It combines network and web checks with offline Active Directory analysis and synthetic password assessment. Results include technical evidence, risk severity, remediation guidance and references.

Every built-in network operation passes through a shared transport that enforces scope, request limits, timeouts and audit logging.

**Current version: `1.0.0rc1` — release candidate.**

## 🔴 Modules

| Module | Capabilities |
| --- | --- |
| **Reconnaissance** | DNS records, explicit subdomain queries, direct WHOIS, HTTP technology hints and TLS inspection |
| **Network Assessment** | Async TCP connect scanning, passive banners, reachability and service inventory |
| **Web Audit** | Security headers, CORS, cookie flags, directory listings, diagnostic disclosures and advertised HTTP methods |
| **Active Directory** | Offline policy review, Kerberos settings, privileged memberships, delegation and normalized permission analysis |
| **Password Assessment** | Synthetic password patterns, substitutions, repetition, contextual terms and policy review |
| **Reporting** | JSON, Markdown and self-contained HTML reports |

Findings distinguish observed configurations from assumptions that require further validation.

## 🔴 Installation

Requires **Python 3.12 or newer**.

From the project directory on Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .

scopeweaver --help
```

On Windows:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install .

.venv\Scripts\scopeweaver.exe --help
```

## 🔴 Usage

### Explore available modules

```bash
scopeweaver modules
```

### Run the offline laboratory

```bash
scopeweaver lab --output reports/lab
```

Open `reports/lab/assessment.html` to review the generated report.

### Create and validate a scope

```bash
scopeweaver init-config scope.json
scopeweaver validate --config scope.json
```

The generated configuration permits loopback addresses and ports **8000/8443** only. Review it before approving other targets.

### Audit the local web fixture

Start the synthetic fixture:

```bash
python examples/local_web_lab.py --port 8000
```

Run the assessment in another terminal:

```bash
scopeweaver run \
  --config examples/scope-loopback.json \
  --target http://127.0.0.1:8000/ \
  --module web \
  --module network \
  --output reports/local-web
```

### Analyze a synthetic AD export

```bash
scopeweaver ad audit \
  --input examples/ad-synthetic.json \
  --output reports/ad
```

### Assess synthetic passwords

```bash
scopeweaver passwords audit \
  --input examples/passwords-synthetic.json \
  --output reports/passwords
```

Password values and hashes are excluded from assessment results.

## 🔴 Scope Controls

- Explicit IP, domain and port allowlists
- Hostname checks against every returned A/AAAA address
- Connections pinned to a vetted numeric address
- Explicit DNS and WHOIS infrastructure endpoints
- Global operation budgets and request pacing
- Bounded response reads and connection timeouts
- Structured JSONL audit logs
- Ctrl+C cancellation and an optional stop file

HTTP redirects are not followed automatically. Cookies are not replayed, and environment proxy settings are ignored.

External plugins are explicitly enabled, trusted Python code. The plugin system is not a sandbox.

## 🔴 Reports

Each assessment can produce:

```text
assessment.json
assessment.md
assessment.html
```

Reports include:

- Executive summary and approved scope
- Discovered services and module status
- Severity and technical evidence
- CWE identifiers and reference links
- Remediation recommendations
- Finding counts and assessment limitations

CVSS scores are left unassigned when the available evidence does not establish the required context.

## 🔴 Validation

Local verification on **Linux / Python 3.12.14**:

| Check | Result |
| --- | --- |
| Automated tests | **123 passed** |
| Combined statement and branch coverage | **95.48%** |
| Ruff lint and formatting | **Passed** |
| Strict mypy checks | **Passed** |
| Wheel and source distribution build | **Passed** |
| Clean-environment wheel smoke checks | **Passed** |

Integration tests use real loopback DNS, TCP, HTTP and TLS fixtures. Test guards reject accidental external network activity.

GitHub Actions is configured for Ubuntu and Windows across Python 3.12–3.14. Remote CI results and native target-platform validation remain release gates.

See [the validation record](docs/VALIDATION.md) for details.

## 🔴 Limitations

ScopeWeaver does not implement exploitation, credential extraction, password guessing, persistence, lateral movement or monitoring evasion.

AD analysis consumes normalized offline exports and does not calculate Windows effective access. Password scores are explainable heuristics, not entropy measurements or cracking-time predictions.

A completed assessment with no findings is not proof that a system is secure.

## 🔴 Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Active Directory exports](docs/AD_EXPORT.md)
- [Plugin development](docs/PLUGINS.md)
- [Reproducible CLI output](docs/CLI_TRANSCRIPT.txt)
- [Examples](examples/)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release checklist](docs/RELEASING.md)

---

<div align="center">

**🔴 SCOPEWEAVER**

Explicit scope. Traceable checks. Reviewable evidence.

Released under the [MIT License](LICENSE).

</div>
