# Reproducible examples

| File | Purpose |
| --- | --- |
| `scope-loopback.json` | Working local scope for ports 8000 and 8443 on loopback only |
| `scope-isolated-lab.json` | Documentation-only lab addresses; review and replace before use |
| `local_web_lab.py` | Intentionally misconfigured HTTP fixture bound to 127.0.0.1 |
| `ad-synthetic.json` | Synthetic AD policy, nested memberships, account flags and permission evidence |
| `passwords-synthetic.json` | Explicit synthetic samples; no real credentials |
| `export_ad.ps1` | Optional read-only RSAT collector, not executed in the Linux validation environment |
| `schemas/` | JSON Schemas generated from the actual validation models |
| `sample-reports/` | Actual JSON/HTML/Markdown output from the loopback HTTP fixture |

The primary README contains runnable commands. The sample web report is deliberately
vulnerable laboratory evidence, not a third-party scan or a claim about a production system.
Captured output is in `docs/CLI_TRANSCRIPT.txt`; local quality evidence is in `docs/VALIDATION.md`.
