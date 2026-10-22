# Configuration

Configuration is JSON, schema version `1.0`. Unknown fields fail validation. Generated
schemas are in `examples/schemas/`. Paths resolve against the current working directory,
not automatically against the configuration file's directory.

| Scope field | Meaning |
| --- | --- |
| `scope.networks` | Explicit strict CIDRs; `/32` for one IPv4 address, `/128` for IPv6 |
| `scope.domains` | Exact names or explicit `*.example.test` descendant rules |
| `scope.ports` | Allowed target TCP ports |
| `scope.dns.servers` | Approved numeric DNS endpoints; the first is used |
| `scope.dns.port` | DNS UDP/TCP port, independent of the target port allowlist |
| `scope.whois` | Map an exact domain to an approved numeric `{ip, port}` endpoint |
| `scan_ports` | Requested scan ports, all within `scope.ports` |
| `subdomains` | Single labels to query beneath an explicit target domain |
| `dns_types` | A, AAAA, MX, NS, TXT, SOA, CAA, CNAME or SRV; no AXFR/ANY |

DNS/WHOIS endpoints are explicit infrastructure exceptions, not target scope extensions.
There is no infrastructure hostname bootstrap. The approved DNS resolver may perform
recursion as part of its own service. Direct host connections still require all answers
to fit `scope.networks`. Discovered names and WHOIS referrals are never followed implicitly.

| Control | Default | Bound/behavior |
| --- | ---: | --- |
| `limits.concurrency` | 4 | 1–32 in-flight operations |
| `limits.requests_per_second` | 2 | More than 0, up to 50; global paced starts |
| `limits.max_operations` | 200 | 1–100000 for the entire run |
| `limits.timeout` | 4 s | More than 0, up to 60 s per operation |
| `limits.max_response_bytes` | 131072 | 256–1048576; HTTP/WHOIS read limit |
| `limits.max_targets` | 32 | 1–1000 explicit targets |
| `whois_enabled` | false | Requires an approved endpoint per domain |
| `tls_legacy_probes` | false | Adds two TLS-only handshake attempts |
| `ca_file` | null | Optional PEM trust anchor for a permitted lab |
| `audit_log` | `scopeweaver-audit.jsonl` | Must be writable before activity |
| `stop_file` | null | An existing file cancels activity; remove before resuming |
| `enabled_plugins` | empty | Explicit trusted installed entry-point names |

A numeric-URL web audit normally uses four HTTP operations. HTTPS adds a TLS inspection
handshake; a rejected certificate may add a separate certificate-only handshake. Each
hostname resolution adds A/AAAA queries, and a truncated UDP DNS response adds a TCP
operation. Recon also performs the configured record queries and selected port scan.

Proxy variables are ignored and there is no insecure-HTTP switch. Trust a lab CA with
`ca_file`. Approve a redirected destination as a separate explicit target if needed.

Create the configured stop marker with `touch STOP` on Linux or `New-Item STOP -ItemType File`
on PowerShell. The watcher polls during execution; it is not a background automation.
