# Architecture and boundary decisions

Candidate names were ScopeWeaver, AuditHarbor, BoundaryForge, LanternScope and TraceWard.
ScopeWeaver was selected because explicit scope connects every collection module to one
shared execution boundary. Name availability and trademarks have not been independently checked.

## Data flow

`CLI → validated Config + Target → Engine → Plugin → Transport → approved endpoint`

Results use Pydantic models shared by the online and offline modules. The reporting engine
renders the same validated assessment into a JSON document, Markdown and self-contained
HTML. The JSON envelope includes an assessment and a recomputed summary. Loading a report
rejects a summary that disagrees with its underlying evidence; this is not a signature.

## Components

| Component | Responsibility |
| --- | --- |
| `core/config.py` | Strict JSON schema, sensible limits and cross-field validation |
| `core/scope.py` | Canonical targets, exact/wildcard domain policy, IP and port checks |
| `core/transport.py` | Explicit DNS, pinned HTTP/TCP, global pacing/budget, bounded reads |
| `core/engine.py` | Module scheduling, error isolation, cancellation and completed evidence |
| `core/plugins.py` | Built-in registry and explicitly enabled Python entry points |
| `core/logger.py` | Flushed structured audit events; fail closed on unavailable logging |
| `modules/*` | Evidence collection and rule evaluation |
| `reporting/engine.py` | Severity counts, deduplication, safe rendering and no-clobber writes |

Typer provides discoverable, typed commands; Rich provides readable progress and result
tables. asyncio supplies cancellation and concurrency on all target platforms. aiohttp is
used with a one-address resolver and a fresh connector per HTTP operation. dnspython sends
queries directly to a configured numeric DNS endpoint; there is no system-resolver fallback.
cryptography decodes certificates obtained by the bounded TLS transport. Jinja autoescapes
all target-controlled HTML content; a restrictive CSP also limits report capabilities.

## Scope semantics

1. A numeric target must belong to an explicit CIDR. A hostname must match an explicit
   domain rule, and **every** A/AAAA answer must belong to an explicit CIDR.
2. `lab.example` matches only that name. `*.lab.example` matches descendants, not the apex.
   There is no suffix guessing, public suffix lookup or implicit inclusion of sibling names.
3. A target port must be listed in `scope.ports`; `scan_ports` must be a subset.
4. DNS endpoints are authorized independently by exact numeric address and configured
   port. WHOIS endpoints are authorized independently for an exact target domain.
5. Discovered names, CNAMEs, service metadata and WHOIS referrals are evidence, not scope
   extensions. No HTTP redirect is followed. Subdomain labels must be explicitly configured
   **and** the resulting name must match the scope rules.
6. Every network operation is checked before queueing and again immediately before I/O.
   The global operation budget includes DNS queries, TCP attempts, HTTP requests and TLS
   handshakes. UDP-to-TCP DNS fallback consumes an additional operation.

Rate limiting spaces operation starts globally; it does not permit an initial burst.
Concurrency bounds in-flight operations, not the number of checks configured. The budget
has no automatic retries or reset per module. The first configured DNS server is used;
additional entries are reserved for manual operator changes, not automatic failover.

## Failure and interruption

Normal refused TCP connections are inventory observations. Timeouts are inconclusive
reachability observations. Module failures do not discard other completed module results.
Budget exhaustion and a stop request mark the assessment interrupted; CLI returns 130.
The stop-file watcher runs at a 100 ms interval and cancels in-flight work. Reports are
written after execution, not continuously checkpointed. Some observations in a cancelled
in-flight module can be lost; completed module results are retained.

## Extension trust

The registry accepts an asynchronous `run(Target, Transport) → ModuleResult` implementation.
Entry points are imported only after explicit configuration. External plugins run with the
operator's process privileges; native sockets or subprocesses inside a plugin can bypass
framework controls. Do not treat Python interfaces as an isolation mechanism.

Offline AD permissions are normalized ACE observations. Windows effective access, deny ACE
precedence, GUID-specific rights, cross-domain trusts, resultant fine-grained policies and
complete attack-path analysis are outside the implementation. Unknown fields are reported
as unknown, and unsupported export schemas fail validation.
