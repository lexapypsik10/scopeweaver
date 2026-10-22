from __future__ import annotations

import ssl
import warnings
from datetime import UTC, datetime
from typing import Any

from cryptography import x509

from scopeweaver.core.errors import NetworkError
from scopeweaver.core.models import Finding, Severity, finding
from scopeweaver.core.transport import Transport


async def audit_tls(
    transport: Transport,
    host: str,
    port: int,
    module: str,
) -> tuple[dict[str, Any], list[Finding]]:
    ip = (await transport.resolve(host))[0]
    label = f"{host}:{port}"
    findings: list[Finding] = []
    context = ssl.create_default_context(cafile=transport.config.ca_file)
    verified = True
    metadata: dict[str, Any] = {}
    try:
        _, metadata = await transport.exchange(
            host, ip, port, ssl_context=context, connect_only=True
        )
    except NetworkError as exc:
        if not isinstance(exc.__cause__, ssl.SSLCertVerificationError):
            if not transport.config.tls_legacy_probes:
                raise
            verified = False
            metadata["modern_handshake_error"] = str(exc)
        else:
            verified = False
            verification_error = exc.__cause__.verify_message
            findings.append(
                finding(
                    module,
                    label,
                    "tls-certificate",
                    "TLS certificate validation failed",
                    Severity.MEDIUM,
                    "The platform trust store rejected the certificate or hostname.",
                    {"verification_error": verification_error},
                    "Deploy a valid certificate, correct SANs and a complete trusted certificate chain.",
                    "CWE-295",
                )
            )
            diagnostic = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            diagnostic.check_hostname = False
            diagnostic.verify_mode = ssl.CERT_NONE
            try:
                _, metadata = await transport.exchange(
                    host,
                    ip,
                    port,
                    ssl_context=diagnostic,
                    connect_only=True,
                )
            except NetworkError as diagnostic_error:
                metadata["diagnostic_handshake_error"] = str(diagnostic_error)
    der = metadata.pop("certificate_der", None)
    observation: dict[str, Any] = {"ip": ip, "verified": verified, **metadata}
    if der:
        cert = x509.load_der_x509_certificate(der)
        observation["certificate"] = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "serial": str(cert.serial_number),
            "signature_oid": cert.signature_algorithm_oid.dotted_string,
        }
        days = (cert.not_valid_after_utc - datetime.now(UTC)).days
        if 0 <= days <= 30:
            findings.append(
                finding(
                    module,
                    label,
                    "tls-expiring",
                    "TLS certificate expires soon",
                    Severity.LOW,
                    "Certificate expiry can interrupt service and trusted connections.",
                    {"days_remaining": days},
                    "Renew the certificate and automate renewal monitoring.",
                    "CWE-324",
                )
            )
    observation["legacy_protocols"] = {"status": "not_tested", "reason": "opt-in probes disabled"}
    if transport.config.tls_legacy_probes:
        probes: dict[str, str] = {}
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            legacy.check_hostname = False
            legacy.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                legacy.minimum_version = legacy.maximum_version = version
            try:
                legacy.set_ciphers("DEFAULT:@SECLEVEL=0")
                _, data = await transport.exchange(
                    host,
                    ip,
                    port,
                    ssl_context=legacy,
                    connect_only=True,
                )
            except (NetworkError, ssl.SSLError) as exc:
                probes[version.name] = f"not_negotiated; inconclusive ({type(exc).__name__})"
            else:
                probes[version.name] = f"accepted: {data.get('version')}"
                findings.append(
                    finding(
                        module,
                        label,
                        f"legacy-{version.name}",
                        "Deprecated TLS protocol accepted",
                        Severity.MEDIUM,
                        "A dedicated handshake negotiated an obsolete protocol.",
                        {"negotiated": data.get("version")},
                        "Require TLS 1.2 or TLS 1.3.",
                        "CWE-327",
                        ["https://datatracker.ietf.org/doc/html/rfc8996"],
                    )
                )
        observation["legacy_protocols"] = probes
    return observation, findings
