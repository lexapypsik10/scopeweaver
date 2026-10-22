from __future__ import annotations

import re
from collections.abc import Mapping
from http.cookies import CookieError, SimpleCookie

from scopeweaver.core.errors import BudgetExceeded, ScopeWeaverError, StopRequested
from scopeweaver.core.models import Finding, ModuleResult, Severity, finding
from scopeweaver.core.scope import Target
from scopeweaver.core.transport import HTTPResponse, Transport
from scopeweaver.utils.text import safe_text
from scopeweaver.utils.tls import audit_tls

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
OWASP_CORS = "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"


def analyze_response(response: HTTPResponse) -> list[Finding]:
    findings: list[Finding] = []
    target = response.url
    https = target.startswith("https://")
    html = "text/html" in response.header("Content-Type").lower()

    def add(
        rule: str,
        title: str,
        severity: Severity,
        description: str,
        evidence: Mapping[str, object],
        remedy: str,
        cwe: str = "CWE-693",
    ) -> None:
        findings.append(
            finding(
                "web",
                target,
                rule,
                title,
                severity,
                description,
                dict(evidence),
                remedy,
                cwe,
                [OWASP_HEADERS, f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"],
            )
        )

    if 200 <= response.status < 300:
        if https:
            hsts = response.header("Strict-Transport-Security")
            max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
            if not max_age or int(max_age[1]) == 0:
                add(
                    "hsts",
                    "HSTS missing or disabled",
                    Severity.LOW,
                    "The response does not establish an effective HTTPS-only browser policy.",
                    {"Strict-Transport-Security": safe_text(hsts) or "absent"},
                    "Set an appropriate nonzero Strict-Transport-Security max-age after testing HTTPS.",
                    "CWE-319",
                )
        if response.header("X-Content-Type-Options").lower() != "nosniff":
            add(
                "nosniff",
                "Content type sniffing is not disabled",
                Severity.LOW,
                "The response lacks an effective X-Content-Type-Options policy.",
                {"X-Content-Type-Options": safe_text(response.header("X-Content-Type-Options"))},
                "Send X-Content-Type-Options: nosniff and accurate Content-Type values.",
            )
        if html:
            csp = response.header("Content-Security-Policy")
            if not csp:
                add(
                    "csp",
                    "HTML response has no enforced CSP",
                    Severity.LOW,
                    "CSP defense in depth is absent. This is not evidence of an XSS vulnerability.",
                    {"Content-Type": response.header("Content-Type")},
                    "Deploy a tested nonce- or hash-based Content Security Policy.",
                )
            xfo = response.header("X-Frame-Options").upper()
            if xfo not in {"DENY", "SAMEORIGIN"} and not re.search(
                r"(?:^|;)\s*frame-ancestors\s+",
                csp,
                re.I,
            ):
                add(
                    "framing",
                    "HTML response has no framing restriction",
                    Severity.LOW,
                    "No X-Frame-Options or CSP frame-ancestors directive was observed.",
                    {"X-Frame-Options": safe_text(xfo), "frame-ancestors": "absent"},
                    "Set CSP frame-ancestors to the required allowlist or use X-Frame-Options: DENY.",
                    "CWE-1021",
                )
            if not response.header("Referrer-Policy"):
                add(
                    "referrer",
                    "Referrer policy relies on browser defaults",
                    Severity.INFO,
                    "An explicit policy can make referrer handling consistent across clients.",
                    {"Referrer-Policy": "absent"},
                    "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter suitable policy.",
                    "CWE-200",
                )
    for raw in response.values("Set-Cookie"):
        cookies = SimpleCookie()
        try:
            cookies.load(raw)
        except CookieError:
            continue
        for name, cookie in cookies.items():
            flags = {
                "secure": bool(cookie["secure"]),
                "httponly": bool(cookie["httponly"]),
                "samesite": str(cookie["samesite"]).lower() or "absent",
            }
            missing = []
            if not flags["secure"]:
                missing.append("Secure")
            if not flags["httponly"]:
                missing.append("HttpOnly")
            if flags["samesite"] not in {"strict", "lax", "none"}:
                missing.append("SameSite")
            if flags["samesite"] == "none" and not flags["secure"]:
                missing.append("SameSite=None requires Secure")
            if missing:
                add(
                    "cookie-" + name,
                    f"Cookie {safe_text(name)} needs security flag review",
                    Severity.LOW,
                    "Cookie attributes may permit unnecessary exposure. "
                    "Confirm whether this cookie contains sensitive state; values are never recorded.",
                    {"cookie_name": safe_text(name), "flags": flags, "review": missing},
                    "Use Secure for HTTPS cookies, HttpOnly for cookies not needed by JavaScript, "
                    "and an appropriate explicit SameSite policy.",
                    "CWE-614",
                )
    if html and re.search(r"<(?:title|h1)[^>]*>\s*Index of\s+/", response.body, re.I):
        add(
            "directory-listing",
            "Directory index exposed",
            Severity.MEDIUM,
            "The response contains a conventional directory autoindex heading.",
            {"matched_heading": "Index of /", "status": response.status},
            "Disable directory autoindex and restrict access to unintended files.",
            "CWE-548",
        )
    disclosure_patterns = [
        r"Traceback \(most recent call last\):",
        r"Fatal error:\s*Uncaught",
        r"Microsoft\.AspNetCore\.Diagnostics\.DeveloperExceptionPageMiddleware",
        r"System\.Data\.SqlClient\.SqlException",
    ]
    for pattern in disclosure_patterns:
        match = re.search(pattern, response.body, re.I)
        if match:
            add(
                "debug-disclosure",
                "Application diagnostic output exposed",
                Severity.MEDIUM,
                "The response contains a framework or interpreter diagnostic marker.",
                {"marker": safe_text(match[0])},
                "Disable public debug pages and return generic errors with private server-side logs.",
                "CWE-209",
            )
            break
    versions = {
        name: safe_text(response.header(name))
        for name in ("Server", "X-Powered-By", "X-AspNet-Version")
        if response.header(name)
    }
    if versions:
        add(
            "server-disclosure",
            "Server software metadata advertised",
            Severity.INFO,
            "Headers disclose self-reported server software; this does not establish vulnerable versions.",
            versions,
            "Minimize unnecessary version headers and keep software patched.",
            "CWE-200",
        )
    return findings


def analyze_cors(first: HTTPResponse, second: HTTPResponse) -> list[Finding]:
    origins = ("https://scopeweaver-a.invalid", "https://scopeweaver-b.invalid")
    reflected = all(
        response.header("Access-Control-Allow-Origin") == origin
        for response, origin in zip((first, second), origins, strict=True)
    )
    credentials = all(
        response.header("Access-Control-Allow-Credentials").lower() == "true"
        for response in (first, second)
    )
    if reflected and credentials:
        return [
            finding(
                "web",
                first.url,
                "cors-reflection",
                "Arbitrary origins accepted with credentials",
                Severity.MEDIUM,
                "Two distinct untrusted origins were reflected with credentials enabled. "
                "Exposure of authenticated data still requires application-specific validation.",
                {
                    "probes": [
                        {
                            "origin": origin,
                            "allow_origin": response.header("Access-Control-Allow-Origin"),
                            "allow_credentials": response.header(
                                "Access-Control-Allow-Credentials"
                            ),
                        }
                        for response, origin in zip((first, second), origins, strict=True)
                    ]
                },
                "Validate origins against an exact trusted allowlist and limit credentialed CORS.",
                "CWE-942",
                [OWASP_CORS, "https://cwe.mitre.org/data/definitions/942.html"],
            )
        ]
    if first.header("Access-Control-Allow-Origin") == "*" and credentials:
        return [
            finding(
                "web",
                first.url,
                "cors-invalid-wildcard",
                "Invalid wildcard credentialed CORS policy",
                Severity.INFO,
                "Browsers reject wildcard origins for credentialed CORS; "
                "this response alone is not an authenticated data exposure.",
                {"allow_origin": "*", "allow_credentials": "true"},
                "Use explicit trusted origins with credentials, or disable credentials for public resources.",
                "CWE-942",
                [OWASP_CORS],
            )
        ]
    return []


class WebPlugin:
    name = "web"
    description = "Read-only headers, CORS, cookies, TLS, diagnostics and advertised methods"

    async def run(self, target: Target, transport: Transport) -> ModuleResult:
        if target.url is None:
            raise ValueError("web module requires an explicit http:// or https:// target")
        result = ModuleResult(module=self.name, target=target.url)
        try:
            if target.url.startswith("https://") and target.port:
                try:
                    tls, findings = await audit_tls(transport, target.host, target.port, self.name)
                    result.observations["tls"] = tls
                    result.findings.extend(findings)
                except (BudgetExceeded, StopRequested):
                    raise
                except ScopeWeaverError as exc:
                    result.errors.append(str(exc))
            root = await transport.request(target.url)
            result.observations["http"] = {
                "status": root.status,
                "ip": root.ip,
                "body_truncated": root.truncated,
                "redirect_followed": False,
                "cookie_values_stored": False,
            }
            result.findings.extend(analyze_response(root))
            if 300 <= root.status < 400:
                result.observations["skipped"] = "Redirects are reported, never followed."
                return result
            first = await transport.request(target.url, origin="https://scopeweaver-a.invalid")
            second = await transport.request(target.url, origin="https://scopeweaver-b.invalid")
            result.findings.extend(analyze_cors(first, second))
            options = await transport.request(target.url, method="OPTIONS")
            methods = sorted(
                {v.strip().upper() for v in options.header("Allow").split(",") if v.strip()}
            )
            result.observations["http_methods"] = {
                "status": options.status,
                "advertised": methods,
                "verified_by_execution": False,
            }
            review = sorted(set(methods) & {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"})
            if 200 <= options.status < 300 and review:
                result.findings.append(
                    finding(
                        "web",
                        target.url,
                        "methods",
                        "Advertised HTTP methods require review",
                        Severity.INFO,
                        "OPTIONS advertises methods which may be legitimate API operations. "
                        "No state-changing method was executed and authorization was not tested.",
                        {"advertised": review, "executed": ["GET", "OPTIONS"]},
                        "Restrict methods and enforce authentication and authorization where required.",
                        "CWE-749",
                        ["https://owasp.org/www-project-web-security-testing-guide/"],
                    )
                )
        except (BudgetExceeded, StopRequested) as exc:
            result.status = "interrupted"
            result.errors.append(str(exc))
            transport.stopped.set()
        except ScopeWeaverError as exc:
            result.errors.append(str(exc))
        if result.errors and result.status != "interrupted":
            result.status = "partial" if result.observations or result.findings else "error"
        return result
