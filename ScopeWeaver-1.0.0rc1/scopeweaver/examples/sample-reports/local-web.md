# ScopeWeaver security assessment

## Executive Summary

Run: 7ac0a989-b305-45d8-90d8-31b03121af2f · Version: 1.0.0rc1

Findings: **9** · Open services: **1** · Incomplete module results: **0**

Interrupted: **False** · Network operations: **5**

Observed configuration only; absence of findings is not proof of security.

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 4 |
| Info | 3 |

## Scope

```
{
  "domains": [],
  "networks": [
    "127.0.0.1/32",
    "::1/128"
  ],
  "ports": [
    8000,
    8443
  ],
  "dns": {
    "servers": [],
    "port": 53
  },
  "whois": {}
}
```

## Service Inventory

| Host | IP | Port | State | Service | Detection |
| --- | --- | ---: | --- | --- | --- |
| 127.0.0.1 | 127.0.0.1 | 8000 | open | unknown | port convention only; not verified |

## Findings

### Arbitrary origins accepted with credentials

**Medium** · SW-337a49ca8e456034 · http://127.0.0.1:8000/

Two distinct untrusted origins were reflected with credentials enabled. Exposure of authenticated data still requires application-specific validation.

**Technical Evidence**

```
{
  "probes": [
    {
      "origin": "https://scopeweaver-a.invalid",
      "allow_origin": "https://scopeweaver-a.invalid",
      "allow_credentials": "true"
    },
    {
      "origin": "https://scopeweaver-b.invalid",
      "allow_origin": "https://scopeweaver-b.invalid",
      "allow_credentials": "true"
    }
  ]
}
```

**Remediation**: Validate origins against an exact trusted allowlist and limit credentialed CORS.

**CWE**: CWE-942

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-community/attacks/CORS\_OriginHeaderScrutiny · https://cwe.mitre.org/data/definitions/942.html

### Directory index exposed

**Medium** · SW-d57277ab8930232c · http://127.0.0.1:8000/

The response contains a conventional directory autoindex heading.

**Technical Evidence**

```
{
  "matched_heading": "Index of /",
  "status": 200
}
```

**Remediation**: Disable directory autoindex and restrict access to unintended files.

**CWE**: CWE-548

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-secure-headers/ · https://cwe.mitre.org/data/definitions/548.html

### HTML response has no enforced CSP

**Low** · SW-08bb8f9ab63bcc44 · http://127.0.0.1:8000/

CSP defense in depth is absent. This is not evidence of an XSS vulnerability.

**Technical Evidence**

```
{
  "Content-Type": "text/html; charset=utf-8"
}
```

**Remediation**: Deploy a tested nonce- or hash-based Content Security Policy.

**CWE**: CWE-693

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-secure-headers/ · https://cwe.mitre.org/data/definitions/693.html

### Cookie lab\_session needs security flag review

**Low** · SW-4fcf0c5c7c09e101 · http://127.0.0.1:8000/

Cookie attributes may permit unnecessary exposure. Confirm whether this cookie contains sensitive state; values are never recorded.

**Technical Evidence**

```
{
  "cookie_name": "lab_session",
  "flags": {
    "secure": false,
    "httponly": false,
    "samesite": "absent"
  },
  "review": [
    "Secure",
    "HttpOnly",
    "SameSite"
  ]
}
```

**Remediation**: Use Secure for HTTPS cookies, HttpOnly for cookies not needed by JavaScript, and an appropriate explicit SameSite policy.

**CWE**: CWE-614

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-secure-headers/ · https://cwe.mitre.org/data/definitions/614.html

### HTML response has no framing restriction

**Low** · SW-6f395dd25146a71e · http://127.0.0.1:8000/

No X-Frame-Options or CSP frame-ancestors directive was observed.

**Technical Evidence**

```
{
  "X-Frame-Options": "",
  "frame-ancestors": "absent"
}
```

**Remediation**: Set CSP frame-ancestors to the required allowlist or use X-Frame-Options: DENY.

**CWE**: CWE-1021

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-secure-headers/ · https://cwe.mitre.org/data/definitions/1021.html

### Content type sniffing is not disabled

**Low** · SW-d8ddc370c1bbd4d4 · http://127.0.0.1:8000/

The response lacks an effective X-Content-Type-Options policy.

**Technical Evidence**

```
{
  "X-Content-Type-Options": ""
}
```

**Remediation**: Send X-Content-Type-Options: nosniff and accurate Content-Type values.

**CWE**: CWE-693

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-secure-headers/ · https://cwe.mitre.org/data/definitions/693.html

### Advertised HTTP methods require review

**Info** · SW-73514b4bb9797f9c · http://127.0.0.1:8000/

OPTIONS advertises methods which may be legitimate API operations. No state-changing method was executed and authorization was not tested.

**Technical Evidence**

```
{
  "advertised": [
    "PUT"
  ],
  "executed": [
    "GET",
    "OPTIONS"
  ]
}
```

**Remediation**: Restrict methods and enforce authentication and authorization where required.

**CWE**: CWE-749

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-web-security-testing-guide/

### Referrer policy relies on browser defaults

**Info** · SW-d1c5b566ba50e84d · http://127.0.0.1:8000/

An explicit policy can make referrer handling consistent across clients.

**Technical Evidence**

```
{
  "Referrer-Policy": "absent"
}
```

**Remediation**: Set Referrer-Policy: strict-origin-when-cross-origin or a stricter suitable policy.

**CWE**: CWE-200

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-secure-headers/ · https://cwe.mitre.org/data/definitions/200.html

### Server software metadata advertised

**Info** · SW-f41c2a8308ed6473 · http://127.0.0.1:8000/

Headers disclose self-reported server software; this does not establish vulnerable versions.

**Technical Evidence**

```
{
  "Server": "ScopeWeaver-Lab/1.0"
}
```

**Remediation**: Minimize unnecessary version headers and keep software patched.

**CWE**: CWE-200

**CVSS**: Not assigned; context required

**References**: https://owasp.org/www-project-secure-headers/ · https://cwe.mitre.org/data/definitions/200.html


## Module Evidence and Limitations

### network · 127.0.0.1 · completed

```
{
  "observations": {
    "technique": "TCP connect; no authentication; passive banners",
    "attempted": 1,
    "unattempted": 0
  },
  "errors": []
}
```

### web · http://127.0.0.1:8000/ · completed

```
{
  "observations": {
    "http": {
      "status": 200,
      "ip": "127.0.0.1",
      "body_truncated": false,
      "redirect_followed": false,
      "cookie_values_stored": false
    },
    "http_methods": {
      "status": 204,
      "advertised": [
        "GET",
        "OPTIONS",
        "PUT"
      ],
      "verified_by_execution": false
    }
  },
  "errors": []
}
```

