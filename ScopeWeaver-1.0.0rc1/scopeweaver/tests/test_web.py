import json

import pytest
from aiohttp import web

from scopeweaver.core.scope import Target
from scopeweaver.core.transport import HTTPResponse
from scopeweaver.modules.web import WebPlugin, analyze_cors, analyze_response


def response(headers=(), body="", url="https://lab.test/", status=200):
    return HTTPResponse(url, status, tuple(headers), body, False, "127.0.0.1")


def test_missing_headers_only_flag_applicable_content():
    findings = analyze_response(response([("Content-Type", "application/json")]))
    assert {f.title for f in findings} == {
        "HSTS missing or disabled",
        "Content type sniffing is not disabled",
    }
    findings = analyze_response(response([("Content-Type", "text/html")], url="http://lab.test/"))
    assert not any(f.title == "HSTS missing or disabled" for f in findings)
    assert any("CSP" in f.title for f in findings)


def test_effective_headers_do_not_create_false_findings():
    headers = [
        ("Content-Type", "text/html"),
        ("Strict-Transport-Security", "max-age=31536000"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ]
    assert analyze_response(response(headers)) == []


@pytest.mark.parametrize("hsts", ["max-age=0", "max-age=abc", "includeSubDomains"])
def test_invalid_hsts(hsts):
    assert any(
        f.title == "HSTS missing or disabled"
        for f in analyze_response(response([("Strict-Transport-Security", hsts)]))
    )


def test_cookie_values_are_never_persisted():
    findings = analyze_response(
        response([("Set-Cookie", "session=VERY_SECRET_VALUE; SameSite=None")])
    )
    serialized = json.dumps([f.model_dump(mode="json") for f in findings])
    assert "VERY_SECRET_VALUE" not in serialized
    cookie = next(f for f in findings if "Cookie session" in f.title)
    assert "SameSite=None requires Secure" in cookie.evidence["review"]


def test_secure_cookie_and_diagnostic_disclosure():
    headers = [
        ("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax"),
        ("Content-Type", "text/html"),
        ("Server", "Fixture/1.0"),
    ]
    findings = analyze_response(
        response(headers, "<h1>Index of /</h1>Traceback (most recent call last):")
    )
    titles = {f.title for f in findings}
    assert "Directory index exposed" in titles
    assert "Application diagnostic output exposed" in titles
    assert "Server software metadata advertised" in titles
    assert not any(title.startswith("Cookie") for title in titles)
    assert all(f.cwe and f.remediation and f.references for f in findings)


@pytest.mark.parametrize(
    "origin,credentials,expected",
    [("*", "true", "Info"), ("*", "false", None), ("https://trusted.test", "true", None)],
)
def test_cors_avoids_claiming_public_api_exposure(origin, credentials, expected):
    snapshot = response(
        [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", credentials)]
    )
    findings = analyze_cors(snapshot, snapshot)
    assert (findings[0].severity.value if findings else None) == expected


@pytest.mark.integration
async def test_web_end_to_end_safe_methods_cors_and_redaction(
    config, web_server, transport_factory
):
    requests = []

    async def handler(request):
        requests.append(request.method)
        headers = {
            "Access-Control-Allow-Origin": request.headers.get("Origin", "https://trusted.test"),
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": "sid=DO_NOT_STORE",
        }
        if request.method == "OPTIONS":
            headers["Allow"] = "GET, OPTIONS, PUT, DELETE, TRACE"
        return web.Response(
            text="<html><h1>Index of /</h1></html>", content_type="text/html", headers=headers
        )

    url, port = await web_server(handler)
    config.scope.ports = [port]
    result = await WebPlugin().run(Target.parse(url), transport_factory())
    assert result.status == "completed"
    assert requests == ["GET", "GET", "GET", "OPTIONS"]
    assert "DO_NOT_STORE" not in result.model_dump_json()
    titles = {f.title for f in result.findings}
    assert "Arbitrary origins accepted with credentials" in titles
    assert "Advertised HTTP methods require review" in titles
    assert "Directory index exposed" in titles


@pytest.mark.integration
async def test_web_redirect_stops_further_probes(config, web_server, transport_factory):
    async def handler(request):
        return web.Response(status=301, headers={"Location": "https://external.invalid/"})

    url, port = await web_server(handler)
    config.scope.ports = [port]
    transport = transport_factory()
    result = await WebPlugin().run(Target.parse(url), transport)
    assert transport.operations == 1
    assert result.observations["http"]["redirect_followed"] is False


async def test_web_requires_explicit_url(transport_factory):
    with pytest.raises(ValueError, match="explicit"):
        await WebPlugin().run(Target.parse("127.0.0.1"), transport_factory())
