import json

import pytest
from pydantic import ValidationError

from scopeweaver.core.config import Config, ScopeConfig, load_config, normalize_domain
from scopeweaver.core.errors import ScopeViolation
from scopeweaver.core.scope import ScopeManager, Target


@pytest.mark.parametrize(
    "value,host,port",
    [
        ("127.0.0.1", "127.0.0.1", None),
        ("::1", "::1", None),
        ("https://LAB.test/path", "lab.test", 443),
        ("http://[::1]:8000/", "::1", 8000),
        ("LAB.test.", "lab.test", None),
        ("пример.рф", "xn--e1afmkfd.xn--p1ai", None),
    ],
)
def test_target_valid(value, host, port):
    target = Target.parse(value)
    assert (target.host, target.port) == (host, port)


@pytest.mark.parametrize(
    "value",
    [
        "https://u:p@lab.test",
        "ftp://lab.test",
        "https://lab.test:0",
        "https://lab.test:99999",
        "http://lab.test/?secret=x",
        "http://lab.test/#x",
        "lab.test\n",
        "http://lab.test\\@evil.test",
        "*.test",
        "",
        "http://",
        "::1%eth0",
        "-bad.test",
        "a..test",
    ],
)
def test_target_rejects_ambiguous_or_sensitive_input(value):
    with pytest.raises(ValueError):
        Target.parse(value)


@pytest.mark.parametrize(
    "host,allowed",
    [
        ("lab.test", True),
        ("a.lab.test", True),
        ("nested.a.lab.test", True),
        ("evillab.test", False),
        ("lab.test.evil.test", False),
        ("evil.test", False),
        ("127.0.0.1", True),
        ("127.0.0.2", False),
        ("::1", True),
        ("::ffff:127.0.0.1", False),
        ("0.0.0.0", False),
        ("224.0.0.1", False),
    ],
)
def test_scope_boundary(config, host, allowed):
    scope = ScopeManager(config.scope)
    if allowed:
        scope.host(host)
    else:
        with pytest.raises(ScopeViolation):
            scope.host(host)


def test_wildcard_never_includes_apex():
    scope = ScopeManager(ScopeConfig(domains=["*.lab.test"]))
    scope.host("x.lab.test")
    with pytest.raises(ScopeViolation):
        scope.host("lab.test")


def test_scope_requires_name_and_ip_and_port(config):
    scope = ScopeManager(config.scope)
    scope.endpoint("lab.test", "127.0.0.1", 8000)
    for args in [
        ("lab.test", "203.0.113.5", 8000),
        ("evil.test", "127.0.0.1", 8000),
        ("lab.test", "127.0.0.1", 22),
    ]:
        with pytest.raises(ScopeViolation):
            scope.endpoint(*args)
    with pytest.raises(ScopeViolation):
        scope.dns_server("127.0.0.1", 53)
    with pytest.raises(ScopeViolation):
        scope.whois_server("lab.test", "127.0.0.1", 43)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": "2"},
        {"scan_ports": [22]},
        {"scan_ports": []},
        {"dns_types": ["AXFR"]},
        {"subdomains": ["a.b"]},
        {"unknown": True},
        {"limits": {"concurrency": 0}},
        {"limits": {"max_operations": 0}},
    ],
)
def test_invalid_config_fails_closed(config, change):
    data = config.model_dump(mode="json")
    data.update(change)
    with pytest.raises(ValidationError):
        Config.model_validate(data)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"networks": ["127.0.0.1/24"]},
        {"domains": ["*"]},
        {"ports": [0]},
        {"dns": {"servers": ["dns.test"]}},
    ],
)
def test_scope_config_validation(kwargs):
    with pytest.raises(ValidationError):
        ScopeConfig(**kwargs)


def test_round_trip_and_size_limit(config, tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(config.model_dump_json())
    assert load_config(path) == config
    path.write_text(json.dumps({"padding": "x" * 1_048_576}))
    with pytest.raises(ValueError, match="exceeds"):
        load_config(path)


@pytest.mark.parametrize("value", ["", " a.test", "a.test ", "a\ttest", "a..test"])
def test_normalization_rejects_invalid(value):
    with pytest.raises(ValueError):
        normalize_domain(value)
