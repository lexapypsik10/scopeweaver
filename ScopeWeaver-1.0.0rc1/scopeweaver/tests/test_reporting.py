import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from scopeweaver.core.models import Assessment, ModuleResult, Service, Severity, finding
from scopeweaver.reporting.engine import (
    code_block,
    html_report,
    load_report,
    markdown_report,
    write_reports,
)


def make_report():
    issue = finding(
        "web",
        "<script>alert(1)</script>",
        "test",
        "unsafe <img src=x onerror=alert(1)>",
        Severity.HIGH,
        "A finding",
        {"banner": "```\n<script>alert(1)</script>\n```"},
        "Fix it",
        "CWE-200",
        ["javascript:alert(1)", "https://owasp.org/"],
    )
    result = ModuleResult(
        module="web",
        target="test",
        findings=[issue, issue],
        services=[Service(host="lab.test", ip="127.0.0.1", port=80, state="open")],
        observations={"note": "<iframe src=x></iframe>"},
    )
    return Assessment(results=[result], finished_at=datetime.now(UTC), scope={"mode": "fixture"})


def test_reports_roundtrip_correct_counts_and_safe_rendering(tmp_path):
    report = make_report()
    paths = write_reports(report, tmp_path)
    assert len(paths) == 3
    parsed = load_report(tmp_path / "assessment.json")
    assert len(parsed.findings) == 1
    assert parsed.statistics["High"] == 1
    data = json.loads((tmp_path / "assessment.json").read_text())
    assert data["summary"]["open_services"] == 1
    html = (tmp_path / "assessment.html").read_text()
    assert "<script>" not in html and "<iframe" not in html
    assert 'href="javascript:' not in html
    assert "&lt;script&gt;" in html
    assert "Content-Security-Policy" in html
    md = (tmp_path / "assessment.md").read_text()
    assert "Executive Summary" in md and "Technical Evidence" in md
    assert "````" in md
    assert "<script>" in md  # Only inside a longer evidence fence.


def test_report_collision_no_silent_overwrite_and_format_validation(tmp_path):
    report = make_report()
    paths = write_reports(report, tmp_path, ["json"])
    before = paths[0].read_bytes()
    with pytest.raises(FileExistsError):
        write_reports(report, tmp_path)
    assert paths[0].read_bytes() == before
    write_reports(report, tmp_path, ["json"], overwrite=True)
    with pytest.raises(ValueError, match="formats"):
        write_reports(report, tmp_path / "other", ["pdf"])


def test_report_rejects_tampered_summary_and_unknown_fields(tmp_path):
    write_reports(make_report(), tmp_path, ["json"])
    path = tmp_path / "assessment.json"
    data = json.loads(path.read_text())
    data["summary"]["findings"] = 999
    path.write_text(json.dumps(data))
    with pytest.raises(ValidationError, match="summary"):
        load_report(path)


def test_empty_report_has_explicit_limitations():
    report = Assessment()
    assert "No findings" in html_report(report)
    assert "No findings" in markdown_report(report)
    assert code_block("a````b").startswith("`````\n")
