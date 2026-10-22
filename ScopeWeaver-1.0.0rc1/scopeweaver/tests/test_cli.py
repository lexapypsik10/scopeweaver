import json

import pytest
from typer.testing import CliRunner

from scopeweaver.cli import app
from scopeweaver.modules.passwords import synthetic_lab
from scopeweaver.reporting import load_report

runner = CliRunner()


@pytest.mark.parametrize(
    "args,contains",
    [
        (["--help"], "ScopeWeaver"),
        (["run", "--help"], "--target"),
        (["--version"], "1.0.0rc1"),
        (["modules"], "Modules"),
    ],
)
def test_cli_help_and_version(args, contains):
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert contains in result.output


def test_init_validate_and_refuse_overwrite(tmp_path):
    path = tmp_path / "scope.json"
    assert runner.invoke(app, ["init-config", str(path)]).exit_code == 0
    assert runner.invoke(app, ["validate", "-c", str(path)]).exit_code == 0
    assert runner.invoke(app, ["init-config", str(path)]).exit_code == 2
    path.write_text('{"scope":{"networks":["bad"]}}')
    bad = runner.invoke(app, ["validate", "-c", str(path)])
    assert bad.exit_code == 2 and "Traceback" not in bad.output


def test_lab_and_report_regeneration(tmp_path):
    result = runner.invoke(app, ["lab", "-o", str(tmp_path / "lab")])
    assert result.exit_code == 0, result.output
    report = load_report(tmp_path / "lab/assessment.json")
    assert report.network_operations == 0
    result = runner.invoke(
        app,
        [
            "report",
            str(tmp_path / "lab/assessment.json"),
            "-o",
            str(tmp_path / "export"),
            "-f",
            "html",
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "export/assessment.html").exists()
    assert runner.invoke(app, ["lab", "-o", str(tmp_path / "lab")]).exit_code == 2


def test_password_command_and_validation_redacts_input(tmp_path):
    path = tmp_path / "samples.json"
    data = synthetic_lab().model_dump(mode="json")
    data["samples"] = [{"id": "fixture", "value": "UniqueSyntheticValue321"}]
    path.write_text(json.dumps(data))
    result = runner.invoke(
        app, ["passwords", "audit", "-i", str(path), "-o", str(tmp_path / "out")]
    )
    assert result.exit_code == 0, result.output
    assert "UniqueSyntheticValue321" not in result.output
    data["samples"][0]["value"] = "PRIVATE_SENTINEL" * 100
    path.write_text(json.dumps(data))
    result = runner.invoke(
        app, ["passwords", "audit", "-i", str(path), "-o", str(tmp_path / "bad")]
    )
    assert result.exit_code == 2
    assert "PRIVATE_SENTINEL" not in result.output


def test_cli_network_scope_denial_never_connects(config, tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(config.model_dump_json())
    result = runner.invoke(
        app,
        [
            "run",
            "-c",
            str(path),
            "-m",
            "network",
            "-t",
            "203.0.113.1",
            "-o",
            str(tmp_path / "denied"),
        ],
    )
    assert result.exit_code == 1, result.output
    report = load_report(tmp_path / "denied/assessment.json")
    assert report.network_operations == 0
