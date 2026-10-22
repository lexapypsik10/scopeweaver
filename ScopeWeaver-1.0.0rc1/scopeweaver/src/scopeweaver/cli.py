from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from scopeweaver import __version__
from scopeweaver.core.config import Config, ScopeConfig, load_config
from scopeweaver.core.engine import Engine
from scopeweaver.core.errors import ScopeWeaverError
from scopeweaver.core.logger import AuditLogger
from scopeweaver.core.models import Assessment, ModuleResult
from scopeweaver.core.plugins import builtin_registry
from scopeweaver.core.scope import Target
from scopeweaver.modules.active_directory import ADExport, audit_export
from scopeweaver.modules.passwords import PasswordDataset, audit_dataset, synthetic_lab
from scopeweaver.reporting import load_report, write_reports

app = typer.Typer(no_args_is_help=True, help="ScopeWeaver — scope-enforced security assessment.")
ad_app = typer.Typer(no_args_is_help=True, help="Offline Active Directory snapshot audit.")
password_app = typer.Typer(no_args_is_help=True, help="Offline synthetic password assessment.")
app.add_typer(ad_app, name="ad")
app.add_typer(password_app, name="passwords")
console = Console(highlight=False)
errors = Console(stderr=True, highlight=False)


def guarded[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return function(*args, **kwargs)
        except ValidationError as exc:
            # Never print the input of a failed validation: it may contain sample secrets.
            detail = "; ".join(
                f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
                for e in exc.errors(include_input=False)
            )
            errors.print("Configuration/input error: " + detail, style="red", markup=False)
            raise typer.Exit(2) from exc
        except (ScopeWeaverError, OSError, ValueError) as exc:
            errors.print("Error: " + str(exc), style="red", markup=False)
            raise typer.Exit(2) from exc
        except KeyboardInterrupt as exc:
            errors.print("Stopped by operator.", style="yellow")
            raise typer.Exit(130) from exc

    return wrapper


def banner() -> None:
    console.print(
        Panel(
            "S C O P E W E A V E R\nAuthorized security assessment\n" + __version__,
            border_style="cyan",
            expand=False,
        )
    )


def display(report: Assessment, paths: list[Path]) -> None:
    table = Table(title="Assessment results")
    table.add_column("Severity")
    table.add_column("Findings", justify="right")
    colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
        "Info": "cyan",
    }
    for severity, count in report.statistics.items():
        table.add_row(severity, str(count), style=colors[severity])
    console.print(table)
    for result in report.results:
        console.print(f"{result.module}: {result.status} — {result.target}", markup=False)
        for error in result.errors:
            errors.print(error, style="yellow", markup=False)
    for path in paths:
        console.print(str(path.resolve()), markup=False)


def read_input(path: Path) -> str:
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("offline input exceeds 20 MiB")
    return path.read_text(encoding="utf-8-sig")


def finish_offline(result: ModuleResult, output: Path, overwrite: bool) -> None:
    report = Assessment(
        scope={"mode": "offline", "dataset": result.target},
        results=[result],
        finished_at=datetime.now(UTC),
    )
    audit = AuditLogger(output / "audit.jsonl", report.run_id)
    try:
        audit.event(
            "offline_audit", module=result.module, target=result.target, status=result.status
        )
        paths = write_reports(report, output, overwrite=overwrite)
    finally:
        audit.close()
    display(report, paths)
    if result.status != "completed":
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(version: Annotated[bool, typer.Option("--version", is_eager=True)] = False) -> None:
    """Assess only assets and infrastructure explicitly allowed by the operator."""
    if version:
        console.print(f"ScopeWeaver {__version__}")
        raise typer.Exit()


@app.command("modules")
def modules() -> None:
    """List the five assessment modules and the reporting engine."""
    banner()
    table = Table(title="Modules")
    table.add_column("Command")
    table.add_column("Purpose")
    for name, desc in [
        ("run --module recon", "DNS, WHOIS, HTTP hints, TLS, TCP"),
        ("run --module network", "TCP connect scan and service inventory"),
        ("run --module web", "Read-only web configuration audit"),
        ("ad audit", "Offline AD policy, groups, delegation and ACE review"),
        ("passwords audit / lab", "Synthetic password and policy analysis"),
        ("report", "JSON, Markdown and HTML reporting"),
    ]:
        table.add_row(name, desc)
    console.print(table)


@app.command("init-config")
@guarded
def init_config(path: Annotated[Path, typer.Argument()] = Path("scope.json")) -> None:
    """Create a conservative loopback-only JSON configuration (never overwrite)."""
    config = Config(
        scope=ScopeConfig(networks=["127.0.0.1/32", "::1/128"], ports=[8000, 8443]),
        scan_ports=[8000, 8443],
    )
    with path.open("x", encoding="utf-8") as stream:
        stream.write(config.model_dump_json(indent=2) + "\n")
    console.print(f"Created {path}. Review scope before use.", markup=False)


@app.command("validate")
@guarded
def validate(config: Annotated[Path, typer.Option("--config", "-c", exists=True)]) -> None:
    """Validate a configuration without performing network I/O or importing plugins."""
    settings = load_config(config)
    console.print(
        f"Valid configuration: {len(settings.scope.networks)} networks; "
        f"{len(settings.scope.domains)} domain rules; "
        f"{settings.limits.max_operations} operation budget."
    )


@app.command("run")
@guarded
def run(
    config: Annotated[Path, typer.Option("--config", "-c", exists=True)],
    target: Annotated[
        list[str], typer.Option("--target", "-t", help="Repeat for multiple explicit hosts/URLs.")
    ],
    module: Annotated[
        list[str], typer.Option("--module", "-m", help="recon, network, web or enabled plugin")
    ],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("reports/latest"),
    overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
) -> None:
    """Run bounded network checks. Ctrl+C saves completed evidence and returns 130."""
    settings = load_config(config)
    targets = list(dict.fromkeys(Target.parse(t) for t in target))
    registry = builtin_registry()
    registry.load_external(settings.enabled_plugins)
    # Preflight output collisions before any target activity.
    if not overwrite and any(
        (output / f"assessment.{ext}").exists() for ext in ("json", "md", "html")
    ):
        raise FileExistsError("report exists; choose a new --output or use --overwrite")
    banner()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task(
            "Assessing approved targets...", total=len(targets) * len(set(module))
        )

        def completed(name: str, status: str) -> None:
            progress.update(task, advance=1, description=f"{name}: {status}")

        report = asyncio.run(Engine(settings, registry).run(targets, module, completed))
    paths = write_reports(report, output, overwrite=overwrite)
    display(report, paths)
    if report.interrupted:
        raise typer.Exit(130)
    if any(r.status != "completed" for r in report.results):
        raise typer.Exit(1)


@ad_app.command("audit")
@guarded
def ad_audit(
    input_file: Annotated[Path, typer.Option("--input", "-i", exists=True)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("reports/ad"),
    overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
) -> None:
    """Analyze a normalized JSON export; never connect to a domain controller."""
    finish_offline(
        audit_export(ADExport.model_validate_json(read_input(input_file))), output, overwrite
    )


@password_app.command("audit")
@guarded
def password_audit(
    input_file: Annotated[Path, typer.Option("--input", "-i", exists=True)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("reports/passwords"),
    overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
) -> None:
    """Assess synthetic samples from a JSON file; no passwords in command-line arguments."""
    finish_offline(
        audit_dataset(PasswordDataset.model_validate_json(read_input(input_file))),
        output,
        overwrite,
    )


@app.command("lab")
@guarded
def lab(
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("reports/lab"),
    overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
) -> None:
    """Run a fully offline synthetic password lab and generate three reports."""
    banner()
    finish_offline(audit_dataset(synthetic_lab()), output, overwrite)


@app.command("report")
@guarded
def report_command(
    input_file: Annotated[Path, typer.Argument(exists=True)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("reports/export"),
    format_: Annotated[str, typer.Option("--format", "-f")] = "all",
    overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
) -> None:
    """Regenerate HTML/Markdown/JSON from a validated ScopeWeaver JSON report."""
    formats = ["json", "md", "html"] if format_ == "all" else [format_]
    report = load_report(input_file)
    display(report, write_reports(report, output, formats, overwrite=overwrite))
